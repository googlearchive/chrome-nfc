/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0
  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @fileoverview 
 */

'use strict';


function TT2(tag_id) {
  this.tag_id = new Uint8Array(tag_id);
  this.type_name = null;  // vendor and its card name

  /*
   * TODO: detect at beginning -- if we have a reliable way to detect.
   *   this.detect_type_name(cb);
  */

  this.lock_contorl = [];
}

TT2.prototype.detect_type_name = function(cb) {
  var self = this;
  var callback = cb;

  if (this.tag_id[0] == 0x04) {
    // NxP, Try to read page 0x10. If success, it is Ultralight C.
    this.device.read_block(0x10, function(rc, bn) {
      if (rc) {
        self.type_name = "Mifare Ultralight";
      } else {
        self.type_name = "Mifare Ultralight C";
      }

      console.log("[DEBUG] TT2.type_name = " + self.type_name);
      if (callback) callback();
    });
  }
}


// read NFC Type 2 tag spec 1.0 for memory structure.
// The callback is called with cb(NDEF Uint8Array).
TT2.prototype.read = function(device, cb) {
  var self = this;
  if (!cb) cb = defaultCallback;
  var callback = cb;

  function poll_block0(rc, b0_b3) {
    if (rc) return callback(rc);

    var card = new Uint8Array(b0_b3);
    var data = new Uint8Array(b0_b3);
    var data_size = data[14] * 8;  // CC2: unit is 8 bytes.
    var CC0 = data[12];            // CC0: 0xE1 = NDEF
    var CC1 = data[13];            // CC1: version of this Type 2 tag spec.
    var CC3 = data[15];            // CC3: b7-b4: read permission.

    function check_ver(cc1) {
      var major = (cc1 & 0xf0 ) >> 4;
      var minor = cc1 & 0x0f;
      if (major == 0x1) return true;
      return false;
    }
    function readable(cc3) {
      return (cc3 & 0xf0) == 0x00 ? true : false;
    }

    /* TODO: support protocol other than NDEF */
    if (CC0 != 0xE1 || !check_ver(CC1) || !readable(CC3)) {
      console.log("UNsupported type 2 tag: CC0=" + CC0 +
                                        ", CC1=" + CC1 +
                                        ", CC3=" + CC3);
      return callback(0x0777, data.buffer);
    }

    // poll data out
    var poll_n = Math.floor((data_size + 15) / 16);
    var block = 4;  // data starts from block 4

    function poll_block(card, block, poll_n) {
      console.log("[DEBUG] poll_n: " + poll_n);
      if (--poll_n < 0) {
        defaultCallback("[DEBUG] got a type 2 tag:", card.buffer);

        /* TODO: call tlv.js instead */
        /* TODO: now pass NDEF only. Support non-NDEF in the future. */
        for (var i = 0x10; i < card.length;) {
          switch (card[i]) {
          case 0x00:  /* NULL */
            console.debug("NULL TLV");
            i++;
            break;

          case 0x01:  /* Lock Control TLV */
            console.debug("Lock Control TLV");

            /* TODO: refactor and share code with Memory Control TLV */
            var PageAddr = card[i + 2] >> 4;
            var ByteOffset = card[i + 2] & 0xf;
            var Size = card[i + 3];
            if (Size == 0) Size = 256;  /* 256 bits */
            var BytesPerPage = Math.pow(2, card[i + 4] & 0xf);
            var BytesLockedPerLockBit = card[i + 4] >> 4;

            console.debug("Lock control: " +
                " BytesLockedPerLockBit=" + BytesLockedPerLockBit +
                ", Size=" + Size);

            var ByteAddr = PageAddr * BytesPerPage + ByteOffset;

            console.info("Lock control: ByteAddr=" + ByteAddr);
            console.info("  Locked bytes:");
            var lock_offset = 64;
            for (var j = 0; j < (Size + 7) / 8; j++) {
              var k = ByteAddr + j;

              if (k >= card.length) {
                console.warn("  card[" + k + "] haven't read out yet.");
                /* TODO: read out and continue the following parse */
                break;
              }

              var mask = card[k];
              console.debug("  [" + k + "]: " + mask.toString(16));

              if (mask & 1) console.debug("* block-locking");
              for (var l = 1; l < 8; l++) {
                if (j * 8 + l >= Size) continue;

                for (var s = "", m = 0;
                     m < BytesLockedPerLockBit;
                     lock_offset++) {
                  s += "0x" + lock_offset.toString(16) + ", ";
                }
                if (mask & (1 << l)) console.info("    " + s);
              }
            }

            i += (1/*T*/ + 1/*L*/ + card[i + 1]/*len: 3*/);
            break;

          /* TODO: 0x02 -- Memory Control TLV */

          case 0xFE:  /* Terminator */
            console.debug("Terminator TLV.");
            return;

          case 0x03: /* NDEF */
            var len = card[i + 1];
            if ((i + 2 + len) > card.length) {
              console.warn("TLV len " + len + " > card len " + card.length);
            }
            return callback(0,
                new Uint8Array(card.subarray(i + 2, i + 2 + len)).buffer);
          default:
            console.error("Unknown Type [" + card[i] + "]");
            return;
          }
        }  /* end of for */
      }

      device.read_block(block, function(rc, bn) {
        if (rc) return callback(rc);
        card = UTIL_concat(card, new Uint8Array(bn));
        return poll_block(card, block + 4, poll_n);
      });
    }
    poll_block(card, block, poll_n);
  }

  device.read_block(0, poll_block0);
}


/* Input:
 *   ndef - Uint8Array
 */
TT2.prototype.compose = function(ndef) {
  var max_len = 64 - 16;
  /*
   * TODO: CCn bytes of MF0ICU1 (MIFARE Ultralight) are OTP(One Time Program).
   *       Thus, we set the maximum available size (48 bytes).
   */
  var blen = 48 / 8;

  var tt2_header = new Uint8Array([
    0x00, 0x00, 0x00, 0x00,  /* UID0, UID1, UID2, Internal0 */
    0x00, 0x00, 0x00, 0x00,  /* UID3, UID4, UID5, UID6 */
    0x00, 0x00, 0x00, 0x00,  /* Internal1, Internal2, Lock0, Lock1 */
    0xe1, 0x10, blen, 0x00   /* CC0, CC1, CC2(len), CC3 */
  ]);
  var ndef_tlv = new Uint8Array([
    0x03, ndef.length        /* NDEF Message TLV */
  ]);
  var terminator_tlv = new Uint8Array([
    0xfe
  ]);
  var ret = UTIL_concat(tt2_header, 
            UTIL_concat(ndef_tlv,
            UTIL_concat(new Uint8Array(ndef),
                        terminator_tlv)));
  return ret;
}


// Input:
//   ndef: ArrayBuffer. Just ndef is needed. TT2 header is handled.
TT2.prototype.write = function(device, ndef, cb) {
  if (!cb) cb = defaultCallback;

  var self = this;
  var callback = cb;
  var card = self.compose(new Uint8Array(ndef));
  var card_blknum = Math.floor((card.length + 3) / 4);

  /* TODO: check memory size according to CC value */
  if (card_blknum > (64 / 4)) {
    console.log("write_tt2() card is too big (max: 64 bytes): " + card.length);
    return callback(0xbbb);
  }

  function write_block(card, block_no) {
    if (block_no >= card_blknum) { return callback(0); }

		var data = card.subarray(block_no * 4, block_no * 4 + 4);
    if (data.length < 4) data = UTIL_concat(data,
                                            new Uint8Array(4 - data.length));

    device.write_block(block_no, data, function(rc) {
      if (rc) return callback(rc);
      write_block(card, block_no + 1);
    });
  }

  /* Start from CC* fields */
  write_block(card, 3);
}


TT2.prototype.emulate = function(device, ndef_obj, timeout, cb) {
  var data = this.compose(new Uint8Array(ndef_obj.compose()));
  return device.emulate_tag(data, timeout, cb);
}
