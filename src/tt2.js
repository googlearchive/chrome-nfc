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


function TT2() {
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
        /* TODO: assume the first TLV is NDEF and only one TLV existed. */
        switch (card[0x10]) {
        case 0x00:  /* NULL */
          console.log("[ERROR] NULL TLV.");
          return;
        case 0xFE:  /* Terminator */
          console.log("[ERROR] Terminator TLV.");
          return;
        case 0x03: /* NDEF */
          var len = card[0x11];
          if ((len + 0x12) > card.length) {
            console.log("[WARN] TLV len " + len + " > card len " + card.length);
          }
          return callback(0, new Uint8Array(card.subarray(0x12, 0x12 + len)).buffer);
        default:
          console.log("[ERROR] bad ... I assume the first TLV is NDEF, but " +
                      card[0x10]);
          return;
        }
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
