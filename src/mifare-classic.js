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
 * @fileoverview Mifare Classic driver
 */

'use strict';

// TODO: support Classic 4K

/*
 * AN1305 - MIFARE Classic as NFC Type MIFARE Classic Tag
 *
 *          +--------------------+
 *          | Manufacturer Block |  Physical Block 0
 *          |--------------------|
 *          |   Logic block 0    |  Physical Block 1 (MAD1)
 * Sector 0 |--------------------|
 *          |   Logic block 1    |  Physical Block 2 (MAD1)
 *          |--------------------|
 *          |   Sector Trailer   |  Physical Block 3
 *        --+--------------------+
 *          |   Logic block 2    |  Physical Block 4
 *          |--------------------|
 *          |   Logic block 3    |  Physical Block 5
 * Sector 1 |--------------------|
 *          |   Logic block 4    |  Physical Block 6
 *          |--------------------|
 *          |   Sector Trailer   |  Physical Block 7
 *        --+--------------------+
 *          |   Logic block 5    |  Physical Block 8
 *          |--------------------|
 *          |   Logic block 6    |  Physical Block 9
 * Sector 2 |--------------------|
 *          |   Logic block 7    |  Physical Block 10
 *          |--------------------|
 *          |   Sector Trailer   |  Physical Block 11
 *          +--------------------+
 *          |        ...         |        ...
 *
 *
 *
 *
 *
 */

function MifareClassic(tag_id) {
  this.tag_id = new Uint8Array(tag_id);
  this.type_name = "MIFARE Classic 1K";

  this.WRITE_COMMAND = 0xA0;  // differ to type 2's 0xA2.
}

// private functions

// Logic block number to sector number
MifareClassic.prototype.log2sec = function(logic_blknum) {
  if (logic_blknum < 2) return 0;
  return Math.floor((logic_blknum - 2) / 3) + 1;
}

// Logic block number to physical block number
MifareClassic.prototype.log2phy = function(logic_blknum) {
  if (logic_blknum < 2) return logic_blknum + 1;

  var sector = this.log2sec(logic_blknum);
  return sector * 4 + ((logic_blknum - 2) % 3);
}

// input: Uint8Array
MifareClassic.prototype.mif_calc_crc8 = function(input) {
  var crc = 0xc7; // bit-swapped 0xe3

  for (var i = 0; i < input.length; i++) {
    crc = crc ^ input[i];

    for (var j = 0; j < 8; j++) {
      if (crc & 0x80)
        crc = (crc << 1) ^ 0x1d;
      else
        crc = crc << 1;
    }
  }
  return crc;
}

// input: Uint8Array
MifareClassic.prototype.mif_calc_crc16 = function(input) {
  var crc = 0xc78c;  // bit-swapped 0x31e3
  for (var i = 0; i < input.length; i++) {
    crc = crc ^ (input[i] << 8);
    for (var j = 0; j < 8; j++) {
      if (crc & 0x8000)
        crc = (crc << 1) ^ 0x1021;
      else
        crc = crc << 1;
    }
  }
  return crc;
}


/* Since the Key A is not readable so that we need to copy that from the
 * successfully authenticated key storage.
 * We keep key B all-0xff until one day we decide to use it.
 */
MifareClassic.prototype.copy_auth_keys = function(data, dev) {
  for (var i = 0; i < 6; i++) {
    data[i] = dev.auth_key[i];
  }
  // Leave KEY B as default. TODO: don't overwrite if key B is readable.
  for (var i = 0; i < 6; i++) {
    data[i + 10] = 0xff;
  }

  return data;
}


MifareClassic.prototype.read_physical = function(device, phy_block, cnt, cb) {
  var self = this;
  var callback = cb;
  var dev = device;
  var readed = new Uint8Array();  // for closure
  var max_block = 1024 / 16;  // TODO: assume Classic 1K

  if (cnt != null) max_block = phy_block + cnt;

  // Reading whole card is too long (~4secs). This function would return
  // a smaller max_block value if MAD is read and NDEF sectors are recognized.
  function fast_read(phy_block, data, max_block) {
    if (phy_block == 3 && data[0x39] != 0x69 ) {  // personalized GBP
      // TODO: check CRC in MAD.
      var nfc_cnt;
      for (nfc_cnt = 0;  // assume the NDEF is in the 1st sector.
           data[0x12 + nfc_cnt * 2 + 0] == 0x03 &&
           data[0x12 + nfc_cnt * 2 + 1] == 0xE1;
           nfc_cnt++) {};
      var new_num = (nfc_cnt + 1) * 4;
      if (new_num < max_block)
        return new_num;
      else
        return max_block;
    } else {
      return max_block;
    }
  }

  function read_next(phy_block) {
    var blk_no = phy_block;
    dev.publicAuthentication(blk_no, function(rc, data) {
      if (rc) return callback(rc);
      dev.read_block(blk_no, function(rc, bn) {
        if (rc) return callback(rc);
        var bn = new Uint8Array(bn);

        // copy KEY A with auth_key from device.
        if ((blk_no % 4) == 3) {
          bn = self.copy_auth_keys(bn, dev);
        }

        readed = UTIL_concat(readed, bn);

        max_block = fast_read(blk_no, readed, max_block);
        if ((blk_no + 1)>= max_block)
          return callback(readed);
        else
          return read_next(blk_no + 1, cb);
      });
    });
  }
  read_next(phy_block);
}


// The callback is called with cb(NDEF Uint8Array).
MifareClassic.prototype.read = function(device, cb) {
  var self = this;
  if (!cb) cb = defaultCallback;
  var callback = cb;
  var card = new Uint8Array();

  self.read_physical(device, 0, null, function(data) {
    for(var i = 0; i < Math.ceil(data.length / 16); i++) {
      console.log(UTIL_fmt("[DEBUG] Sector[" + UTIL_BytesToHex([i]) + "] " +
                  UTIL_BytesToHex(data.subarray(i * 16,
                                                i * 16 + 16))));
    }

    var GPB = data[0x39];  /* the first GPB */
    if (GPB == 0x69) {
      console.log("[DEBUG] Sector 0 is non-personalized (0x69).");
    } else {
      var DA = (GPB & 0x80) >> 7;   // MAD available: 1 for yes.
      var MA = (GPB & 0x40) >> 6;   // Multiapplication card: 1 for yes.
      var ADV = (GPB & 0x03) >> 0;  // (MAD version code: 1 for v1, 2 for v2)

      // TODO: check CRC in MAD.
      var nfc_cnt;
      for (nfc_cnt = 0;  // assume the NDEF is in the 1st sector.
           data[0x12 + nfc_cnt * 2 + 0] == 0x03 &&
           data[0x12 + nfc_cnt * 2 + 1] == 0xE1;
           nfc_cnt++) {};
      var tlv = new Uint8Array();
      for(var i = 1; i <= nfc_cnt; i++) {
        tlv = UTIL_concat(tlv, data.subarray(i * 0x40, i * 0x40 + 0x30));
      }

      // TODO: move to tlv.js
      for (var i = 0; i < tlv.length; i++) {
        switch (tlv[i]) {
        case 0x00:  /* NULL */
          console.log("[DEBUG] NULL TLV.");
          break;
        case 0xFE:  /* Terminator */
          console.log("[DEBUG] Terminator TLV.");
          return;
        case 0x03: /* NDEF */
          var len = tlv[i + 1];
          if ((len + 2) > tlv.length) {
            console.log("[WARN] Vlen:" + len + " > totla len:" + tlv.length);
          }
          return callback(0,
              new Uint8Array(tlv.subarray(i + 2, i + 2 + len)).buffer);
          /* TODO: now pass NDEF only. Support non-NDEF in the future. */
          // i += len + 1;
        default:
          console.log("[ERROR] Unsupported TLV: " + UTIL_BytesToHex(tlv[0]));
          return;
        }
      }
    }
  });
}


MifareClassic.prototype.read_logic = function(device, logic_block, cnt, cb) {
  var self = this;
  var callback = cb;
  var card = new Uint8Array();
  
  function next_logic(logic_block, cnt) {
    var blk_no = logic_block;
    var count = cnt;
    if (count <= 0) return callback(card);
    self.read_physical(device, self.log2phy(logic_block), 1, function(data) {
      card = UTIL_concat(card, data);
      next_logic(blk_no + 1, count - 1);
    });
  }
  next_logic(logic_block, cnt);
}


// TODO: support multiple data set
/* Input:
 *   ndef - Uint8Array
 *
 * Output:
 *   Whole tag image.
 */
MifareClassic.prototype.compose = function(ndef) {
  var self = this;

  /* ====== Build up TLV blocks first ====== */
  var ndef_tlv = new Uint8Array([
    0x03, ndef.length        /* NDEF Message TLV */
  ]);
  var terminator_tlv = new Uint8Array([
    0xfe
  ]);
  var TLV = UTIL_concat(ndef_tlv,
            UTIL_concat(new Uint8Array(ndef),
                        terminator_tlv));

  /* frag into sectors */
  var TLV_sector_num = Math.ceil(TLV.length / 0x30);
  var TLV_blocks = new Uint8Array();
  for (var i = 0; i < TLV_sector_num; i++) {
    TLV_blocks = UTIL_concat(TLV_blocks,
                             TLV.subarray(i * 0x30, (i + 1) * 0x30));

    var padding;
    if ((i + 1) == TLV_sector_num) {  // last sector
      padding = new Uint8Array(0x30 - (TLV.length % 0x30));
    } else {
      padding = new Uint8Array(0);
    }
    TLV_blocks = UTIL_concat(TLV_blocks, padding);
    TLV_blocks = UTIL_concat(TLV_blocks, new Uint8Array([  // Sector Trailer
      0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,  // NFC pub key
      0x7f, 0x07, 0x88, 0x40,              // access bits, GPB
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // KEY B
    ]));
  }

  /* ====== Build up MAD ====== */
  var classic_header = new Uint8Array([
    /* Manufacturer Block */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    /* MAD1 */
    0x00, 0x00, 0x03, 0xe1,  // CRC, info, AID 1
    0x00, 0x00, 0x00, 0x00,  // AID 2, AID 3
    0x00, 0x00, 0x00, 0x00,  // AID 4, AID 5
    0x00, 0x00, 0x00, 0x00,  // AID 6, AID 7
    0x00, 0x00, 0x00, 0x00,  // AID 8, AID 9
    0x00, 0x00, 0x00, 0x00,  // AID a, AID b
    0x00, 0x00, 0x00, 0x00,  // AID c, AID d
    0x00, 0x00, 0x00, 0x00,  // AID e, AID f

    /* Sector Trailer */
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,  // MAD access key
    0x78, 0x77, 0x88, 0xc1,              // access bits, GPB
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // KEY B
  ]);

  for (var i = 0; i < TLV_sector_num; i++) {
    classic_header[0x10 + (i + 1) * 2 + 0] = 0x03;
    classic_header[0x10 + (i + 1) * 2 + 1] = 0xe1;
  }
  classic_header[0x10] =
      self.mif_calc_crc8(classic_header.subarray(0x11, 0x30));

  var ret = UTIL_concat(classic_header, TLV_blocks);
  return ret;
}


// Input:
//   block_no: starting physical block number
//   data: Uint8Array of data to write. Reminding data will be write to
//         next block continously.
MifareClassic.prototype.write_physical = function(device, block_no, key,
                                                  all_data, cb) {
  var dev = device;
  var blk_no = block_no;  // for closure
  var data = all_data;
  var callback = cb;
  var self = this;

  if (data.length == 0) { return callback(0); }
  if (data.length < 16) {
    // Pad to 16 bytes
    data = UTIL_concat(data, new Uint8Array(16 - data.length));
  }

  function authenticationCallback (rc, dummy) {
    if (rc) return callback(rc);

    var block_data = data.subarray(0, 16);
    dev.write_block(blk_no, block_data, function(rc) {
      if (rc) return callback(rc);
      self.write_physical(dev, blk_no + 1, key, data.subarray(16), callback);
    }, self.WRITE_COMMAND);
  }
  if (key == null)
    dev.publicAuthentication(blk_no, authenticationCallback);
  else
    dev.privateAuthentication(blk_no, key, authenticationCallback);
}


// Input:
//   ndef: ArrayBuffer. Just ndef is needed. Classic header is handled.
MifareClassic.prototype.write = function(device, ndef, cb) {
  var self = this;
  if (!cb) cb = defaultCallback;
  var callback = cb;
  var card = self.compose(new Uint8Array(ndef));
  var dev = device;

  var max_block = Math.ceil(card.length / 16);

  if (max_block > (1024 / 16)) {
    console.log("write Classic() card is too big (max: 1024 bytes): " +
                card.length);
    return callback(0xbbb);
  }

  /* Start from MAD */
  self.write_physical(dev, 1, null, card.subarray(16), callback);
}


// Input:
//   logic_block: logic block number
//   data: Uint8Array of data to write. Reminding data will be write to
//         next block continously.
//   
// Note that the GPB will be written to no-MAD (MA=0) to fully access
// all data blocks.
MifareClassic.prototype.write_logic = function(device, logic_block,
                                               all_data, cb) {
  var self = this;
  var callback = cb;


  function write_next(device, logic_block, all_data) {
    var dev = device;
    var blk_no = logic_block;
    var data = all_data;

    if (data.length == 0) return callback(0);
  
    self.write_physical(dev, self.log2phy(blk_no), null,
                        data.subarray(0, 16),
                        function(rc) {
      if (rc) return callback(rc);

      // update the corresponding GPB to 0x00.
      var gpb_phy = self.log2sec(blk_no) * 4 + 3;
      dev.read_block(gpb_phy, function(rc, gpb_data) {
        if (rc) return callback(rc);
        var gpb_data = new Uint8Array(gpb_data);
        gpb_data = self.copy_auth_keys(gpb_data, dev);

        if (gpb_phy == 3)
          gpb_data[0x9] = 0xc1;  // the first GPB: DA=MA=1, ADV=1
        else
          gpb_data[0x9] = 0x40;  // non-first GPB: MA=1.

        dev.write_block(gpb_phy, gpb_data, function(rc) {
          // move to next block
          blk_no = blk_no + 1;
          data = data.subarray(16);
          return write_next(dev, blk_no, data);
        }, self.WRITE_COMMAND);
      });
    });
  }
  write_next(device, logic_block, all_data);
}


MifareClassic.prototype.emulate = function(device, ndef_obj, timeout, cb) {
  /* TODO: still presents as TT2 */
  var data = this.compose(new Uint8Array(ndef_obj.compose()));
  return device.emulate_tag(data, timeout, cb);
}
