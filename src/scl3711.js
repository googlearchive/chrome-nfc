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
 * @fileoverview SCL3711 USB driver.
 */

'use strict';

// Global SCL3711 instance counter.
var scl3711_id = 0;

// Worker SCL3711 instances. Tied 1-on-1 to websocket worker.
function usbSCL3711() {
  this.dev = null;
  // Pick unique channel (within process..)
  this.cid = (++scl3711_id) & 0x00ffffff;
  this.rxframes = [];
  this.rxcb = null;
  this.onclose = null;
  this.detected_tag = null;   // TODO: move this to mifare_classic.js
  this.auth_key = null;       // TODO: move this to mifare_classic.js
  this.authed_sector = null;  // TODO: move this to mifare_classic.js
  this.KEYS = [               // TODO: move this to mifare_classic.js
    new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),  // defailt
    new Uint8Array([0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7]),  // NFC Forum
    new Uint8Array([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5])   // MAD
  ];

  this.strerror = function(errno) {
    var err = {
      0x01: "time out, the target has not answered",
      0x02: "checksum error during rf communication",
      0x03: "parity error during rf communication",
      0x04: "erroneous bit count in anticollision",
      0x05: "framing error during mifare operation",
      0x06: "abnormal bit collision in 106 kbps anticollision",
      0x07: "insufficient communication buffer size",
      0x09: "rf buffer overflow detected by ciu",
      0x0a: "rf field not activated in time by active mode peer",
      0x0b: "protocol error during rf communication",
      0x0d: "overheated - antenna drivers deactivated",
      0x0e: "internal buffer overflow",
      0x10: "invalid command parameter",
      0x12: "unsupported command from initiator",
      0x13: "format error during rf communication",
      0x14: "mifare authentication error",
      0x18: "not support NFC secure",
      0x19: "i2c bus line is busy",
      0x23: "wrong uid check byte (14443-3)",
      0x25: "command invalid in current dep state",
      0x26: "operation not allowed in this configuration",
      0x27: "not acceptable command due to context",
      0x29: "released by initiator while operating as target",
      0x2a: "card ID does not match",
      0x2b: "the card previously activated has disapperaed",
      0x2c: "Mismatch between NFCID3 initiator and target in DEP 212/424 kbps",
      0x2d: "Over-current event has been detected",
      0x2e: "NAD missing in DEP frame",
      0x2f: "deselected by initiator while operating as target",
      0x31: "initiator rf-off state detected in passive mode",
      0x7F: "pn53x application level error"
    };

    if (errno in err) {
      return "[" + errno + "] " + err[errno];
    } else {
      return "Unknown error: " + errno;
    }
  };

}

// Notify callback for every frame received.
usbSCL3711.prototype.notifyFrame = function(cb) {
  if (this.rxframes.length != 0) {
    // Already have frames; continue.
    if (cb) window.setTimeout(cb, 0);
  } else {
    this.rxcb = cb;
  }
};

// Called by low level driver.
// Return true if still interested.
usbSCL3711.prototype.receivedFrame = function(frame) {
  if (!this.rxframes) return false;  // No longer interested.

  this.rxframes.push(frame);

  // Callback self in case we were waiting.
  var cb = this.rxcb;
  this.rxcb = null;
  if (cb) window.setTimeout(cb, 0);

  return true;
};

// Return oldest frame. Throw if none.
usbSCL3711.prototype.readFrame = function() {
  if (this.rxframes.length == 0) throw 'rxframes empty!' ;

  var frame = this.rxframes.shift();
  return frame;
};

// Poll from rxframes[], reconstruct entire message.
// timeout in seconds.
usbSCL3711.prototype.read = function(timeout, cb) {
  if (!this.dev){ cb(1); return; }

  var tid = null;  // timeout timer id.
  var callback = cb;
  var self = this;

  // Schedule call to cb if not called yet.
  function schedule_cb(a, b, c) {
    if (tid) {
      // Cancel timeout timer.
      window.clearTimeout(tid);
      tid = null;
    }
    var C = callback;
    if (C) {
      callback = null;
      window.setTimeout(function() { C(a, b, c); }, 0);
    }
  };

  function read_timeout() {
    if (!callback || !tid) return;  // Already done.

    console.log(UTIL_fmt(
        '[' + self.cid.toString(16) + '] timeout!'));

    tid = null;
  };

  function read_frame() {
    if (!callback || !tid) return;  // Already done.

    var f = new Uint8Array(self.readFrame());

    // http://www.nxp.com/documents/user_manual/157830_PN533_um080103.pdf
    // Section 7.1 ACK frame.
    if (f.length == 6 &&
        f[0] == 0x00 &&
        f[1] == 0x00 &&
        f[2] == 0xff &&
        f[3] == 0x00 &&
        f[4] == 0xff &&
        f[5] == 0x00) {
      // Expected positive ack, read more.
      self.notifyFrame(read_frame);
      return;  // wait for more.
    }

    // Change the ACR122 response to SCL3711 format.
    if (f.length > 10) {
      if (f[0] == 0x80 /* RDR_to_PC_Datablock */) {
        f = UTIL_concat(
              new Uint8Array([0x00, 0x00, 0xff, 0x01, 0xff]),
              new Uint8Array(f.subarray(10)));
      } else if (f[0] == 0x83 /* RDR_to_PC_Escape */) {
        f = UTIL_concat(
              new Uint8Array([0x00, 0x00, 0xff, 0x01, 0xff]),
              new Uint8Array(f.subarray(10)));
      }
    }

    // TODO: implement NACK frame? Error frame?
    // TODO: preamble and postamble frames?

    // TODO: check data checksum?
    // TODO: short cut. Will leave to callback to handle.
    if (f.length == 7) {
      if (f[5] == 0x90 &&
          f[6] == 0x00) {
        /* ACR122U - operation is success. */
        schedule_cb(0, f.buffer);
        return;
      } else if (f[5] == 0x63 &&
                 f[6] == 0x00) {
        /* ACR122U - operation is failed. */
        schedule_cb(0xaaa, f.buffer);
        return;
      }
    } else if (f.length > 6 &&
        f[0] == 0x00 &&
        f[1] == 0x00 &&
        f[2] == 0xff &&
        f[3] + f[4] == 0x100 /* header checksum */) {
      if (f[5] == 0xd5 &&
          f[6] == 0x41 /* InDataExchange reply */) {
        if (f[7] == 0x00 /* status */) {
          schedule_cb(0, new Uint8Array(f.subarray(8, f.length - 2)).buffer);
        } else {
          console.log("ERROR: InDataExchange reply status = " +
                      self.strerror(f[7]));
        }
        return;
      } else if (f[5] == 0xd5 &&
                 f[6] == 0x8d /* TgInitAsTarget reply */) {
        /* TODO: f[7] Mode is ignored. */
        schedule_cb(0, new Uint8Array(f.subarray(8, f.length - 2)).buffer);
        return;
      } else if (f[5] == 0xd5 &&
                 f[6] == 0x89 /* TgGetInitiatorCommand reply */) {
        if (f[7] == 0x00 /* Status */) {
          schedule_cb(0, new Uint8Array(f.subarray(8, f.length - 2)).buffer);
        } else {
          console.log("ERROR: TgGetInitiatorCommand reply status = " +
                      self.strerror(f[7]));
        }
        return;
      } else if (f[5] == 0xd5 &&
                 f[6] == 0x91 /* TgResponseToInitiator reply */) {
        if (f[7] == 0x00 /* Status */) {
          schedule_cb(0, new Uint8Array(f.subarray(8, f.length - 2)).buffer);
        } else {
          console.log("ERROR: TgResponseToInitiator reply status = " +
                      self.strerror(f[7]));
        }
        return;
      } else if (f[5] == 0xd5 &&
                 f[6] == 0x33 /* RFConfiguration reply */) {
        schedule_cb(0, new Uint8Array(f.subarray(7, f.length - 2)).buffer);
        return;
      } else if (f[5] == 0xd5 &&
                 f[6] == 0x4b /* InListPassiveTarget reply */) {
        if (f[7] == 0x01 /* tag number */ &&
            f[8] == 0x01 /* Tg */) {

          /* TODO:
           * Take [SENS_REQ(ATQA), SEL_RES(SAK), tag_id] to ask database.
           * The database would return the corresponding TAG object.
           */

          console.log("DEBUG: InListPassiveTarget SENS_REQ(ATQA)=0x" +
                      (f[9] * 256 + f[10]).toString(16) +
                      ", SEL_RES(SAK)=0x" + f[11].toString(16));
          var NFCIDLength = f[12];
          var tag_id = new Uint8Array(f.subarray(13, 13 + NFCIDLength)).buffer;
          console.log("DEBUG: tag_id: " +
              UTIL_BytesToHex(new Uint8Array(tag_id)));

          if (f[9] == 0x00 && f[10] == 0x44 /* SENS_RES */) {
            /* FIXME: not actually Ultralight. Only when tag_id[0]==0x04 */
            console.log("DEBUG: found Mifare Ultralight (106k type A)");
            self.detected_tag = "Mifare Ultralight";
            self.authed_sector = null;
            self.auth_key = null;
            schedule_cb(0, "tt2", tag_id);
            return;
          } else if (f[9] == 0x00 && f[10] == 0x04 /* SENS_RES */) {
            /* FIXME: not actually Classic. Only when tag_id[0]==0x04 */
            console.log("DEBUG: found Mifare Classic 1K (106k type A)");
            self.detected_tag = "Mifare Classic 1K";
            self.authed_sector = null;
            self.auth_key = null;
            schedule_cb(0, "mifare_classic", tag_id);
            return;
          }
        } else {
          console.log("DEBUG: found " + f[7] + " target, tg=" + f[8]);
          return;
        }
      }
    }

    // Not sure what kind of reply this is. Report w/ error.
    schedule_cb(0x888, f.buffer);
  };

  // Start timeout timer.
  tid = window.setTimeout(read_timeout, 1000.0 * timeout);

  // Schedule read of first frame.
  self.notifyFrame(read_frame);
};

// Wrap data into frame, queue for sending.
usbSCL3711.prototype.write = function(data) {
  this.dev.writeFrame(data);
};

usbSCL3711.prototype.exchange = function(data, timeout, cb) {
  this.write(data);
  this.read(timeout, cb);
};


// TODO: move to ACR122-specific file
usbSCL3711.prototype.acr122_reset_to_good_state = function(cb) {
  var self = this;
  var callback = cb;

  self.exchange(new Uint8Array([
    0x00, 0x00, 0xff, 0x00, 0xff, 0x00]).buffer, 1, function(rc, data) {
      if (rc) {
        console.warn("[FIXME] acr122_reset_to_good_state: rc = " + rc);
      }
      // icc_power_on
      self.exchange(new Uint8Array([
        0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]).buffer,
        10, function(rc, data) {
          if (rc) {
            console.warn("[FIXME] icc_power_on: rc = " + rc);
          }
          console.log("[DEBUG] icc_power_on: turn on the device power");
          if (callback) window.setTimeout(function() { callback(0); }, 100);
      });
  });
}

// set the beep on/off
usbSCL3711.prototype.acr122_set_buzzer = function(enable, cb) {
  var self = this;
  var callback = cb;
  var buzz = (enable) ? 0xff : 0x00;

  self.exchange(new Uint8Array([
    0x6b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0x00, 0x52, buzz, 0x00]).buffer, 1.0, function(rc, data) {
      if (callback) callback(rc, data);
  });
}

usbSCL3711.prototype.acr122_load_authentication_keys = function(key, loc, cb) {
  var self = this;
  var callback = cb;

  if (key == null) key = self.KEYS[0];
  else if (typeof key != "object") key = self.KEYS[key];

  var u8 = new Uint8Array([
    0x6b, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0x82,  /* INS: Load Authentication Keys */
          0x00,  /* P1: Key Structure: volatile memory */
          loc,   /* P2: Key Number (key location): 0 or 1 */
          0x06]);/* Lc: 6 bytes */
  u8 = UTIL_concat(u8, key);

  self.exchange(u8.buffer, 1.0, function(rc, data) {
      console.log("[DEBUG] acr122_load_authentication_keys(loc: " + loc +
                  ", key: " + UTIL_BytesToHex(key) + ") = " + rc);
      if (callback) callback(rc, data);
  });
}

/* the 'block' is in 16-bytes unit. */
usbSCL3711.prototype.acr122_authentication = function(block, loc, type, cb) {
  var self = this;
  var callback = cb;

  self.exchange(new Uint8Array([
    0x6b, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0x86,  /* INS: Authentication */
          0x00,  /* P1: */
          0x00,  /* P2: */
          0x05,  /* Lc: 5 bytes (Authentication Data Bytes) */
          0x01,  /* Version */
          0x00,  /* 0x00 */
          block, /* Block number */
          type,  /* Key type: TYPE A (0x60) or TYPE B (0x61) */ 
          loc    /* Key number (key location): 0 or 1 */
          ]).buffer, 1.0, function(rc, data) {
    console.log("[DEBUG] acr122_authentication(loc: " + loc +
                ", type: " + type + ", block: " + block + ") = " + rc);
    if (callback) callback(rc, data);
  });
};

/* For Mifare Classic only. The 'block' is in 16-bytes unit. */
usbSCL3711.prototype.publicAuthentication = function(block, cb) {
  var self = this;
  var callback = cb;
  var sector = Math.floor(block / 4);

  function try_keyA(k) {
    var ki = k;  // for closure
    if (ki >= 3) {  // failed authentication
      if (callback) callback(0xfff);
      return;
    }
    self.acr122_load_authentication_keys(ki, 0, function(rc, data) {
      if (rc) return;
      self.acr122_authentication(block, 0, 0x60/*KEY A*/, function(rc, data) {
        if (rc) return try_keyA(ki + 1);
        self.authed_sector = sector;
        self.auth_key = self.KEYS[ki];

        // try_keyB(): always the default key
        self.acr122_load_authentication_keys(self.KEYS[0], 1,
          function(rc, data) {
          self.acr122_authentication(block, 1, 0x61/*KEY B*/,
            function(rc, data) {
            if (callback) callback(rc, data);
          });
        });
      });
    });
  }

  if (self.detected_tag == "Mifare Classic 1K") {
    if (self.dev && self.dev.acr122) {
      if (self.authed_sector != sector) {
        console.log("[DEBUG] Public Authenticate sector " + sector);
        try_keyA(0);
      } else {
        if (callback) callback(0, null);
      }
    } else {
      if (callback) callback(0, null);
    }
  } else {
    if (callback) callback(0, null);
  }
};

/* For Mifare Classic only. The 'block' is in 16-bytes unit. */
usbSCL3711.prototype.privateAuthentication = function(block, key, cb) {
  var self = this;
  var callback = cb;
  var sector = Math.floor(block / 4);

  if (self.detected_tag == "Mifare Classic 1K") {
    if (self.dev && self.dev.acr122) {
      if (self.authed_sector != sector) {
        console.log("[DEBUG] Private Authenticate sector " + sector);
        self.acr122_load_authentication_keys(key, 1,
            function(rc, data) {
          self.acr122_authentication(block, 1, 0x61/*KEY B*/,
              function(rc, data) {
            if (rc) { console.log("KEY B AUTH ERROR"); return rc; }
            if (callback) callback(rc, data);
          });
        });
      } else {
        if (callback) callback(0, null);
      }
    } else {
      if (callback) callback(0, null);
    }
  } else {
    if (callback) callback(0, null);
  }
};

usbSCL3711.prototype.acr122_set_timeout = function(timeout /* secs */, cb) {
  var self = this;
  var callback = cb;

  var unit = Math.ceil(timeout / 5);
  if (unit >= 0xff) unit = 0xff;
  console.log("[DEBUG] acr122_set_timeout(round up to " + unit * 5 + " secs)");

  self.exchange(new Uint8Array([
    0x6b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0x00, 0x41, unit, 0x00]).buffer, 1.0, function(rc, data) {
      if (callback) callback(rc, data);
  });
}

// onclose callback gets called when device disappears.
usbSCL3711.prototype.open = function(which, cb, onclose) {
  this.rxframes = [];
  this.onclose = onclose;

  this.cid &= 0x00ffffff;
  this.cid |= ((which + 1) << 24);  // For debugging.

  var self = this;
  var callback = cb;
  dev_manager.open(which, this, function(device) {
    self.dev = device;
    var result = (self.dev != null) ? 0 : 1;

    /* extra configuration for ACR122 */
    if (self.dev && self.dev.acr122) {
      self.acr122_reset_to_good_state(function(rc) {
        if (rc) {
          console.error("[ERROR] acr122_reset_to_good_state() returns " + rc);
          return callback ? callback(rc) : null;
        }
        self.acr122_set_buzzer(false, function(rc) {
          if (rc) {
            console.warn("[FIXME] acr122_set_buzzer: rc = " + rc);
          }
          if (callback) callback(result);
        });
      });
    } else {
      if (callback) callback(result);
    }
  });
};

usbSCL3711.prototype.close = function() {
  var self = this;

  /* deselect and release target if any tag is associated. */
  function deselect_release(cb) {
    self.exchange(self.makeFrame(0x44/* InDeselect */,
                  new Uint8Array([0x01/*Tg*/])), 1.0 /* timeout */,
      function(rc, data) {
        self.exchange(self.makeFrame(0x52/* InRelease */,
                      new Uint8Array([0x01/*Tg*/])), 1.0 /* timeout */,
          function(rc, data) {
          });
      });
  }

  function dev_manager_close() {
    self.rxframes = null;  // So receivedFrame() will return false.
    if (self.dev) {
      dev_manager.close(self.dev, self);
      self.dev = null;
    }
  }

  deselect_release(dev_manager_close);
};


/*
 *  Help to build the USB packet:
 *
 *  ACR122:
 *
 *  CCID header (10bytes)
 *
 *
 *  SCL3711:
 *    00  00  ff  ff  ff  len  len  ~len
 *    d4  cmd data ...
 *    dsc ~dsc
 */
usbSCL3711.prototype.makeFrame = function(cmd, data) {
  var r8 = new Uint8Array(data ? data : []);
  // payload: 2 bytes cmd
  var p8 = new Uint8Array(r8.length + 2);

  var dcslen = r8.length + 2;  // [0xd4, cmd]

  // header
  if (this.dev.acr122) {
    // acr122
    var apdu_len = 5 /* header */ + 2 /* cmd */ + r8.length;
    var c8 = new Uint8Array(10);             // CCID header
    c8[0] = 0x6b;                            //   PC_to_RDR_Escape
    c8[1] = (apdu_len >> 0) & 0xff;          //   LEN (little-endian)
    c8[2] = (apdu_len >> 8) & 0xff;          //
    c8[3] = (apdu_len >> 16) & 0xff;         //
    c8[4] = (apdu_len >> 24) & 0xff;         //
    c8[5] = 0x00;                            //   bSlot
    c8[6] = 0x00;                            //   bSeq
    c8[7] = 0x00;                            //   abRFU
    c8[8] = 0x00;                            //   abRFU
    c8[9] = 0x00;                            //   abRFU

    var a8 = new Uint8Array(5);              // Pseudo-APDU
    a8[0] = 0xFF;                            //   Class
    a8[1] = 0x00;                            //   INS (fixed 0)
    a8[2] = 0x00;                            //   P1 (fixed 0)
    a8[3] = 0x00;                            //   P2 (fixed 0)
    a8[4] = r8.length + 2;                   //   Lc (Number of Bytes to send)

    h8 = UTIL_concat(c8, a8);
  } else {
    // scl3711
    var h8 = new Uint8Array(8);  // header
    h8[0] = 0x00;
    h8[1] = 0x00;
    h8[2] = 0xff;
    h8[3] = 0xff;
    h8[4] = 0xff;
    h8[5] = dcslen >>> 8;
    h8[6] = dcslen & 255;
    h8[7] = 0x100 - ((h8[5] + h8[6]) & 255);  // length checksum
  }

  // cmd
  p8[0] = 0xd4;
  p8[1] = cmd;

  // payload
  var dcs = p8[0] + p8[1];
  for (var i = 0; i < r8.length; ++i) {
    p8[2 + i] = r8[i];
    dcs += r8[i];
  }

  var chksum = null;
  if (this.dev.acr122) {
    chksum = new Uint8Array([]);
  } else {
    chksum = new Uint8Array(2);  // checksum: 2 bytes checksum at the end.
    chksum[0] = 0x100 - (dcs & 255);  // data checksum
    chksum[1] = 0x00;
  }

  return UTIL_concat(UTIL_concat(h8, p8), chksum).buffer;
};


// Wait for a passive target.
usbSCL3711.prototype.wait_for_passive_target = function(timeout, cb) {
  var self = this;

  if (!cb) cb = defaultCallback;

  function InListPassiveTarget(timeout, cb) {
    self.detected_tag = null;
    // Command 0x4a InListPassiveTarget, 0x01/*MaxTg*/, 0x00 (106 kpbs type).
    self.exchange(self.makeFrame(0x4a, new Uint8Array([0x01, 0x00])),
                  timeout, cb);
  }

  if (self.dev.acr122) {
    self.acr122_set_timeout(timeout, function(rc, data) {
      InListPassiveTarget(timeout, cb);
    });
  } else {
    InListPassiveTarget(timeout, cb);
  }
};


// read a block (16-byte) from tag.
// cb(rc, data: ArrayBuffer)
usbSCL3711.prototype.read_block = function(block, cb) {
  var self = this;
  var callback = cb;
  if (!cb) cb = defaultCallback;

  /* function-wise variable */
  var u8 = new Uint8Array(2);  // Type 2 tag command
  u8[0] = 0x30;                // READ command
  u8[1] = block;               // block number

  self.apdu(u8, function (rc, data) {
      callback(rc, data);
  });
}


// Input:
//  data: ArrayBuffer, the type 2 tag content.
usbSCL3711.prototype.emulate_tag = function(data, timeout, cb) {
  if (!cb) cb = defaultCallback;
  var callback = cb;
  var self = this;
  var TIMEOUT = timeout;

  /*
   * Input:
   *   cmd: the TT2 command from initiator.
   */
  var HANDLE_TT2 = function(cmd) {
    switch (cmd[0]) {
    case 0x30:  /* READ */
      var blk_no = cmd[1];
      console.log("recv TT2.READ(blk_no=" + blk_no + ")");
      var ret = data.subarray(blk_no * 4, blk_no * 4 + 16);
      if (ret.length < 16) {
        ret = UTIL_concat(ret, new Uint8Array(16 - ret.length));
      }
      /* TgResponseToInitiator */
      var u8 = self.makeFrame(0x90, ret);
      self.exchange(u8, TIMEOUT, function(rc, data) {
        if (rc) { console.log("exchange(): " + rc); return rc; }
        /* TgGetInitiatorCommand */
        var u8 = self.makeFrame(0x88, []);
        self.exchange(u8, TIMEOUT, function(rc, data) {
          if (rc) { console.log("exchange(): " + rc); return rc; }
          HANDLE_TT2(new Uint8Array(data));
        });
      });
      break;
    case 0x50:  /* HALT */
      console.log("recv TT2.HALT received.");
      callback(0);
      break;
    default:
      console.log("Unsupported TT2 tag: " + cmd[0]);
      callback(0x999);
    }
  }

  function TgInitAsTarget() {
    var req = new Uint8Array([
        0x01, // Mode: passive only
        0x04, 0x00, 0x00, 0xb0, 0x0b, 0x00, // Mifare parameter
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Felica
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID3
        0x00, 0x00]);
    var u8 = self.makeFrame(0x8c, req);
    self.exchange(u8, TIMEOUT, function(rc, data) {
      if (rc != 0) { callback(rc); return; }
      console.log("Emulated as a tag, reply is following:");

      HANDLE_TT2(new Uint8Array(data));
    });
  }

  if (self.dev.acr122) {
    // Set the PICC Operating Parameter
    self.exchange(new Uint8Array([
      0x6b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xff, 0x00, 0x51, 0x00, 0x00]).buffer, 1, function(rc, data) {
        // RFCA:off and RF:off
        self.exchange(new Uint8Array([
          0x6b, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xff, 0x00, 0x00, 0x00, 0x04, 0xd4, 0x32, 0x01, 0x00]).buffer, 1,
          function(rc, data) {
            if (rc != 0) { callback(rc); return; }
            self.acr122_set_timeout(timeout, function(rc, data) {
              if (rc != 0) { callback(rc); return; }
              TgInitAsTarget();
            });
        });
    });
  } else {
    TgInitAsTarget();
  }
}


// Input:
//   blk_no: block number (TT2: 4-byte; Classic: 16-byte)
//   data: Uint8Array.
usbSCL3711.prototype.write_block = function(blk_no, data, cb, write_inst) {
  var callback = cb;

  if (write_inst == null) {
    write_inst = 0xA2;  // TT2 WRITE command
  }

  var u8 = new Uint8Array(2 + data.length);  // Type 2 tag command
  u8[0] = write_inst;               // WRITE command
  u8[1] = blk_no;                   // block number
  for (var i = 0; i < data.length; i++) {
    u8[2 + i] = data[i];
  }

  this.apdu(u8, function(rc, dummy) {
    callback(rc);
  });
}

// Send apdu (0x40 -- InDataExchange), receive response.
usbSCL3711.prototype.apdu = function(req, cb, write_only) {
  if (!cb) cb = defaultCallback;

  // Command 0x40 InDataExchange, our apdu as payload.
  var u8 = new Uint8Array(this.makeFrame(0x40,
                                         UTIL_concat([0x01/*Tg*/], req)));

  // Write out in 64 bytes frames.
  for (var i = 0; i < u8.length; i += 64) {
    this.dev.writeFrame(new Uint8Array(u8.subarray(i, i + 64)).buffer);
  }

  if (write_only) {
    cb(0, null);  // tell caller the packet has been sent.
  } else {
    // Read response, interpret sw12.
    this.read(3.0, function(rc, data, expect_sw12) {
      if (rc != 0) { cb(rc); return; }
      var u8 = new Uint8Array(data);

      if (expect_sw12) {
        if (u8.length < 2) { cb(0x0666); return; }
        var sw12 = u8[u8.length - 2] * 256 + u8[u8.length - 1];
        // Pass all non 9000 responses.
        // 9000 is expected and passed as 0.
        cb(sw12 == 0x9000 ? 0 : sw12,
          new Uint8Array(u8.subarray(0, u8.length - 2)).buffer);
      } else {
        cb(0, u8.buffer);
      }
    });
  }
};
