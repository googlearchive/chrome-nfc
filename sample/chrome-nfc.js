function B64_encode(bytes, opt_length) {
  if (!opt_length) {
    opt_length = bytes.length;
  }
  var b64out = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  var result = "";
  var shift = 0;
  var accu = 0;
  var input_index = 0;
  while (opt_length--) {
    accu <<= 8;
    accu |= bytes[input_index++];
    shift += 8;
    while (shift >= 6) {
      var i = accu >> shift - 6 & 63;
      result += b64out.charAt(i);
      shift -= 6;
    }
  }
  if (shift) {
    accu <<= 8;
    shift += 8;
    var i = accu >> shift - 6 & 63;
    result += b64out.charAt(i);
  }
  return result;
}
function base64_encode(bytes, opt_length) {
  if (!opt_length) {
    opt_length = bytes.length;
  }
  var b64out = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var result = "";
  var shift = 0;
  var accu = 0;
  var input_index = 0;
  while (opt_length--) {
    accu <<= 8;
    accu |= bytes[input_index++];
    shift += 8;
    while (shift >= 6) {
      var i = accu >> shift - 6 & 63;
      result += b64out.charAt(i);
      shift -= 6;
    }
  }
  if (shift) {
    accu <<= 8;
    shift += 8;
    var i = accu >> shift - 6 & 63;
    result += b64out.charAt(i);
  }
  while (result.length % 4) {
    result += "=";
  }
  return result;
}
var B64_inmap = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 0, 0, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 0, 0, 0, 0, 64, 0, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 0, 0, 0, 0, 0];
function B64_decode(string) {
  var bytes = [];
  var accu = 0;
  var shift = 0;
  for (var i = 0;i < string.length;++i) {
    var c = string.charCodeAt(i);
    if (c < 32 || c > 127 || !B64_inmap[c - 32]) {
      return[];
    }
    accu <<= 6;
    accu |= B64_inmap[c - 32] - 1;
    shift += 6;
    if (shift >= 8) {
      bytes.push(accu >> shift - 8 & 255);
      shift -= 8;
    }
  }
  return bytes;
}
;function MifareClassic(tag_id) {
  this.tag_id = new Uint8Array(tag_id);
  this.type_name = "MIFARE Classic 1K";
  this.WRITE_COMMAND = 160;
}
MifareClassic.prototype.log2sec = function(logic_blknum) {
  if (logic_blknum < 2) {
    return 0;
  }
  return Math.floor((logic_blknum - 2) / 3) + 1;
};
MifareClassic.prototype.log2phy = function(logic_blknum) {
  if (logic_blknum < 2) {
    return logic_blknum + 1;
  }
  var sector = this.log2sec(logic_blknum);
  return sector * 4 + (logic_blknum - 2) % 3;
};
MifareClassic.prototype.mif_calc_crc8 = function(input) {
  var crc = 199;
  for (var i = 0;i < input.length;i++) {
    crc = crc ^ input[i];
    for (var j = 0;j < 8;j++) {
      if (crc & 128) {
        crc = crc << 1 ^ 29;
      } else {
        crc = crc << 1;
      }
    }
  }
  return crc;
};
MifareClassic.prototype.mif_calc_crc16 = function(input) {
  var crc = 51084;
  for (var i = 0;i < input.length;i++) {
    crc = crc ^ input[i] << 8;
    for (var j = 0;j < 8;j++) {
      if (crc & 32768) {
        crc = crc << 1 ^ 4129;
      } else {
        crc = crc << 1;
      }
    }
  }
  return crc;
};
MifareClassic.prototype.copy_auth_keys = function(data, dev) {
  for (var i = 0;i < 6;i++) {
    data[i] = dev.auth_key[i];
  }
  for (var i = 0;i < 6;i++) {
    data[i + 10] = 255;
  }
  return data;
};
MifareClassic.prototype.read_physical = function(device, phy_block, cnt, cb) {
  var self = this;
  var callback = cb;
  var dev = device;
  var readed = new Uint8Array;
  var max_block = 1024 / 16;
  if (cnt != null) {
    max_block = phy_block + cnt;
  }
  function fast_read(phy_block, data, max_block) {
    if (phy_block == 3 && data[57] != 105) {
      var nfc_cnt;
      for (nfc_cnt = 0;data[18 + nfc_cnt * 2 + 0] == 3 && data[18 + nfc_cnt * 2 + 1] == 225;nfc_cnt++) {
      }
      var new_num = (nfc_cnt + 1) * 4;
      if (new_num < max_block) {
        return new_num;
      } else {
        return max_block;
      }
    } else {
      return max_block;
    }
  }
  function read_next(phy_block) {
    var blk_no = phy_block;
    dev.publicAuthentication(blk_no, function(rc, data) {
      if (rc) {
        return callback(rc);
      }
      dev.read_block(blk_no, function(rc, bn) {
        if (rc) {
          return callback(rc);
        }
        var bn = new Uint8Array(bn);
        if (blk_no % 4 == 3) {
          bn = self.copy_auth_keys(bn, dev);
        }
        readed = UTIL_concat(readed, bn);
        max_block = fast_read(blk_no, readed, max_block);
        if (blk_no + 1 >= max_block) {
          return callback(readed);
        } else {
          return read_next(blk_no + 1, cb);
        }
      });
    });
  }
  read_next(phy_block);
};
MifareClassic.prototype.read = function(device, cb) {
  var self = this;
  if (!cb) {
    cb = defaultCallback;
  }
  var callback = cb;
  var card = new Uint8Array;
  self.read_physical(device, 0, null, function(data) {
    for (var i = 0;i < Math.ceil(data.length / 16);i++) {
      console.log(UTIL_fmt("[DEBUG] Sector[" + UTIL_BytesToHex([i]) + "] " + UTIL_BytesToHex(data.subarray(i * 16, i * 16 + 16))));
    }
    var GPB = data[57];
    if (GPB == 105) {
      console.log("[DEBUG] Sector 0 is non-personalized (0x69).");
    } else {
      var DA = (GPB & 128) >> 7;
      var MA = (GPB & 64) >> 6;
      var ADV = (GPB & 3) >> 0;
      var nfc_cnt;
      for (nfc_cnt = 0;data[18 + nfc_cnt * 2 + 0] == 3 && data[18 + nfc_cnt * 2 + 1] == 225;nfc_cnt++) {
      }
      var tlv = new Uint8Array;
      for (var i = 1;i <= nfc_cnt;i++) {
        tlv = UTIL_concat(tlv, data.subarray(i * 64, i * 64 + 48));
      }
      for (var i = 0;i < tlv.length;i++) {
        switch(tlv[i]) {
          case 0:
            console.log("[DEBUG] NULL TLV.");
            break;
          case 254:
            console.log("[DEBUG] Terminator TLV.");
            return;
          case 3:
            var len = tlv[i + 1];
            if (len + 2 > tlv.length) {
              console.log("[WARN] Vlen:" + len + " > totla len:" + tlv.length);
            }
            return callback(0, (new Uint8Array(tlv.subarray(i + 2, i + 2 + len))).buffer);
          default:
            console.log("[ERROR] Unsupported TLV: " + UTIL_BytesToHex(tlv[0]));
            return;
        }
      }
    }
  });
};
MifareClassic.prototype.read_logic = function(device, logic_block, cnt, cb) {
  var self = this;
  var callback = cb;
  var card = new Uint8Array;
  function next_logic(logic_block, cnt) {
    var blk_no = logic_block;
    var count = cnt;
    if (count <= 0) {
      return callback(card);
    }
    self.read_physical(device, self.log2phy(logic_block), 1, function(data) {
      card = UTIL_concat(card, data);
      next_logic(blk_no + 1, count - 1);
    });
  }
  next_logic(logic_block, cnt);
};
MifareClassic.prototype.compose = function(ndef) {
  var self = this;
  var ndef_tlv = new Uint8Array([3, ndef.length]);
  var terminator_tlv = new Uint8Array([254]);
  var TLV = UTIL_concat(ndef_tlv, UTIL_concat(new Uint8Array(ndef), terminator_tlv));
  var TLV_sector_num = Math.ceil(TLV.length / 48);
  var TLV_blocks = new Uint8Array;
  for (var i = 0;i < TLV_sector_num;i++) {
    TLV_blocks = UTIL_concat(TLV_blocks, TLV.subarray(i * 48, (i + 1) * 48));
    var padding;
    if (i + 1 == TLV_sector_num) {
      padding = new Uint8Array(48 - TLV.length % 48);
    } else {
      padding = new Uint8Array(0);
    }
    TLV_blocks = UTIL_concat(TLV_blocks, padding);
    TLV_blocks = UTIL_concat(TLV_blocks, new Uint8Array([211, 247, 211, 247, 211, 247, 127, 7, 136, 64, 255, 255, 255, 255, 255, 255]));
  }
  var classic_header = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 161, 162, 163, 164, 165, 120, 119, 136, 193, 255, 255, 255, 255, 255, 255]);
  for (var i = 0;i < TLV_sector_num;i++) {
    classic_header[16 + (i + 1) * 2 + 0] = 3;
    classic_header[16 + (i + 1) * 2 + 1] = 225;
  }
  classic_header[16] = self.mif_calc_crc8(classic_header.subarray(17, 48));
  var ret = UTIL_concat(classic_header, TLV_blocks);
  return ret;
};
MifareClassic.prototype.write_physical = function(device, block_no, key, all_data, cb) {
  var dev = device;
  var blk_no = block_no;
  var data = all_data;
  var callback = cb;
  var self = this;
  if (data.length == 0) {
    return callback(0);
  }
  if (data.length < 16) {
    data = UTIL_concat(data, new Uint8Array(16 - data.length));
  }
  function authenticationCallback(rc, dummy) {
    if (rc) {
      return callback(rc);
    }
    var block_data = data.subarray(0, 16);
    dev.write_block(blk_no, block_data, function(rc) {
      if (rc) {
        return callback(rc);
      }
      self.write_physical(dev, blk_no + 1, key, data.subarray(16), callback);
    }, self.WRITE_COMMAND);
  }
  if (key == null) {
    dev.publicAuthentication(blk_no, authenticationCallback);
  } else {
    dev.privateAuthentication(blk_no, key, authenticationCallback);
  }
};
MifareClassic.prototype.write = function(device, ndef, cb) {
  var self = this;
  if (!cb) {
    cb = defaultCallback;
  }
  var callback = cb;
  var card = self.compose(new Uint8Array(ndef));
  var dev = device;
  var max_block = Math.ceil(card.length / 16);
  if (max_block > 1024 / 16) {
    console.log("write Classic() card is too big (max: 1024 bytes): " + card.length);
    return callback(3003);
  }
  self.write_physical(dev, 1, null, card.subarray(16), callback);
};
MifareClassic.prototype.write_logic = function(device, logic_block, all_data, cb) {
  var self = this;
  var callback = cb;
  function write_next(device, logic_block, all_data) {
    var dev = device;
    var blk_no = logic_block;
    var data = all_data;
    if (data.length == 0) {
      return callback(0);
    }
    self.write_physical(dev, self.log2phy(blk_no), null, data.subarray(0, 16), function(rc) {
      if (rc) {
        return callback(rc);
      }
      var gpb_phy = self.log2sec(blk_no) * 4 + 3;
      dev.read_block(gpb_phy, function(rc, gpb_data) {
        if (rc) {
          return callback(rc);
        }
        var gpb_data = new Uint8Array(gpb_data);
        gpb_data = self.copy_auth_keys(gpb_data, dev);
        if (gpb_phy == 3) {
          gpb_data[9] = 193;
        } else {
          gpb_data[9] = 64;
        }
        dev.write_block(gpb_phy, gpb_data, function(rc) {
          blk_no = blk_no + 1;
          data = data.subarray(16);
          return write_next(dev, blk_no, data);
        }, self.WRITE_COMMAND);
      });
    });
  }
  write_next(device, logic_block, all_data);
};
MifareClassic.prototype.emulate = function(device, ndef_obj, timeout, cb) {
  var data = this.compose(new Uint8Array(ndef_obj.compose()));
  return device.emulate_tag(data, timeout, cb);
};
function NDEF(raw, cb) {
  this.ndef = [];
  this.prepending = ["", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cpa://", "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:"];
  if (raw) {
    this.ndef = this.parse(raw, cb);
  }
}
NDEF.prototype.parse = function(raw, cb) {
  var i;
  var ret = [];
  raw = new Uint8Array(raw);
  for (i = 0;i < raw.length;i++) {
    var MB = (raw[i] & 128) >> 7;
    var ME = (raw[i] & 64) >> 6;
    var CF = (raw[i] & 32) >> 5;
    var SR = (raw[i] & 16) >> 4;
    var IL = (raw[i] & 8) >> 3;
    var TNF = (raw[i] & 7) >> 0;
    var type_off;
    var type_len = raw[i + 1];
    var id;
    var type;
    var payload_off = 4 + type_len;
    var payload_len;
    var payload;
    if (SR) {
      type_off = 3;
      payload_off = 3 + type_len;
      payload_len = raw[i + 2];
    } else {
      type_off = 6;
      payload_off = 6 + type_len;
      payload_len = ((raw[i + 2] * 256 + raw[i + 3]) * 256 + raw[i + 4]) * 256 + raw[i + 5];
    }
    if (IL) {
      type_off += 1;
      var id_len = raw[i + type_off - 1];
      payload_off += 1 + id_len;
      var id_off = type_off + type_len;
      id = raw.subarray(i + id_off, i + id_off + id_len);
    } else {
      id = null;
    }
    type = new Uint8Array(raw.subarray(i + type_off, i + type_off + type_len));
    payload = new Uint8Array(raw.subarray(i + payload_off, i + payload_off + payload_len));
    if (1) {
      console.log("raw[i]: " + raw[i]);
      console.log("MB: " + MB);
      console.log("ME: " + ME);
      console.log("SR: " + SR);
      console.log("IL: " + IL);
      console.log("TNF: " + TNF);
      console.log("type_off: " + type_off);
      console.log("type_len: " + type_len);
      console.log("payload_off: " + payload_off);
      console.log("payload_len: " + payload_len);
      console.log("type: " + UTIL_BytesToHex(type));
      console.log("payload: " + UTIL_BytesToHex(payload));
    }
    switch(TNF) {
      case 1:
        ret.push(this.parse_RTD(type[0], payload));
        break;
      case 2:
        ret.push(this.parse_MIME(type, payload));
        break;
      default:
        console.log("Unsupported TNF: " + TNF);
        break;
    }
    i = payload_off + payload_len - 1;
    if (ME) {
      break;
    }
  }
  if (cb) {
    cb(ret);
  }
  return ret;
};
NDEF.prototype.compose = function() {
  var out = new Uint8Array;
  var arr = [];
  for (var i = 0;i < this.ndef.length;i++) {
    var entry = this.ndef[i];
    switch(entry["type"]) {
      case "TEXT":
      ;
      case "Text":
        arr.push({"TNF":1, "TYPE":new Uint8Array([84]), "PAYLOAD":this.compose_RTD_TEXT(entry["lang"], entry["text"])});
        break;
      case "URI":
        arr.push({"TNF":1, "TYPE":new Uint8Array([85]), "PAYLOAD":this.compose_RTD_URI(entry["uri"])});
        break;
      case "MIME":
        arr.push({"TNF":2, "TYPE":new Uint8Array(UTIL_StringToBytes(entry["mime_type"])), "PAYLOAD":this.compose_MIME(entry["payload"])});
        break;
      default:
        console.log("Unsupported RTD type:" + entry["type"]);
        break;
    }
  }
  for (var i = 0;i < arr.length;i++) {
    var flags = 16 | arr[i]["TNF"];
    flags |= i == 0 ? 128 : 0;
    flags |= i == arr.length - 1 ? 64 : 0;
    var type = arr[i]["TYPE"];
    var payload = arr[i]["PAYLOAD"];
    out = UTIL_concat(out, [flags, type.length, payload.length]);
    out = UTIL_concat(out, type);
    out = UTIL_concat(out, payload);
  }
  return out.buffer;
};
NDEF.prototype.add = function(d) {
  if ("uri" in d) {
    d["type"] = "URI";
  } else {
    if ("text" in d) {
      d["type"] = "TEXT";
    } else {
      if ("payload" in d) {
        d["type"] = "MIME";
      }
    }
  }
  switch(d["type"]) {
    case "TEXT":
    ;
    case "Text":
      if (!("encoding" in d)) {
        d["encoding"] = "utf8";
      }
      if (!("lang" in d)) {
        d["lang"] = "en";
      }
      if ("text" in d) {
        this.ndef.push(d);
        return true;
      }
      break;
    case "URI":
      if ("uri" in d) {
        this.ndef.push(d);
        return true;
      }
      break;
    case "MIME":
      if ("mime_type" in d && "payload" in d) {
        this.ndef.push(d);
        return true;
      }
    ;
    default:
      console.log("Unsupported RTD type:" + entry["type"]);
      break;
  }
  return false;
};
NDEF.prototype.parse_RTD = function(type, rtd) {
  switch(type) {
    case 84:
      return this.parse_RTD_TEXT(rtd);
    case 85:
      return this.parse_RTD_URI(rtd);
    default:
      console.log("Unsupported RTD type: " + type);
  }
};
NDEF.prototype.parse_MIME = function(mime_type, payload) {
  return{"type":"MIME", "mime_type":UTIL_BytesToString(mime_type), "payload":UTIL_BytesToString(payload)};
};
NDEF.prototype.compose_MIME = function(payload) {
  return new Uint8Array(UTIL_StringToBytes(payload));
};
NDEF.prototype.parse_RTD_TEXT = function(rtd_text) {
  var utf16 = (rtd_text[0] & 128) >> 7;
  var lang_len = rtd_text[0] & 63;
  var lang = rtd_text.subarray(1, 1 + lang_len);
  var text = rtd_text.subarray(1 + lang_len, rtd_text.length);
  return{"type":"Text", "encoding":utf16 ? "utf16" : "utf8", "lang":UTIL_BytesToString(lang), "text":UTIL_BytesToString(text)};
};
NDEF.prototype.compose_RTD_TEXT = function(lang, text) {
  var l = lang.length;
  l = l > 63 ? 63 : l;
  return new Uint8Array([l].concat(UTIL_StringToBytes(lang.substring(0, l))).concat(UTIL_StringToBytes(text)));
};
NDEF.prototype.parse_RTD_URI = function(rtd_uri) {
  return{"type":"URI", "uri":this.prepending[rtd_uri[0]] + UTIL_BytesToString(rtd_uri.subarray(1, rtd_uri.length))};
};
NDEF.prototype.compose_RTD_URI = function(uri) {
  var longest = -1;
  var longest_i;
  for (var i = 0;i < this.prepending.length;i++) {
    if (uri.substring(0, this.prepending[i].length) == this.prepending[i]) {
      if (this.prepending[i].length > longest) {
        longest_i = i;
        longest = this.prepending[i].length;
      }
    }
  }
  return new Uint8Array([longest_i].concat(UTIL_StringToBytes(uri.substring(longest))));
};
function NFC() {
  var self = this;
  function construct_ndef_obj(ndef_array) {
    var ndef_obj = new NDEF;
    for (var i = 0;i < ndef_array.length;i++) {
      ndef_obj.add(ndef_array[i]);
    }
    return ndef_obj;
  }
  function wait_for_passive_target(device, cb, timeout) {
    if (timeout == undefined) {
      timeout = 9999999999;
    }
    device.wait_for_passive_target(timeout, function(rc, tag_type, tag_id) {
      if (rc) {
        console.log("NFC.wait_for_passive_target() = " + rc);
        cb(rc);
        return rc;
      }
      console.log("[DEBUG] nfc.wait_for_passive_target: " + tag_type + " with ID: " + UTIL_BytesToHex(new Uint8Array(tag_id)));
      cb(rc, tag_type, tag_id);
    });
  }
  var pub = {"findDevices":function(cb) {
    var device = new usbSCL3711;
    window.setTimeout(function() {
      device.open(0, function(rc) {
        if (rc) {
          console.log("NFC.device.open() = " + rc);
          cb([]);
          return rc;
        }
        device.vendorId = device.dev.dev.vendorId;
        device.productId = device.dev.dev.productId;
        cb([device]);
      });
    }, 1E3);
  }, "read":function(device, options, cb) {
    var timeout = options["timeout"];
    var callback = cb;
    wait_for_passive_target(device, function(rc, tag_type, tag_id) {
      var tag = new Tag(tag_type, tag_id);
      if (!tag) {
        console.log("nfc.read: unknown tag_type: " + tag_type);
        return;
      }
      tag.read(device, function(rc, ndef) {
        if (rc) {
          console.log("NFC.read.read() = " + rc);
          callback(null, null);
          return rc;
        }
        var ndef_obj = new NDEF(ndef);
        callback(tag_type + ".ndef", ndef_obj);
      });
    }, timeout);
  }, "read_logic":function(device, logic_block, cnt, cb) {
    var callback = cb;
    wait_for_passive_target(device, function(rc, tag_type, tag_id) {
      var tag = new Tag(tag_type, tag_id);
      if (!tag) {
        console.log("nfc.read_logic: unknown tag_type: " + tag_type);
        return;
      }
      if (!tag.read_logic) {
        console.log("nfc.read: " + tag_type + " doesn't support reading logic block");
        return;
      }
      tag.read_logic(device, logic_block, cnt, function(data) {
        callback(0, data);
      });
    });
  }, "wait_for_tag":function(device, timeout, cb) {
    var callback = cb;
    var loop = function(timeout) {
      wait_for_passive_target(device, function(rc, tag_type, tag_id) {
        if (rc >= 0) {
          callback(tag_type, tag_id);
        } else {
          if (timeout > 0) {
            window.setTimeout(function() {
              loop(timeout - 250);
            }, 250);
          } else {
            callback(null, null);
          }
        }
      });
    };
    loop(timeout);
  }, "write":function(device, content, cb, timeout) {
    wait_for_passive_target(device, function(rc, tag_type, tag_id) {
      var tag = new Tag(tag_type, tag_id);
      if (!tag) {
        console.log("nfc.write: unknown tag_type: " + tag_type);
        return;
      }
      var ndef_obj = construct_ndef_obj(content["ndef"]);
      tag.write(device, ndef_obj.compose(), function(rc) {
        cb(rc);
      });
    }, timeout);
  }, "write_logic":function(device, logic_block, data, cb) {
    var callback = cb;
    wait_for_passive_target(device, function(rc, tag_type, tag_id) {
      var tag = new Tag(tag_type, tag_id);
      if (!tag) {
        console.log("nfc.write_logic: unknown tag_type: " + tag_type);
        return;
      }
      if (!tag.write_logic) {
        console.log("nfc.read: " + tag_type + " doesn't support reading logic block");
        return;
      }
      tag.write_logic(device, logic_block, data, function(rc) {
        callback(rc);
      });
    });
  }, "write_physical":function(device, physical_block, key, data, cb) {
    var callback = cb;
    wait_for_passive_target(device, function(rc, tag_type, tag_id) {
      var tag = new Tag(tag_type, tag_id);
      if (!tag) {
        console.log("nfc.write_physical: unknown tag_type: " + tag_type);
        return;
      }
      if (!tag.write_physical) {
        console.log("nfc.read: " + tag_type + " doesn't support reading physical block");
        return;
      }
      tag.write_physical(device, physical_block, key, data, function(rc) {
        callback(rc);
      });
    });
  }, "emulate_tag":function(device, content, cb, timeout) {
    if (timeout == undefined) {
      timeout = 9999999999;
    }
    wait_for_passive_target(device, function(rc, tag_type, tag_id) {
      var tt2 = new TT2;
      var ndef_obj = construct_ndef_obj(content["ndef"]);
      tt2.emulate(device, ndef_obj, timeout, function(rc) {
        cb(rc);
      });
    }, timeout);
  }};
  return pub;
}
chrome.nfc = NFC();
function devManager() {
  this.devs = [];
  this.enumerators = [];
}
devManager.prototype.dropDevice = function(dev) {
  var tmp = this.devs;
  this.devs = [];
  var present = false;
  for (var i = 0;i < tmp.length;++i) {
    if (tmp[i] !== dev) {
      this.devs.push(tmp[i]);
    } else {
      present = true;
    }
  }
  if (!present) {
    return;
  }
  if (dev.dev) {
    chrome.usb.releaseInterface(dev.dev, 0, function() {
      console.log(UTIL_fmt("released"));
    });
    chrome.usb.closeDevice(dev.dev, function() {
      console.log(UTIL_fmt("closed"));
    });
    dev.dev = null;
  }
  console.log(this.devs.length + " devices remaining");
};
devManager.prototype.closeAll = function(cb) {
  console.debug("devManager.closeAll() is called");
  var d = this.devs.slice(0);
  for (var i = 0;i < d.length;++i) {
    d[i].close();
  }
  chrome.usb.findDevices({"vendorId":1254, "productId":21905}, function(d) {
    if (!d) {
      return;
    }
    for (var i = 0;i < d.length;++i) {
      chrome.usb.closeDevice(d[i]);
    }
  });
  chrome.usb.findDevices({"vendorId":1839, "productId":8704}, function(d) {
    if (!d) {
      return;
    }
    for (var i = 0;i < d.length;++i) {
      chrome.usb.closeDevice(d[i]);
    }
  });
  if (cb) {
    cb();
  }
  self.devs = [];
};
devManager.prototype.enumerate = function(cb) {
  var self = this;
  function enumerated(d, acr122) {
    var nDevice = 0;
    if (d && d.length != 0) {
      console.log(UTIL_fmt("Enumerated " + d.length + " devices"));
      console.log(d);
      nDevice = d.length;
    } else {
      if (d) {
        console.log("No devices found");
      } else {
        console.log("Lacking permission?");
        do {
          (function(cb) {
            if (cb) {
              window.setTimeout(function() {
                cb(-666);
              }, 0);
            }
          })(self.enumerators.shift());
        } while (self.enumerators.length);
        return;
      }
    }
    for (var i = 0;i < nDevice;++i) {
      (function(dev, i) {
        window.setTimeout(function() {
          chrome.usb.claimInterface(dev, 0, function(result) {
            console.log(UTIL_fmt("claimed"));
            console.log(dev);
            self.devs.push(new llSCL3711(dev, acr122));
            if (i == nDevice - 1) {
              var u8 = new Uint8Array(4);
              u8[0] = nDevice >> 24;
              u8[1] = nDevice >> 16;
              u8[2] = nDevice >> 8;
              u8[3] = nDevice;
              while (self.enumerators.length) {
                (function(cb) {
                  window.setTimeout(function() {
                    if (cb) {
                      cb(0, u8);
                    }
                  }, 20);
                })(self.enumerators.shift());
              }
            }
          });
        }, 0);
      })(d[i], i);
    }
  }
  if (this.devs.length != 0) {
    var u8 = new Uint8Array(4);
    u8[0] = this.devs.length >> 24;
    u8[1] = this.devs.length >> 16;
    u8[2] = this.devs.length >> 8;
    u8[3] = this.devs.length;
    if (cb) {
      cb(0, u8);
    }
  } else {
    var first = this.enumerators.length == 0;
    this.enumerators.push(cb);
    if (first) {
      window.setTimeout(function() {
        chrome.usb.findDevices({"vendorId":1254, "productId":21905}, function(d) {
          if (d && d.length != 0) {
            enumerated(d, false);
          } else {
            chrome.usb.findDevices({"vendorId":1839, "productId":8704}, function(d) {
              if (d && d.length != 0) {
                enumerated(d, true);
              }
            });
          }
        });
      }, 0);
    }
  }
};
devManager.prototype.open = function(which, who, cb) {
  var self = this;
  this.enumerate(function() {
    var dev = self.devs[which];
    if (dev) {
      dev.registerClient(who);
    }
    if (cb) {
      cb(dev || null);
    }
  });
};
devManager.prototype.close = function(singledev, who) {
  var alldevs = this.devs;
  for (var i = 0;i < alldevs.length;++i) {
    var dev = alldevs[i];
    var nremaining = dev.deregisterClient(who);
  }
};
var defaultCallback = function(rc, data) {
  var msg = "defaultCallback(" + rc;
  if (data) {
    msg += ", " + UTIL_BytesToHex(new Uint8Array(data));
  }
  msg += ")";
  console.log(UTIL_fmt(msg));
};
var dev_manager = new devManager;
var scl3711_id = 0;
function usbSCL3711() {
  this.dev = null;
  this.cid = ++scl3711_id & 16777215;
  this.rxframes = [];
  this.rxcb = null;
  this.onclose = null;
  this.detected_tag = null;
  this.auth_key = null;
  this.authed_sector = null;
  this.KEYS = [new Uint8Array([255, 255, 255, 255, 255, 255]), new Uint8Array([211, 247, 211, 247, 211, 247]), new Uint8Array([160, 161, 162, 163, 164, 165])];
  this.strerror = function(errno) {
    var err = {1:"time out, the target has not answered", 2:"checksum error during rf communication", 3:"parity error during rf communication", 4:"erroneous bit count in anticollision", 5:"framing error during mifare operation", 6:"abnormal bit collision in 106 kbps anticollision", 7:"insufficient communication buffer size", 9:"rf buffer overflow detected by ciu", 10:"rf field not activated in time by active mode peer", 11:"protocol error during rf communication", 13:"overheated - antenna drivers deactivated", 
    14:"internal buffer overflow", 16:"invalid command parameter", 18:"unsupported command from initiator", 19:"format error during rf communication", 20:"mifare authentication error", 24:"not support NFC secure", 25:"i2c bus line is busy", 35:"wrong uid check byte (14443-3)", 37:"command invalid in current dep state", 38:"operation not allowed in this configuration", 39:"not acceptable command due to context", 41:"released by initiator while operating as target", 42:"card ID does not match", 43:"the card previously activated has disapperaed", 
    44:"Mismatch between NFCID3 initiator and target in DEP 212/424 kbps", 45:"Over-current event has been detected", 46:"NAD missing in DEP frame", 47:"deselected by initiator while operating as target", 49:"initiator rf-off state detected in passive mode", 127:"pn53x application level error"};
    if (errno in err) {
      return "[" + errno + "] " + err[errno];
    } else {
      return "Unknown error: " + errno;
    }
  };
}
usbSCL3711.prototype.notifyFrame = function(cb) {
  if (this.rxframes.length != 0) {
    if (cb) {
      window.setTimeout(cb, 0);
    }
  } else {
    this.rxcb = cb;
  }
};
usbSCL3711.prototype.receivedFrame = function(frame) {
  if (!this.rxframes) {
    return false;
  }
  this.rxframes.push(frame);
  var cb = this.rxcb;
  this.rxcb = null;
  if (cb) {
    window.setTimeout(cb, 0);
  }
  return true;
};
usbSCL3711.prototype.readFrame = function() {
  if (this.rxframes.length == 0) {
    throw "rxframes empty!";
  }
  var frame = this.rxframes.shift();
  return frame;
};
usbSCL3711.prototype.read = function(timeout, cb) {
  if (!this.dev) {
    cb(1);
    return;
  }
  var tid = null;
  var callback = cb;
  var self = this;
  function schedule_cb(a, b, c) {
    if (tid) {
      window.clearTimeout(tid);
      tid = null;
    }
    var C = callback;
    if (C) {
      callback = null;
      window.setTimeout(function() {
        C(a, b, c);
      }, 0);
    }
  }
  function read_timeout() {
    if (!callback || !tid) {
      return;
    }
    console.log(UTIL_fmt("[" + self.cid.toString(16) + "] timeout!"));
    tid = null;
    dev_manager.closeAll(function() {
      schedule_cb(-5);
    });
  }
  function read_frame() {
    if (!callback || !tid) {
      return;
    }
    var f = new Uint8Array(self.readFrame());
    if (f.length == 6 && f[0] == 0 && f[1] == 0 && f[2] == 255 && f[3] == 0 && f[4] == 255 && f[5] == 0) {
      self.notifyFrame(read_frame);
      return;
    }
    if (f.length > 10) {
      if (f[0] == 128) {
        f = UTIL_concat(new Uint8Array([0, 0, 255, 1, 255]), new Uint8Array(f.subarray(10)));
      } else {
        if (f[0] == 131) {
          f = UTIL_concat(new Uint8Array([0, 0, 255, 1, 255]), new Uint8Array(f.subarray(10)));
        }
      }
    }
    if (f.length == 7) {
      if (f[5] == 144 && f[6] == 0) {
        schedule_cb(0, f.buffer);
        return;
      } else {
        if (f[5] == 99 && f[6] == 0) {
          schedule_cb(2730, f.buffer);
          return;
        }
      }
    } else {
      if (f.length > 6 && f[0] == 0 && f[1] == 0 && f[2] == 255 && f[3] + f[4] == 256) {
        if (f[5] == 213 && f[6] == 65) {
          if (f[7] == 0) {
            schedule_cb(0, (new Uint8Array(f.subarray(8, f.length - 2))).buffer);
          } else {
            console.log("ERROR: InDataExchange reply status = " + self.strerror(f[7]));
          }
          return;
        } else {
          if (f[5] == 213 && f[6] == 141) {
            schedule_cb(0, (new Uint8Array(f.subarray(8, f.length - 2))).buffer);
            return;
          } else {
            if (f[5] == 213 && f[6] == 137) {
              if (f[7] == 0) {
                schedule_cb(0, (new Uint8Array(f.subarray(8, f.length - 2))).buffer);
              } else {
                console.log("ERROR: TgGetInitiatorCommand reply status = " + self.strerror(f[7]));
              }
              return;
            } else {
              if (f[5] == 213 && f[6] == 145) {
                if (f[7] == 0) {
                  schedule_cb(0, (new Uint8Array(f.subarray(8, f.length - 2))).buffer);
                } else {
                  console.log("ERROR: TgResponseToInitiator reply status = " + self.strerror(f[7]));
                }
                return;
              } else {
                if (f[5] == 213 && f[6] == 51) {
                  schedule_cb(0, (new Uint8Array(f.subarray(7, f.length - 2))).buffer);
                  return;
                } else {
                  if (f[5] == 213 && f[6] == 75) {
                    if (f[7] == 1 && f[8] == 1) {
                      console.log("DEBUG: InListPassiveTarget SENS_REQ(ATQA)=0x" + (f[9] * 256 + f[10]).toString(16) + ", SEL_RES(SAK)=0x" + f[11].toString(16));
                      var NFCIDLength = f[12];
                      var tag_id = (new Uint8Array(f.subarray(13, 13 + NFCIDLength))).buffer;
                      console.log("DEBUG: tag_id: " + UTIL_BytesToHex(new Uint8Array(tag_id)));
                      if (f[9] == 0 && f[10] == 68) {
                        console.log("DEBUG: found Mifare Ultralight (106k type A)");
                        self.detected_tag = "Mifare Ultralight";
                        self.authed_sector = null;
                        self.auth_key = null;
                        schedule_cb(0, "tt2", tag_id);
                        return;
                      } else {
                        if (f[9] == 0 && f[10] == 4) {
                          console.log("DEBUG: found Mifare Classic 1K (106k type A)");
                          self.detected_tag = "Mifare Classic 1K";
                          self.authed_sector = null;
                          self.auth_key = null;
                          schedule_cb(0, "mifare_classic", tag_id);
                          return;
                        }
                      }
                    } else {
                      console.log("DEBUG: found " + f[7] + " target, tg=" + f[8]);
                      return;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    schedule_cb(2184, f.buffer);
  }
  tid = window.setTimeout(read_timeout, 1E3 * timeout);
  self.notifyFrame(read_frame);
};
usbSCL3711.prototype.write = function(data) {
  this.dev.writeFrame(data);
};
usbSCL3711.prototype.exchange = function(data, timeout, cb) {
  this.write(data);
  this.read(timeout, cb);
};
usbSCL3711.prototype.acr122_reset_to_good_state = function(cb) {
  var self = this;
  var callback = cb;
  self.exchange((new Uint8Array([0, 0, 255, 0, 255, 0])).buffer, 1, function(rc, data) {
    if (rc) {
      console.warn("[FIXME] acr122_reset_to_good_state: rc = " + rc);
    }
    self.exchange((new Uint8Array([98, 0, 0, 0, 0, 0, 0, 1, 0, 0])).buffer, 10, function(rc, data) {
      if (rc) {
        console.warn("[FIXME] icc_power_on: rc = " + rc);
      }
      console.log("[DEBUG] icc_power_on: turn on the device power");
      if (callback) {
        window.setTimeout(function() {
          callback(0);
        }, 100);
      }
    });
  });
};
usbSCL3711.prototype.acr122_set_buzzer = function(enable, cb) {
  var self = this;
  var callback = cb;
  var buzz = enable ? 255 : 0;
  self.exchange((new Uint8Array([107, 5, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 82, buzz, 0])).buffer, 1, function(rc, data) {
    if (callback) {
      callback(rc, data);
    }
  });
};
usbSCL3711.prototype.acr122_load_authentication_keys = function(key, loc, cb) {
  var self = this;
  var callback = cb;
  if (key == null) {
    key = self.KEYS[0];
  } else {
    if (typeof key != "object") {
      key = self.KEYS[key];
    }
  }
  var u8 = new Uint8Array([107, 11, 0, 0, 0, 0, 0, 0, 0, 0, 255, 130, 0, loc, 6]);
  u8 = UTIL_concat(u8, key);
  self.exchange(u8.buffer, 1, function(rc, data) {
    console.log("[DEBUG] acr122_load_authentication_keys(loc: " + loc + ", key: " + UTIL_BytesToHex(key) + ") = " + rc);
    if (callback) {
      callback(rc, data);
    }
  });
};
usbSCL3711.prototype.acr122_authentication = function(block, loc, type, cb) {
  var self = this;
  var callback = cb;
  self.exchange((new Uint8Array([107, 10, 0, 0, 0, 0, 0, 0, 0, 0, 255, 134, 0, 0, 5, 1, 0, block, type, loc])).buffer, 1, function(rc, data) {
    console.log("[DEBUG] acr122_authentication(loc: " + loc + ", type: " + type + ", block: " + block + ") = " + rc);
    if (callback) {
      callback(rc, data);
    }
  });
};
usbSCL3711.prototype.publicAuthentication = function(block, cb) {
  var self = this;
  var callback = cb;
  var sector = Math.floor(block / 4);
  function try_keyA(k) {
    var ki = k;
    if (ki >= 3) {
      if (callback) {
        callback(4095);
      }
      return;
    }
    self.acr122_load_authentication_keys(ki, 0, function(rc, data) {
      if (rc) {
        return;
      }
      self.acr122_authentication(block, 0, 96, function(rc, data) {
        if (rc) {
          return try_keyA(ki + 1);
        }
        self.authed_sector = sector;
        self.auth_key = self.KEYS[ki];
        self.acr122_load_authentication_keys(self.KEYS[0], 1, function(rc, data) {
          self.acr122_authentication(block, 1, 97, function(rc, data) {
            if (callback) {
              callback(rc, data);
            }
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
        if (callback) {
          callback(0, null);
        }
      }
    } else {
      if (callback) {
        callback(0, null);
      }
    }
  } else {
    if (callback) {
      callback(0, null);
    }
  }
};
usbSCL3711.prototype.privateAuthentication = function(block, key, cb) {
  var self = this;
  var callback = cb;
  var sector = Math.floor(block / 4);
  if (self.detected_tag == "Mifare Classic 1K") {
    if (self.dev && self.dev.acr122) {
      if (self.authed_sector != sector) {
        console.log("[DEBUG] Private Authenticate sector " + sector);
        self.acr122_load_authentication_keys(key, 1, function(rc, data) {
          self.acr122_authentication(block, 1, 97, function(rc, data) {
            if (rc) {
              console.log("KEY B AUTH ERROR");
              return rc;
            }
            if (callback) {
              callback(rc, data);
            }
          });
        });
      } else {
        if (callback) {
          callback(0, null);
        }
      }
    } else {
      if (callback) {
        callback(0, null);
      }
    }
  } else {
    if (callback) {
      callback(0, null);
    }
  }
};
usbSCL3711.prototype.acr122_set_timeout = function(timeout, cb) {
  var self = this;
  var callback = cb;
  var unit = Math.ceil(timeout / 5);
  if (unit >= 255) {
    unit = 255;
  }
  console.log("[DEBUG] acr122_set_timeout(round up to " + unit * 5 + " secs)");
  self.exchange((new Uint8Array([107, 5, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 65, unit, 0])).buffer, 1, function(rc, data) {
    if (callback) {
      callback(rc, data);
    }
  });
};
usbSCL3711.prototype.open = function(which, cb, onclose) {
  this.rxframes = [];
  this.onclose = onclose;
  this.cid &= 16777215;
  this.cid |= which + 1 << 24;
  var self = this;
  var callback = cb;
  dev_manager.open(which, this, function(device) {
    self.dev = device;
    var result = self.dev != null ? 0 : 1;
    if (self.dev && self.dev.acr122) {
      self.acr122_reset_to_good_state(function(rc) {
        if (rc) {
          console.error("[ERROR] acr122_reset_to_good_state() returns " + rc);
          return callback ? callback(rc) : null;
        }
        self.acr122_set_buzzer(false, function(rc) {
          if (rc) {
            console.error("[ERROR] acr122_reset_to_good_state() returns " + rc);
            return callback ? callback(rc) : null;
          }
          if (callback) {
            callback(result);
          }
        });
      });
    } else {
      if (callback) {
        callback(result);
      }
    }
  });
};
usbSCL3711.prototype.close = function() {
  var self = this;
  function deselect_release(cb) {
    self.exchange(self.makeFrame(68, new Uint8Array([1])), 1, function(rc, data) {
      self.exchange(self.makeFrame(82, new Uint8Array([1])), 1, function(rc, data) {
      });
    });
  }
  function dev_manager_close() {
    self.rxframes = null;
    if (self.dev) {
      dev_manager.close(self.dev, self);
      self.dev = null;
    }
  }
  deselect_release(dev_manager_close);
};
usbSCL3711.prototype.makeFrame = function(cmd, data) {
  var r8 = new Uint8Array(data ? data : []);
  var p8 = new Uint8Array(r8.length + 2);
  var dcslen = r8.length + 2;
  if (this.dev.acr122) {
    var apdu_len = 5 + 2 + r8.length;
    var c8 = new Uint8Array(10);
    c8[0] = 107;
    c8[1] = apdu_len >> 0 & 255;
    c8[2] = apdu_len >> 8 & 255;
    c8[3] = apdu_len >> 16 & 255;
    c8[4] = apdu_len >> 24 & 255;
    c8[5] = 0;
    c8[6] = 0;
    c8[7] = 0;
    c8[8] = 0;
    c8[9] = 0;
    var a8 = new Uint8Array(5);
    a8[0] = 255;
    a8[1] = 0;
    a8[2] = 0;
    a8[3] = 0;
    a8[4] = r8.length + 2;
    h8 = UTIL_concat(c8, a8);
  } else {
    var h8 = new Uint8Array(8);
    h8[0] = 0;
    h8[1] = 0;
    h8[2] = 255;
    h8[3] = 255;
    h8[4] = 255;
    h8[5] = dcslen >>> 8;
    h8[6] = dcslen & 255;
    h8[7] = 256 - (h8[5] + h8[6] & 255);
  }
  p8[0] = 212;
  p8[1] = cmd;
  var dcs = p8[0] + p8[1];
  for (var i = 0;i < r8.length;++i) {
    p8[2 + i] = r8[i];
    dcs += r8[i];
  }
  var chksum = null;
  if (this.dev.acr122) {
    chksum = new Uint8Array([]);
  } else {
    chksum = new Uint8Array(2);
    chksum[0] = 256 - (dcs & 255);
    chksum[1] = 0;
  }
  return UTIL_concat(UTIL_concat(h8, p8), chksum).buffer;
};
usbSCL3711.prototype.wait_for_passive_target = function(timeout, cb) {
  var self = this;
  if (!cb) {
    cb = defaultCallback;
  }
  function InListPassiveTarget(timeout, cb) {
    self.detected_tag = null;
    self.exchange(self.makeFrame(74, new Uint8Array([1, 0])), timeout, cb);
  }
  if (self.dev.acr122) {
    self.acr122_set_timeout(timeout, function(rc, data) {
      InListPassiveTarget(timeout, cb);
    });
  } else {
    InListPassiveTarget(timeout, cb);
  }
};
usbSCL3711.prototype.read_block = function(block, cb) {
  var self = this;
  var callback = cb;
  if (!cb) {
    cb = defaultCallback;
  }
  var u8 = new Uint8Array(2);
  u8[0] = 48;
  u8[1] = block;
  self.apdu(u8, function(rc, data) {
    callback(rc, data);
  });
};
usbSCL3711.prototype.emulate_tag = function(data, timeout, cb) {
  if (!cb) {
    cb = defaultCallback;
  }
  var callback = cb;
  var self = this;
  var TIMEOUT = timeout;
  var HANDLE_TT2 = function(cmd) {
    switch(cmd[0]) {
      case 48:
        var blk_no = cmd[1];
        console.log("recv TT2.READ(blk_no=" + blk_no + ")");
        var ret = data.subarray(blk_no * 4, blk_no * 4 + 16);
        if (ret.length < 16) {
          ret = UTIL_concat(ret, new Uint8Array(16 - ret.length));
        }
        var u8 = self.makeFrame(144, ret);
        self.exchange(u8, TIMEOUT, function(rc, data) {
          if (rc) {
            console.log("exchange(): " + rc);
            return rc;
          }
          var u8 = self.makeFrame(136, []);
          self.exchange(u8, TIMEOUT, function(rc, data) {
            if (rc) {
              console.log("exchange(): " + rc);
              return rc;
            }
            HANDLE_TT2(new Uint8Array(data));
          });
        });
        break;
      case 80:
        console.log("recv TT2.HALT received.");
        callback(0);
        break;
      default:
        console.log("Unsupported TT2 tag: " + cmd[0]);
        callback(2457);
    }
  };
  function TgInitAsTarget() {
    var req = new Uint8Array([1, 4, 0, 0, 176, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    var u8 = self.makeFrame(140, req);
    self.exchange(u8, TIMEOUT, function(rc, data) {
      if (rc != 0) {
        callback(rc);
        return;
      }
      console.log("Emulated as a tag, reply is following:");
      HANDLE_TT2(new Uint8Array(data));
    });
  }
  if (self.dev.acr122) {
    self.exchange((new Uint8Array([107, 5, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 81, 0, 0])).buffer, 1, function(rc, data) {
      self.exchange((new Uint8Array([107, 9, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 4, 212, 50, 1, 0])).buffer, 1, function(rc, data) {
        if (rc != 0) {
          callback(rc);
          return;
        }
        self.acr122_set_timeout(timeout, function(rc, data) {
          if (rc != 0) {
            callback(rc);
            return;
          }
          TgInitAsTarget();
        });
      });
    });
  } else {
    TgInitAsTarget();
  }
};
usbSCL3711.prototype.write_block = function(blk_no, data, cb, write_inst) {
  var callback = cb;
  if (write_inst == null) {
    write_inst = 162;
  }
  var u8 = new Uint8Array(2 + data.length);
  u8[0] = write_inst;
  u8[1] = blk_no;
  for (var i = 0;i < data.length;i++) {
    u8[2 + i] = data[i];
  }
  this.apdu(u8, function(rc, dummy) {
    callback(rc);
  });
};
usbSCL3711.prototype.apdu = function(req, cb, write_only) {
  if (!cb) {
    cb = defaultCallback;
  }
  var u8 = new Uint8Array(this.makeFrame(64, UTIL_concat([1], req)));
  for (var i = 0;i < u8.length;i += 64) {
    this.dev.writeFrame((new Uint8Array(u8.subarray(i, i + 64))).buffer);
  }
  if (write_only) {
    cb(0, null);
  } else {
    this.read(3, function(rc, data, expect_sw12) {
      if (rc != 0) {
        cb(rc);
        return;
      }
      var u8 = new Uint8Array(data);
      if (expect_sw12) {
        if (u8.length < 2) {
          cb(1638);
          return;
        }
        var sw12 = u8[u8.length - 2] * 256 + u8[u8.length - 1];
        cb(sw12 == 36864 ? 0 : sw12, (new Uint8Array(u8.subarray(0, u8.length - 2))).buffer);
      } else {
        cb(0, u8.buffer);
      }
    });
  }
};
function SHA256() {
  this._buf = new Array(64);
  this._W = new Array(64);
  this._pad = new Array(64);
  this._k = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 
  3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298];
  this._pad[0] = 128;
  for (var i = 1;i < 64;++i) {
    this._pad[i] = 0;
  }
  this.reset();
}
SHA256.prototype.reset = function() {
  this._chain = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];
  this._inbuf = 0;
  this._total = 0;
};
SHA256.prototype._compress = function(buf) {
  var W = this._W;
  var k = this._k;
  function _rotr(w, r) {
    return w << 32 - r | w >>> r;
  }
  for (var i = 0;i < 64;i += 4) {
    var w = buf[i] << 24 | buf[i + 1] << 16 | buf[i + 2] << 8 | buf[i + 3];
    W[i / 4] = w;
  }
  for (var i = 16;i < 64;++i) {
    var s0 = _rotr(W[i - 15], 7) ^ _rotr(W[i - 15], 18) ^ W[i - 15] >>> 3;
    var s1 = _rotr(W[i - 2], 17) ^ _rotr(W[i - 2], 19) ^ W[i - 2] >>> 10;
    W[i] = W[i - 16] + s0 + W[i - 7] + s1 & 4294967295;
  }
  var A = this._chain[0];
  var B = this._chain[1];
  var C = this._chain[2];
  var D = this._chain[3];
  var E = this._chain[4];
  var F = this._chain[5];
  var G = this._chain[6];
  var H = this._chain[7];
  for (var i = 0;i < 64;++i) {
    var S0 = _rotr(A, 2) ^ _rotr(A, 13) ^ _rotr(A, 22);
    var maj = A & B ^ A & C ^ B & C;
    var t2 = S0 + maj & 4294967295;
    var S1 = _rotr(E, 6) ^ _rotr(E, 11) ^ _rotr(E, 25);
    var ch = E & F ^ ~E & G;
    var t1 = H + S1 + ch + k[i] + W[i] & 4294967295;
    H = G;
    G = F;
    F = E;
    E = D + t1 & 4294967295;
    D = C;
    C = B;
    B = A;
    A = t1 + t2 & 4294967295;
  }
  this._chain[0] += A;
  this._chain[1] += B;
  this._chain[2] += C;
  this._chain[3] += D;
  this._chain[4] += E;
  this._chain[5] += F;
  this._chain[6] += G;
  this._chain[7] += H;
};
SHA256.prototype.update = function(bytes, opt_length) {
  if (!opt_length) {
    opt_length = bytes.length;
  }
  this._total += opt_length;
  for (var n = 0;n < opt_length;++n) {
    this._buf[this._inbuf++] = bytes[n];
    if (this._inbuf == 64) {
      this._compress(this._buf);
      this._inbuf = 0;
    }
  }
};
SHA256.prototype.updateRange = function(bytes, start, end) {
  this._total += end - start;
  for (var n = start;n < end;++n) {
    this._buf[this._inbuf++] = bytes[n];
    if (this._inbuf == 64) {
      this._compress(this._buf);
      this._inbuf = 0;
    }
  }
};
SHA256.prototype.digest = function() {
  for (var i = 0;i < arguments.length;++i) {
    this.update(arguments[i]);
  }
  var digest = new Array(32);
  var totalBits = this._total * 8;
  if (this._inbuf < 56) {
    this.update(this._pad, 56 - this._inbuf);
  } else {
    this.update(this._pad, 64 - (this._inbuf - 56));
  }
  for (var i = 63;i >= 56;--i) {
    this._buf[i] = totalBits & 255;
    totalBits >>>= 8;
  }
  this._compress(this._buf);
  var n = 0;
  for (var i = 0;i < 8;++i) {
    for (var j = 24;j >= 0;j -= 8) {
      digest[n++] = this._chain[i] >> j & 255;
    }
  }
  return digest;
};
function Tag(tag_name, tag_id) {
  switch(tag_name) {
    case "tt2":
      return new TT2(tag_id);
    case "mifare_classic":
      return new MifareClassic(tag_id);
  }
  return null;
}
;function TT2(tag_id) {
  this.tag_id = new Uint8Array(tag_id);
  this.type_name = null;
  this.lock_contorl = [];
}
TT2.prototype.detect_type_name = function(cb) {
  var self = this;
  var callback = cb;
  if (this.tag_id[0] == 4) {
    this.device.read_block(16, function(rc, bn) {
      if (rc) {
        self.type_name = "Mifare Ultralight";
      } else {
        self.type_name = "Mifare Ultralight C";
      }
      console.log("[DEBUG] TT2.type_name = " + self.type_name);
      if (callback) {
        callback();
      }
    });
  }
};
TT2.prototype.read = function(device, cb) {
  var self = this;
  if (!cb) {
    cb = defaultCallback;
  }
  var callback = cb;
  function poll_block0(rc, b0_b3) {
    if (rc) {
      return callback(rc);
    }
    var card = new Uint8Array(b0_b3);
    var data = new Uint8Array(b0_b3);
    var data_size = data[14] * 8;
    var CC0 = data[12];
    var CC1 = data[13];
    var CC3 = data[15];
    function check_ver(cc1) {
      var major = (cc1 & 240) >> 4;
      var minor = cc1 & 15;
      if (major == 1) {
        return true;
      }
      return false;
    }
    function readable(cc3) {
      return(cc3 & 240) == 0 ? true : false;
    }
    if (CC0 != 225 || !check_ver(CC1) || !readable(CC3)) {
      console.log("UNsupported type 2 tag: CC0=" + CC0 + ", CC1=" + CC1 + ", CC3=" + CC3);
      return callback(1911, data.buffer);
    }
    var poll_n = Math.floor((data_size + 15) / 16);
    var block = 4;
    function poll_block(card, block, poll_n) {
      console.log("[DEBUG] poll_n: " + poll_n);
      if (--poll_n < 0) {
        defaultCallback("[DEBUG] got a type 2 tag:", card.buffer);
        for (var i = 16;i < card.length;) {
          switch(card[i]) {
            case 0:
              console.debug("NULL TLV");
              i++;
              break;
            case 1:
              console.debug("Lock Control TLV");
              var PageAddr = card[i + 2] >> 4;
              var ByteOffset = card[i + 2] & 15;
              var Size = card[i + 3];
              if (Size == 0) {
                Size = 256;
              }
              var BytesPerPage = Math.pow(2, card[i + 4] & 15);
              var BytesLockedPerLockBit = card[i + 4] >> 4;
              console.debug("Lock control: " + " BytesLockedPerLockBit=" + BytesLockedPerLockBit + ", Size=" + Size);
              var ByteAddr = PageAddr * BytesPerPage + ByteOffset;
              console.info("Lock control: ByteAddr=" + ByteAddr);
              console.info("  Locked bytes:");
              var lock_offset = 64;
              for (var j = 0;j < (Size + 7) / 8;j++) {
                var k = ByteAddr + j;
                if (k >= card.length) {
                  console.warn("  card[" + k + "] haven't read out yet.");
                  break;
                }
                var mask = card[k];
                console.debug("  [" + k + "]: " + mask.toString(16));
                if (mask & 1) {
                  console.debug("* block-locking");
                }
                for (var l = 1;l < 8;l++) {
                  if (j * 8 + l >= Size) {
                    continue;
                  }
                  for (var s = "", m = 0;m < BytesLockedPerLockBit;lock_offset++) {
                    s += "0x" + lock_offset.toString(16) + ", ";
                  }
                  if (mask & 1 << l) {
                    console.info("    " + s);
                  }
                }
              }
              i += 1 + 1 + card[i + 1];
              break;
            case 254:
              console.debug("Terminator TLV.");
              return;
            case 3:
              var len = card[i + 1];
              if (i + 2 + len > card.length) {
                console.warn("TLV len " + len + " > card len " + card.length);
              }
              return callback(0, (new Uint8Array(card.subarray(i + 2, i + 2 + len))).buffer);
            default:
              console.error("Unknown Type [" + card[i] + "]");
              return;
          }
        }
      }
      device.read_block(block, function(rc, bn) {
        if (rc) {
          return callback(rc);
        }
        card = UTIL_concat(card, new Uint8Array(bn));
        return poll_block(card, block + 4, poll_n);
      });
    }
    poll_block(card, block, poll_n);
  }
  device.read_block(0, poll_block0);
};
TT2.prototype.compose = function(ndef) {
  var max_len = 64 - 16;
  var blen = 48 / 8;
  var tt2_header = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 225, 16, blen, 0]);
  var ndef_tlv = new Uint8Array([3, ndef.length]);
  var terminator_tlv = new Uint8Array([254]);
  var ret = UTIL_concat(tt2_header, UTIL_concat(ndef_tlv, UTIL_concat(new Uint8Array(ndef), terminator_tlv)));
  return ret;
};
TT2.prototype.write = function(device, ndef, cb) {
  if (!cb) {
    cb = defaultCallback;
  }
  var self = this;
  var callback = cb;
  var card = self.compose(new Uint8Array(ndef));
  var card_blknum = Math.floor((card.length + 3) / 4);
  if (card_blknum > 64 / 4) {
    console.log("write_tt2() card is too big (max: 64 bytes): " + card.length);
    return callback(3003);
  }
  function write_block(card, block_no) {
    if (block_no >= card_blknum) {
      return callback(0);
    }
    var data = card.subarray(block_no * 4, block_no * 4 + 4);
    if (data.length < 4) {
      data = UTIL_concat(data, new Uint8Array(4 - data.length));
    }
    device.write_block(block_no, data, function(rc) {
      if (rc) {
        return callback(rc);
      }
      write_block(card, block_no + 1);
    });
  }
  write_block(card, 3);
};
TT2.prototype.emulate = function(device, ndef_obj, timeout, cb) {
  var data = this.compose(new Uint8Array(ndef_obj.compose()));
  return device.emulate_tag(data, timeout, cb);
};
function llSCL3711(dev, acr122) {
  this.dev = dev;
  this.txqueue = [];
  this.clients = [];
  this.acr122 = acr122;
  if (acr122) {
    this.endpoint = 2;
  } else {
    this.endpoint = 4;
  }
  this.readLoop();
}
llSCL3711.prototype.notifyClientOfClosure = function(client) {
  var cb = client.onclose;
  if (cb) {
    window.setTimeout(cb, 0);
  }
};
llSCL3711.prototype.close = function() {
  while (this.clients.length != 0) {
    this.notifyClientOfClosure(this.clients.shift());
  }
  dev_manager.dropDevice(this);
};
llSCL3711.prototype.publishFrame = function(f) {
  var old = this.clients;
  var remaining = [];
  var changes = false;
  for (var i = 0;i < old.length;++i) {
    var client = old[i];
    if (client.receivedFrame(f)) {
      remaining.push(client);
    } else {
      changes = true;
      console.log(UTIL_fmt("[" + client.cid.toString(16) + "] left?"));
    }
  }
  if (changes) {
    this.clients = remaining;
  }
};
llSCL3711.prototype.readLoop = function() {
  if (!this.dev) {
    return;
  }
  var self = this;
  chrome.usb.bulkTransfer(this.dev, {direction:"in", endpoint:this.endpoint, length:2048}, function(x) {
    if (x.data) {
      if (x.data.byteLength >= 5) {
        var u8 = new Uint8Array(x.data);
        console.log(UTIL_fmt("<" + UTIL_BytesToHex(u8)));
        self.publishFrame(x.data);
        window.setTimeout(function() {
          self.readLoop();
        }, 0);
      } else {
        console.error(UTIL_fmt("tiny reply!"));
        console.error(x);
      }
    } else {
      console.log("no x.data!");
      console.log(x);
      throw "no x.data!";
    }
  });
};
llSCL3711.prototype.registerClient = function(who) {
  this.clients.push(who);
};
llSCL3711.prototype.deregisterClient = function(who) {
  var current = this.clients;
  this.clients = [];
  for (var i = 0;i < current.length;++i) {
    var client = current[i];
    if (client != who) {
      this.clients.push(client);
    }
  }
  return this.clients.length;
};
llSCL3711.prototype.writePump = function() {
  if (!this.dev) {
    return;
  }
  if (this.txqueue.length == 0) {
    return;
  }
  var frame = this.txqueue[0];
  var self = this;
  function transferComplete(x) {
    self.txqueue.shift();
    if (self.txqueue.length != 0) {
      window.setTimeout(function() {
        self.writePump();
      }, 0);
    }
  }
  var u8 = new Uint8Array(frame);
  console.log(UTIL_fmt(">" + UTIL_BytesToHex(u8)));
  chrome.usb.bulkTransfer(this.dev, {direction:"out", endpoint:this.endpoint, data:frame}, transferComplete);
};
llSCL3711.prototype.writeFrame = function(frame) {
  if (!this.dev) {
    return false;
  }
  var wasEmpty = this.txqueue.length == 0;
  this.txqueue.push(frame);
  if (wasEmpty) {
    this.writePump();
  }
  return true;
};
function UTIL_StringToBytes(s, bytes) {
  bytes = bytes || new Array(s.length);
  for (var i = 0;i < s.length;++i) {
    bytes[i] = s.charCodeAt(i);
  }
  return bytes;
}
function UTIL_BytesToString(b) {
  var tmp = new String;
  for (var i = 0;i < b.length;++i) {
    tmp += String.fromCharCode(b[i]);
  }
  return tmp;
}
function UTIL_BytesToHex(b) {
  if (!b) {
    return "(null)";
  }
  var hexchars = "0123456789ABCDEF";
  var hexrep = new Array(b.length * 2);
  for (var i = 0;i < b.length;++i) {
    hexrep[i * 2 + 0] = hexchars.charAt(b[i] >> 4 & 15);
    hexrep[i * 2 + 1] = hexchars.charAt(b[i] & 15);
  }
  return hexrep.join("");
}
function UTIL_BytesToHexWithSeparator(b, sep) {
  var hexchars = "0123456789ABCDEF";
  var stride = 2 + (sep ? 1 : 0);
  var hexrep = new Array(b.length * stride);
  for (var i = 0;i < b.length;++i) {
    if (sep) {
      hexrep[i * stride + 0] = sep;
    }
    hexrep[i * stride + stride - 2] = hexchars.charAt(b[i] >> 4 & 15);
    hexrep[i * stride + stride - 1] = hexchars.charAt(b[i] & 15);
  }
  return(sep ? hexrep.slice(1) : hexrep).join("");
}
function UTIL_HexToBytes(h) {
  var hexchars = "0123456789ABCDEFabcdef";
  var res = new Uint8Array(h.length / 2);
  for (var i = 0;i < h.length;i += 2) {
    if (hexchars.indexOf(h.substring(i, i + 1)) == -1) {
      break;
    }
    res[i / 2] = parseInt(h.substring(i, i + 2), 16);
  }
  return res;
}
function UTIL_equalArrays(a, b) {
  if (!a || !b) {
    return false;
  }
  if (a.length != b.length) {
    return false;
  }
  var accu = 0;
  for (var i = 0;i < a.length;++i) {
    accu |= a[i] ^ b[i];
  }
  return accu === 0;
}
function UTIL_ltArrays(a, b) {
  if (a.length < b.length) {
    return true;
  }
  if (a.length > b.length) {
    return false;
  }
  for (var i = 0;i < a.length;++i) {
    if (a[i] < b[i]) {
      return true;
    }
    if (a[i] > b[i]) {
      return false;
    }
  }
  return false;
}
function UTIL_geArrays(a, b) {
  return!UTIL_ltArrays(a, b);
}
function UTIL_getRandom(a) {
  var tmp = new Array(a);
  var rnd = new Uint8Array(a);
  window.crypto.getRandomValues(rnd);
  for (var i = 0;i < a;++i) {
    tmp[i] = rnd[i] & 255;
  }
  return tmp;
}
function UTIL_equalArrays(a, b) {
  if (!a || !b) {
    return false;
  }
  if (a.length != b.length) {
    return false;
  }
  var accu = 0;
  for (var i = 0;i < a.length;++i) {
    accu |= a[i] ^ b[i];
  }
  return accu === 0;
}
function UTIL_setFavicon(icon) {
  var faviconLink = document.createElement("link");
  faviconLink.rel = "Shortcut Icon";
  faviconLink.type = "image/x-icon";
  faviconLink.href = icon;
  var head = document.getElementsByTagName("head")[0];
  var links = head.getElementsByTagName("link");
  for (var i = 0;i < links.length;i++) {
    var link = links[i];
    if (link.type == faviconLink.type && link.rel == faviconLink.rel) {
      head.removeChild(link);
    }
  }
  head.appendChild(faviconLink);
}
function UTIL_clear(a) {
  if (a instanceof Array) {
    for (var i = 0;i < a.length;++i) {
      a[i] = 0;
    }
  }
}
function UTIL_time() {
  var d = new Date;
  var m = "000" + d.getMilliseconds();
  var s = d.toTimeString().substring(0, 8) + "." + m.substring(m.length - 3);
  return s;
}
function UTIL_fmt(s) {
  return UTIL_time() + " " + s;
}
function UTIL_concat(a, b) {
  var c = new Uint8Array(a.length + b.length);
  var i, n = 0;
  for (i = 0;i < a.length;i++, n++) {
    c[n] = a[i];
  }
  for (i = 0;i < b.length;i++, n++) {
    c[n] = b[i];
  }
  return c;
}
;