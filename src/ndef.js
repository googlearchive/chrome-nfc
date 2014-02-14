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
 * @fileoverview NDEF messgae parser.
 */

'use strict';


/* Input:
 *   raw is either ArrayBuffer.
 */
function NDEF(raw, cb) {
  this.ndef = [];
  this.prepending = [  /* for RTD_URI */
    "",
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    "tel:",
    "mailto:",
    "ftp://anonymous:anonymous@",
    "ftp://ftp.",
    "ftps://",
    "sftp://",
    "smb://",
    "nfs://",
    "ftp://",
    "dav://",
    "news:",
    "telnet://",
    "imap:",
    "rtsp://",
    "urn:",
    "pop:",
    "sip:",
    "sips:",
    "tftp:",
    "btspp://",
    "btl2cpa://",
    "btgoep://",
    "tcpobex://",
    "irdaobex://",
    "file://",
    "urn:epc:id:",
    "urn:epc:tag:",
    "urn:epc:pat:",
    "urn:epc:raw:",
    "urn:epc:",
    "urn:nfc:"
  ];

  if (raw) {
    this.ndef = this.parse(raw, cb);
  }

}

/* Input:
 *   raw is either ArrayBuffer.
 *
 * Output:
 *   The callback function will get a JS structure for NDEF content.
 *
 * For the message format, please refer to Chapter 3 of NDEF spec.
 */
NDEF.prototype.parse = function(raw, cb) {
  var i;  /* index to access raw[] */
  var ret = [];
  raw = new Uint8Array(raw);

  for (i = 0; i < raw.length; i++) {
    var MB = (raw[i] & 0x80) >> 7;   /* Message Begin */
    var ME = (raw[i] & 0x40) >> 6;   /* Message End */
    var CF = (raw[i] & 0x20) >> 5;   /* Chunk Flag */
    var SR = (raw[i] & 0x10) >> 4;   /* Short Record */
    var IL = (raw[i] & 0x08) >> 3;   /* ID_LENGTH field is present */
    var TNF = (raw[i] & 0x07) >> 0;  /* Type Name Format */
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
      payload_len = ((raw[i + 2] * 256 + raw[i + 3]) * 256 +
                      raw[i + 4]) * 256 + raw[i + 5];
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
    payload = new Uint8Array(
                raw.subarray(i + payload_off, i + payload_off + payload_len));

    if (1) {  /* for DEBUG */
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

    switch (TNF) {
    case 0x01:  /* NFC RTD - so called Well-known type */
      ret.push(this.parse_RTD(type[0], payload));
      break;
    case 0x02:  /* MIME - RFC 2046 */
      ret.push(this.parse_MIME(type, payload));
      break;
    default:
      console.log("Unsupported TNF: " + TNF);
      break;
    }

    i = payload_off + payload_len - 1;
    if (ME) break;
  }

  if (cb)
    cb(ret);

  return ret;
}


/* Input:
 *   None.
 *
 * Output:
 *   ArrayBuffer.
 *
 */
NDEF.prototype.compose = function() {
  var out = new Uint8Array();
  var arr = [];

  for (var i = 0; i < this.ndef.length; i++) {
    var entry = this.ndef[i];

    switch (entry["type"]) {
    case "TEXT":
    case "Text":
      arr.push({"TNF": 1,
                "TYPE": new Uint8Array([0x54 /* T */]),
                "PAYLOAD": this.compose_RTD_TEXT(entry["lang"],
                                                 entry["text"])});
      break;
    case "URI":
      arr.push({"TNF": 1,
                "TYPE": new Uint8Array([0x55 /* U */]),
                "PAYLOAD": this.compose_RTD_URI(entry["uri"])});
      break;
    case "MIME":
      arr.push({"TNF": 2, 
                "TYPE": new Uint8Array(UTIL_StringToBytes(entry["mime_type"])),
                "PAYLOAD": this.compose_MIME(entry["payload"])});
      break;
    default:
      console.log("Unsupported RTD type:" + entry["type"]);
      break;
    }
  }

  for (var i = 0; i < arr.length; i++) {
    var flags = 0x10 | arr[i]["TNF"];  /* SR and TNF */
    flags |= (i == 0) ? 0x80 : 0x00;  /* MB */
    flags |= (i == (arr.length - 1)) ? 0x40 : 0x00;  /* ME */

    var type = arr[i]["TYPE"];
    var payload = arr[i]["PAYLOAD"];
    out = UTIL_concat(out, [flags, type.length, payload.length]);
    out = UTIL_concat(out, type);
    out = UTIL_concat(out, payload);
  }

  return out.buffer;
}


/* Input:
 *   A dictionary, with "type":
 *     "Text": RTD Text. Require: "encoding", "lang" and "text".
 *     "URI": RTD URI. Require: "uri".
 *     "MIME": RFC 2046 media types. Require: "mime_type" and "payload".
 *
 * Output:
 *   true for success.
 *
 */
NDEF.prototype.add = function(d) {
  // short-cut
  if ("uri" in d) {
    d["type"] = "URI";
  } else if ("text" in d) {
    d["type"] = "TEXT";
  } else if ("payload" in d) {
    d["type"] = "MIME";
  }

  switch (d["type"]) {
  case "TEXT":
  case "Text":
    /* set default values */
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
    if (("mime_type" in d) && ("payload" in d)) {
      this.ndef.push(d);
      return true;
    }

  default:
    console.log("Unsupported RTD type:" + entry["type"]);
    break;
  }
  return false;
}


/*
 * Input:
 *   type -- a byte, see RTD Type Names
 *   rtd  -- Uint8Array.
 *
 * Output:
 *   JS structure
 */
NDEF.prototype.parse_RTD = function(type, rtd) {
  switch (type) {
  case 0x54:  /* 'T' */
    return this.parse_RTD_TEXT(rtd);
  case 0x55:  /* 'U' */
    return this.parse_RTD_URI(rtd);
  default:
    console.log("Unsupported RTD type: " + type);
  }
}


/*
 * Input:
 *   mime_type -- Uint8Array. See RFC 2046.
 *   payload  -- Uint8Array.
 *
 * Output:
 *   JS structure
 */
NDEF.prototype.parse_MIME = function(mime_type, payload) {
  return {"type": "MIME",
          "mime_type": UTIL_BytesToString(mime_type),
          "payload": UTIL_BytesToString(payload)};
}


/*
 * Input:
 *   mime_type and payload: string.
 *
 * Output:
 *   rtd_text  -- Uint8Array.
 */
NDEF.prototype.compose_MIME = function(payload) {
  return new Uint8Array(UTIL_StringToBytes(payload));
}


/*
 * Input:
 *   rtd_text  -- Uint8Array.
 *
 * Output:
 *   JS structure
 */
NDEF.prototype.parse_RTD_TEXT = function(rtd_text) {
  var utf16 = (rtd_text[0] & 0x80) >> 7;
  var lang_len = (rtd_text[0] & 0x3f);
  var lang = rtd_text.subarray(1, 1 + lang_len);
  var text = rtd_text.subarray(1 + lang_len, rtd_text.length);

  return {"type": "Text",
          "encoding": utf16 ? "utf16" : "utf8",
          "lang": UTIL_BytesToString(lang),
          "text": UTIL_BytesToString(text)};
}


/*
 * Input:
 *   Language and text (assume UTF-8 encoded).
 *
 * Output:
 *   rtd_text  -- Uint8Array.
 */
NDEF.prototype.compose_RTD_TEXT = function(lang, text) {
  var l = lang.length;
  l = (l > 0x3f) ? 0x3f : l;
  return new Uint8Array([l].concat(
                        UTIL_StringToBytes(lang.substring(0, l))).concat(
                        UTIL_StringToBytes(text)));
}


/*
 * Input:
 *   rtd_uri  -- Uint8Array.
 *
 * Output:
 *   JS structure
 */
NDEF.prototype.parse_RTD_URI = function(rtd_uri) {
  return {"type": "URI",
          "uri": this.prepending[rtd_uri[0]] +
                 UTIL_BytesToString(rtd_uri.subarray(1, rtd_uri.length))};
}

/*
 * Input:
 *   Thr URI to compose (assume UTF-8).
 *
 * Output:
 *   Uint8Array.
 */
NDEF.prototype.compose_RTD_URI = function(uri) {
  var longest = -1;
  var longest_i;
  for (var i = 0; i < this.prepending.length; i++) {
    if (uri.substring(0, this.prepending[i].length) == this.prepending[i]) {
      if (this.prepending[i].length > longest) {
        longest_i = i;
        longest = this.prepending[i].length;
      }
    }
  }
  // assume at least longest_i matches prepending[0], which is "".

  return new Uint8Array([longest_i].concat(
                        UTIL_StringToBytes(uri.substring(longest))));
}

