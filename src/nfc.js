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
 * @fileoverview chrome.nfc
 */

'use strict';

function NFC() {
  var self = this;

  // private functions
  function construct_ndef_obj(ndef_array) {
    var ndef_obj = new NDEF();

    for (var i = 0; i < ndef_array.length; i++) {
      ndef_obj.add(ndef_array[i]);
    }

    return ndef_obj;
  }

  function wait_for_passive_target(device, cb, timeout) {
    if (timeout == undefined) timeout = 9999999999;

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

  var pub = {
    /*
     *  This function is to get use-able NFC device(s).
     *
     *  TODO: Currently, this function returns at most 1 device.
     *
     *  cb(devices) is called after enumeration. 'devices' is an array of all
     *  found devices. It is an empty array if no NFC device is found.
     */
    "findDevices": function(cb) {
      var device = new usbSCL3711();
      window.setTimeout(function() {
        device.open(0, function(rc) {
          if (rc) {
            console.log("NFC.device.open() = " + rc);
            cb([]);
            return rc;
          }
          // cache device info
          device.vendorId = device.dev.dev.vendorId;
          device.productId = device.dev.dev.productId;

          cb([device]);
        }, function() {
          console.debug("device.onclose() is called.");
        });
      }, 1000);
    },

    /*
     *  Read a tag.
     *
     *  'options' is a dictionary with optional parameters. If a parameter is
     *  missed, a default value is applied. Options include:
     *
     *    'timeout': timeout for this operation. Default: infinite
     *    TODO: 'type': type of tag to listen. Default: "any" for any type.
     *                  However, currently only tag 2 and NDEF is supported.
     *
     *  'cb' lists callback functions for particular tag contents.
     *  When called, 2 parameters are given: 'type' and 'content'.
     *  'type' indicates the tag type detected in the hierarchical form, ex:
     *  "tt2.ndef". Then 'content' is the NDEF object.
     */
    "read": function(device, options, cb) {
      var timeout = options["timeout"];
      var callback = cb;

      wait_for_passive_target(device, function(rc, tag_type, tag_id) {
        var tag = new Tag(tag_type, tag_id);
        if (!tag) {
            console.log("nfc.read: unknown tag_type: " + tag_type);
            return;
        }

        tag.read(device, function(rc, ndef){
          if (rc) {
            console.log("NFC.read.read() = " + rc);
            callback(null, null);  /* no type reported */
            return rc;
          }
          var ndef_obj = new NDEF(ndef);
          callback(tag_type + ".ndef", ndef_obj);
        });
      }, timeout);
    },

    /*
     * Read logic blocks.
     */
    "read_logic": function(device, logic_block, cnt, cb) {
      var callback = cb;

      wait_for_passive_target(device, function(rc, tag_type, tag_id) {
        var tag = new Tag(tag_type, tag_id);
        if (!tag) {
          console.log("nfc.read_logic: unknown tag_type: " + tag_type);
          return;
        }
        if (!tag.read_logic) {
          console.log("nfc.read: " + tag_type +
                      " doesn't support reading logic block");
          return;
        }

        tag.read_logic(device, logic_block, cnt, function(data) {
          callback(0, data);
        });
      });
    },

    /*
     * Return tag_id as soon as a tag is detected.
     */
    "wait_for_tag": function(device, timeout, cb) {
        var callback = cb;

        var loop = function(timeout) {

            wait_for_passive_target(device, function(rc, tag_type, tag_id) {
                if(rc >= 0) {
                    callback(tag_type, tag_id);
                }
                else {
                    if(timeout > 0) {
                        window.setTimeout(function() {
                            loop(timeout-250)
                        }, 250);
                    } else
                        callback(null, null);
                }
            });
        }
        loop(timeout);
    },

    /*
     *  Write content to tag.
     *
     *  'content' is a dictionary containing structures to write. Supports:
     *    ['ndef']: an array of NDEF dictionary. Will be written as a tag
     *              type 2.
     *
     *  cb(0) is called if success.
     *  timeout is optional.
     */
    "write": function(device, content, cb, timeout) {
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
    },

    /*
     *  Write to logic blocks.
     *
     *  'logic_block': the starting logic block number.
     *  'data': Uint8Array. Can large than 16-byte.
     */
    "write_logic": function(device, logic_block, data, cb) {
      var callback = cb;

      wait_for_passive_target(device, function(rc, tag_type, tag_id) {
        var tag = new Tag(tag_type, tag_id);
        if (!tag) {
            console.log("nfc.write_logic: unknown tag_type: " + tag_type);
            return;
        }

        if (!tag.write_logic) {
          console.log("nfc.read: " + tag_type +
                      " doesn't support reading logic block");
          return;
        }

        tag.write_logic(device, logic_block, data, function(rc) {
          callback(rc);
        });
      });
    },


    /*
     *  Write to physical blocks.
     *
     *  'physical_block': the starting physical block number.
     *  'data': Uint8Array. Can large than 16-byte.
     */
    "write_physical": function(device, physical_block, key, data, cb) {
      var callback = cb;

      wait_for_passive_target(device, function(rc, tag_type, tag_id) {
        var tag = new Tag(tag_type, tag_id);
        if (!tag) {
            console.log("nfc.write_physical: unknown tag_type: " + tag_type);
            return;
        }

        if (!tag.write_physical) {
          console.log("nfc.read: " + tag_type +
                      " doesn't support reading physical block");
          return;
        }

        tag.write_physical(device, physical_block, key, data, function(rc) {
          callback(rc);
        });
      });
    },

    /*
     *  Emulate as a tag.
     *
     *  'content' is a dictionary containing structures to write. Supports:
     *    ['ndef']: an array of NDEF dictionary. Will be written as a tag
     *              type 2.
     *
     *  cb(0) is called if success.
     *  timeout is optional.
     */
    "emulate_tag": function(device, content, cb, timeout) {
      if (timeout == undefined) timeout = 9999999999;
      wait_for_passive_target(device, function(rc, tag_type, tag_id) {
        var tt2 = new TT2();
        var ndef_obj = construct_ndef_obj(content["ndef"]);
        tt2.emulate(device, ndef_obj, timeout, function(rc) {
          cb(rc);
        });
      }, timeout);
    }
  };

  return pub;
}

chrome.nfc = NFC();
