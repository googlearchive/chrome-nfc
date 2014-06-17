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
 * @fileoverview USB device manager.
 *
 * +-----------------+
 * | Reader-specific |
 * |   driver, like  |  The "who" in the open() function.
 * |    scl3711.js   |
 * +-----------------+  For low level driver, this is "client".
 *         |
 *         v
 * +-----------------+
 * |  dev_manager:   |
 * | open and enum   |
 * | low level devs  |
 * +-----------------+
 *     |         |
 *     v         v
 * +-------+ +-------+  The "which" in the open() function.
 * |llSCL37| |llSCL37|
 * |       | |       |  Low level USB driver.
 * |       | |       |  each maps to a physical device instance.
 * |       | |       |  handling Tx/Rx queues.
 * +-------+ +-------+
 *
 */

'use strict';


// List of enumerated usb devices.
function devManager() {
  this.devs = [];         // array storing the low level device.
  this.enumerators = [];  // array storing the pending callers of enumerate().
}

// Remove a device from devs[] list.
devManager.prototype.dropDevice = function(dev) {
  var tmp = this.devs;
  this.devs = [];

  var present = false;
  for (var i = 0; i < tmp.length; ++i) {
    if (tmp[i] !== dev) {
      this.devs.push(tmp[i]);
    } else {
      present = true;
    }
  }
  if (!present) return;  // Done.

  if (dev.dev) {
    chrome.usb.releaseInterface(dev.dev, 0,
        function() { console.log(UTIL_fmt('released')); });
    chrome.usb.closeDevice(dev.dev,
        function() { console.log(UTIL_fmt('closed')); });
    dev.dev = null;
  }

  console.log(this.devs.length + ' devices remaining');
};

// Close all enumerated devices.
devManager.prototype.closeAll = function(cb) {

  console.debug("devManager.closeAll() is called");

  // First close and stop talking to any device we already
  // have enumerated.
  var d = this.devs.slice(0);
  for (var i = 0; i < d.length; ++i) {
    d[i].close();
  }

  // Next, find current devices and explictly close them.
  chrome.usb.findDevices({'vendorId': 0x04e6, 'productId': 0x5591},
      function(d) {
        if (!d) return;
          for(var i = 0; i < d.length; ++i) {
            chrome.usb.closeDevice(d[i]);
        }
    });
  chrome.usb.findDevices({'vendorId': 0x072f, 'productId': 0x2200},
      function (d) {
        if (!d) return;
          for(var i = 0; i < d.length; ++i) {
            chrome.usb.closeDevice(d[i]);
        }
    });

  if (cb) {
    cb();
  }

  /* TODO(yjlou): Devices should be gracefully removed one by one in
   *              the close() function, instead of rudely removed here.
   */
  self.devs = [];
};

// When an app needs a device, it must claim before use (so that kernel
// can handle the lock).
devManager.prototype.enumerate = function(cb) {
  var self = this;

  function enumerated(d, acr122) {
    var nDevice = 0;

    if (d && d.length != 0) {
      console.log(UTIL_fmt('Enumerated ' + d.length + ' devices'));
      console.log(d);
      nDevice = d.length;
    } else {
      if (d) {
        console.log('No devices found');
      } else {
        /* TODO(yjlou): Review this case later (d==undefined).
         *              Is this real lacking permission.
         */
        console.log('Lacking permission?');
        do {
          (function(cb) {
            if (cb) window.setTimeout(function() { cb(-666); }, 0);
          })(self.enumerators.shift());
        } while (self.enumerators.length);
        return;
      }
    }

    // Found multiple devices. Create a low level SCL3711 per device.
    for (var i = 0; i < nDevice; ++i) {
      (function(dev, i) {
        window.setTimeout(function() {
            chrome.usb.claimInterface(dev, 0, function(result) {
              console.log(UTIL_fmt('claimed'));
              console.log(dev);

              // Push the new low level device to the devs[].
              self.devs.push(new llSCL3711(dev, acr122));

              // Only callback after the last device is claimed.
              if (i == (nDevice - 1)) {
                var u8 = new Uint8Array(4);
                u8[0] = nDevice >> 24;
                u8[1] = nDevice >> 16;
                u8[2] = nDevice >> 8;
                u8[3] = nDevice;

                // Notify all enumerators.
                while (self.enumerators.length) {
                  (function(cb) {
                    window.setTimeout(function() { if (cb) cb(0, u8); }, 20);
                  })(self.enumerators.shift());
                }
              }
            });
          }, 0);
      })(d[i], i);
    }
  };
  /* end of enumerated() */


  if (this.devs.length != 0) {
    // Already have devices. Report number right away.
    // TODO(yjlou): The new plugged-in NFC reader may not be detected after
    //              the first time enumerate() is called.
    var u8 = new Uint8Array(4);
    u8[0] = this.devs.length >> 24;
    u8[1] = this.devs.length >> 16;
    u8[2] = this.devs.length >> 8;
    u8[3] = this.devs.length;
    if (cb) cb(0, u8);
  } else {
    var first = this.enumerators.length == 0;

    // Queue callback.
    this.enumerators.push(cb);

    if (first) {
      // Only first requester calls actual low level.
      window.setTimeout(function() {
          chrome.usb.findDevices({'vendorId': 0x04e6, 'productId': 0x5591},
            function (d) {
              if (d && d.length != 0) {
                enumerated(d, false);
              } else {
                chrome.usb.findDevices(
                    {'vendorId': 0x072f, 'productId': 0x2200},
                    function (d) {
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
  // Make sure we have enumerated devices.
  this.enumerate(function() {
    var dev = self.devs[which];
    if (dev) dev.registerClient(who);
    if (cb) { cb(dev || null); }
  });
};

devManager.prototype.close = function(singledev, who) {
  // De-register client from all known devices,
  // since the client might have opened them implicitly w/ enumerate().
  // This will thus release any device without active clients.
  var alldevs = this.devs;
  for (var i = 0; i < alldevs.length; ++i) {
    var dev = alldevs[i];
    var nremaining = dev.deregisterClient(who);
    // TODO: uncomment when Chrome stabilizes.
    /*
    if (nremaining == 0) {
      // This device has no active clients remaining.
      // Close it so libusb releases its claim and other processes
      // can try attach to the device.
      this.dropDevice(dev);
    }
    */
  }
};

// For console interaction.
//  rc   - a number.
//  data - an ArrayBuffer.
var defaultCallback = function(rc, data) {
  var msg = 'defaultCallback('+rc;
  if (data) msg += ', ' + UTIL_BytesToHex(new Uint8Array(data));
  msg += ')';
  console.log(UTIL_fmt(msg));
};


// Singleton tracking available devices.
var dev_manager = new devManager();

