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
 * @fileoverview Low level usb cruft to SCL3711 NFC token.
 */

'use strict';

// Low level 'driver'. One per physical USB device.
function llSCL3711(dev, acr122) {
  this.dev = dev;
  this.txqueue = [];
  this.clients = [];
  this.acr122 = acr122;
  if (acr122) {
    this.endpoint = 2;
  } else {
    // scl3711
    this.endpoint = 4;
  }

  this.readLoop();
}

llSCL3711.prototype.notifyClientOfClosure = function(client) {
  var cb = client.onclose;
  if (cb) window.setTimeout(cb, 0);
};

llSCL3711.prototype.close = function() {
  // Tell clients.
  while (this.clients.length != 0) {
    this.notifyClientOfClosure(this.clients.shift());
  }

  // Tell global list to drop this device.
  dev_manager.dropDevice(this);
};

llSCL3711.prototype.publishFrame = function(f) {
  // Push frame to all clients.
  var old = this.clients;

  var remaining = [];
  var changes = false;
  for (var i = 0; i < old.length; ++i) {
    var client = old[i];
    if (client.receivedFrame(f)) {
      // Client still alive; keep on list.
      remaining.push(client);
    } else {
      changes = true;
      console.log(UTIL_fmt(
          '[' + client.cid.toString(16) + '] left?'));
    }
  }
  if (changes) this.clients = remaining;
};

llSCL3711.prototype.readLoop = function() {
  if (!this.dev) return;

  // console.log(UTIL_fmt('entering readLoop ' + this.dev.handle));

  var self = this;
  chrome.usb.bulkTransfer(
    this.dev,
    { direction:'in', endpoint:this.endpoint, length:2048 },
    function(x) {
      if (x.data) {
        if (x.data.byteLength >= 5) {

          var u8 = new Uint8Array(x.data);
          console.log(UTIL_fmt('<' + UTIL_BytesToHex(u8)));

          self.publishFrame(x.data);

          // Read more.
          window.setTimeout(function() { self.readLoop(); } , 0);
        } else {
          console.error(UTIL_fmt('tiny reply!'));
          console.error(x);
          // TODO(yjlou): I don't think a tiny reply requires close.
          //              Maybe call dev_manager.close(null, clients[0])?
          // window.setTimeout(function() { self.close(); }, 0);
        }

      } else {
        console.log('no x.data!');
        console.log(x);
        throw 'no x.data!';
      }
    }
  );
};

// Register an opener.
llSCL3711.prototype.registerClient = function(who) {
  this.clients.push(who);
};

// De-register an opener.
// Returns number of remaining listeners for this device.
llSCL3711.prototype.deregisterClient = function(who) {
  var current = this.clients;
  this.clients = [];
  for (var i = 0; i < current.length; ++i) {
    var client = current[i];
    if (client != who) this.clients.push(client);
  }
  return this.clients.length;
};

// Stuffs all queued frames from txqueue[] to device.
llSCL3711.prototype.writePump = function() {
  if (!this.dev) return;  // Ignore.

  if (this.txqueue.length == 0) return;  // Done with current queue.

  var frame = this.txqueue[0];

  var self = this;
  function transferComplete(x) {
    self.txqueue.shift();  // drop sent frame from queue.
    if (self.txqueue.length != 0) {
      window.setTimeout(function() { self.writePump(); }, 0);
    }
  };

  var u8 = new Uint8Array(frame);
  console.log(UTIL_fmt('>' + UTIL_BytesToHex(u8)));

  chrome.usb.bulkTransfer(
      this.dev,
      {direction:'out', endpoint:this.endpoint, data:frame},
      transferComplete
  );
};

// Queue frame to be sent.
// If queue was empty, start the write pump.
// Returns false if device is MIA.
llSCL3711.prototype.writeFrame = function(frame) {
  if (!this.dev) return false;

  var wasEmpty = (this.txqueue.length == 0);
  this.txqueue.push(frame);
  if (wasEmpty) this.writePump();

  return true;
};
