# Chrome App NFC Library


## Status

TODO

## Sample

* Open `chrome://extensions` page
* Make sure the "Developer mode" is checked
* Click on the "Load unpacked extension" button
* Select the "sample" folder
* Launch it.

## Usage

### Add permissions to your manifest.json file

```json
"permissions": [
  "usb",
  {
    "usbDevices": [
      { "vendorId":1254, "productId":21905 },
      { "vendorId":1839, "productId":8704 }
    ]
  }
]
```

### Enumerate NFC readers

``` javascript
chrome.nfc.findDevices(function(devices) {
  console.log("Found " + devices.length + " NFC device(s)");
  for (var i = 0; i < devices.length; i++) {
    var device = devices[i];
    console.log(device.vendorId, device.productId);
  }
});
```

### Read NFC tag

``` javascript
chrome.nfc.findDevices(function(devices) {
  var device = devices[0];
  chrome.nfc.read(device, {}, function(type, ndef) {
    var text = ndef.ndef[0]["text"];
    console.log(text);
  });
});
```

### Write NFC tag

``` javascript
chrome.nfc.findDevices(function(devices) {
  var device = devices[0];
  var ndef = [
    {"text": "Chromium.org website" },
    {"uri": "http://chromium.org" },
  ];
  chrome.nfc.write(device, {"ndef": ndef}, function(rc) {
    if (!rc) {
      console.log("WRITE() success!");
    } else {
      console.log("WRITE() FAILED, rc = " + rc);
    }
  });
});
```

### Emulate NFC tag

``` javascript
chrome.nfc.findDevices(function(devices) {
  var device = devices[0];
  var ndef = [
    {"type": "URI", "uri": "http://chromium.org"}
  ];
  chrome.nfc.emulate_tag(device, {"ndef": ndef}, function(rc) {
    if (!rc) {
      console.log("EMULATE() success!");
    } else {
      console.log("EMULATE() FAILED, rc = " + rc);
    }
  });
});
```


### Read Mifare Classic tag (Logic Mode)

``` javascript
chrome.nfc.findDevices(function(devices) {
  var device = devices[0];
  chrome.nfc.read_logic(device, 0, 2, function(rc, data) {
    console.log(UTIL_BytesToHex(data));
  });
});
```


### Write Mifare Classic tag (Logic Mode)

``` javascript
chrome.nfc.findDevices(function(devices) {
  var device = devices[0];
  var data = new Uint8Array([ // NDEF(http://google.com)
    0xdb, 0x00, 0x03, 0xe1, 0x00, 0x00, 0x00, 0x00, // block 0 (MAD1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // block 1 (MAD1)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x0f, 0xd1, 0x01, 0x0b, 0x55, 0x03, 0x67, // block 2 (NDEF)
    0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // block 3 (NDEF)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]);
  chrome.nfc.write_logic(device, 0, data, function(rc) {
    console.log("WRITE_LOGIC() SUCCESS");
  });
});
```
