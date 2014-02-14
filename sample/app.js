/* enumerate NFC readers */
chrome.nfc.findDevices(function(devices) {
  console.log("Found " + devices.length + " NFC device(s), listing below...");
  for (var i = 0; i < devices.length; i++) {
    var r = devices[i];
    console.log("device[" + i + "]=(" + r.vendorId + ", " + r.productId + ")");
  }
});
