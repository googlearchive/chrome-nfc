var compatibleDevices = [
  {
    deviceName: 'ACR122U USB NFC Reader',
    productId: 0x2200,
    vendorId: 0x072f,
    thumbnailURL: chrome.runtime.getURL('images/acr122u.png')
  },
  {
    deviceName: 'SCL3711 Contactless USB Smart Card Reader',
    productId: 0x5591,
    vendorId: 0x04e6,
    thumbnailURL: chrome.runtime.getURL('images/scl3711.png')
  }
]

var device = null;

function log(message, object) {
  var logArea = document.querySelector('.log');
  var pre = document.createElement('pre');
  pre.textContent += message + ':\n';
  pre.textContent += JSON.stringify(object, null, 2) + '\n';
  logArea.appendChild(pre);
  logArea.scrollTop = logArea.scrollHeight;
}

function readNdefTag() {
  chrome.nfc.read(device, {}, function(type, ndef) {
    for (var i = 0; i < ndef.ndef.length; i++)
      log('New NDEF Tag', ndef.ndef[i]);
  });
}

function readMifareTag() {
  chrome.nfc.read_logic(device, 0, 2, function(rc, data) {
    log('New Mifare Classic Tag', UTIL_BytesToHex(data));
  });
}

function showDeviceInfo() {
  var deviceInfo = null;
  for (var i = 0; i < compatibleDevices.length; i++)
    if (device.productId === compatibleDevices[i].productId && 
        device.vendorId === compatibleDevices[i].vendorId)
      deviceInfo = compatibleDevices[i];
    
  if (!deviceInfo)
    return;
  
  var thumbnail = document.querySelector('#device-thumbnail');
  thumbnail.src = deviceInfo.thumbnailURL;
  thumbnail.classList.remove('hidden');
  
  var deviceName = document.querySelector('#device-name');
  deviceName.textContent = deviceInfo.deviceName;
  
  var productId = document.querySelector('#device-product-id');
  productId.textContent = deviceInfo.productId;
  
  var vendorId = document.querySelector('#device-vendor-id');
  vendorId.textContent = deviceInfo.vendorId;
  
  $('a[href="#device-info"]').tab('show');
}

function enumerateDevices() {
  chrome.nfc.findDevices(function(devices) {
    device = devices[0];
    showDeviceInfo(); 
  });
}

enumerateDevices();

document.querySelector('#read-ndef pre').textContent = readNdefTag.toString();
document.querySelector('#read-ndef button').addEventListener('click', readNdefTag);

document.querySelector('#read-mifare pre').textContent = readMifareTag.toString();
document.querySelector('#read-mifare button').addEventListener('click', readMifareTag);