chrome.app.runtime.onLaunched.addListener(function() {
  chrome.app.window.create('app.html', {
    'id': 'appWindow',
    'bounds': { 'width': 1024, 'height': 768 }});
});
