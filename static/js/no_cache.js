window.addEventListener('pageshow', function(event) {
  if (event.persisted) {
    // This means the page was restored from the browser's cache
    // We force a full reload to check the server for session validity
    window.location.reload();
  }
});