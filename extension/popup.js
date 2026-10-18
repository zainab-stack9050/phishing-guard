// Show the URL of the active tab to confirm the popup can see it.
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs && tabs[0] ? tabs[0].url : "unavailable";
  document.getElementById("url").textContent = url;
});
