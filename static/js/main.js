/**
 * main.js - Minimal Academic Forensic Helper Functions.
 * Provides copy-to-clipboard for SHA-256 hashes and action confirmations.
 */

function copyHash(hashText) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(hashText).then(() => {
      alert("SHA-256 hash copied to clipboard:\n" + hashText);
    });
  } else {
    // Fallback for non-https or older browser contexts
    const textArea = document.createElement("textarea");
    textArea.value = hashText;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      document.execCommand('copy');
      alert("SHA-256 hash copied to clipboard:\n" + hashText);
    } catch (err) {
      prompt("Copy hash manually:", hashText);
    }
    document.body.removeChild(textArea);
  }
}

function confirmAction(message) {
  return confirm(message);
}
