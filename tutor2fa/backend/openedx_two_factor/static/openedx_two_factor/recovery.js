"use strict";

(() => {
  const list = document.getElementById("recovery-codes");
  if (!list) return;
  const status = document.getElementById("recovery-copy-status");
  document.querySelector(".recovery-actions[hidden]").hidden = false;

  let statusTimer;
  function showStatus(message, success = false) {
    clearTimeout(statusTimer);
    status.classList.toggle("recovery-copy-success", success);
    status.textContent = success ? "✓ " + message : message;
    if (success) statusTimer = setTimeout(() => {
      status.textContent = "";
      status.classList.remove("recovery-copy-success");
    }, 10000);
  }

  async function acknowledgeSaved() {
    try {
      const csrf = document.querySelector('[name="csrfmiddlewaretoken"]').value;
      const response = await fetch(window.location.pathname, {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type": "application/x-www-form-urlencoded", "X-CSRFToken": csrf},
        body: new URLSearchParams({action: "acknowledge", receipt: status.dataset.receipt}),
      });
      if (!response.ok || !(await response.json()).saved) throw new Error("Acknowledgement failed");
      document.getElementById("recovery-continue").disabled = false;
      showStatus(status.dataset.success, true);
    } catch (_) {
      showStatus(status.dataset.saveError);
    }
  }

  function fallbackCopy(text) {
    // Clipboard API is unavailable on local HTTP and may be denied by the browser.
    const field = document.createElement("textarea");
    field.value = text;
    field.readOnly = true;
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.appendChild(field);
    field.select();
    try {
      return document.execCommand("copy");
    } finally {
      field.remove();
      document.getElementById("copy-recovery-codes").focus();
    }
  }

  document.getElementById("copy-recovery-codes").addEventListener("click", async () => {
    const text = Array.from(list.querySelectorAll("code"), code => code.textContent).join("\n");
    let copied = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        copied = true;
      }
    } catch (_) {
      // Try the local HTTP-compatible fallback below.
    }
    if (!copied) {
      try { copied = fallbackCopy(text); } catch (_) { /* Manual copy remains available. */ }
    }
    if (copied) await acknowledgeSaved();
    else showStatus(status.dataset.failure);
  });
})();
