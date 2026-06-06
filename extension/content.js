// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// Content script: runs in each page, bridges window.nostr (inpage.js) to
// the extension service worker.

const SOURCE = "prime-nostr-signer";

// Inject inpage.js into the page's main world so window.nostr is defined
// before any site script runs. We use a <script src> pointing at a
// web_accessible_resource so the injected code can access page globals.
(function inject() {
  try {
    const el = document.createElement("script");
    el.src = chrome.runtime.getURL("inpage.js");
    el.async = false;
    (document.head || document.documentElement).appendChild(el);
    el.onload = () => el.remove();
  } catch (e) {
    console.error("[prime-signer] failed to inject inpage:", e);
  }
})();

// Forward inpage request → service worker; reply the response back as a
// matching window message.
window.addEventListener("message", async (ev) => {
  if (ev.source !== window) return;
  const d = ev.data;
  if (!d || d.source !== SOURCE || d.kind !== "request") return;
  try {
    const resp = await chrome.runtime.sendMessage({
      method: d.method,
      params: d.params,
      origin: window.location.origin,
    });
    window.postMessage(
      {
        source: SOURCE,
        id: d.id,
        kind: "response",
        result: resp?.result,
        error: resp?.error,
      },
      window.location.origin,
    );
  } catch (e) {
    window.postMessage(
      {
        source: SOURCE,
        id: d.id,
        kind: "response",
        error: { code: 99, message: String(e && e.message ? e.message : e) },
      },
      window.location.origin,
    );
  }
});
