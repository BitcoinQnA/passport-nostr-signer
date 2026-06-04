// SPDX-License-Identifier: GPL-3.0-or-later
// Offscreen document — hosts the WebUSB transport on behalf of the
// service worker (background.js). navigator.usb is not exposed in MV3
// service workers, so we proxy: background forwards RPC requests to
// this document via chrome.runtime.sendMessage, we do the actual USB
// I/O, and we return the result.

import { WebUsbTransport } from "./webusb-transport.js";

const transport = new WebUsbTransport();

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== "offscreen-usb") return;
  (async () => {
    try {
      if (msg.type === "connect") {
        await transport.connect();
        sendResponse({ ok: true });
      } else if (msg.type === "disconnect") {
        await transport.disconnect();
        sendResponse({ ok: true });
      } else if (msg.type === "rpc") {
        const result = await transport.rpc(msg.method, msg.params);
        sendResponse({ ok: true, result });
      } else {
        sendResponse({ ok: false, error: `unknown type ${msg.type}` });
      }
    } catch (e) {
      sendResponse({
        ok: false,
        error: e && typeof e === "object"
          ? (e.message || JSON.stringify(e))
          : String(e),
      });
    }
  })();
  return true; // signal we'll respond asynchronously
});
