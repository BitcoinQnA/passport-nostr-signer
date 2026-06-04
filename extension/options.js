// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

const urlEl = document.getElementById("url");
const devModeEl = document.getElementById("devMode");
const forgetStatusEl = document.getElementById("forget-status");
const savedEl = document.getElementById("saved-indicator");
const pairBtn = document.getElementById("pair");
const pairStatusEl = document.getElementById("pair-status");

// Match what the device registers in webusb.rs: vendor-class interface
// (0xFF/0xFF/0xFF). VID/PID aren't constrained here — KeyOS's default
// pair varies per firmware build, so class-based filtering is the
// portable choice until a dedicated VID/PID is allocated.
const DEVICE_FILTERS = [
  { classCode: 0xff, subclassCode: 0xff, protocolCode: 0xff },
];

let savedTimer = null;
function pulseSaved() {
  savedEl.classList.add("visible");
  if (savedTimer) clearTimeout(savedTimer);
  savedTimer = setTimeout(() => savedEl.classList.remove("visible"), 1200);
}

// Load current settings into the form. `transportKind` is stored as
// "webusb" or "ws"; the UI `devMode` checkbox represents the opt-in
// to the WebSocket simulator transport.
chrome.storage.local.get(["serverUrl", "transportKind", "pendingPair"], (v) => {
  urlEl.value = v.serverUrl || "ws://127.0.0.1:9876";
  devModeEl.checked = v.transportKind === "ws";
  // If the popup sent us here to pair, clear the flag and highlight
  // the Pair button. We can't auto-click it — Chrome only honours
  // requestDevice inside a real user gesture, not a synthetic click.
  if (v.pendingPair) {
    chrome.storage.local.remove("pendingPair");
    pairBtn.focus();
    pairBtn.classList.add("flash");
    setTimeout(() => pairBtn.classList.remove("flash"), 1500);
  }
});

async function runPair() {
  pairBtn.disabled = true;
  pairBtn.textContent = "Selecting device…";
  try {
    await navigator.usb.requestDevice({ filters: DEVICE_FILTERS });
    await chrome.storage.local.set({ transportKind: "webusb" });
    pairStatusEl.textContent = "Connected. Open the popup to see your keys.";
    pairStatusEl.classList.add("visible");
  } catch (e) {
    const msg = String(e?.message || e);
    if (!/No device selected/i.test(msg)) {
      pairStatusEl.textContent = `Connect failed: ${msg}`;
      pairStatusEl.classList.add("visible");
    }
  } finally {
    pairBtn.disabled = false;
    pairBtn.textContent = "Connect Passport Prime";
  }
}

pairBtn.addEventListener("click", runPair);

// Save on change. No Save button — every input commits immediately.
urlEl.addEventListener("input", async () => {
  const url = urlEl.value.trim() || "ws://127.0.0.1:9876";
  await chrome.storage.local.set({ serverUrl: url });
  pulseSaved();
});

devModeEl.addEventListener("change", async () => {
  await chrome.storage.local.set({ transportKind: devModeEl.checked ? "ws" : "webusb" });
  pulseSaved();
});

// Full reset: drop every WebUSB grant AND clear the cached key
// selection. Intended for demos / handing the device off — the popup
// should look fresh, with no stale "signing with: …" ghost from a
// previous session.
document.getElementById("forget-ports").addEventListener("click", async () => {
  try {
    const devices = await navigator.usb.getDevices();
    for (const d of devices) {
      try { await d.forget(); } catch (e) { console.warn("forget failed:", e); }
    }
    await chrome.storage.local.remove("selectedUuid");
    const remaining = (await navigator.usb.getDevices()).length;
    forgetStatusEl.textContent = devices.length === 0
      ? "nothing to reset"
      : `cleared ${devices.length} device(s) and key selection, ${remaining} remaining`;
    forgetStatusEl.classList.add("visible");
    setTimeout(() => forgetStatusEl.classList.remove("visible"), 2500);
  } catch (e) {
    forgetStatusEl.textContent = `error: ${e.message || e}`;
    forgetStatusEl.classList.add("visible");
  }
});
