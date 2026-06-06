// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

const bgPort = chrome.runtime.connect({ name: "popup" });
const statusEl = document.getElementById("status");
const pillEl = document.getElementById("status-pill");
const selectedEl = document.getElementById("selected");
const keysEl = document.getElementById("keys");
const originsEl = document.getElementById("origins");
const pairBtn = document.getElementById("pair");

bgPort.onMessage.addListener((msg) => {
  if (msg.connected) {
    statusEl.textContent = msg.transportKind === "webusb"
      ? "Connected to Passport Prime"
      : "Connected to simulator";
    pillEl.className = "pill pill-ok";
    pairBtn.hidden = true;
  } else {
    statusEl.textContent = msg.error || "Not connected to Passport Prime";
    pillEl.className = "pill pill-err";
    // Offer the pair button whenever we're in WebUSB mode and not connected.
    // "Not connected" in WebUSB mode almost always means "no Prime paired"
    // and the next step is the picker on the options page.
    pairBtn.hidden = msg.transportKind !== "webusb";
  }

  // Only show the "signing with" line when actually connected. Without
  // a live session we can't verify the stored uuid still exists on the
  // device, so displaying it is misleading (e.g. after a "Forget all"
  // reset or a Prime reboot that wiped Airlock).
  if (msg.connected && msg.selectedUuid) {
    selectedEl.textContent = `signing with: ${shortHex(msg.selectedUuid)}`;
  } else if (msg.connected && msg.keys && msg.keys.length > 0) {
    selectedEl.textContent = "no key selected — click one below";
  } else {
    selectedEl.textContent = "";
  }

  keysEl.innerHTML = "";
  for (const k of msg.keys || []) {
    const li = document.createElement("li");
    li.className = k.uuid === msg.selectedUuid ? "active" : "";
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = k.label;
    const pub = document.createElement("div");
    pub.className = "pubkey";
    pub.textContent = shortNpub(k.pubkey);
    li.appendChild(label);
    li.appendChild(pub);
    li.addEventListener("click", () => {
      bgPort.postMessage({ type: "select", uuid: k.uuid });
    });
    keysEl.appendChild(li);
  }

  renderOrigins(msg.pending || {}, msg.permissions || {});
});

// First-time pairing. `navigator.usb.requestDevice` has to run inside a
// document with stable user-activation. An extension popup loses focus
// the instant the OS device picker appears, which tears down the popup
// script mid-await and silently kills the grant. Options.html is
// configured with `open_in_tab: true`, so it survives focus changes —
// we route the Pair click there with an auto-trigger flag and let the
// options page drive the picker.
pairBtn.addEventListener("click", async () => {
  // Set the flag BEFORE opening the options page — the openOptionsPage
  // callback fires after the page has already loaded and read storage,
  // so writing the flag there is too late.
  await chrome.storage.local.set({ pendingPair: true });
  chrome.runtime.openOptionsPage();
  // Close this popup so the options tab gets focus.
  window.close();
});

document.getElementById("openOptions").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

function renderOrigins(pending, permissions) {
  originsEl.innerHTML = "";
  const pendingList = Object.values(pending).sort((a, b) => a.firstSeen - b.firstSeen);
  if (pendingList.length > 0) {
    const title = document.createElement("div");
    title.className = "section-title";
    title.textContent = "Site access";
    originsEl.appendChild(title);
  }
  for (const entry of pendingList) {
    const row = document.createElement("div");
    row.className = "origin-row";

    const meta = document.createElement("div");
    meta.className = "origin-meta";
    const origin = document.createElement("div");
    origin.className = "origin";
    origin.textContent = entry.origin;
    const method = document.createElement("div");
    method.className = "origin-method";
    method.textContent = methodLabel(entry.method);
    meta.appendChild(origin);
    meta.appendChild(method);

    const actions = document.createElement("div");
    actions.className = "origin-actions";
    const deny = document.createElement("button");
    deny.className = "mini";
    deny.type = "button";
    deny.textContent = "Block";
    deny.addEventListener("click", () => {
      bgPort.postMessage({ type: "deny-origin", origin: entry.origin });
    });
    const allow = document.createElement("button");
    allow.className = "mini primary-mini";
    allow.type = "button";
    allow.textContent = "Allow";
    allow.addEventListener("click", () => {
      bgPort.postMessage({ type: "allow-origin", origin: entry.origin });
    });
    actions.appendChild(deny);
    actions.appendChild(allow);

    row.appendChild(meta);
    row.appendChild(actions);
    originsEl.appendChild(row);
  }

  const allowed = Object.entries(permissions).filter(([, v]) => v === "allowed");
  if (pendingList.length === 0 && allowed.length > 0) {
    const note = document.createElement("div");
    note.className = "origin-note";
    note.textContent = `${allowed.length} site${allowed.length === 1 ? "" : "s"} allowed`;
    originsEl.appendChild(note);
  }
}

function methodLabel(method) {
  switch (method) {
    case "get_public_key": return "wants your public key";
    case "sign_event": return "wants to sign";
    case "nip04_encrypt":
    case "nip44_encrypt": return "wants to encrypt";
    case "nip04_decrypt":
    case "nip44_decrypt": return "wants to decrypt";
    default: return method || "requested access";
  }
}

function shortHex(s) {
  if (!s) return "";
  return s.length > 16 ? `${s.slice(0, 8)}…${s.slice(-8)}` : s;
}

// Bech32 (NIP-19 npub) encoder for displaying x-only hex pubkeys in
// the form Nostr users expect. Compact BIP-173 reference impl.
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= BECH32_GEN[i];
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32Encode(hrp, data) {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = bech32Polymod(values) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  let out = hrp + "1";
  for (const v of data.concat(checksum)) out += BECH32_CHARSET[v];
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const ret = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || (v >>> from) !== 0) return null;
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) { bits -= to; ret.push((acc >>> bits) & maxv); }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null;
  }
  return ret;
}

function hexToBytes(hex) {
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

function hexToNpub(hex) {
  if (!hex) return "";
  try {
    const bytes = hexToBytes(hex);
    const data = convertBits(bytes, 8, 5, true);
    if (!data) return hex;
    return bech32Encode("npub", data);
  } catch {
    return hex;
  }
}

function shortNpub(hex) {
  const npub = hexToNpub(hex);
  if (!npub || npub.length < 20) return npub;
  return `${npub.slice(0, 12)}…${npub.slice(-6)}`;
}
