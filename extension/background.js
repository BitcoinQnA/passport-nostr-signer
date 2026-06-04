// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// Service worker: maintains a connection to the signer, tracks the
// currently selected key uuid, and dispatches incoming requests from
// content scripts.
//
// Two transports are supported:
//   - "ws"     WebSocket to ws://127.0.0.1:9876 (simulator / hosted mode)
//   - "webusb" WebUSB to a Passport Prime's vendor-class interface (production)
// The active transport is persisted in chrome.storage.local under
// `transportKind`. It can be changed from the options page.

// The WebUSB transport lives in an offscreen document because
// navigator.usb is not exposed in MV3 service workers. We proxy RPC
// through it below.

const DEFAULT_WS = "ws://127.0.0.1:9876";
// Default to the production transport. Developers flip the "simulator mode"
// checkbox on the options page to switch to WS; this is stored as
// transportKind: "ws" in chrome.storage.local.
const DEFAULT_TRANSPORT = "webusb";

// Methods the signer treats as unit variants — do NOT attach params to
// these. Adding origin/uuid would yield `invalid type: map, expected
// unit variant` on the server.
const UNIT_METHODS = new Set(["ping", "list_keys", "get_public_key"]);

let ws = null;
let wsReady = null; // Promise<void>
let wsQueue = new Map(); // id → { resolve, reject }
let serverUrl = DEFAULT_WS;
let selectedUuid = null;
let transportKind = DEFAULT_TRANSPORT;
// --- Offscreen document proxy for Web Serial --------------------------------
//
// Web Serial is only available in document contexts. We create a hidden
// offscreen document (offscreen.html) that owns the WebSerialTransport
// instance, and proxy requests to it via chrome.runtime.sendMessage.

const OFFSCREEN_URL = chrome.runtime.getURL("offscreen.html");

async function ensureOffscreen() {
  // hasDocument may be undefined in older Chromium; guard for it.
  if (chrome.offscreen?.hasDocument) {
    if (await chrome.offscreen.hasDocument()) return;
  }
  try {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_URL,
      // WORKERS is the closest documented reason for "background
      // execution that requires DOM APIs", which is what we need to
      // reach navigator.usb.
      reasons: ["WORKERS"],
      justification:
        "WebUSB access to paired Passport Prime is not available in the MV3 service worker.",
    });
  } catch (e) {
    // Races with another ensureOffscreen or already-exists errors are
    // ignored — any subsequent sendMessage will route to the live doc.
    if (!String(e).includes("Only a single offscreen document")) throw e;
  }
}

async function offscreenCall(type, extra) {
  await ensureOffscreen();
  return await chrome.runtime.sendMessage({ target: "offscreen-usb", type, ...extra });
}

const usb = {
  async connect() {
    const res = await offscreenCall("connect");
    if (!res?.ok) throw new Error(res?.error || "offscreen connect failed");
  },
  async disconnect() {
    try {
      await offscreenCall("disconnect");
    } catch { /* fine — offscreen may not exist */ }
  },
  async rpc(method, params) {
    const res = await offscreenCall("rpc", { method, params });
    if (!res?.ok) throw new Error(res?.error || "offscreen rpc failed");
    return res.result;
  },
};

// Load settings from chrome.storage on startup.
chrome.storage.local.get(["serverUrl", "selectedUuid", "transportKind"], (v) => {
  serverUrl = v.serverUrl || DEFAULT_WS;
  selectedUuid = v.selectedUuid || null;
  transportKind = v.transportKind || DEFAULT_TRANSPORT;
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.serverUrl) {
    serverUrl = changes.serverUrl.newValue || DEFAULT_WS;
    try { ws?.close(); } catch {}
    ws = null;
    wsReady = null;
  }
  if (changes.selectedUuid) {
    selectedUuid = changes.selectedUuid.newValue || null;
  }
  if (changes.transportKind) {
    const old = transportKind;
    transportKind = changes.transportKind.newValue || DEFAULT_TRANSPORT;
    if (old !== transportKind) {
      // Drop both transports so the new one is used on next request.
      try { ws?.close(); } catch {}
      ws = null;
      wsReady = null;
      try { usb.disconnect(); } catch {}
    }
  }
});

function uuid() {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

async function ensureConnected() {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  if (wsReady) return wsReady;

  wsReady = new Promise((resolve, reject) => {
    try {
      ws = new WebSocket(serverUrl);
    } catch (e) {
      reject(e);
      wsReady = null;
      return;
    }
    ws.addEventListener("open", () => {
      resolve();
      // Re-sync the selected key after every (re)connect so the server's
      // in-process selection survives our service-worker being torn down
      // between signing requests.
      if (selectedUuid && ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({
            id: uuid(),
            method: "select_key",
            params: { uuid: selectedUuid },
          }));
        } catch (e) {
          console.warn("[prime-signer] select_key resync failed:", e);
        }
      }
    });
    ws.addEventListener("error", () => {
      reject(new Error("cannot reach signer at " + serverUrl));
      wsReady = null;
    });
    ws.addEventListener("close", () => {
      ws = null;
      wsReady = null;
      for (const [, entry] of wsQueue) {
        entry.reject(new Error("connection closed"));
      }
      wsQueue.clear();
    });
    ws.addEventListener("message", (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch (e) {
        console.warn("[prime-signer] non-json frame:", ev.data);
        return;
      }
      const entry = wsQueue.get(msg.id);
      if (!entry) return;
      wsQueue.delete(msg.id);
      if (msg.error) {
        entry.reject(msg.error);
      } else {
        entry.resolve(msg.result);
      }
    });
  });
  return wsReady;
}

// Raw RPC. For unit-variant methods (UNIT_METHODS), params MUST be null —
// serde tag+content cannot deserialise `{}` into a unit variant.
async function rpc(method, params) {
  const cleanParams =
    UNIT_METHODS.has(method) || !params || Object.keys(params).length === 0 ? null : params;
  if (transportKind === "webusb") {
    return usb.rpc(method, cleanParams);
  }
  await ensureConnected();
  return new Promise((resolve, reject) => {
    const id = uuid();
    wsQueue.set(id, { resolve, reject });
    const payload = { id, method };
    if (cleanParams) payload.params = cleanParams;
    try {
      ws.send(JSON.stringify(payload));
    } catch (e) {
      wsQueue.delete(id);
      reject(e);
    }
    setTimeout(() => {
      if (wsQueue.has(id)) {
        wsQueue.delete(id);
        reject({ code: 5, message: "signer timeout" });
      }
    }, 5 * 60 * 1000);
  });
}

// Map NIP-07 call + metadata (origin, selectedUuid) to the signer's method
// surface, building exactly the right params for each method.
async function ensureValidSelection() {
  try {
    const listRes = await rpc("list_keys", null);
    const keys = listRes?.keys || [];
    if (selectedUuid && !keys.some((k) => k.uuid === selectedUuid)) {
      selectedUuid = null;
      await chrome.storage.local.set({ selectedUuid: null });
    }
    if (!selectedUuid && keys.length > 0) {
      selectedUuid = keys[0].uuid;
      await chrome.storage.local.set({ selectedUuid });
      await rpc("select_key", { uuid: selectedUuid });
    }
  } catch (e) {
    // If list_keys itself fails we can't validate — let the original
    // request surface whatever error comes next.
  }
}

async function handleMethod(method, params, origin) {
  switch (method) {
    case "get_public_key":
      await ensureValidSelection();
      // Unit variant on the server. No params.
      return await rpc("get_public_key", null);

    case "sign_event":
      await ensureValidSelection();
      return await rpc("sign_event", pruneEmpty({
        uuid: selectedUuid,
        origin,
        event: params?.event,
      }));

    case "nip04_encrypt":
    case "nip44_encrypt":
      return await rpc(method, pruneEmpty({
        uuid: selectedUuid,
        origin,
        peer_pubkey: params?.peer_pubkey,
        plaintext: params?.plaintext,
      }));

    case "nip04_decrypt":
    case "nip44_decrypt":
      return await rpc(method, pruneEmpty({
        uuid: selectedUuid,
        origin,
        peer_pubkey: params?.peer_pubkey,
        ciphertext: params?.ciphertext,
      }));

    default:
      // Unknown NIP-07 method — let the server return unknown_method.
      return await rpc(method, params);
  }
}

function pruneEmpty(o) {
  const out = {};
  for (const k of Object.keys(o)) {
    const v = o[k];
    if (v !== undefined && v !== null && v !== "") out[k] = v;
  }
  return out;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Messages targeted at the offscreen USB doc are handled there;
  // ignore them here so we don't double-respond.
  if (msg?.target === "offscreen-usb") return;
  (async () => {
    try {
      const result = await handleMethod(msg.method, msg.params, msg.origin);
      sendResponse({ result });
    } catch (err) {
      sendResponse({ error: { code: err?.code ?? 99, message: err?.message || String(err) } });
    }
  })();
  return true;
});

self.addEventListener("message", () => {});

// Popup port: status + key selection.
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "popup") return;

  // When the popup closes, an async `send()` may still be mid-flight on a
  // pending list_keys or USB ping. Flag the port as dead so the follow-up
  // postMessage doesn't throw "Attempting to use a disconnected port object".
  let alive = true;
  port.onDisconnect.addListener(() => { alive = false; });
  const safePost = (payload) => { if (alive) port.postMessage(payload); };

  const send = async () => {
    try {
      if (transportKind !== "webusb") {
        await ensureConnected();
      }
      const listRes = await rpc("list_keys", null);
      const keys = listRes?.keys || [];

      // Self-heal: if the cached selection doesn't match any stored key
      // (e.g. the signer's keystore was reset while this extension kept
      // its stale uuid), silently fall back to the first available key.
      if (selectedUuid && !keys.some((k) => k.uuid === selectedUuid)) {
        console.info("[prime-signer] stored uuid no longer valid, clearing");
        selectedUuid = null;
        await chrome.storage.local.set({ selectedUuid: null });
      }
      if (!selectedUuid && keys.length > 0) {
        selectedUuid = keys[0].uuid;
        await chrome.storage.local.set({ selectedUuid });
        try {
          await rpc("select_key", { uuid: selectedUuid });
        } catch {}
      }

      safePost({
        connected: true,
        transportKind,
        serverUrl,
        selectedUuid,
        keys,
      });
    } catch (err) {
      safePost({
        connected: false,
        transportKind,
        serverUrl,
        selectedUuid,
        error: err?.message || String(err),
      });
    }
  };
  port.onMessage.addListener(async (cmd) => {
    if (cmd?.type === "refresh") await send();
    if (cmd?.type === "select" && cmd.uuid) {
      await chrome.storage.local.set({ selectedUuid: cmd.uuid });
      selectedUuid = cmd.uuid;
      try {
        await rpc("select_key", { uuid: cmd.uuid });
      } catch {}
      await send();
    }
  });
  send();
});
