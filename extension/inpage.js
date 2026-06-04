// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// Injected into every page. Defines `window.nostr` per NIP-07 and relays
// calls to the content script via window.postMessage.
//
// Wire protocol (both directions):
//   { source: "prime-nostr-signer", id: <uuid>, kind: "request" | "response",
//     method: <str>, params?: any, result?: any, error?: any }
//
// The content script runs in the ISOLATED world, listens for "request"
// messages on window, forwards to the service worker, and posts back a
// "response" with the matching id.

(function () {
  "use strict";

  const SOURCE = "prime-nostr-signer";
  const pending = new Map();

  function uuid() {
    // Short random id is fine — only needs to be unique while in-flight.
    const b = new Uint8Array(8);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  }

  function call(method, params) {
    return new Promise((resolve, reject) => {
      const id = uuid();
      pending.set(id, { resolve, reject });
      window.postMessage(
        { source: SOURCE, id, kind: "request", method, params: params || {} },
        "*",
      );
      // Safety: time out after 5 minutes so approval prompts don't leak.
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error("signer request timed out"));
        }
      }, 5 * 60 * 1000);
    });
  }

  window.addEventListener("message", (ev) => {
    const data = ev.data;
    if (!data || data.source !== SOURCE || data.kind !== "response") return;
    const entry = pending.get(data.id);
    if (!entry) return;
    pending.delete(data.id);
    if (data.error) {
      entry.reject(new Error(data.error.message || "signer error"));
    } else {
      entry.resolve(data.result);
    }
  });

  const nip04 = {
    encrypt: (pubkey, plaintext) =>
      call("nip04_encrypt", { peer_pubkey: pubkey, plaintext }).then((r) => r.ciphertext),
    decrypt: (pubkey, ciphertext) =>
      call("nip04_decrypt", { peer_pubkey: pubkey, ciphertext }).then((r) => r.plaintext),
  };

  const nip44 = {
    encrypt: (pubkey, plaintext) =>
      call("nip44_encrypt", { peer_pubkey: pubkey, plaintext }).then((r) => r.ciphertext),
    decrypt: (pubkey, ciphertext) =>
      call("nip44_decrypt", { peer_pubkey: pubkey, ciphertext }).then((r) => r.plaintext),
  };

  window.nostr = {
    async getPublicKey() {
      const r = await call("get_public_key", {});
      return r.pubkey;
    },

    async signEvent(event) {
      return await call("sign_event", { event });
    },

    async getRelays() {
      // Signer does not track relay preferences in v1.
      return {};
    },

    nip04,
    nip44,
  };

  // Let consumers feature-detect.
  Object.defineProperty(window.nostr, "_provider", {
    value: "passport-prime",
    enumerable: false,
    writable: false,
    configurable: false,
  });
})();
