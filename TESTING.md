<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Testing the Nostr Signer end to end

The signer is exercised through the browser: load the extension, point a NIP-07
Nostr client at it, and watch requests surface on Passport for approval unless
they match an owner-configured auto-sign rule. There are two transports — pick
the track that matches your setup.

| Track | Device side | Transport | Needs hardware |
|-------|-------------|-----------|----------------|
| **A — Simulator** | KeyOS hosted sim | WebSocket `ws://127.0.0.1:9876` | No |
| **B — Device** | Passport Prime | WebUSB | Yes |

Both tracks use the same extension and the same NIP-07 clients (e.g.
[noStrudel](https://nostrudel.ninja), [Snort](https://snort.social)).

---

## Track A — Simulator (no hardware)

1. **Run the app in the sim.** From your KeyOS checkout (app integrated per
   [`SDK-SETUP.md`](SDK-SETUP.md)):

   ```bash
   just sim          # or: cargo xtask run --hosted
   ```

   Open **Nostr Signer** in the simulator and derive or import an identity from
   the main screen. The app listens on `ws://127.0.0.1:9876`.

2. **Load the extension.** `chrome://extensions` → enable **Developer mode** →
   **Load unpacked** → select `extension/`.

3. **Switch the extension to simulator mode.** Open the extension's **Settings**
   (options) page and enable **Simulator mode** (WebSocket). It will connect to
   `ws://127.0.0.1:9876`.

4. **Use a NIP-07 client.** Visit noStrudel or Snort, choose **Sign in with
   extension** (`window.nostr`). `getPublicKey` returns the sim identity; when
   you publish a note, the **approval screen appears in the simulator** — approve
   it, and the client receives the signed event.

5. **Test auto-sign.** Open the key's detail page in the app, expand
   **Auto-sign rules**, and add:

   - Origin: `https://nostrudel.ninja`
   - Event kind: `22242`
   - Expiry hours: `24`
   - Max per hour: `2`

   In noStrudel, trigger a NIP-42 auth event, or run this in the page console:

   ```js
   await window.nostr.signEvent({
     kind: 22242,
     created_at: Math.floor(Date.now() / 1000),
     tags: [["relay", "wss://relay.damus.io"], ["challenge", "test"]],
     content: ""
   })
   ```

   The matching event should return without an approval screen. A normal kind
   `1` note should still prompt. After two matching auth events in the same
   hour, the next matching event should fall back to manual approval.

---

## Track B — Device (Passport Prime)

1. **Build and sideload the standalone app:**

   ```bash
   foundation doctor
   foundation build --release
   foundation sideload --release
   ```

2. **Open the app and add a key.** Derive a deterministic NIP-06 identity from
   the protected app seed, or import an existing `nsec` by QR. Verify local
   select, rename, archive, restore, delete, and policy-management flows.

3. **Confirm the transport status.** SDK 1.4 does not expose raw USB or a public
   QuantumLink app transport, so the device must report that the host link is
   offline. Run browser protocol tests in Track A until that API is public.

---

## What "pass" looks like

- `getPublicKey` returns the device's identity (npub) to the client.
- A new origin cannot access `window.nostr` results until allowed in the
  extension popup.
- A normal `signEvent` request raises an approval on the device; rejecting it
  returns an error to the client and signs nothing.
- A configured auto-sign rule only skips approval for the exact key, origin,
  kind, expiry, and rate-limit window shown on the key detail page.
- An approved event verifies (valid BIP-340 Schnorr signature over the NIP-01
  id) in the client and broadcasts to relays.
- The `nsec` is never transmitted: the extension only ever receives signatures
  and decrypted payloads, never the secret key.

## Notes

- **Simulator file/key state** lives under the app's data dir
  (`.passport-nostr-signer-keyos`); deleting it resets identities in the sim.
- The extension's WebUSB client is retained as a prototype and is not supported
  by the standalone SDK device build.
