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

1. **Flash a KeyOS build that includes the app** (and the USB PIO fixes — see
   [`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md)). Build the image on Ubuntu
   or in the KeyOS Nix shell, then flash over USB (SAM-BA):

   ```bash
   cargo xtask build && cargo xtask flash
   ```

2. **Open the app and add a key.** Launch **Nostr Signer** on Passport (hidden
   apps / Secret Menu) and derive a deterministic NIP-06 identity from the
   device seed, or import an existing `nsec` by QR.

3. **Load the extension** (`chrome://extensions` → Developer mode → Load
   unpacked → `extension/`). Leave it on the default **WebUSB** transport.

4. **Pair over WebUSB.** Open the extension's **Settings** page and click
   **Pair Passport Prime**, then select your Prime in the Chromium WebUSB picker
   (this requires a user gesture, which is why it is initiated from the options
   page). The device registers a vendor-class interface
   (class/subclass/protocol = `0xFF/0xFF/0xFF`) with two 64-byte interrupt
   endpoints.

5. **Allow the site and sign.** On noStrudel/Snort, sign in with the extension.
   The first call from that origin is blocked until you open the extension popup
   and click **Allow** for the site. After that, `getPublicKey` returns your
   npub; publishing a note triggers the **on-device approval screen** showing
   the origin, event kind, content preview, and tags. Approve on Passport, and
   the client gets the signed event. Try `nip04`/`nip44` encrypt + decrypt the
   same way — each sensitive operation is gated by on-device approval.

6. **Verify a no-swipe rule on hardware.** From the selected key's detail page,
   create the same `https://nostrudel.ninja` / kind `22242` auto-sign rule used
   in Track A. Repeat the console `signEvent` call above. The auth event should
   sign without a swipe, while a kind `1` note and all `nip04`/`nip44`
   encrypt/decrypt requests still require approval.

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
- The older WebSerial (CDC-ACM) extension build is **not** included here; this
  repo ships the WebUSB build that matches `src/transport/webusb.rs`.
- Production USB VID/PID for the vendor interface is still TBD (see
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md)); dev builds pair by device selection
  in the WebUSB picker.
