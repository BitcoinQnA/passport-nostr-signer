<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Testing the Nostr Signer end to end

The signer is exercised through the browser: load the extension, point a NIP-07
Nostr client at it, and watch each request surface on Passport for approval.
There are two transports — pick the track that matches your setup.

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

   Open **Nostr Signer** in the simulator. On first launch it seeds a dev key so
   there is an identity to sign with; add or import more from the main screen.
   The app listens on `ws://127.0.0.1:9876`.

2. **Load the extension.** `chrome://extensions` → enable **Developer mode** →
   **Load unpacked** → select `extension/`.

3. **Switch the extension to simulator mode.** Open the extension's **Settings**
   (options) page and enable **Simulator mode** (WebSocket). It will connect to
   `ws://127.0.0.1:9876`.

4. **Use a NIP-07 client.** Visit noStrudel or Snort, choose **Sign in with
   extension** (`window.nostr`). `getPublicKey` returns the sim identity; when
   you publish a note, the **approval screen appears in the simulator** — approve
   it, and the client receives the signed event.

---

## Track B — Device (Passport Prime)

1. **Flash a KeyOS build that includes the app** (and the USB PIO fixes — see
   [`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md)). Build the image on Ubuntu
   or in the KeyOS Nix shell, then flash over USB (SAM-BA):

   ```bash
   cargo xtask build && cargo xtask flash
   ```

2. **Open the app and add a key.** Launch **Nostr Signer** on Passport (hidden
   apps / Secret Menu) and generate or import an identity. The `nsec` is sealed
   to this device.

3. **Load the extension** (`chrome://extensions` → Developer mode → Load
   unpacked → `extension/`). Leave it on the default **WebUSB** transport.

4. **Pair over WebUSB.** Open the extension's **Settings** page and click
   **Pair Passport Prime**, then select your Prime in the Chromium WebUSB picker
   (this requires a user gesture, which is why it is initiated from the options
   page). The device registers a vendor-class interface
   (class/subclass/protocol = `0xFF/0xFF/0xFF`) with two 64-byte interrupt
   endpoints.

5. **Sign from a NIP-07 client.** On noStrudel/Snort, sign in with the
   extension. `getPublicKey` returns your npub; publishing a note triggers the
   **on-device approval screen** showing the origin, event kind, content
   preview, and tags. Approve on Passport, and the client gets the signed event.
   Try `nip04`/`nip44` encrypt + decrypt the same way — each is gated by an
   approval.

---

## What "pass" looks like

- `getPublicKey` returns the device's identity (npub) to the client.
- A `signEvent` request **always** raises an approval on the device; rejecting
  it returns an error to the client and signs nothing.
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
