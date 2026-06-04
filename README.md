<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Nostr Signer for Passport Prime

A hardware [Nostr](https://nostr.com) signer that runs natively on the
[Foundation Passport Prime](https://foundation.xyz), built on KeyOS. Your `nsec`
is sealed to the device and never leaves it: the browser stays the Nostr client,
and Passport only ever returns a signature (or a decrypted payload) after you
approve the request on the device screen.

It has two halves that ship together in this repo:

- **`/` (the KeyOS app)** — a Rust + Slint application that holds the keys,
  derives them from the device's hardware-backed app seed, and shows an
  on-device approval screen for every signing and encryption request.
- **`extension/` (the browser extension)** — a Chromium extension that
  implements the standard NIP-07 `window.nostr` surface and relays requests to
  Passport over WebUSB (or WebSocket against the simulator).

> **Proof-of-concept.** This is a KeyOS application (it builds inside a KeyOS
> workspace, not standalone — see [Building](#building)) plus a companion
> extension. Validated on a Passport Prime dev unit over WebUSB.

## Demo

A short video of the signer running on real (dev) Passport Prime hardware,
signing a Nostr event end to end:

▶ **[Watch the demo on Nostr](https://primal.net/e/nevent1qqsvfcu924zerqmwux6uftfuhuz5lyqme3lrzmcjat8hrz4x6vwt9qc445tlt)**

## Why one repo

The signer and the extension are two halves of one mechanism — the device is
inert without the host-side NIP-07 provider, and both sides speak the same wire
protocol (the `protocol` crate, mirrored in the extension's JS). Keeping them
together means the firmware and the extension move in lockstep and share one
version. See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire format.

## What it does

The extension exposes the full NIP-07 surface; each call is brokered to the
device:

- **`getPublicKey`** — returns the active identity's public key (npub).
- **`signEvent`** — signs a NIP-01 event with BIP-340 Schnorr, but only after
  you approve it on the device. The approval screen shows the origin, event
  kind, a content preview, and tags.
- **`nip04` / `nip44` encrypt & decrypt** — legacy (AES-256-CBC + ECDH) and v2
  (ChaCha20 + HMAC-SHA256 + HKDF) DM encryption, also behind approval.

On the device, the **Nostr Signer** app manages identities: generate a new key,
import one by QR, label and colour it, archive/restore, and delete. The secret
key can be revealed only deliberately, behind a confirmation, for transferring
the identity to another signer.

## How the keys stay safe

- **Sealed to the device.** Identities are derived from the KeyOS **app seed**
  (`os/security` → `GetAppSeed`), so the `nsec` is bound to this Passport and is
  not backed up. Removing a key is irreversible.
- **Approval gate.** Nothing is signed or decrypted silently. Every request
  routes through the `Approver` trait (`src/approval.rs`), which drives the
  on-device approve/reject screen (`src/engine.rs`). The extension can only ever
  obtain a result the device owner explicitly approved.
- **The crypto is host-testable and KeyOS-free.** All Nostr primitives live in
  `logic/nostr-core` with no KeyOS dependencies, so they run under `cargo test`
  on the host.

## Architecture

- **`logic/`** — a vendored, self-contained sub-workspace (no external repo
  needed to build):
  - **`nostr-core`** — pure-Rust Nostr primitives: BIP-340 x-only keys, NIP-01
    event id + Schnorr sign/verify, NIP-19 bech32 (`nsec`/`npub`/`note`), NIP-04
    and NIP-44 v2 encryption, NIP-06 BIP-39 derivation (`m/44'/1237'/acct'/0/0`).
  - **`keystore`** — identity storage and the master-key source abstraction.
  - **`protocol`** — the request/response wire types shared with the extension.
- **`src/`** — the KeyOS/Slint app shell: the engine/dispatcher, the approval
  screen wiring, the QR import flow, and the device-key wiring (app seed →
  master key). `transport/` carries WebUSB (device) and WebSocket (simulator).
- **`ui/`** — Slint pages under `ui/pages/*`; routing in `ui/gen/*` is generated
  by `build.rs` from each page's `props.slint`.
- **`extension/`** — the Chromium WebUSB extension (NIP-07 provider).
- **`i18n/en.json`** — user-facing strings (localization scaffold; see
  [SDK-SETUP.md](SDK-SETUP.md)).

## Building

This is a KeyOS app and builds **inside a KeyOS workspace** (it depends on KeyOS
crates such as `slint_keyos_platform`, `security`, `server`, and `usb`). See
[`SDK-SETUP.md`](SDK-SETUP.md) for the toolchain and integration, and
[`TESTING.md`](TESTING.md) for the end-to-end test. In a KeyOS checkout the app
lives at `apps/gui-app-nostr-signer`.

Unlike a typical app, the on-device USB transport also needs two small KeyOS USB
(PIO) fixes — see [`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md) and
[`docs/keyos-pio-fixes.patch`](docs/keyos-pio-fixes.patch).

The extension installs unpacked (`chrome://extensions` → Developer mode → Load
unpacked → `extension/`); see [`extension/README.md`](extension/README.md).

## Status

Proof-of-concept, validated on a Passport Prime dev unit over WebUSB: add a key,
expose `window.nostr` in the browser, sign a NIP-01 event with on-device
approval, and verify the signature in a NIP-07 client.

## License

GPL-3.0-or-later. Copyright Foundation Devices, Inc. Source files carry SPDX
headers; the full text is in [`LICENSE`](LICENSE).
