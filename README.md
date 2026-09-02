<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Nostr Signer for Passport Prime

A hardware [Nostr](https://nostr.com) signer that runs natively on the
[Foundation Passport Prime](https://foundation.xyz), built on KeyOS. Your `nsec`
is sealed to the device and never leaves it: the browser stays the Nostr client,
and Passport only ever returns a signature (or a decrypted payload) after you
approve the request on the device screen, unless it matches a narrow auto-sign
rule that you configured on Passport Prime.

It has two halves that ship together in this repo:

- **`/` (the KeyOS app)** — a Rust + Slint application that holds the keys,
  derives new Nostr identities deterministically from its protected app seed, seals
  identity records with the app seed, and shows an on-device approval screen
  for signing, encryption, and decryption requests that are not covered by an
  owner-configured auto-sign rule.
- **`extension/` (the browser extension)** — a Chromium extension that
  implements the standard NIP-07 `window.nostr` surface and relays requests to
  the simulator over WebSocket. Its experimental WebUSB client is retained for
  a future public KeyOS host transport.

> **Proof-of-concept.** The app is a standalone Foundation SDK project. The
> signer UI and crypto run on Passport Prime, but SDK 1.4 does not expose a
> public app-owned USB or QuantumLink transport, so browser signing on hardware
> is unavailable in this build.

## Quickstart

Three levels, from "works on any laptop right now" to "on real hardware". An AI
coding agent can drive all of them; each doc linked below is written to be read
by one.

### 1. Verify the crypto and protocol (no hardware, no KeyOS)

All the Nostr primitives and the wire types live in a self-contained Rust
workspace under [`logic/`](logic) with **no KeyOS dependencies**, so they build
and test on any machine with Rust installed:

```bash
git clone https://github.com/BitcoinQnA/passport-nostr-signer.git
cd passport-nostr-signer/logic
cargo test
# => 55 tests pass across nostr-core (30), keystore (8), protocol (17)
```

This exercises BIP-340 signing, NIP-04/44 encryption, NIP-06 key derivation,
bech32, and the request/response envelope. It is the fastest way to confirm the
core is sound.

### 2. Run the full signer in the simulator

The signer is a KeyOS app, so it builds inside a **KeyOS workspace** (KeyOS is
Foundation's device OS, public at launch). Drop this repo in at
`apps/gui-app-nostr-signer` per [`SDK-SETUP.md`](SDK-SETUP.md), then from the
KeyOS root run the hosted simulator:

```bash
just sim
```

Open the launcher and select **Nostr Signer**. It serves a WebSocket on
`127.0.0.1:9876`; confirm it is alive with any WebSocket client:

```bash
echo '{"id":"1","method":"ping"}' | websocat ws://127.0.0.1:9876
# => {"id":"1","result":{"pong":true}}
```

See [`TESTING.md`](TESTING.md) for the full end-to-end walkthrough and
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire format.

### 3. Use it from a browser

Load the extension unpacked (`chrome://extensions` -> Developer mode -> Load
unpacked -> [`extension/`](extension)), allow a site, and sign a NIP-01 event in
any NIP-07 client. The extension talks to the simulator over WebSocket. Hardware
transport will require a public QuantumLink app API. See
[`extension/README.md`](extension/README.md).

> **Working with an AI agent?** Every layer has a doc: the wire protocol
> ([`docs/PROTOCOL.md`](docs/PROTOCOL.md)), the auto-sign policy model
> ([`docs/AUTO-SIGN.md`](docs/AUTO-SIGN.md)), hardware transport
> ([`docs/HARDWARE.md`](docs/HARDWARE.md)), and KeyOS integration
> ([`SDK-SETUP.md`](SDK-SETUP.md)). Point your agent at these and the repo is
> self-navigating.

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

- **`getPublicKey`** — returns the active identity's public key (npub), after
  the browser extension has been allowed for that site origin.
- **`signEvent`** — signs a NIP-01 event with BIP-340 Schnorr. By default you
  approve on the device; exact-origin/exact-kind auto-sign rules can skip the
  swipe for trusted, low-risk events while keeping an expiry and hourly cap.
- **`nip04` / `nip44` encrypt & decrypt** — legacy (AES-256-CBC + ECDH) and v2
  (ChaCha20 + HMAC-SHA256 + HKDF) DM encryption, also behind on-device
  approval.

On the device, the **Nostr Signer** app manages identities: generate a new key,
import one by QR, label and colour it, configure per-key auto-sign rules,
archive/restore, and delete. The secret key can be revealed only deliberately,
behind a confirmation, for transferring the identity to another signer.

## How the keys stay safe

- **Recoverable deterministic generation.** New identities are derived via
  NIP-06 from the app-scoped seed (`m/44'/1237'/account'/0/0`). Restoring the
  same device backup and installing the app with its unchanged app ID recovers
  the same Nostr key. Imported `nsec` keys remain supported for migration.
- **Sealed local storage.** Stored identity records are encrypted with the KeyOS
  app seed (`os/security` → `GetAppSeed`) before they touch the filesystem.
- **Approval gate.** Every origin must first be allowed in the extension popup,
  and sensitive requests route through the `Approver` trait
  (`src/approval.rs`), which drives the on-device approve/reject screen
  (`src/engine.rs`). The only no-swipe path is a device-local auto-sign policy:
  exact key, exact HTTP(S) origin, exact kind, expiry, hourly cap, authenticated
  storage, and an audit record. The extension cannot create or relax these
  policies.
- **Auto-sign policy model.** The current no-swipe scope and future hardening
  plan are documented in [`docs/AUTO-SIGN.md`](docs/AUTO-SIGN.md).
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
  screen wiring, auto-sign policy enforcement, the QR import flow, and the
  device-key wiring (app seed to master key). `transport/` carries WebSocket
  for the simulator and an explicit offline status on device.
- **`ui/`** — Slint pages under `ui/pages/*`; routing in `ui/gen/*` is generated
  by `build.rs` from each page's `props.slint`.
- **`extension/`** — the experimental Chromium NIP-07 provider.
- **`i18n/en.json`** — user-facing strings (localization scaffold; see
  [SDK-SETUP.md](SDK-SETUP.md)).

## Building

This is a **self-contained Foundation SDK app**. Clone it and build with the
Foundation SDK; **no KeyOS source checkout and no private-repo access are
required**. The KeyOS platform crates (`slint-keyos-platform`, `security`,
`server`, ...) are provided by the installed SDK, which the CLI maps into
the project under `.foundation-sdk/` (gitignored) at build time.

```bash
foundation doctor            # verify the SDK toolchain
foundation cert gen <name>   # one-time signing identity
foundation build --release   # build + sign for the device
foundation sideload --release # install onto a Passport Prime (1.4 beta)
foundation sim               # or run in the hosted simulator, no hardware
```

Full details, including Developer Mode / Airlock requirements, are in
[`SDK-SETUP.md`](SDK-SETUP.md); the end-to-end test is in
[`TESTING.md`](TESTING.md).

The earlier raw-WebUSB experiment is retained only as design history in
[`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md). It is not part of the SDK app.

The extension installs unpacked (`chrome://extensions` → Developer mode → Load
unpacked → `extension/`); see [`extension/README.md`](extension/README.md).

## Status

Proof-of-concept: key management, crypto, QR import, approval, and auto-sign
policy logic are implemented. Simulator NIP-07 works over WebSocket. Hardware
browser signing is pending a public KeyOS host transport.

## License

GPL-3.0-or-later. Copyright Foundation Devices, Inc. Source files carry SPDX
headers; the full text is in [`LICENSE`](LICENSE).
