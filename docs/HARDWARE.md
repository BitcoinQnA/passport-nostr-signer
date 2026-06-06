# Running the Nostr Signer on real Passport Prime hardware

This doc walks through the first end-to-end run on a physical Passport
Prime device: build the firmware, flash it, onboard, pair with a
Chromium browser over WebUSB, and sign a real Nostr event.

Prerequisites:

- An Ubuntu 22.04 or 24.04 machine (or the KeyOS Docker image) with the
  KeyOS checkout and Rust toolchain per `KeyOS/DEVELOPMENT.md`. macOS
  hosts can run the simulator but not a real flash build — the
  `armv7a-unknown-xous-elf` sysroot builds on Ubuntu.
- A Passport Prime with USB access, and the short-to-enter SAM-BA
  instructions from `KeyOS/DEVELOPMENT.md`.
- The Chromium-family browser on your Mac (Chrome, Brave, Edge, Arc).
  WebUSB is not available in Safari.

The Nostr Signer app itself already type-checks for the ARM target
(confirmed via `cargo xtask check gui-app-nostr-signer`). The
transport-level code is behind `cfg(target_os = "xous")` and only
compiles into the production binary — on hosted mode the WebSocket
transport runs instead.

## 1. Build the firmware

From the KeyOS checkout on your Ubuntu box:

```sh
# One-time toolchain install (downloads the custom Xous sysroot):
cargo xtask install-toolchain

# Build all services, apps, and the kernel for Prime:
cargo xtask build --dont-sign

# Or, for a full flash-able firmware image (bootloader + recovery + normal):
cargo xtask build-all
```

The resulting binaries land in `target/armv7a-unknown-xous-elf/release/`
and the bundled image in the paths documented in `DEVELOPMENT.md`.

## 2. Flash

Short the SAM-BA contacts on the device per the bricked-recovery section
of `DEVELOPMENT.md`, or enter SAM-BA mode through the boot menu (hold
power 10s, tap power 3 times when the logo appears, pick SAM-BA). Then:

```sh
just flash
```

Disconnect the device only after flashing completes.

## 3. First boot and onboarding

1. Power up Prime. Complete the standard onboarding flow (set PIN,
   generate or restore a seed). The Nostr Signer derives its keystore
   master from `security.app_seed()`, so you need a real seed and a
   logged-in session for the keystore to unlock.
2. From the launcher, navigate to **Nostr Signer**.
3. Tap **Add key** and choose one of:
   - **Derive from device seed** — NIP-06 account 0 over the BIP-39
     mnemonic that secures the rest of the device. Deterministic,
     recoverable from your seed and account index.
   - **Scan nsec1 QR code** — for migrating an existing identity (e.g.
     from another signer). You can print the target nsec as a QR on your
     laptop.

Tap the key row's edit icon to rename at any time. The radio circle on
the left selects the active identity.

## 4. Install the browser extension

On your Mac, in Chrome (or any Chromium browser):

1. Open `chrome://extensions`.
2. Toggle **Developer mode** on.
3. Click **Load unpacked** and point at
   `passport-nostr-signer/extension/`.
4. Pin the extension from the puzzle icon.

## 5. Pair over WebUSB

1. Plug Prime into your Mac.
2. Open the Nostr Signer app on Prime. The WebUSB interface is registered
   when the app starts; it deregisters when you navigate away.
3. In Chrome, open the extension's **Settings** page:
   - Transport: **WebUSB (Passport Prime hardware)**
   - Click **Pair Passport Prime**
4. Chrome shows the WebUSB device picker. Pick your Prime. Chrome remembers
   the grant.

The extension's popup should now show **connected** and list the keys
stored on your device.

## 6. Sign your first event

1. In a new tab, go to `https://nostrudel.ninja` (or any NIP-07 client).
2. Sign in with **Extension**. The first site request is blocked until you open
   the extension popup and allow that origin.
3. Retry sign-in. The site calls
   `window.nostr.getPublicKey()` → extension → WebUSB → Prime → returns
   the npub. No on-device approval prompt yet (read-only after origin allow).
4. Write a test note and click Post. The approval card now pops up
   **on Prime's screen**:
   - Origin (e.g. `https://nostrudel.ninja`)
   - Key label and short npub
   - Event kind (e.g. "text note") and content preview
5. Tap **Approve** on Prime. The signed event returns over USB to the
   browser and publishes to your relays. Tap **Reject** instead and the
   site sees a `user_rejected` error.

## Troubleshooting

### Prime doesn't show up in the Chrome WebUSB picker

- Confirm the **Nostr Signer** app is open on Prime (not just in the
  background — the switcher closes the app-owned WebUSB interface on app hide).
- Check `chrome://device-log` for USB events. You should see the Prime
  enumeration when you plug it in with the app open.
- On Linux/macOS: `lsusb` / `system_profiler SPUSBDataType` should
  include a new vendor-class interface alongside Prime's existing interfaces.

### WebUSB picker doesn't filter our device

The development extension filters on the vendor-class interface triple
`0xFF/0xFF/0xFF` until a dedicated production VID/PID is assigned.

### "no such uuid" in the browser

The extension has a stale `selected_uuid` in `chrome.storage`. Click the
extension popup and tap your key to re-select, or clear via the
extension's Settings page. The background script also self-heals on the
next `list_keys` call.

### Approval prompt appears but tapping Approve does nothing

Check Prime's system log via the serial console or the log-viewer tool
(`just logs-serial /dev/tty.usbmodem…`). Look for lines tagged
`gui_app_nostr_signer::transport::webusb` and the engine's sign_event
flow.

### Coexistence with FIDO

Prime already exposes a FIDO interface for security-key use cases.
Our signer adds a separate vendor-class WebUSB interface on its own endpoints
when the app is open. If two interfaces try to claim the same endpoint numbers,
you'll
see a `register_interface` error at app startup — report this and we'll
assign fixed endpoint ranges.

## What's known-good vs. scaffolded

**Known-good, tested end-to-end in the hosted simulator:**

- Multi-key keystore with AES-256-GCM sealing via `security.app_seed()`
- NIP-01 event signing (BIP-340 schnorr, regression-tested against
  nostr-tools `verifyEvent`)
- NIP-04 legacy DM encryption, NIP-44 v2 encryption
- NIP-06 mnemonic-to-nostr-key derivation
- NIP-19 bech32 encoding
- Slint approval UI, tap-to-select, tap-to-rename, add-key flows
- Browser extension's NIP-07 surface, WebSocket and WebUSB transports

**Scaffolded, first hardware run is the validation:**

- WebUSB interface registration on real device
- Coexistence with the FIDO interface at runtime
- Vendor VID/PID — currently unassigned; the KeyOS USB server will use
  its default. Foundation may want to allocate a dedicated VID/PID pair
  for production.
- Endpoint enumeration and the first WebUSB handshake from Chrome on
  macOS / Linux / Windows

If anything breaks on first run, the failure will almost certainly be
in this second bucket. The code underneath is the same that signs real
Nostr events in the simulator today.
