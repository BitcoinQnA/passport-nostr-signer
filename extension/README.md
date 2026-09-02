# Passport Prime Nostr Signer — Browser Extension

Chromium browser extension that implements the NIP-07 `window.nostr`
surface on top of the Passport Prime signer. The nsec never leaves the
device; this extension only relays signing requests. Auto-sign rules, when
used, are configured on Passport Prime and are not editable from the extension.

The WebUSB client in this extension is an experimental prototype. The standalone
SDK app cannot expose raw USB in SDK 1.4, so use WebSocket with the simulator.

The prototype hardware transport matches
the KeyOS `dev-v1.3.0` port of `gui-app-nostr-signer` which registers a
vendor-class interface (class/subclass/protocol = `0xFF/0xFF/0xFF`)
with two 64-byte Interrupt endpoints.

## Two transports

Selectable on the options page:

- **WebUSB** (default) — `navigator.usb` to a physical Passport Prime.
  First-time pairing requires the Chromium WebUSB picker (a user
  gesture), which you initiate from the options page.
- **WebSocket** — `ws://127.0.0.1:9876`, served either by the standalone
  `signer` binary on your Mac or by the KeyOS hosted-mode simulator.
  Flip the "simulator mode" checkbox in Settings to switch.

## Install (dev mode)

1. Flash Prime with a KeyOS build that includes `gui-app-nostr-signer`
   on the `qna/nostr-signer-1.3` branch. Open the Nostr Signer app on
   Prime and add a key.

2. Open `chrome://extensions`, enable **Developer mode**, click
   **Load unpacked**, and select this `extension/`
   directory.

3. In the extension's **Settings** page, click **Pair Passport Prime**
   and select your Prime in the system WebUSB picker.

4. Visit any Nostr client that supports NIP-07 (e.g.
   [noStrudel](https://nostrudel.ninja), [Snort](https://snort.social))
   and pick the "Sign in with extension" option. On first use, open the
   extension popup and allow that site origin before retrying the client action.

## Architecture

```
page script  ──window.postMessage──  content.js ──chrome.runtime── background.js
 (inpage.js)                                                              │
                                                                          ▼
                                                             ┌──────────┴──────────┐
                                                             │                     │
                                                       WebSocket              WebUSB
                                                             │                     │
                                                             ▼                     ▼
                                                       signer binary        Passport Prime
                                                       or simulator         (hardware, 1.3)
```

Wire format is newline-delimited JSON on both transports. On WebUSB the
browser chunks payloads into 64-byte `transferOut` calls and accumulates
`transferIn` results until it sees a `\n`.

The provider is injected broadly into HTTP/HTTPS pages for NIP-07 compatibility,
but requests fail closed until the user allows the exact site origin in the
extension popup. A device-local auto-sign rule can skip the on-device approval
screen only for the exact key/origin/kind/expiry/rate-limit policy configured on
Prime. Use **Settings → Reset extension state** to clear paired USB devices,
selected key, and site permissions during demos.

## License

GPL-3.0-or-later.
