# Passport Prime Nostr Signer — Browser Extension (1.3 / WebUSB build)

Chromium browser extension that implements the NIP-07 `window.nostr`
surface on top of the Passport Prime signer. The nsec never leaves the
device; this extension only relays signing requests.

This is the **1.3 build**: the hardware transport is WebUSB, matching
the KeyOS `dev-v1.3.0` port of `gui-app-nostr-signer` which registers a
vendor-class interface (class/subclass/protocol = `0xFF/0xFF/0xFF`)
with two 64-byte Interrupt endpoints. The older v1.2.1 build lives
alongside at `../browser-extension/` and uses Web Serial (CDC-ACM);
that one stays unchanged as a reference.

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
   **Load unpacked**, and select this `browser-extension-1.3/`
   directory.

3. In the extension's **Settings** page, click **Pair Passport Prime**
   and select your Prime in the system WebUSB picker.

4. Visit any Nostr client that supports NIP-07 (e.g.
   [noStrudel](https://nostrudel.ninja), [Snort](https://snort.social))
   and pick the "Sign in with extension" option.

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

## License

GPL-3.0-or-later.
