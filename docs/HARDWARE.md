# Running Nostr Signer on Passport Prime

The standalone Foundation SDK build installs and runs on Passport Prime. Key
management, app-scoped deterministic derivation, QR import, local storage, and
the approval UI are device features.

## Current host-link limitation

Foundation SDK 1.4 does not expose raw USB or a public QuantumLink transport to
third-party apps. This app intentionally requests neither `os/usbdev` nor the
device master seed. On device, its status banner reports that the host link is
offline. Browser NIP-07 requests therefore work only with the hosted simulator's
WebSocket transport for now.

The extension's WebUSB implementation and the USB patch notes are retained as
prototype material. They are not compiled into the installable SDK app.

## Install

Enable Developer Mode and Airlock on Passport Prime, then run:

```sh
foundation doctor
foundation build --release
foundation sideload --release
```

The packaged `.app` is self-signed with the local `passport-prime-dev`
identity. It does not require a Foundation production signature.

## Device flows

1. Open **Nostr Signer** from the launcher.
2. Add a key by deriving an account from the protected app seed or scanning an
   `nsec1` QR code.
3. Select, rename, archive, restore, or delete identities locally.
4. Configure auto-sign policy data locally. The policy engine is testable in
   the simulator, but cannot receive browser requests on hardware until a
   public host transport exists.

The app ID must remain unchanged. KeyOS derives the protected app seed from the
device backup and app identity, so restoring the backup and reinstalling this
same app recovers deterministic identities for the same account indexes.

## Simulator integration

Run the hosted simulator and connect the extension to
`ws://127.0.0.1:9876`. The simulator exercises the protocol, approval, signing,
encryption, and decryption paths without relying on private KeyOS services.

## Future transport

When a public QuantumLink app API becomes available, implement the existing
JSON request/response protocol over that API and replace the device-side
offline stub in `src/transport.rs`. Do not restore direct `os/usbdev` access in
a third-party SDK app.
