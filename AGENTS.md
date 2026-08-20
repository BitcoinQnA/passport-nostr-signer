# Passport Nostr Signer

## What this repository is

- A **self-contained Foundation SDK app**: a hardware Nostr signer that runs on
  Passport Prime (KeyOS 1.4 beta), plus a companion browser extension under
  `extension/`.
- The app builds **only** through the standalone Foundation SDK workflow. It does
  **not** require a KeyOS source checkout or any private-repo access.
- The KeyOS platform crates are provided by the installed SDK and mapped into the
  project under `.foundation-sdk/` (gitignored) by the CLI. Do not commit that
  directory, and do not repoint its paths at a local KeyOS checkout.
- `logic/` is a vendored, KeyOS-free Rust workspace (`nostr-core`, `keystore`,
  `protocol`); it builds and tests on any host with `cargo test`.

## Build / run (see SDK-SETUP.md for detail)

- `foundation doctor` — run this first before diagnosing any SDK/toolchain error.
- `foundation build --release` — build + sign for the device.
- `foundation sim` — hosted simulator, no hardware.
- `foundation sideload --release` — install onto connected hardware.

## Safety rules

- Use only `foundation build` / `foundation sim` / `foundation sideload`; never
  build or flash full KeyOS firmware for this app.
- Do **not** run `foundation sideload` or other hardware-affecting commands
  unless the user asks to use a connected Passport Prime.
- Do **not** create or rotate signing identities (`foundation cert gen`) unless
  the user explicitly asks for signing setup.
- The app ID `0x1f8f092a30b7425273d9b15d5f3dd8c8` is stable and seed-deriving.
  Never change it for an upgrade.

## Generated, do-not-commit paths

`.foundation-sdk/`, `ui/ui`, `manifest.toml`, and `target/` are CLI-owned and
gitignored. Reset them with `foundation clean`.

## Layout

- `src/` — app engine, approval flow, transports (`websocket.rs` simulator,
  `webusb.rs` device)
- `ui/` — Slint UI (`ui/pages/*`, `ui/compat/*`)
- `logic/` — vendored KeyOS-free crates (host-testable)
- `app-config.toml` — the authored manifest (`manifest.toml` is generated)
- `docs/` — `PROTOCOL.md`, `AUTO-SIGN.md`, `HARDWARE.md`, `KEYOS-PATCHES.md`
- `extension/` — the NIP-07 browser extension
