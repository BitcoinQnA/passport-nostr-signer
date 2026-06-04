<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Nostr Signer — SDK setup & integration

## Is this an "SDK app"? Yes.

The official Foundation developer docs (<https://docs.foundation.xyz/developers>)
describe an `app-config.toml` + `foundation sideload` flow. The **shipped
`foundation` CLI is ahead-of / behind those docs**: running
`foundation new <name> --template multi-page-app` produces a project that is
**structurally identical to this one** — a `manifest.toml` (not `app-config.toml`),
the same `slint-keyos-platform` path-deps, the same `src/main.rs` + `ui/pages/*`
+ `build.rs` + `resources/icon.svg` + `i18n/en.json` layout, the `app!()` macro,
and the `@ui` widget library. So **`manifest.toml` is the real SDK manifest**,
and this app already conforms to the SDK project shape.

**CLI maturity (important):** at the time of writing only `foundation new` and
`foundation develop` are implemented; `sim`, `sideload`, and `cert` are not. So
the CLI can scaffold a project and open the Nix dev shell, but it cannot yet
build or install to hardware. Use KeyOS's own `cargo xtask` flow for that (it is
the same toolchain the CLI will eventually wrap).

## Layout vs. the SDK template

| SDK template (`foundation new`) | This repo |
|---|---|
| `manifest.toml` | ✅ `manifest.toml` |
| `Cargo.toml`, `build.rs` | ✅ |
| `src/main.rs` + `ui/app.slint` + `ui/pages/*` | ✅ |
| `resources/icon.svg` | ✅ |
| `i18n/en.json` | ✅ (scaffold — see note) |
| — | `logic/` vendored crates, `extension/`, `docs/` (this app's extras) |

> **i18n note.** `i18n/en.json` is present for SDK-template parity and as the
> localization source-of-truth, but strings are currently inline in the Slint
> pages (`build.rs` sets `include_translations: false`). Wiring `@tr`/keyed
> lookups through the pages is a follow-up; the JSON already mirrors every
> user-facing string.

## Build & run (today, via `cargo xtask`)

From a KeyOS checkout with this app integrated (see below):

```bash
# Type/borrow-check the app for BOTH device (ARM/xous) and the simulator:
cargo xtask check gui-app-nostr-signer

# Run the hosted simulator (opens the Passport window):
just sim            # or: cargo xtask run --hosted
```

The app appears in the dev **Secret Menu** / hidden-apps launcher list. For the
end-to-end browser test, see [`TESTING.md`](TESTING.md).

**Device image build** (full flashable firmware) is done on **Ubuntu** (the
supported build host) or inside the KeyOS Nix flake; macOS is not supported for
the full image (an unrelated `rfal-sys` NFC `build.rs` step needs Linux/Nix
headers). Once in that environment:

```bash
cargo xtask build && cargo xtask flash    # signed image + flash over USB (SAM-BA)
```

## Integrating into a KeyOS checkout

This repo is the app plus its vendored logic and companion extension. To build
it you drop the app into a KeyOS workspace. From a clean KeyOS checkout:

1. **Copy the app in** (the whole repo minus the host-side extras):

   ```bash
   mkdir -p <keyos>/apps/gui-app-nostr-signer
   # copy: Cargo.toml manifest.toml build.rs src/ ui/ resources/ i18n/ logic/
   ```

   The app path-depends into its own bundled `logic/` sub-workspace
   (`logic/nostr-core`, `logic/keystore`, `logic/protocol`), so `logic/` rides
   inside the app directory — nothing else to place.

2. **Register it in the workspace** (`<keyos>/Cargo.toml`):
   - add `"apps/gui-app-nostr-signer"` to `[workspace].members`
   - ensure `[workspace].exclude` covers the nested logic workspace, e.g.
     `exclude = ["logic", "apps/gui-app-nostr-signer/logic"]`

3. **Hook the launcher + build lists** (mirrors the reference integration):
   - `os/gui-app-launcher/src/main.rs` — add a `HiddenApp { label: "Nostr
     Signer", app_id: "0x1f8f092a30b7425273d9b15d5f3dd8c8" }` entry.
   - `xtask/src/main.rs` — add `"gui-app-nostr-signer"` to `DEV_APPS` and to
     `DEFAULT_SERVICES_HOSTED` (so it builds for device and the simulator).

4. **Apply the USB (PIO) fixes.** The on-device WebUSB transport relies on two
   small fixes to the KeyOS USB stack (an IRQ-storm guard and a multi-packet
   OUT truncation fix). Apply [`docs/keyos-pio-fixes.patch`](docs/keyos-pio-fixes.patch)
   and read [`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md). The simulator
   (WebSocket transport) does not need these.

After that, `cargo xtask check gui-app-nostr-signer` should pass for both
targets.

## Adopting the official `foundation` CLI later

Once `foundation sim`/`sideload`/`cert` ship, the migration is mechanical:
`foundation new nostr-signer --template multi-page-app`, then move `src/`,
`ui/`, `resources/`, `i18n/`, `logic/`, and `manifest.toml` into the scaffold —
the layout already matches. `foundation sideload` would then push the signed app
bundle over USB without a full firmware rebuild.

## Open items

- Full signed device image + sideload via the `foundation` CLI (pending CLI
  `build`/`sideload`).
- Wire `i18n/en.json` through the Slint pages (currently inline strings).
- Production USB VID/PID assignment for the vendor-class interface (see
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md)).
