<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Nostr Signer — Foundation SDK setup

This app is a **self-contained Foundation SDK app**. You do not need a KeyOS
source checkout, and you do not need access to any private Foundation
repository. The KeyOS platform crates come from the installed Foundation SDK,
which the CLI maps into the project under `.foundation-sdk/` (gitignored) at
build time.

Target: **Passport Prime running the KeyOS 1.4 beta**.

## 1. Install the Foundation SDK

Install the Foundation SDK bundle for your OS and put its `foundation` binary on
`PATH`, then verify:

```bash
foundation doctor
```

Fix anything it flags. If it reports the **KeyOS target** or **Nix shell** as
missing, enter the SDK environment once (this provides the `rust-keyos`
toolchain that supplies the `armv7a-unknown-xous-elf` device target):

```bash
foundation develop
```

## 2. Create a signing identity (one time)

Sideloading installs a *signed* app bundle, so create a local publisher identity
(long-lived, stored under `~/.foundation/signing/<name>`):

```bash
foundation cert gen <name>
```

## 3. Build

From the repository root:

```bash
foundation build --release
```

The CLI resolves the KeyOS platform crates from the SDK (via `.foundation-sdk/`),
generates the Slint UI, compiles for the device target, and signs the bundle.
Output lands in `target/keyos/gui-app-nostr-signer/` (`app.elf`,
`manifest.json`, `icon.bin`, `resources`).

To run it in the hosted simulator instead (no hardware needed):

```bash
foundation sim
```

## 4. Sideload to Passport Prime

Connect a Passport Prime running the 1.4 beta over USB with **Developer Mode**
enabled and **Airlock** in Read/Write mode, then:

```bash
foundation sideload --release
```

This copies the signed bundle to the device and launches it. Use `--no-run` to
copy without launching.

## Generated, CLI-owned paths (never commit these)

The CLI owns and regenerates these; they are gitignored:

- `.foundation-sdk/` — the project-local SDK mapping (KeyOS crates + the `@ui`
  component surface). Do not replace it with a path to a local KeyOS checkout.
- `ui/ui` — the generated shared `@ui` component surface
- `manifest.toml` — generated from `app-config.toml`
- `target/` — build output

Reset generated state with `foundation clean`, then rebuild.

## App identity and permissions

- `app-config.toml` is the authored manifest: app ID, icon, version,
  `min-keyos-version`, publisher, and permissions. `manifest.toml` is generated
  from it.
- The app ID `0x1f8f092a30b7425273d9b15d5f3dd8c8` is stable. KeyOS derives the
  app seed (and therefore every seed-derived Nostr identity) from it, so never
  change it for an upgrade.

## On-device USB (WebUSB) note

The on-device transport is a vendor-class WebUSB interface. It depends on two
small KeyOS USB-stack fixes documented in
[`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md) and
[`docs/keyos-pio-fixes.patch`](docs/keyos-pio-fixes.patch). These are KeyOS-side,
not part of this app; a device whose KeyOS build predates them may need them for
reliable WebUSB. See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire protocol
and [`extension/README.md`](extension/README.md) for the browser side.
