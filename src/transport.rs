// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Transport abstraction for the Nostr Signer.
//!
//! The same request/response engine runs behind either of two transports:
//!
//!   - **WebSocket** on `cfg(not(keyos))` — used by the hosted-mode
//!     simulator so the browser extension can reach the app during
//!     development.
//!
//!   - **WebUSB** on `cfg(keyos)` — the production path on Passport
//!     Prime hardware. The app registers a vendor-class USB interface
//!     and the browser extension (browser-extension-1.3) reaches it via
//!     Chromium's WebUSB API (`navigator.usb`). Wire format is
//!     newline-delimited JSON, chunked across 64-byte transfers.
//!
//! The split keeps the USB implementation off the host build (it needs the
//! `os/usbdev` server which only exists on device).

use std::sync::{Mutex, OnceLock};

#[cfg(not(keyos))]
mod websocket;
#[cfg(not(keyos))]
pub use websocket::serve;

#[cfg(keyos)]
mod webusb;
#[cfg(keyos)]
pub use webusb::serve;

/// Shared, human-readable status line for the currently-running transport.
/// Written by the transport worker; read by the UI banner poll-timer in
/// `main.rs`. Using a lock-free `OnceLock<Mutex<_>>` avoids the need to
/// thread a Slint handle into the transport crate.
pub fn status() -> &'static Mutex<String> {
    static INSTANCE: OnceLock<Mutex<String>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new("starting…".into()))
}

/// Convenience: replace the status string.
pub fn set_status(msg: impl Into<String>) {
    if let Ok(mut g) = status().lock() {
        *g = msg.into();
    }
}
