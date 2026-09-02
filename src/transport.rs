// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Transport abstraction for the Nostr Signer.
//!
//! The same request/response engine runs behind the hosted WebSocket transport.
//!
//!   - **WebSocket** on `cfg(not(keyos))` — used by the hosted-mode simulator so the browser extension can
//!     reach the app during development.
//!
//! KeyOS SDK 1.4 does not expose a public app-owned USB transport. The device
//! build therefore stays offline until QuantumLink exposes an app transport.

use std::sync::{Mutex, OnceLock};

#[cfg(not(keyos))]
mod websocket;
#[cfg(not(keyos))]
pub use websocket::serve;

#[cfg(keyos)]
pub async fn serve<M>(
    _engine: std::sync::Arc<crate::engine::Engine<M>>,
    _bind: &str,
) -> anyhow::Result<()>
where
    M: keystore::MasterKeySource + Send + Sync + 'static,
{
    // TODO: localize
    set_status("Offline: host link requires public QuantumLink");
    Ok(())
}

/// Shared, human-readable status line for the currently-running transport.
/// Written by the transport worker; read by the UI banner poll-timer in
/// `main.rs`. Using a lock-free `OnceLock<Mutex<_>>` avoids the need to
/// thread a Slint handle into the transport crate.
pub fn status() -> &'static Mutex<String> {
    static INSTANCE: OnceLock<Mutex<String>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new("starting...".into()))
}

/// Convenience: replace the status string.
pub fn set_status(msg: impl Into<String>) {
    if let Ok(mut g) = status().lock() {
        *g = msg.into();
    }
}
