// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure-Rust Nostr primitives used by the Passport Prime signer.
//!
//! Modules:
//!   - [`keys`]   secret/public keys (BIP-340 x-only)
//!   - [`event`]  NIP-01 events: canonical id, schnorr sign/verify
//!   - [`bech32`] NIP-19 encodings (nsec/npub/note)
//!   - [`nip04`]  legacy DM encryption (AES-256-CBC + ECDH)
//!   - [`nip44`]  v2 encryption (ChaCha20 + HMAC-SHA256 + HKDF)
//!   - [`nip06`]  BIP-39 mnemonic → m/44'/1237'/acct'/0/0
//!
//! Design: no KeyOS dependencies here. Everything is testable on host with
//! `cargo test`.

pub mod bech32;
pub mod error;
pub mod event;
pub mod keys;
pub mod nip04;
pub mod nip06;
pub mod nip44;

pub use error::Error;
pub use event::{Event, UnsignedEvent};
pub use keys::{PublicKey, SecretKey};

pub type Result<T> = core::result::Result<T, Error>;
