// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("invalid key length: expected {expected}, got {got}")]
    KeyLength { expected: usize, got: usize },

    #[error("invalid secp256k1 key")]
    InvalidKey,

    #[error("signature verification failed")]
    BadSignature,

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("bech32: {0}")]
    Bech32(String),

    #[error("wrong bech32 hrp: expected {expected}, got {got}")]
    Bech32Hrp { expected: &'static str, got: String },

    #[error("nip-44: {0}")]
    Nip44(&'static str),

    #[error("nip-04: {0}")]
    Nip04(&'static str),

    #[error("nip-06: {0}")]
    Nip06(&'static str),

    #[error("event id mismatch")]
    EventIdMismatch,

    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
}
