// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! JSON request/response types. Serde is the source of truth — no manual
//! parsing. The JSON layout is intentionally close to NIP-46 so the same
//! vocabulary will work when we add a relay-proxied transport in v2.
//!
//! Envelope:
//!   Request  = { "id": "...", "method": "<name>", "params": { ... } }
//!   Response = { "id": "...", "ok": true/false,
//!                "result": { ... } | "error": { "code": int, "message": str } }

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    #[serde(flatten)]
    pub method: Method,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Method {
    Ping,
    ListKeys,
    SelectKey(SelectKeyParams),
    GetPublicKey,
    SignEvent(SignEventParams),
    Nip04Encrypt(EncryptParams),
    Nip04Decrypt(DecryptParams),
    Nip44Encrypt(EncryptParams),
    Nip44Decrypt(DecryptParams),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectKeyParams {
    /// hex-encoded 16-byte key uuid
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignEventParams {
    /// Optional: hex uuid of the identity to sign with. If absent, uses the
    /// currently-selected key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uuid: Option<String>,
    /// Origin URL of the requesting dapp, surfaced in the approval UI.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin: Option<String>,
    pub event: UnsignedEvent,
}

/// Mirrors [`nostr_core::UnsignedEvent`] but without depending on the core
/// crate here — the `protocol` crate stays domain-light.
///
/// `pubkey` is optional because NIP-07 clients differ: noStrudel sends it,
/// jumble.social omits it and expects the signer to fill it in from the
/// selected key. The engine ignores this field regardless (it always uses
/// the selected key's pubkey when assembling the signed event), so making
/// it optional just tolerates both client styles at parse time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedEvent {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pubkey: Option<String>,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptParams {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin: Option<String>,
    /// Peer x-only pubkey (hex).
    pub peer_pubkey: String,
    pub plaintext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptParams {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin: Option<String>,
    pub peer_pubkey: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub id: String,
    #[serde(flatten)]
    pub body: ResponseBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ResponseBody {
    Ok { result: serde_json::Value },
    Err { error: ErrorPayload },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorPayload {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest = 1,
    UnknownMethod = 2,
    UnknownKey = 3,
    UserRejected = 4,
    Timeout = 5,
    NotUnlocked = 6,
    Internal = 99,
}

impl ErrorCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Public-facing key listing entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyInfo {
    pub uuid: String,
    pub label: String,
    /// x-only hex pubkey (aka npub in hex form).
    pub pubkey: String,
    pub created_at: u64,
}

impl Response {
    pub fn ok(id: impl Into<String>, result: serde_json::Value) -> Self {
        Self {
            id: id.into(),
            body: ResponseBody::Ok { result },
        }
    }

    pub fn err(id: impl Into<String>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            body: ResponseBody::Err {
                error: ErrorPayload {
                    code: code.as_i32(),
                    message: message.into(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ping_roundtrip() {
        let r = Request {
            id: "1".into(),
            method: Method::Ping,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"method\":\"ping\""));
        let back: Request = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn sign_event_has_params() {
        let r = Request {
            id: "x".into(),
            method: Method::SignEvent(SignEventParams {
                uuid: None,
                origin: Some("https://nostrudel.ninja".into()),
                event: UnsignedEvent {
                    pubkey: Some("aa".repeat(32)),
                    created_at: 1,
                    kind: 1,
                    tags: vec![],
                    content: "gm".into(),
                },
            }),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"method\":\"sign_event\""));
        let back: Request = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn response_ok_shape() {
        let r = Response::ok("42", serde_json::json!({"pong": true}));
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"result\""));
        assert!(!j.contains("\"error\""));
        let back: Response = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn unit_variant_accepts_explicit_null_params() {
        // The browser extension omits `params` for unit-variant methods;
        // the server must also tolerate explicit `null` for robustness.
        let r: Request = serde_json::from_str(r#"{"id":"a","method":"ping"}"#).unwrap();
        assert!(matches!(r.method, Method::Ping));
        let r: Request =
            serde_json::from_str(r#"{"id":"a","method":"ping","params":null}"#).unwrap();
        assert!(matches!(r.method, Method::Ping));
        let r: Request = serde_json::from_str(r#"{"id":"a","method":"list_keys"}"#).unwrap();
        assert!(matches!(r.method, Method::ListKeys));
        let r: Request = serde_json::from_str(r#"{"id":"a","method":"get_public_key"}"#).unwrap();
        assert!(matches!(r.method, Method::GetPublicKey));
    }

    #[test]
    fn response_err_shape() {
        let r = Response::err("7", ErrorCode::UserRejected, "nope");
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"code\":4"));
        let back: Response = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
