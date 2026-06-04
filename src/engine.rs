// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Request dispatcher. Mirrors the logic in
//! `nostr-signer/keyos-app/src/engine.rs` so the simulator behaves
//! identically to the standalone binary. The on-device approval screen is
//! driven by the [`Approver`] trait — we plug in a Slint-backed
//! implementation in `main.rs`.

use std::sync::{Arc, Mutex};

use keystore::{Keystore, MasterKeySource};
use nostr_core::{nip04, nip44, Event, PublicKey, SecretKey, UnsignedEvent};
use protocol::{
    message::{
        EncryptParams, KeyInfo as ProtoKeyInfo, Method, Request, SignEventParams,
    },
    ErrorCode, Response,
};

use crate::approval::{ApprovalDecision, ApprovalRequest, ArcApprover};

pub struct EngineConfig {
    pub content_preview_chars: usize,
}

impl Default for EngineConfig {
    fn default() -> Self { Self { content_preview_chars: 140 } }
}

pub struct Engine<M: MasterKeySource> {
    keystore: Arc<Mutex<Keystore<M>>>,
    approver: ArcApprover,
    selected: Mutex<Option<[u8; 16]>>,
    config: EngineConfig,
}

impl<M: MasterKeySource> Engine<M> {
    pub fn new(
        keystore: Arc<Mutex<Keystore<M>>>,
        approver: ArcApprover,
        config: EngineConfig,
    ) -> Self {
        Self { keystore, approver, selected: Mutex::new(None), config }
    }

    /// Set the active identity (called from the on-device UI as well as
    /// from the WebSocket `select_key` method). Returns true if the uuid
    /// matches a stored identity.
    pub fn select(&self, uuid: [u8; 16]) -> bool {
        let ks = self.keystore.lock().unwrap();
        if ks.get_info(&uuid).is_none() {
            return false;
        }
        drop(ks);
        *self.selected.lock().unwrap() = Some(uuid);
        true
    }

    /// Currently-active identity, if any.
    pub fn selected(&self) -> Option<[u8; 16]> { *self.selected.lock().unwrap() }

    /// Rename a stored identity.
    pub fn rename(&self, uuid: &[u8; 16], label: String) -> Result<(), String> {
        let mut ks = self.keystore.lock().unwrap();
        ks.rename(uuid, label).map_err(|e| e.to_string())
    }

    /// Change the on-device colour for a stored identity.
    pub fn set_color(&self, uuid: &[u8; 16], color: u8) -> Result<(), String> {
        let mut ks = self.keystore.lock().unwrap();
        ks.set_color(uuid, color).map_err(|e| e.to_string())
    }

    /// Archive or restore a stored identity.
    pub fn set_archived(&self, uuid: &[u8; 16], archived: bool) -> Result<(), String> {
        let mut ks = self.keystore.lock().unwrap();
        ks.set_archived(uuid, archived).map_err(|e| e.to_string())
    }

    /// Reveal the nsec for a stored identity as a bech32 `nsec1…` string.
    /// Callers are responsible for gating this behind a user confirmation.
    pub fn reveal_nsec(&self, uuid: &[u8; 16]) -> Result<String, String> {
        let ks = self.keystore.lock().unwrap();
        let sk = ks.reveal(uuid).map_err(|e| e.to_string())?;
        nostr_core::bech32::encode_nsec(&sk).map_err(|e| e.to_string())
    }

    /// Permanently delete an identity. The nsec is unrecoverable once this
    /// returns — this is a terminal action.
    pub fn delete(&self, uuid: &[u8; 16]) -> Result<(), String> {
        let mut ks = self.keystore.lock().unwrap();
        ks.remove(uuid).map_err(|e| e.to_string())?;
        // If we just removed the selected identity, clear the cache too.
        let mut selected = self.selected.lock().unwrap();
        if *selected == Some(*uuid) {
            *selected = None;
        }
        Ok(())
    }

    /// Import a new identity. Returns the hex uuid on success.
    pub fn add_key(&self, label: String, sk: &SecretKey, color: u8) -> Result<String, String> {
        let mut ks = self.keystore.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let uuid = ks.add(label, sk, now).map_err(|e| e.to_string())?;
        // Colour is set after insertion since Keystore::add doesn't accept it.
        let _ = ks.set_color(&uuid, color);
        drop(ks);
        *self.selected.lock().unwrap() = Some(uuid);
        Ok(hex::encode(uuid))
    }

    /// Copy the list of stored identities. Each entry is
    /// (uuid_hex, label, npub_hex, color, archived).
    pub fn key_list(&self) -> Vec<(String, String, String, u8, bool)> {
        let ks = self.keystore.lock().unwrap();
        ks.list()
            .into_iter()
            .map(|k| (hex::encode(k.uuid), k.label, hex::encode(k.npub), k.color, k.archived))
            .collect()
    }

    pub async fn handle(&self, req: Request) -> Response {
        let id = req.id.clone();
        match req.method {
            Method::Ping => Response::ok(id, serde_json::json!({ "pong": true })),
            Method::ListKeys => self.list_keys(id),
            Method::SelectKey(p) => self.select_key(id, &p.uuid),
            Method::GetPublicKey => self.get_public_key(id, None),
            Method::SignEvent(p) => self.sign_event(id, p).await,
            Method::Nip04Encrypt(p) => self.encrypt(id, p, CipherKind::Nip04).await,
            Method::Nip04Decrypt(p) => {
                self.decrypt(id, p.uuid, p.peer_pubkey, p.ciphertext, CipherKind::Nip04)
            }
            Method::Nip44Encrypt(p) => self.encrypt(id, p, CipherKind::Nip44).await,
            Method::Nip44Decrypt(p) => {
                self.decrypt(id, p.uuid, p.peer_pubkey, p.ciphertext, CipherKind::Nip44)
            }
        }
    }

    fn list_keys(&self, id: String) -> Response {
        let ks = self.keystore.lock().unwrap();
        let keys: Vec<ProtoKeyInfo> = ks
            .list()
            .into_iter()
            .map(|k| ProtoKeyInfo {
                uuid: hex::encode(k.uuid),
                label: k.label,
                pubkey: hex::encode(k.npub),
                created_at: k.created_at,
            })
            .collect();
        Response::ok(id, serde_json::json!({ "keys": keys }))
    }

    fn select_key(&self, id: String, uuid_hex: &str) -> Response {
        match parse_uuid(uuid_hex) {
            Ok(uuid) => {
                let ks = self.keystore.lock().unwrap();
                if ks.get_info(&uuid).is_none() {
                    return Response::err(id, ErrorCode::UnknownKey, "no such uuid");
                }
                drop(ks);
                *self.selected.lock().unwrap() = Some(uuid);
                Response::ok(id, serde_json::json!({ "selected": uuid_hex }))
            }
            Err(msg) => Response::err(id, ErrorCode::InvalidRequest, msg),
        }
    }

    fn get_public_key(&self, id: String, uuid_hex: Option<String>) -> Response {
        let uuid = match self.resolve_uuid(uuid_hex.as_deref()) {
            Ok(u) => u,
            Err(r) => return r.into_response(id),
        };
        let ks = self.keystore.lock().unwrap();
        let info = match ks.get_info(&uuid) {
            Some(i) => i,
            None => return Response::err(id, ErrorCode::UnknownKey, "no such uuid"),
        };
        Response::ok(id, serde_json::json!({ "pubkey": hex::encode(info.npub) }))
    }

    async fn sign_event(&self, id: String, params: SignEventParams) -> Response {
        let uuid = match self.resolve_uuid(params.uuid.as_deref()) {
            Ok(u) => u,
            Err(r) => return r.into_response(id),
        };
        let (info, sk) = match self.reveal(&uuid) {
            Ok(pair) => pair,
            Err(r) => return r.into_response(id),
        };

        let preview = truncate(&params.event.content, self.config.content_preview_chars);
        let approval_req = ApprovalRequest::SignEvent {
            origin: params.origin.clone(),
            key_label: info.label.clone(),
            npub_hex: hex::encode(info.npub),
            kind: params.event.kind,
            content_preview: preview,
            tag_count: params.event.tags.len(),
        };
        if let ApprovalDecision::Reject = self.approver.request(approval_req).await {
            return Response::err(id, ErrorCode::UserRejected, "user rejected sign request");
        }

        let pk = match PublicKey::from_bytes(info.npub) {
            Ok(p) => p,
            Err(e) => return Response::err(id, ErrorCode::Internal, e.to_string()),
        };
        let unsigned = UnsignedEvent {
            pubkey: pk,
            created_at: params.event.created_at,
            kind: params.event.kind,
            tags: params.event.tags,
            content: params.event.content,
        };
        let signed: Event = match unsigned.sign(&sk) {
            Ok(s) => s,
            Err(e) => return Response::err(id, ErrorCode::Internal, e.to_string()),
        };
        match serde_json::to_value(&signed) {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, ErrorCode::Internal, e.to_string()),
        }
    }

    async fn encrypt(&self, id: String, params: EncryptParams, kind: CipherKind) -> Response {
        let uuid = match self.resolve_uuid(params.uuid.as_deref()) {
            Ok(u) => u,
            Err(r) => return r.into_response(id),
        };
        let peer = match PublicKey::from_hex(&params.peer_pubkey) {
            Ok(p) => p,
            Err(e) => return Response::err(id, ErrorCode::InvalidRequest, e.to_string()),
        };
        let (info, sk) = match self.reveal(&uuid) {
            Ok(pair) => pair,
            Err(r) => return r.into_response(id),
        };

        let preview = truncate(&params.plaintext, self.config.content_preview_chars);
        let approval_req = match kind {
            CipherKind::Nip04 => ApprovalRequest::Nip04Encrypt {
                origin: params.origin.clone(),
                key_label: info.label.clone(),
                peer_pubkey_hex: params.peer_pubkey.clone(),
                plaintext_preview: preview,
            },
            CipherKind::Nip44 => ApprovalRequest::Nip44Encrypt {
                origin: params.origin.clone(),
                key_label: info.label.clone(),
                peer_pubkey_hex: params.peer_pubkey.clone(),
                plaintext_preview: preview,
            },
        };
        if let ApprovalDecision::Reject = self.approver.request(approval_req).await {
            return Response::err(id, ErrorCode::UserRejected, "user rejected encryption");
        }

        let ct = match kind {
            CipherKind::Nip04 => nip04::encrypt(&sk, &peer, &params.plaintext),
            CipherKind::Nip44 => nip44::encrypt(&sk, &peer, &params.plaintext),
        };
        match ct {
            Ok(s) => Response::ok(id, serde_json::json!({ "ciphertext": s })),
            Err(e) => Response::err(id, ErrorCode::Internal, e.to_string()),
        }
    }

    fn decrypt(
        &self,
        id: String,
        uuid_hex: Option<String>,
        peer_hex: String,
        ciphertext: String,
        kind: CipherKind,
    ) -> Response {
        let uuid = match self.resolve_uuid(uuid_hex.as_deref()) {
            Ok(u) => u,
            Err(r) => return r.into_response(id),
        };
        let peer = match PublicKey::from_hex(&peer_hex) {
            Ok(p) => p,
            Err(e) => return Response::err(id, ErrorCode::InvalidRequest, e.to_string()),
        };
        let (_info, sk) = match self.reveal(&uuid) {
            Ok(pair) => pair,
            Err(r) => return r.into_response(id),
        };

        let pt = match kind {
            CipherKind::Nip04 => nip04::decrypt(&sk, &peer, &ciphertext),
            CipherKind::Nip44 => nip44::decrypt(&sk, &peer, &ciphertext),
        };
        match pt {
            Ok(s) => Response::ok(id, serde_json::json!({ "plaintext": s })),
            Err(e) => Response::err(id, ErrorCode::Internal, e.to_string()),
        }
    }

    fn resolve_uuid(&self, uuid_hex: Option<&str>) -> Result<[u8; 16], EngineError> {
        if let Some(hex_str) = uuid_hex {
            parse_uuid(hex_str).map_err(|m| EngineError { code: ErrorCode::InvalidRequest, msg: m })
        } else {
            self.selected.lock().unwrap().ok_or(EngineError {
                code: ErrorCode::InvalidRequest,
                msg: "no key selected and no uuid supplied".into(),
            })
        }
    }

    fn reveal(&self, uuid: &[u8; 16]) -> Result<(keystore::KeyInfo, SecretKey), EngineError> {
        let ks = self.keystore.lock().unwrap();
        let info = ks.get_info(uuid).ok_or(EngineError {
            code: ErrorCode::UnknownKey,
            msg: "no such uuid".into(),
        })?;
        let sk = ks.reveal(uuid).map_err(|e| EngineError {
            code: ErrorCode::Internal,
            msg: e.to_string(),
        })?;
        Ok((info, sk))
    }
}

fn parse_uuid(s: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(s).map_err(|e| format!("bad uuid hex: {e}"))?;
    if bytes.len() != 16 {
        return Err(format!("uuid must be 16 bytes hex, got {}", bytes.len()));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

struct EngineError {
    code: ErrorCode,
    msg: String,
}

impl EngineError {
    fn into_response(self, id: String) -> Response { Response::err(id, self.code, self.msg) }
}

#[derive(Copy, Clone)]
enum CipherKind {
    Nip04,
    Nip44,
}
