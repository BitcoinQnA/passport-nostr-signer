// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Persistent auto-sign policy store.
//!
//! These rules are intentionally local to the Prime UI. The browser transport
//! cannot create or edit them, and matching is exact by key, origin, and kind.

use std::{
    fs,
    path::{Path, PathBuf},
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_RULES_PER_KEY: usize = 24;

const ONE_HOUR_SECS: u64 = 60 * 60;
const AUDIT_LIMIT: usize = 100;
const MAC_DOMAIN: &[u8] = b"nostr-signer-v1/autosign/mac-key";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct AutoSignRuleInfo {
    pub id: [u8; 16],
    pub origin: String,
    pub kind: u32,
    pub enabled: bool,
    pub expires_at: u64,
    pub max_per_hour: u32,
    pub used_in_window: u32,
    pub total_uses: u64,
    pub last_used_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSignAuditEntry {
    pub timestamp: u64,
    #[serde(with = "hex_bytes_16")]
    pub rule_id: [u8; 16],
    #[serde(with = "hex_bytes_16")]
    pub key_uuid: [u8; 16],
    pub origin: String,
    pub kind: u32,
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutoSignRule {
    #[serde(with = "hex_bytes_16")]
    id: [u8; 16],
    #[serde(with = "hex_bytes_16")]
    key_uuid: [u8; 16],
    origin: String,
    kind: u32,
    enabled: bool,
    expires_at: u64,
    max_per_hour: u32,
    used_in_window: u32,
    window_started_at: u64,
    total_uses: u64,
    created_at: u64,
    last_used_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSignStore {
    version: u32,
    #[serde(default)]
    rules: Vec<AutoSignRule>,
    #[serde(default)]
    audit: Vec<AutoSignAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutoSignPayload {
    version: u32,
    #[serde(default)]
    rules: Vec<AutoSignRule>,
    #[serde(default)]
    audit: Vec<AutoSignAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutoSignFile {
    version: u32,
    #[serde(default)]
    rules: Vec<AutoSignRule>,
    #[serde(default)]
    audit: Vec<AutoSignAuditEntry>,
    mac: String,
}

impl Default for AutoSignStore {
    fn default() -> Self { Self { version: FORMAT_VERSION, rules: Vec::new(), audit: Vec::new() } }
}

impl AutoSignStore {
    pub fn from_bytes(bytes: &[u8], mac_key: &[u8; 32]) -> anyhow::Result<Self> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let parsed: AutoSignFile = serde_json::from_slice(bytes)?;
        if parsed.version != FORMAT_VERSION {
            anyhow::bail!("unsupported auto-sign policy format version: {}", parsed.version);
        }
        let payload = AutoSignPayload { version: parsed.version, rules: parsed.rules, audit: parsed.audit };
        let mac = hex::decode(&parsed.mac)?;
        let expected = mac_bytes(mac_key, &payload)?;
        if !constant_time_eq(&mac, &expected) {
            anyhow::bail!("auto-sign policy MAC verification failed");
        }
        Ok(Self { version: payload.version, rules: payload.rules, audit: payload.audit })
    }

    pub fn to_bytes(&self, mac_key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        let payload =
            AutoSignPayload { version: self.version, rules: self.rules.clone(), audit: self.audit.clone() };
        let file = AutoSignFile {
            version: payload.version,
            rules: payload.rules.clone(),
            audit: payload.audit.clone(),
            mac: hex::encode(mac_bytes(mac_key, &payload)?),
        };
        Ok(serde_json::to_vec_pretty(&file)?)
    }

    pub fn rules_for_key(&self, key_uuid: &[u8; 16]) -> Vec<AutoSignRuleInfo> {
        let mut rules: Vec<_> =
            self.rules.iter().filter(|r| &r.key_uuid == key_uuid).map(AutoSignRule::info).collect();
        rules.sort_by(|a, b| a.origin.cmp(&b.origin).then(a.kind.cmp(&b.kind)));
        rules
    }

    pub fn add_rule(
        &mut self,
        key_uuid: [u8; 16],
        origin: String,
        kind: u32,
        expires_at: u64,
        max_per_hour: u32,
        now: u64,
    ) -> Result<[u8; 16], String> {
        let origin = normalize_origin(&origin)?;
        let rules_for_key = self.rules.iter().filter(|r| r.key_uuid == key_uuid).count();
        if rules_for_key >= MAX_RULES_PER_KEY {
            return Err(format!("This key already has the maximum of {MAX_RULES_PER_KEY} auto-sign rules."));
        }
        if self.rules.iter().any(|r| r.key_uuid == key_uuid && r.origin == origin && r.kind == kind) {
            return Err("An auto-sign rule for this origin and kind already exists.".into());
        }
        if max_per_hour == 0 || max_per_hour > 1_000 {
            return Err("Max per hour must be between 1 and 1000.".into());
        }
        if expires_at != 0 && expires_at <= now {
            return Err("Expiry must be in the future.".into());
        }

        let id = *Uuid::new_v4().as_bytes();
        self.rules.push(AutoSignRule {
            id,
            key_uuid,
            origin,
            kind,
            enabled: true,
            expires_at,
            max_per_hour,
            used_in_window: 0,
            window_started_at: now,
            total_uses: 0,
            created_at: now,
            last_used_at: 0,
        });
        Ok(id)
    }

    pub fn remove_rule(&mut self, rule_id: &[u8; 16]) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| &r.id != rule_id);
        before != self.rules.len()
    }

    pub fn remove_key_rules(&mut self, key_uuid: &[u8; 16]) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| &r.key_uuid != key_uuid);
        before != self.rules.len()
    }

    pub fn set_rule_enabled(&mut self, rule_id: &[u8; 16], enabled: bool) -> bool {
        let Some(rule) = self.rules.iter_mut().find(|r| &r.id == rule_id) else {
            return false;
        };
        rule.enabled = enabled;
        true
    }

    pub fn disable_key_rules(&mut self, key_uuid: &[u8; 16]) -> bool {
        let mut changed = false;
        for rule in &mut self.rules {
            if &rule.key_uuid == key_uuid && rule.enabled {
                rule.enabled = false;
                changed = true;
            }
        }
        changed
    }

    pub fn reserve_match(
        &mut self,
        key_uuid: &[u8; 16],
        origin: &str,
        kind: u32,
        now: u64,
    ) -> Option<[u8; 16]> {
        let origin = normalize_origin(origin).ok()?;
        let rule = self.rules.iter_mut().find(|r| {
            r.enabled && &r.key_uuid == key_uuid && r.origin == origin && r.kind == kind && !r.is_expired(now)
        })?;

        rule.roll_window(now);
        if rule.used_in_window >= rule.max_per_hour {
            return None;
        }

        rule.used_in_window += 1;
        rule.total_uses += 1;
        rule.last_used_at = now;
        Some(rule.id)
    }

    pub fn record_signed(
        &mut self,
        rule_id: [u8; 16],
        key_uuid: [u8; 16],
        origin: &str,
        kind: u32,
        event_id: String,
        now: u64,
    ) {
        let origin = normalize_origin(origin).unwrap_or_else(|_| origin.trim().to_string());
        self.audit.push(AutoSignAuditEntry { timestamp: now, rule_id, key_uuid, origin, kind, event_id });
        if self.audit.len() > AUDIT_LIMIT {
            let excess = self.audit.len() - AUDIT_LIMIT;
            self.audit.drain(0..excess);
        }
    }
}

impl AutoSignRule {
    fn info(&self) -> AutoSignRuleInfo {
        AutoSignRuleInfo {
            id: self.id,
            origin: self.origin.clone(),
            kind: self.kind,
            enabled: self.enabled,
            expires_at: self.expires_at,
            max_per_hour: self.max_per_hour,
            used_in_window: self.used_in_window,
            total_uses: self.total_uses,
            last_used_at: self.last_used_at,
        }
    }

    fn is_expired(&self, now: u64) -> bool { self.expires_at != 0 && now >= self.expires_at }

    fn roll_window(&mut self, now: u64) {
        if now < self.window_started_at || now.saturating_sub(self.window_started_at) >= ONE_HOUR_SECS {
            self.window_started_at = now;
            self.used_in_window = 0;
        }
    }
}

pub fn normalize_origin(input: &str) -> Result<String, String> {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("Origin is required.".into());
    }
    if trimmed.len() > 200 {
        return Err("Origin is too long.".into());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("Origin must not contain spaces.".into());
    }

    let (scheme, rest) =
        trimmed.split_once("://").ok_or_else(|| "Origin must start with https:// or http://.".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err("Only http:// and https:// origins are supported.".into());
    }
    if rest.is_empty() {
        return Err("Origin host is required.".into());
    }
    if rest.contains('/') || rest.contains('?') || rest.contains('#') || rest.contains('@') {
        return Err("Use only the site origin, for example https://nostrudel.ninja.".into());
    }

    Ok(format!("{}://{}", scheme, rest.to_ascii_lowercase()))
}

pub fn derive_mac_key(app_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(app_seed).expect("HMAC accepts keys of any byte length");
    mac.update(MAC_DOMAIN);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub fn load(path: &Path, mac_key: &[u8; 32]) -> anyhow::Result<AutoSignStore> {
    if path.exists() {
        AutoSignStore::from_bytes(&fs::read(path)?, mac_key)
    } else {
        Ok(AutoSignStore::default())
    }
}

pub fn save(store: &AutoSignStore, path: &Path, mac_key: &[u8; 32]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = temp_path(path);
    fs::write(&tmp, store.to_bytes(mac_key)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn mac_bytes(mac_key: &[u8; 32], payload: &AutoSignPayload) -> anyhow::Result<[u8; 32]> {
    let bytes = serde_json::to_vec(payload)?;
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts keys of any byte length");
    mac.update(&bytes);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn constant_time_eq(left: &[u8], right: &[u8; 32]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|s| s.to_os_string()).unwrap_or_else(|| "autosign".into());
    name.push(".tmp");
    path.with_file_name(name)
}

mod hex_bytes_16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 16 {
            return Err(serde::de::Error::custom("expected 16-byte hex"));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 16] { [7u8; 16] }

    fn mac_key() -> [u8; 32] { derive_mac_key(&[9u8; 32]) }

    #[test]
    fn origin_normalization_is_exact_and_pathless() {
        assert_eq!(normalize_origin(" HTTPS://NOSTRUDEL.NINJA/ ").unwrap(), "https://nostrudel.ninja");
        assert!(normalize_origin("https://nostrudel.ninja/write").is_err());
        assert!(normalize_origin("chrome-extension://abc").is_err());
    }

    #[test]
    fn reserve_respects_hourly_limit() {
        let mut store = AutoSignStore::default();
        store.add_rule(key(), "https://nostrudel.ninja".into(), 22242, 0, 1, 10).unwrap();
        assert!(store.reserve_match(&key(), "https://nostrudel.ninja", 22242, 20).is_some());
        assert!(store.reserve_match(&key(), "https://nostrudel.ninja", 22242, 30).is_none());
        assert!(store.reserve_match(&key(), "https://nostrudel.ninja", 22242, 3_700).is_some());
    }

    #[test]
    fn serializes_ids_as_hex() {
        let mut store = AutoSignStore::default();
        store.add_rule(key(), "https://example.com".into(), 1, 0, 10, 1).unwrap();
        let json = String::from_utf8(store.to_bytes(&mac_key()).unwrap()).unwrap();
        assert!(json.contains("\"key_uuid\": \"07070707070707070707070707070707\""));
        let restored = AutoSignStore::from_bytes(json.as_bytes(), &mac_key()).unwrap();
        assert_eq!(restored.rules_for_key(&key()).len(), 1);
    }

    #[test]
    fn rejects_tampered_policy_file() {
        let mut store = AutoSignStore::default();
        store.add_rule(key(), "https://example.com".into(), 1, 0, 10, 1).unwrap();
        let json = String::from_utf8(store.to_bytes(&mac_key()).unwrap()).unwrap();
        let tampered = json.replace("https://example.com", "https://evil.example");
        assert!(AutoSignStore::from_bytes(tampered.as_bytes(), &mac_key()).is_err());
    }
}
