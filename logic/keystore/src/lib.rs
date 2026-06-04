// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Encrypted nsec storage.
//!
//! Each identity (label + nsec) is encrypted with its own AES-256-GCM key
//! derived from a master secret. The master lives behind the
//! [`MasterKeySource`] trait:
//!
//!   - On Passport Prime it is `security.app_seed()`, a 32-byte per-app key
//!     that is only accessible when the user is logged in with PIN.
//!   - On macOS tests it is a random value persisted to a file.
//!
//! Per-key encryption keys are derived with HKDF-Expand so that rotating one
//! identity does not touch any others, and the master key itself never
//! leaves the keystore.

use std::{
    fs,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use nostr_core::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

pub const FORMAT_VERSION: u32 = 1;
const HKDF_INFO_PREFIX: &[u8] = b"nostr-signer-v1/key/";

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("nostr: {0}")]
    Nostr(#[from] nostr_core::Error),
    #[error("aead: {0}")]
    Aead(&'static str),
    #[error("unsupported keystore format version: {0}")]
    UnsupportedVersion(u32),
    #[error("unknown key uuid")]
    UnknownKey,
    #[error("duplicate key uuid")]
    DuplicateKey,
    #[error("rng failed")]
    Rng,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Source of the 32-byte master secret used to wrap nsecs. On Prime this is
/// `security.app_seed()`; in tests it's a file-backed fake.
pub trait MasterKeySource {
    fn app_seed(&self) -> Result<[u8; 32]>;
}

/// A 128-bit identifier for a stored identity.
pub type KeyId = [u8; 16];

/// Public metadata for a stored key. Safe to surface without PIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Hex-encoded 16-byte uuid.
    #[serde(with = "hex_bytes_16")]
    pub uuid: KeyId,
    pub label: String,
    /// Hex-encoded 32-byte x-only npub.
    #[serde(with = "hex_bytes_32")]
    pub npub: [u8; 32],
    pub created_at: u64,
    /// Index into the UI's CardColor picker palette. Defaults to 3
    /// (purple) for records that predate this field.
    #[serde(default = "default_color")]
    pub color: u8,
    /// Archived keys are hidden from the main list but remain on-device;
    /// they can be restored or permanently deleted from the archive view.
    #[serde(default)]
    pub archived: bool,
}

fn default_color() -> u8 { 3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedRecord {
    #[serde(with = "hex_bytes_16")]
    uuid: KeyId,
    label: String,
    #[serde(with = "hex_bytes_32")]
    npub: [u8; 32],
    #[serde(with = "hex_bytes_12")]
    nonce: [u8; 12],
    /// hex-encoded 48 bytes (32 nsec + 16 gcm tag)
    ciphertext: String,
    created_at: u64,
    #[serde(default = "default_color")]
    color: u8,
    #[serde(default)]
    archived: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeystoreFile {
    version: u32,
    records: Vec<EncryptedRecord>,
}

pub struct Keystore<M: MasterKeySource> {
    master: M,
    records: Vec<EncryptedRecord>,
}

impl<M: MasterKeySource> Keystore<M> {
    pub fn new(master: M) -> Self { Self { master, records: Vec::new() } }

    pub fn from_bytes(master: M, data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self::new(master));
        }
        let parsed: KeystoreFile = serde_json::from_slice(data)?;
        if parsed.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(parsed.version));
        }
        Ok(Self { master, records: parsed.records })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let file = KeystoreFile { version: FORMAT_VERSION, records: self.records.clone() };
        Ok(serde_json::to_vec_pretty(&file)?)
    }

    pub fn list(&self) -> Vec<KeyInfo> {
        self.records
            .iter()
            .map(|r| KeyInfo {
                uuid: r.uuid,
                label: r.label.clone(),
                npub: r.npub,
                created_at: r.created_at,
                color: r.color,
                archived: r.archived,
            })
            .collect()
    }

    pub fn get_info(&self, uuid: &KeyId) -> Option<KeyInfo> {
        self.records.iter().find(|r| &r.uuid == uuid).map(|r| KeyInfo {
            uuid: r.uuid,
            label: r.label.clone(),
            npub: r.npub,
            created_at: r.created_at,
            color: r.color,
            archived: r.archived,
        })
    }

    pub fn count(&self) -> usize { self.records.len() }

    /// Encrypt and insert a new identity. Returns its uuid.
    pub fn add(&mut self, label: impl Into<String>, sk: &SecretKey, now: u64) -> Result<KeyId> {
        let mut uuid = [0u8; 16];
        getrandom::getrandom(&mut uuid).map_err(|_| Error::Rng)?;
        if self.records.iter().any(|r| r.uuid == uuid) {
            return Err(Error::DuplicateKey);
        }

        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Rng)?;

        let master = self.master.app_seed()?;
        let key_bytes = derive_key(&master, &uuid);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), sk.as_bytes().as_slice())
            .map_err(|_| Error::Aead("encrypt failed"))?;

        let npub = sk.public_key();
        let record = EncryptedRecord {
            uuid,
            label: label.into(),
            npub: *npub.as_bytes(),
            nonce,
            ciphertext: hex::encode(&ct),
            created_at: now,
            color: default_color(),
            archived: false,
        };
        self.records.push(record);

        let mut wipe = key_bytes;
        wipe.zeroize();
        let mut wipe_master = master;
        wipe_master.zeroize();
        Ok(uuid)
    }

    /// Decrypt and return the nsec for a stored identity.
    pub fn reveal(&self, uuid: &KeyId) -> Result<SecretKey> {
        let record = self.records.iter().find(|r| &r.uuid == uuid).ok_or(Error::UnknownKey)?;
        let master = self.master.app_seed()?;
        let key_bytes = derive_key(&master, uuid);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let ct = hex::decode(&record.ciphertext)?;
        let pt = cipher
            .decrypt(Nonce::from_slice(&record.nonce), ct.as_slice())
            .map_err(|_| Error::Aead("decrypt failed (wrong master or tampered record)"))?;
        let sk = SecretKey::from_slice(&pt)?;

        let mut wipe = key_bytes;
        wipe.zeroize();
        let mut wipe_master = master;
        wipe_master.zeroize();
        let mut wipe_pt = pt;
        wipe_pt.zeroize();
        Ok(sk)
    }

    pub fn remove(&mut self, uuid: &KeyId) -> Result<()> {
        let pos = self.records.iter().position(|r| &r.uuid == uuid).ok_or(Error::UnknownKey)?;
        self.records.remove(pos);
        Ok(())
    }

    pub fn rename(&mut self, uuid: &KeyId, new_label: impl Into<String>) -> Result<()> {
        let record = self.records.iter_mut().find(|r| &r.uuid == uuid).ok_or(Error::UnknownKey)?;
        record.label = new_label.into();
        Ok(())
    }

    pub fn set_color(&mut self, uuid: &KeyId, color: u8) -> Result<()> {
        let record = self.records.iter_mut().find(|r| &r.uuid == uuid).ok_or(Error::UnknownKey)?;
        record.color = color;
        Ok(())
    }

    pub fn set_archived(&mut self, uuid: &KeyId, archived: bool) -> Result<()> {
        let record = self.records.iter_mut().find(|r| &r.uuid == uuid).ok_or(Error::UnknownKey)?;
        record.archived = archived;
        Ok(())
    }

    pub fn lookup_by_npub(&self, npub: &PublicKey) -> Option<KeyInfo> {
        self.records
            .iter()
            .find(|r| &r.npub == npub.as_bytes())
            .map(|r| KeyInfo {
                uuid: r.uuid,
                label: r.label.clone(),
                npub: r.npub,
                created_at: r.created_at,
                color: r.color,
                archived: r.archived,
            })
    }
}

fn derive_key(master: &[u8; 32], uuid: &KeyId) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(master).expect("master is 32 bytes");
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + uuid.len());
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(uuid);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("32 <= 255 * HashLen");
    out
}

// --- master key sources --------------------------------------------------

/// Master key that never leaves memory. Useful for tests and the simulator.
pub struct InMemoryMasterKey(pub [u8; 32]);

impl MasterKeySource for InMemoryMasterKey {
    fn app_seed(&self) -> Result<[u8; 32]> { Ok(self.0) }
}

/// File-backed master key for macOS dev. Generates a random 32-byte master
/// on first use and persists it unencrypted at the supplied path. **Only**
/// for development — the real deployment derives the master from
/// `security.app_seed()` on Prime (PIN-gated, hardware-rooted).
pub struct FileMasterKey {
    path: PathBuf,
}

impl FileMasterKey {
    pub fn new(path: impl Into<PathBuf>) -> Self { Self { path: path.into() } }
}

impl MasterKeySource for FileMasterKey {
    fn app_seed(&self) -> Result<[u8; 32]> {
        if self.path.exists() {
            let bytes = fs::read(&self.path)?;
            if bytes.len() != 32 {
                return Err(Error::Aead("file master must be 32 bytes"));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        } else {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut buf = [0u8; 32];
            getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
            fs::write(&self.path, buf)?;
            Ok(buf)
        }
    }
}

// --- convenience: load/save to a file ------------------------------------

pub fn load<M: MasterKeySource>(master: M, path: &Path) -> Result<Keystore<M>> {
    if path.exists() {
        let bytes = fs::read(path)?;
        Keystore::from_bytes(master, &bytes)
    } else {
        Ok(Keystore::new(master))
    }
}

pub fn save<M: MasterKeySource>(keystore: &Keystore<M>, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = keystore.to_bytes()?;
    fs::write(path, bytes)?;
    Ok(())
}

// --- serde helpers ------------------------------------------------------

mod hex_bytes_16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 16 {
            return Err(serde::de::Error::custom("expected 16-byte hex"));
        }
        let mut o = [0u8; 16];
        o.copy_from_slice(&v);
        Ok(o)
    }
}

mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hex"));
        }
        let mut o = [0u8; 32];
        o.copy_from_slice(&v);
        Ok(o)
    }
}

mod hex_bytes_12 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 12 {
            return Err(serde::de::Error::custom("expected 12-byte hex"));
        }
        let mut o = [0u8; 12];
        o.copy_from_slice(&v);
        Ok(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Keystore<InMemoryMasterKey> {
        let mut master = [0u8; 32];
        getrandom::getrandom(&mut master).unwrap();
        Keystore::new(InMemoryMasterKey(master))
    }

    #[test]
    fn add_list_reveal_roundtrip() {
        let mut ks = fresh();
        let sk = SecretKey::generate().unwrap();
        let uuid = ks.add("main", &sk, 1_714_000_000).unwrap();

        let list = ks.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].label, "main");
        assert_eq!(list[0].npub, *sk.public_key().as_bytes());

        let revealed = ks.reveal(&uuid).unwrap();
        assert_eq!(revealed.to_hex(), sk.to_hex());
    }

    #[test]
    fn multiple_keys_are_isolated() {
        let mut ks = fresh();
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        let ua = ks.add("a", &a, 1).unwrap();
        let ub = ks.add("b", &b, 2).unwrap();
        assert_ne!(ua, ub);
        assert_eq!(ks.reveal(&ua).unwrap().to_hex(), a.to_hex());
        assert_eq!(ks.reveal(&ub).unwrap().to_hex(), b.to_hex());
    }

    #[test]
    fn wrong_master_rejects() {
        let sk = SecretKey::generate().unwrap();
        let bytes = {
            let mut ks = Keystore::new(InMemoryMasterKey([0x11; 32]));
            ks.add("x", &sk, 0).unwrap();
            ks.to_bytes().unwrap()
        };
        // Reload with a different master.
        let ks = Keystore::from_bytes(InMemoryMasterKey([0x22; 32]), &bytes).unwrap();
        let list = ks.list();
        assert_eq!(list.len(), 1);
        let err = ks.reveal(&list[0].uuid).unwrap_err();
        assert!(matches!(err, Error::Aead(_)));
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let master = [0x42u8; 32];
        let sk = SecretKey::generate().unwrap();
        let uuid;
        let bytes = {
            let mut ks = Keystore::new(InMemoryMasterKey(master));
            uuid = ks.add("zapper", &sk, 9).unwrap();
            ks.to_bytes().unwrap()
        };
        let ks2 = Keystore::from_bytes(InMemoryMasterKey(master), &bytes).unwrap();
        assert_eq!(ks2.count(), 1);
        assert_eq!(ks2.reveal(&uuid).unwrap().to_hex(), sk.to_hex());
    }

    #[test]
    fn remove_works() {
        let mut ks = fresh();
        let sk = SecretKey::generate().unwrap();
        let u = ks.add("x", &sk, 0).unwrap();
        assert_eq!(ks.count(), 1);
        ks.remove(&u).unwrap();
        assert_eq!(ks.count(), 0);
        assert!(matches!(ks.remove(&u), Err(Error::UnknownKey)));
    }

    #[test]
    fn lookup_by_npub() {
        let mut ks = fresh();
        let sk = SecretKey::generate().unwrap();
        let uuid = ks.add("q", &sk, 0).unwrap();
        let info = ks.lookup_by_npub(&sk.public_key()).unwrap();
        assert_eq!(info.uuid, uuid);
    }

    #[test]
    fn file_master_key_is_stable() {
        let tmp = std::env::temp_dir().join(format!("nostr-signer-test-{}.master", rand_suffix()));
        let fm = FileMasterKey::new(&tmp);
        let a = fm.app_seed().unwrap();
        let b = fm.app_seed().unwrap();
        assert_eq!(a, b);
        fs::remove_file(&tmp).ok();
    }

    fn rand_suffix() -> u64 {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).unwrap();
        u64::from_le_bytes(b)
    }
}
