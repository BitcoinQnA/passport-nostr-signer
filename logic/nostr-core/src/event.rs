// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use k256::schnorr::{
    signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    Signature,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{keys::PublicKey, keys::SecretKey, Error, Result};

/// An event that is fully signed and ready for a relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(with = "hex32")]
    pub id: [u8; 32],
    #[serde(with = "pubkey_hex")]
    pub pubkey: PublicKey,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(with = "hex64")]
    pub sig: [u8; 64],
}

/// An event payload that has not yet been signed.
#[derive(Debug, Clone)]
pub struct UnsignedEvent {
    pub pubkey: PublicKey,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl UnsignedEvent {
    /// Compute the NIP-01 canonical event id.
    ///
    /// The serialization is a JSON array:
    ///     [0, pubkey_hex, created_at, kind, tags, content]
    /// with no whitespace; sha256 of the UTF-8 bytes is the id.
    pub fn id(&self) -> Result<[u8; 32]> {
        let value = serde_json::json!([
            0u8,
            self.pubkey.to_hex(),
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]);
        let serialised = serde_json::to_string(&value)?;
        let mut hasher = Sha256::new();
        hasher.update(serialised.as_bytes());
        Ok(hasher.finalize().into())
    }

    /// Sign the event. Uses BIP-340 schnorr with an auxiliary random nonce
    /// (randomised variant). Caller is responsible for passing a `SecretKey`
    /// whose public key matches `self.pubkey`.
    pub fn sign(self, sk: &SecretKey) -> Result<Event> {
        if sk.public_key() != self.pubkey {
            return Err(Error::InvalidKey);
        }
        let id = self.id()?;
        let signing = sk.signing_key();
        // BIP-340 signs the message AS IS — the event id is already the
        // sha256 of the canonical serialization, so we use the prehash
        // variant to avoid k256's `sign`/`try_sign_with_rng` convenience
        // hashing the id a second time.
        let sig: Signature = signing
            .sign_prehash_with_rng(&mut OsRng, &id)
            .map_err(|_| Error::InvalidKey)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig.to_bytes());
        Ok(Event {
            id,
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags,
            content: self.content,
            sig: sig_bytes,
        })
    }
}

impl Event {
    /// Check that `id` matches the canonical hash of the contents, and that
    /// `sig` is a valid BIP-340 signature over `id` by `pubkey`.
    pub fn verify(&self) -> Result<()> {
        let unsigned = UnsignedEvent {
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
        };
        let expected = unsigned.id()?;
        if expected != self.id {
            return Err(Error::EventIdMismatch);
        }
        let vk = self.pubkey.verifying_key();
        let sig = Signature::try_from(&self.sig[..]).map_err(|_| Error::BadSignature)?;
        vk.verify_prehash(&self.id, &sig)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

// --- serde helpers for hex-encoded binary fields ----------------------------

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hex"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom("expected 64-byte hex"));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod pubkey_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::PublicKey;

    pub fn serialize<S: Serializer>(pk: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&pk.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let s = String::deserialize(d)?;
        PublicKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk() -> SecretKey {
        SecretKey::from_hex("7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a")
            .unwrap()
    }

    #[test]
    fn event_id_is_stable() {
        let sk = sk();
        let unsigned = UnsignedEvent {
            pubkey: sk.public_key(),
            created_at: 1714078911,
            kind: 1,
            tags: vec![],
            content: "Hello, I'm signing remotely".into(),
        };
        let id = unsigned.id().unwrap();
        // Sanity: id must be deterministic across calls.
        assert_eq!(id, unsigned.id().unwrap());
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let sk = sk();
        let unsigned = UnsignedEvent {
            pubkey: sk.public_key(),
            created_at: 1714078911,
            kind: 1,
            tags: vec![vec!["t".into(), "nostr".into()]],
            content: "gm".into(),
        };
        let signed = unsigned.sign(&sk).unwrap();
        signed.verify().unwrap();
    }

    #[test]
    fn tampered_content_fails_verify() {
        let sk = sk();
        let unsigned = UnsignedEvent {
            pubkey: sk.public_key(),
            created_at: 1714078911,
            kind: 1,
            tags: vec![],
            content: "original".into(),
        };
        let mut signed = unsigned.sign(&sk).unwrap();
        signed.content = "forged".into();
        assert!(matches!(signed.verify(), Err(Error::EventIdMismatch)));
    }

    #[test]
    fn json_roundtrip() {
        let sk = sk();
        let unsigned = UnsignedEvent {
            pubkey: sk.public_key(),
            created_at: 1714078911,
            kind: 1,
            tags: vec![vec!["p".into(), "deadbeef".repeat(8)]],
            content: "hi".into(),
        };
        let signed = unsigned.sign(&sk).unwrap();
        let json = signed.to_json().unwrap();
        let parsed = Event::from_json(&json).unwrap();
        parsed.verify().unwrap();
        assert_eq!(parsed.id, signed.id);
    }

    /// Regression test for a BIP-340 implementation bug: previously the
    /// crate used k256's `try_sign_with_rng` + `verify` pair which both
    /// silently sha256'd the input again. Self-consistent, but produced
    /// signatures that did not validate under any external BIP-340
    /// implementation. Event below was produced by this crate (post-fix)
    /// and independently confirmed via nostr-tools' verifyEvent. If our
    /// verify regresses to pre-hashing, this test breaks.
    #[test]
    fn externally_validated_event_verifies() {
        let evt = Event {
            id: hex_to_arr32("6f1fe4853ffc63a8e3e6c634b7e740adbddbb08198221e3b998940264e2e0b3c"),
            pubkey: PublicKey::from_hex(
                "634b0ca8cce792b32cf343162f106b8792570ffda74e27985e1515c4ec2f9c56",
            )
            .unwrap(),
            created_at: 1_776_780_129,
            kind: 1,
            tags: vec![],
            content: "Hello world!".into(),
            sig: hex_to_arr64(
                "d06a16cd5b8ff82a690017d1391645ede662d47d2d696babb519c7670fcc1a06\
                 e683494eb377a4eaefd2069afa53d74f7f7a538e1154af073a27bca8147539da",
            ),
        };
        evt.verify()
            .expect("BIP-340 sig must verify under prehash semantics");
    }

    fn hex_to_arr32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut o = [0u8; 32];
        o.copy_from_slice(&v);
        o
    }

    fn hex_to_arr64(s: &str) -> [u8; 64] {
        let v = hex::decode(s).unwrap();
        let mut o = [0u8; 64];
        o.copy_from_slice(&v);
        o
    }

    #[test]
    fn rejects_pubkey_sk_mismatch() {
        let sk = sk();
        let other_pk = SecretKey::generate().unwrap().public_key();
        let unsigned = UnsignedEvent {
            pubkey: other_pk,
            created_at: 0,
            kind: 1,
            tags: vec![],
            content: "".into(),
        };
        assert!(matches!(unsigned.sign(&sk), Err(Error::InvalidKey)));
    }
}
