// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::fmt;

use k256::schnorr::{SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// A Nostr secret key: 32 bytes of secp256k1 scalar. Zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

/// A Nostr public key: BIP-340 x-only 32-byte representation.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        // Validate by trying to build a schnorr SigningKey from it.
        SigningKey::from_bytes(&bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Self(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::KeyLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        Self::from_bytes(buf)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }

    /// Generate a fresh key using the OS RNG (via `getrandom`).
    pub fn generate() -> Result<Self> {
        loop {
            let mut buf = [0u8; 32];
            getrandom::getrandom(&mut buf).map_err(|_| Error::InvalidKey)?;
            if let Ok(k) = Self::from_bytes(buf) {
                return Ok(k);
            }
            // Extremely unlikely, but retry on invalid scalar.
        }
    }

    pub fn public_key(&self) -> PublicKey {
        let sk = SigningKey::from_bytes(&self.0).expect("validated in ctor");
        let vk: &VerifyingKey = sk.verifying_key();
        let mut out = [0u8; 32];
        out.copy_from_slice(&vk.to_bytes());
        PublicKey(out)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Internal: get a k256 SigningKey. Callers should zeroise inputs themselves.
    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0).expect("validated in ctor")
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the scalar.
        f.debug_struct("SecretKey")
            .field("pubkey", &self.public_key())
            .finish()
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Self(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::KeyLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        Self::from_bytes(buf)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("validated in ctor")
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_roundtrip_hex() {
        let hex = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
        let sk = SecretKey::from_hex(hex).unwrap();
        assert_eq!(sk.to_hex(), hex);
    }

    #[test]
    fn derives_nip06_reference_pubkey() {
        // NIP-06 test vector: sk above should produce this x-only npub hex.
        let sk =
            SecretKey::from_hex("7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a")
                .unwrap();
        let pk = sk.public_key();
        assert_eq!(
            pk.to_hex(),
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
        );
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(matches!(
            SecretKey::from_slice(&[0u8; 31]),
            Err(Error::KeyLength { .. })
        ));
    }

    #[test]
    fn generate_produces_valid_pubkey() {
        let sk = SecretKey::generate().unwrap();
        let pk = sk.public_key();
        // Round-trip through bytes to confirm validity.
        let pk2 = PublicKey::from_bytes(*pk.as_bytes()).unwrap();
        assert_eq!(pk, pk2);
    }
}
