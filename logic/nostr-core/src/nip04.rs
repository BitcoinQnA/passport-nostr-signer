// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! NIP-04: legacy direct-message encryption.
//!
//! - Shared secret = ECDH(sk, pk).x (32 bytes)
//! - AES-256-CBC with PKCS#7 padding, key = shared secret, iv = 16 random bytes
//! - Payload = base64(ciphertext) + "?iv=" + base64(iv)

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint, AffinePoint, ProjectivePoint, PublicKey as K256Pub, Scalar,
};

use crate::{Error, PublicKey, Result, SecretKey};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Compute the 32-byte shared secret used for NIP-04.
///
/// This is the x-coordinate of the ECDH point. Both NIP-04 and NIP-44 v2
/// start from this same x-only shared secret.
pub fn shared_secret(sk: &SecretKey, peer: &PublicKey) -> Result<[u8; 32]> {
    // Lift x-only pubkey to an AffinePoint with even Y, then ECDH.
    let peer_point = lift_x(peer.as_bytes())?;
    let scalar = sk_to_scalar(sk)?;
    let shared = ProjectivePoint::from(peer_point) * scalar;
    let affine = AffinePoint::from(shared);
    let encoded = affine.to_encoded_point(false);
    // Uncompressed SEC1 is 0x04 || X(32) || Y(32). Take X.
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Error::Nip04("ecdh yielded unexpected point encoding"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[1..33]);
    Ok(out)
}

pub fn encrypt(sk: &SecretKey, peer: &PublicKey, plaintext: &str) -> Result<String> {
    let key = shared_secret(sk, peer)?;
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut iv).map_err(|_| Error::Nip04("rng failed"))?;
    let ct = Aes256CbcEnc::new((&key).into(), (&iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
    Ok(format!("{}?iv={}", B64.encode(&ct), B64.encode(iv)))
}

pub fn decrypt(sk: &SecretKey, peer: &PublicKey, payload: &str) -> Result<String> {
    let (ct_b64, iv_b64) = payload
        .split_once("?iv=")
        .ok_or(Error::Nip04("missing ?iv= delimiter"))?;
    let ct = B64.decode(ct_b64)?;
    let iv = B64.decode(iv_b64)?;
    if iv.len() != 16 {
        return Err(Error::Nip04("iv must be 16 bytes"));
    }
    let key = shared_secret(sk, peer)?;
    let pt = Aes256CbcDec::new((&key).into(), iv.as_slice().into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| Error::Nip04("cbc decrypt / padding error"))?;
    String::from_utf8(pt).map_err(|_| Error::Nip04("plaintext not utf-8"))
}

/// Given an x-only pubkey, reconstruct the secp256k1 point with even Y.
fn lift_x(x: &[u8; 32]) -> Result<AffinePoint> {
    // Prepend 0x02 (even Y tag) and parse as compressed SEC1.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);
    let pk = K256Pub::from_sec1_bytes(&compressed).map_err(|_| Error::InvalidKey)?;
    Ok(*pk.as_affine())
}

fn sk_to_scalar(sk: &SecretKey) -> Result<Scalar> {
    use k256::elliptic_curve::scalar::ScalarPrimitive;
    use k256::elliptic_curve::generic_array::GenericArray;
    let ga = GenericArray::from_slice(sk.as_bytes());
    let sp: ScalarPrimitive<k256::Secp256k1> =
        ScalarPrimitive::from_bytes(ga).into_option().ok_or(Error::InvalidKey)?;
    Ok(sp.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_is_commutative() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        let sab = shared_secret(&a, &b.public_key()).unwrap();
        let sba = shared_secret(&b, &a.public_key()).unwrap();
        assert_eq!(sab, sba);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice = SecretKey::generate().unwrap();
        let bob = SecretKey::generate().unwrap();
        let msg = "Zap me, sir. ⚡";
        let payload = encrypt(&alice, &bob.public_key(), msg).unwrap();
        assert!(payload.contains("?iv="));
        let decrypted = decrypt(&bob, &alice.public_key(), &payload).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn rejects_bad_iv_length() {
        let alice = SecretKey::generate().unwrap();
        let bob = SecretKey::generate().unwrap();
        let bad = "AAAA?iv=AA";
        assert!(decrypt(&alice, &bob.public_key(), bad).is_err());
    }

    #[test]
    fn rejects_missing_delimiter() {
        let alice = SecretKey::generate().unwrap();
        let bob = SecretKey::generate().unwrap();
        assert!(decrypt(&alice, &bob.public_key(), "just-some-base64").is_err());
    }
}
