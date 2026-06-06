// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! NIP-06: deterministic Nostr key derivation from BIP-39 mnemonic.
//!
//! Path: m/44'/1237'/<account>'/0/0
//! Standard BIP-32 derivation over secp256k1.

use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::{generic_array::GenericArray, scalar::ScalarPrimitive, sec1::ToEncodedPoint},
    ProjectivePoint, PublicKey as K256Pub, Scalar, SecretKey as K256Sec,
};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::{Error, Result, SecretKey};

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x80000000;
const NOSTR_COIN: u32 = 1237;

/// Derive a Nostr SecretKey from a BIP-39 mnemonic and account index, per
/// NIP-06 (path m/44'/1237'/account'/0/0). `passphrase` is the BIP-39
/// passphrase — pass "" for the standard "no passphrase" case.
pub fn derive(mnemonic: &str, passphrase: &str, account: u32) -> Result<SecretKey> {
    let mnemonic_parsed =
        bip39::Mnemonic::parse(mnemonic).map_err(|_| Error::Nip06("invalid mnemonic"))?;
    let seed = mnemonic_parsed.to_seed(passphrase);

    let (mut k, mut c) = master_from_seed(&seed)?;

    // m/44'/1237'/account'/0/0
    let path = [
        44 | HARDENED,
        NOSTR_COIN | HARDENED,
        account | HARDENED,
        0,
        0,
    ];
    for &index in &path {
        let (nk, nc) = derive_child(&k, &c, index)?;
        k.zeroize();
        c.zeroize();
        k = nk;
        c = nc;
    }

    let sk = SecretKey::from_bytes(k)?;
    c.zeroize();
    Ok(sk)
}

fn master_from_seed(seed: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut mac = <HmacSha512 as Mac>::new_from_slice(b"Bitcoin seed")
        .map_err(|_| Error::Nip06("hmac init"))?;
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    let mut c = [0u8; 32];
    k.copy_from_slice(&i[0..32]);
    c.copy_from_slice(&i[32..64]);
    // Validate master key scalar is valid.
    let _ = scalar_from_bytes(&k)?;
    Ok((k, c))
}

fn derive_child(
    parent_k: &[u8; 32],
    parent_c: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32])> {
    let mut mac =
        <HmacSha512 as Mac>::new_from_slice(parent_c).map_err(|_| Error::Nip06("hmac init"))?;

    if index >= HARDENED {
        // Hardened: 0x00 || k_parent || i_be
        mac.update(&[0u8]);
        mac.update(parent_k);
    } else {
        // Public: compressed pubkey (33 bytes) || i_be
        let parent_scalar = scalar_from_bytes(parent_k)?;
        let point = ProjectivePoint::GENERATOR * parent_scalar;
        let pk = K256Pub::from_affine(point.into()).map_err(|_| Error::Nip06("bad point"))?;
        let compressed = pk.to_encoded_point(true);
        mac.update(compressed.as_bytes());
    }
    mac.update(&index.to_be_bytes());
    let i = mac.finalize().into_bytes();

    let il = &i[0..32];
    let ir = &i[32..64];

    let il_scalar = scalar_from_bytes_allow_zero(il)?;
    let parent_scalar = scalar_from_bytes(parent_k)?;
    let child_scalar = il_scalar + parent_scalar;
    // BIP-32 spec: if IL >= n or child_k == 0, derivation fails. Practically
    // negligible; surface as a clean error.
    if bool::from(child_scalar.is_zero()) {
        return Err(Error::Nip06("derived zero key"));
    }

    let child_k: [u8; 32] = child_scalar.to_bytes().into();
    let mut child_c = [0u8; 32];
    child_c.copy_from_slice(ir);
    Ok((child_k, child_c))
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar> {
    let ga = GenericArray::from_slice(bytes);
    let sp: ScalarPrimitive<k256::Secp256k1> = ScalarPrimitive::from_bytes(ga)
        .into_option()
        .ok_or(Error::Nip06("scalar out of range"))?;
    let s: Scalar = sp.into();
    if bool::from(s.is_zero()) {
        return Err(Error::Nip06("zero scalar"));
    }
    Ok(s)
}

fn scalar_from_bytes_allow_zero(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != 32 {
        return Err(Error::Nip06("bad scalar length"));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    let ga = GenericArray::from_slice(&buf);
    let sp: ScalarPrimitive<k256::Secp256k1> = ScalarPrimitive::from_bytes(ga)
        .into_option()
        .ok_or(Error::Nip06("IL out of range"))?;
    Ok(sp.into())
}

// Keep K256Sec import used so the crate reports it; also useful for future
// public-key derivation helpers.
#[allow(dead_code)]
fn _unused_import_anchor(_sk: &K256Sec) {}

#[cfg(test)]
mod tests {
    use super::*;

    // NIP-06 official test vectors
    const MN1: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const SK1_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";

    const MN2: &str = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
    const SK2_HEX: &str = "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add";

    #[test]
    fn nip06_vector_one() {
        let sk = derive(MN1, "", 0).unwrap();
        assert_eq!(sk.to_hex(), SK1_HEX);
    }

    #[test]
    fn nip06_vector_two() {
        let sk = derive(MN2, "", 0).unwrap();
        assert_eq!(sk.to_hex(), SK2_HEX);
    }

    #[test]
    fn account_changes_key() {
        let k0 = derive(MN1, "", 0).unwrap();
        let k1 = derive(MN1, "", 1).unwrap();
        assert_ne!(k0.to_hex(), k1.to_hex());
    }

    #[test]
    fn bad_mnemonic_errors() {
        assert!(derive("not a real mnemonic at all", "", 0).is_err());
    }
}
