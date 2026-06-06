// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! NIP-19: bech32-encoded entities. Phase 1 scope: `nsec`, `npub`, `note`.
//! TLV-based forms (`nprofile`, `nevent`, `naddr`) are deferred.

use bech32::{Bech32, Hrp};

use crate::{Error, PublicKey, Result, SecretKey};

const HRP_NSEC: &str = "nsec";
const HRP_NPUB: &str = "npub";
const HRP_NOTE: &str = "note";

fn encode(hrp_str: &'static str, data: &[u8]) -> Result<String> {
    let hrp = Hrp::parse(hrp_str).map_err(|e| Error::Bech32(e.to_string()))?;
    bech32::encode::<Bech32>(hrp, data).map_err(|e| Error::Bech32(e.to_string()))
}

fn decode(expected_hrp: &'static str, s: &str) -> Result<Vec<u8>> {
    let (hrp, data) = bech32::decode(s).map_err(|e| Error::Bech32(e.to_string()))?;
    if hrp.as_str() != expected_hrp {
        return Err(Error::Bech32Hrp {
            expected: expected_hrp,
            got: hrp.as_str().to_string(),
        });
    }
    Ok(data)
}

pub fn encode_nsec(sk: &SecretKey) -> Result<String> {
    encode(HRP_NSEC, sk.as_bytes())
}

pub fn decode_nsec(s: &str) -> Result<SecretKey> {
    let bytes = decode(HRP_NSEC, s)?;
    SecretKey::from_slice(&bytes)
}

pub fn encode_npub(pk: &PublicKey) -> Result<String> {
    encode(HRP_NPUB, pk.as_bytes())
}

pub fn decode_npub(s: &str) -> Result<PublicKey> {
    let bytes = decode(HRP_NPUB, s)?;
    PublicKey::from_slice(&bytes)
}

pub fn encode_note(event_id: &[u8; 32]) -> Result<String> {
    encode(HRP_NOTE, event_id)
}

pub fn decode_note(s: &str) -> Result<[u8; 32]> {
    let bytes = decode(HRP_NOTE, s)?;
    if bytes.len() != 32 {
        return Err(Error::KeyLength {
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIP-19 published vector:
    //   pubkey hex = 3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d
    //   npub       = npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6
    const NPUB_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const NPUB_STR: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    // nsec vector:
    //   sk hex = 67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa
    //   nsec   = nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5
    const NSEC_HEX: &str = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    const NSEC_STR: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    #[test]
    fn npub_encode_matches_vector() {
        let pk = PublicKey::from_hex(NPUB_HEX).unwrap();
        assert_eq!(encode_npub(&pk).unwrap(), NPUB_STR);
    }

    #[test]
    fn npub_decode_matches_vector() {
        let pk = decode_npub(NPUB_STR).unwrap();
        assert_eq!(pk.to_hex(), NPUB_HEX);
    }

    #[test]
    fn nsec_encode_matches_vector() {
        let sk = SecretKey::from_hex(NSEC_HEX).unwrap();
        assert_eq!(encode_nsec(&sk).unwrap(), NSEC_STR);
    }

    #[test]
    fn nsec_decode_matches_vector() {
        let sk = decode_nsec(NSEC_STR).unwrap();
        assert_eq!(sk.to_hex(), NSEC_HEX);
    }

    #[test]
    fn note_roundtrip() {
        let id = [0xabu8; 32];
        let encoded = encode_note(&id).unwrap();
        assert!(encoded.starts_with("note1"));
        let decoded = decode_note(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn wrong_hrp_is_rejected() {
        let err = decode_npub(NSEC_STR).unwrap_err();
        assert!(matches!(
            err,
            Error::Bech32Hrp {
                expected: "npub",
                ..
            }
        ));
    }
}
