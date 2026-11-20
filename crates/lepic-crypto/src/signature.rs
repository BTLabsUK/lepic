// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2018 The Grin Developers
// Portions Copyright 2020 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic core/src/ser.rs, core/src/libtx/secp_ser.rs (Apache-2.0); see NOTICE
// and upstream.toml.

use std::fmt;

use secp256k1zkp::Message as BackendMessage;
use secp256k1zkp::Signature as BackendSignature;
use secp256k1zkp::constants::{COMPACT_SIGNATURE_SIZE, MAX_SIGNATURE_SIZE, MESSAGE_SIZE};

use crate::context::secp;
use crate::error::{CryptoError, Item};
use crate::hex;
use crate::item_hex;
use crate::public_key::PublicKey;
use crate::secret::SecretKey;

/// A 32-byte digest to be signed. Hashing the content is the caller's job.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Message([u8; MESSAGE_SIZE]);

impl Message {
    pub const LEN: usize = MESSAGE_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        <[u8; MESSAGE_SIZE]>::try_from(bytes)
            .map(Self)
            .map_err(|_| CryptoError::WrongLength {
                item: Item::Message,
                expected: Self::LEN,
                actual: bytes.len(),
            })
    }

    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        item_hex::decode_array(hex, Item::Message).map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; MESSAGE_SIZE] {
        &self.0
    }

    pub(crate) fn to_backend(self) -> BackendMessage {
        BackendMessage::from(self.0)
    }
}

impl From<[u8; MESSAGE_SIZE]> for Message {
    fn from(digest: [u8; MESSAGE_SIZE]) -> Self {
        Self(digest)
    }
}

/// A 64-byte signature as the wrapper holds it, used for kernel and aggregate signatures.
///
/// It has two encodings and they differ: the binary transaction format writes the wrapper's raw
/// 64 bytes, while JSON (slates, node API) writes the ECDSA compact serialization of the same
/// value. Both are kept so each format can reproduce upstream exactly.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(BackendSignature);

impl Signature {
    pub const LEN: usize = COMPACT_SIGNATURE_SIZE;

    /// Parses the compact form, rejecting scalars that are not below the curve order.
    pub fn from_compact(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_signature_length(bytes)?;
        BackendSignature::from_compact(secp(), bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    pub fn from_compact_hex(hex: &str) -> Result<Self, CryptoError> {
        Self::from_compact(&item_hex::decode_array::<COMPACT_SIGNATURE_SIZE>(
            hex,
            Item::Signature,
        )?)
    }

    pub fn to_compact(&self) -> [u8; COMPACT_SIGNATURE_SIZE] {
        self.0.serialize_compact(secp())
    }

    pub fn to_compact_hex(&self) -> String {
        hex::encode(&self.to_compact())
    }

    /// Takes the raw form exactly as upstream's binary reader does: any 64 bytes. Whether they
    /// form a valid signature is decided by verification.
    pub fn from_raw(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_signature_length(bytes)?;
        let raw = <[u8; COMPACT_SIGNATURE_SIZE]>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;
        BackendSignature::from_raw_data(&raw)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    pub fn to_raw(&self) -> [u8; COMPACT_SIGNATURE_SIZE] {
        self.0.to_raw_data()
    }
}

fn check_signature_length(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.len() == COMPACT_SIGNATURE_SIZE {
        Ok(())
    } else {
        Err(CryptoError::WrongLength {
            item: Item::Signature,
            expected: COMPACT_SIGNATURE_SIZE,
            actual: bytes.len(),
        })
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(..)")
    }
}

/// An ECDSA signature over a [`Message`], DER-encoded on the wire as Epicbox expects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EcdsaSignature(BackendSignature);

impl EcdsaSignature {
    /// The shortest strict DER encoding of an ECDSA signature.
    pub const MIN_DER_LEN: usize = 8;
    pub const MAX_DER_LEN: usize = MAX_SIGNATURE_SIZE;

    /// Signs with an RFC 6979 deterministic nonce, so equal inputs give equal signatures.
    pub fn sign(digest: &Message, key: &SecretKey) -> Result<Self, CryptoError> {
        Ok(Self(secp().sign(&digest.to_backend(), key.as_backend())?))
    }

    pub fn verify(&self, digest: &Message, key: &PublicKey) -> Result<(), CryptoError> {
        secp()
            .verify(&digest.to_backend(), &self.0, key.as_backend())
            .map_err(|_| CryptoError::SignatureMismatch)
    }

    /// Parses strict DER. High-S signatures parse but do not verify, matching upstream.
    pub fn from_der(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < Self::MIN_DER_LEN || bytes.len() > Self::MAX_DER_LEN {
            return Err(CryptoError::LengthOutOfRange {
                item: Item::EcdsaSignature,
                min: Self::MIN_DER_LEN,
                max: Self::MAX_DER_LEN,
                actual: bytes.len(),
            });
        }
        BackendSignature::from_der(secp(), bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    pub fn from_der_hex(hex: &str) -> Result<Self, CryptoError> {
        Self::from_der(&item_hex::decode_bounded(
            hex,
            Self::MIN_DER_LEN,
            Self::MAX_DER_LEN,
            Item::EcdsaSignature,
        )?)
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.0.serialize_der(secp())
    }

    pub fn to_der_hex(&self) -> String {
        hex::encode(&self.to_der())
    }
}

impl fmt::Debug for EcdsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaSignature(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn digest(byte: u8) -> Message {
        Message::from([byte; 32])
    }

    #[test]
    fn rejects_message_of_the_wrong_length() {
        assert_eq!(
            Message::from_bytes(&[0u8; 31]),
            Err(CryptoError::WrongLength {
                item: Item::Message,
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            Message::from_hex("00").err(),
            Some(CryptoError::WrongLength {
                item: Item::Message,
                expected: 32,
                actual: 1
            })
        );
    }

    #[test]
    fn ecdsa_signature_verifies_and_round_trips_through_der() {
        let key = secret(9);
        let public = PublicKey::from_secret_key(&key).unwrap();
        let signature = EcdsaSignature::sign(&digest(1), &key).unwrap();
        assert_eq!(signature.verify(&digest(1), &public), Ok(()));

        let der = signature.to_der();
        assert!(der.len() >= EcdsaSignature::MIN_DER_LEN && der.len() <= 72);
        assert_eq!(der.first(), Some(&0x30));
        assert_eq!(EcdsaSignature::from_der(&der), Ok(signature));
        assert_eq!(
            EcdsaSignature::from_der_hex(&signature.to_der_hex()),
            Ok(signature)
        );
    }

    #[test]
    fn ecdsa_signing_is_deterministic() {
        let key = secret(9);
        assert_eq!(
            EcdsaSignature::sign(&digest(1), &key),
            EcdsaSignature::sign(&digest(1), &key)
        );
    }

    #[test]
    fn rejects_ecdsa_signature_over_another_message() {
        let key = secret(9);
        let public = PublicKey::from_secret_key(&key).unwrap();
        let signature = EcdsaSignature::sign(&digest(1), &key).unwrap();
        assert_eq!(
            signature.verify(&digest(2), &public),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_ecdsa_signature_from_another_key() {
        let signature = EcdsaSignature::sign(&digest(1), &secret(9)).unwrap();
        let other = PublicKey::from_secret_key(&secret(10)).unwrap();
        assert_eq!(
            signature.verify(&digest(1), &other),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_der_outside_the_length_bounds() {
        assert_eq!(
            EcdsaSignature::from_der(&[0x30; 7]),
            Err(CryptoError::LengthOutOfRange {
                item: Item::EcdsaSignature,
                min: 8,
                max: 72,
                actual: 7
            })
        );
        assert_eq!(
            EcdsaSignature::from_der(&[0x30; 73]),
            Err(CryptoError::LengthOutOfRange {
                item: Item::EcdsaSignature,
                min: 8,
                max: 72,
                actual: 73
            })
        );
        assert_eq!(
            EcdsaSignature::from_der_hex(&"30".repeat(73)),
            Err(CryptoError::LengthOutOfRange {
                item: Item::EcdsaSignature,
                min: 8,
                max: 72,
                actual: 73
            })
        );
    }

    #[test]
    fn rejects_malformed_der() {
        let mut der = EcdsaSignature::sign(&digest(1), &secret(9))
            .unwrap()
            .to_der();
        der[0] = 0x31;
        assert_eq!(
            EcdsaSignature::from_der(&der),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_der_with_trailing_bytes() {
        let mut der = EcdsaSignature::sign(&digest(1), &secret(9))
            .unwrap()
            .to_der();
        der.push(0);
        assert_eq!(
            EcdsaSignature::from_der(&der),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn compact_signature_round_trips() {
        let ecdsa = EcdsaSignature::sign(&digest(1), &secret(9)).unwrap();
        let compact = ecdsa.0.serialize_compact(secp());
        let signature = Signature::from_compact(&compact).unwrap();
        assert_eq!(signature.to_compact(), compact);
        assert_eq!(
            Signature::from_compact_hex(&signature.to_compact_hex()),
            Ok(signature)
        );
        assert_eq!(Signature::from_raw(&signature.to_raw()), Ok(signature));
    }

    #[test]
    fn rejects_signature_of_the_wrong_length() {
        for bytes in [&[0u8; 63][..], &[0u8; 65][..]] {
            let expected = Err(CryptoError::WrongLength {
                item: Item::Signature,
                expected: 64,
                actual: bytes.len(),
            });
            assert_eq!(Signature::from_compact(bytes), expected);
            assert_eq!(Signature::from_raw(bytes), expected);
        }
    }

    #[test]
    fn rejects_compact_signature_with_scalar_above_the_curve_order() {
        assert_eq!(
            Signature::from_compact(&[0xff; 64]),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn signature_debug_hides_bytes() {
        let signature = Signature::from_raw(&[0xab; 64]).unwrap();
        assert_eq!(format!("{signature:?}"), "Signature(..)");
    }
}
