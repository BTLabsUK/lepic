// SPDX-License-Identifier: Apache-2.0
//! Signatures by the address key over app-chosen bytes, kept apart from every text the key signs
//! for the relay.
//!
//! The relay picks the challenge text the address key signs as SHA-256 of its UTF-8 bytes
//! ([`crate::sign_text`]). These signatures are made over a tagged hash instead,
//! SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ message), whose preimage holds a byte that never
//! occurs in UTF-8 (0xC0, 0xC1 and 0xF5 to 0xFF). No text hashes to one of these digests without a
//! SHA-256 collision, so no text signature passes as an address signature and no address
//! signature passes as a text signature.

use lepic_crypto::{CryptoError, EcdsaSignature, Message, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::address::EpicboxAddress;

/// Changing the tag changes every signature; its SHA-256 must keep a byte that UTF-8 never uses.
const TAG: &[u8] = b"lepic/address-signature/v1";

/// Signs `message` with the address key `key`, under the address-signature tag only.
pub fn sign_address_message(
    message: &[u8],
    key: &SecretKey,
) -> Result<EcdsaSignature, CryptoError> {
    EcdsaSignature::sign(&address_message_digest(message), key)
}

/// Fails with [`CryptoError::SignatureMismatch`] unless `signature` is
/// [`sign_address_message`] of `message` by the key of `key`.
pub fn verify_address_message(
    message: &[u8],
    signature: &EcdsaSignature,
    key: &PublicKey,
) -> Result<(), CryptoError> {
    signature.verify(&address_message_digest(message), key)
}

/// True when `signature_hex` (DER hex) is [`sign_address_message`] of `message` by the key of
/// `address`.
pub fn address_message_verifies(
    address: &EpicboxAddress,
    message: &[u8],
    signature_hex: &str,
) -> bool {
    EcdsaSignature::from_der_hex(signature_hex).is_ok_and(|signature| {
        verify_address_message(message, &signature, address.public_key()).is_ok()
    })
}

fn address_message_digest(message: &[u8]) -> Message {
    let tag = Sha256::digest(TAG);
    let digest = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(message)
        .finalize();
    Message::from(<[u8; 32]>::from(digest))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{sign_text, verify_text};

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn public(byte: u8) -> PublicKey {
        PublicKey::from_secret_key(&secret(byte)).unwrap()
    }

    fn preimage(message: &[u8]) -> Vec<u8> {
        let tag = Sha256::digest(TAG);
        [tag.as_slice(), tag.as_slice(), message].concat()
    }

    fn never_in_utf8(byte: u8) -> bool {
        matches!(byte, 0xC0 | 0xC1 | 0xF5..=0xFF)
    }

    #[test]
    fn signature_verifies_with_the_signing_key() {
        let signature = sign_address_message(b"hello", &secret(1)).unwrap();
        verify_address_message(b"hello", &signature, &public(1)).unwrap();
    }

    #[test]
    fn signature_is_deterministic() {
        assert_eq!(
            sign_address_message(b"hello", &secret(1)).unwrap(),
            sign_address_message(b"hello", &secret(1)).unwrap()
        );
    }

    #[test]
    fn rejects_another_key() {
        let signature = sign_address_message(b"hello", &secret(1)).unwrap();
        assert_eq!(
            verify_address_message(b"hello", &signature, &public(2)),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_another_message() {
        let signature = sign_address_message(b"hello", &secret(1)).unwrap();
        assert_eq!(
            verify_address_message(b"hellp", &signature, &public(1)),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn tag_hash_holds_a_byte_utf8_never_uses() {
        assert!(Sha256::digest(TAG).iter().copied().any(never_in_utf8));
    }

    #[test]
    fn text_and_address_signatures_never_stand_in_for_each_other() {
        let text = "challenge";
        let as_text = sign_text(text, &secret(1)).unwrap();
        let as_address = sign_address_message(text.as_bytes(), &secret(1)).unwrap();
        assert_ne!(as_text, as_address);
        assert_eq!(
            verify_address_message(text.as_bytes(), &as_text, &public(1)),
            Err(CryptoError::SignatureMismatch)
        );
        assert_eq!(
            verify_text(text, &as_address, &public(1)),
            Err(CryptoError::SignatureMismatch)
        );
    }

    proptest! {
        #[test]
        fn preimage_is_never_utf8(message in proptest::collection::vec(any::<u8>(), 0..256)) {
            prop_assert!(std::str::from_utf8(&preimage(&message)).is_err());
        }

        #[test]
        fn digest_is_the_hash_of_the_preimage(
            message in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let expected = Message::from(<[u8; 32]>::from(Sha256::digest(preimage(&message))));
            prop_assert_eq!(address_message_digest(&message), expected);
        }
    }
}
