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
    key_message_verifies(address.public_key(), message, signature_hex)
}

/// [`address_message_verifies`] for the key alone, as
/// [`EpicboxAddress::parse_key`] reads it from an address with or without its relay.
pub fn key_message_verifies(key: &PublicKey, message: &[u8], signature_hex: &str) -> bool {
    EcdsaSignature::from_der_hex(signature_hex)
        .is_ok_and(|signature| verify_address_message(message, &signature, key).is_ok())
}

/// The tag of signatures by a listing's address key; its SHA-256 holds a byte UTF-8 never uses,
/// and it is neither the address-signature tag nor any other.
const LISTING_TAG: &[u8] = b"lepic/listing-signature/v1";

/// The longest service domain: its length is one byte in the signed digest.
pub const MAX_SERVICE_DOMAIN_LEN: usize = 64;

/// What a listing signature is for, chosen by the app: lowercase ASCII `name/version`, such as
/// `epic-listing/1`. Domains starting with `lepic` are LEPIC's own and are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDomain(String);

/// Why a text is no service domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServiceDomainError {
    #[error("a service domain is 3 to {MAX_SERVICE_DOMAIN_LEN} bytes")]
    Length,
    #[error("a service domain is lowercase name/version")]
    Format,
    #[error("service domains starting with lepic are reserved")]
    Reserved,
}

impl ServiceDomain {
    pub fn parse(text: &str) -> Result<Self, ServiceDomainError> {
        if text.len() < 3 || text.len() > MAX_SERVICE_DOMAIN_LEN {
            return Err(ServiceDomainError::Length);
        }
        if text.to_ascii_lowercase().starts_with("lepic") {
            return Err(ServiceDomainError::Reserved);
        }
        let (name, version) = text.split_once('/').ok_or(ServiceDomainError::Format)?;
        let name_ok = !name.is_empty()
            && name
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'));
        let version_ok = !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit());
        if !name_ok || !version_ok {
            return Err(ServiceDomainError::Format);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Signs `message` for `domain` with a listing's address key `key`.
pub fn sign_listing_message(
    domain: &ServiceDomain,
    message: &[u8],
    key: &SecretKey,
) -> Result<EcdsaSignature, CryptoError> {
    EcdsaSignature::sign(&listing_message_digest(domain, message), key)
}

/// Whether `signature` is [`sign_listing_message`] of `message` for `domain` by the key of
/// `key`. Needs no wallet.
pub fn listing_message_verifies(
    key: &PublicKey,
    domain: &ServiceDomain,
    message: &[u8],
    signature: &EcdsaSignature,
) -> bool {
    signature
        .verify(&listing_message_digest(domain, message), key)
        .is_ok()
}

/// [`listing_message_verifies`] of a DER hex `signature_hex`; false when it does not parse.
pub fn listing_message_verifies_hex(
    key: &PublicKey,
    domain: &ServiceDomain,
    message: &[u8],
    signature_hex: &str,
) -> bool {
    EcdsaSignature::from_der_hex(signature_hex)
        .is_ok_and(|signature| listing_message_verifies(key, domain, message, &signature))
}

fn listing_message_digest(domain: &ServiceDomain, message: &[u8]) -> Message {
    let tag = Sha256::digest(LISTING_TAG);
    // The domain is at most MAX_SERVICE_DOMAIN_LEN bytes, so its length fits the byte.
    let length = u8::try_from(domain.0.len()).unwrap_or(u8::MAX);
    let digest = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update([length])
        .chain_update(domain.0.as_bytes())
        .chain_update(message)
        .finalize();
    Message::from(<[u8; 32]>::from(digest))
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
        assert!(
            Sha256::digest(LISTING_TAG)
                .iter()
                .copied()
                .any(never_in_utf8)
        );
    }

    fn domain(text: &str) -> ServiceDomain {
        ServiceDomain::parse(text).unwrap()
    }

    #[test]
    fn service_domains_are_lowercase_name_and_version_and_never_lepics() {
        for good in [
            "epic-listing/1",
            "epic-payreq/1",
            "a/0",
            "epic-dir-hello/12",
        ] {
            assert_eq!(ServiceDomain::parse(good).unwrap().as_str(), good);
        }
        for (bad, error) in [
            ("lepic/addr-proof/1", ServiceDomainError::Reserved),
            ("lepic/x", ServiceDomainError::Reserved),
            ("LEPIC-x/1", ServiceDomainError::Reserved),
            ("Lepic/1", ServiceDomainError::Reserved),
            ("lepicx/1", ServiceDomainError::Reserved),
            ("Epic/1", ServiceDomainError::Format),
            ("epic", ServiceDomainError::Format),
            ("epic/", ServiceDomainError::Format),
            ("/12", ServiceDomainError::Format),
            ("epic/1/2", ServiceDomainError::Format),
            ("epic/v1", ServiceDomainError::Format),
            ("ep ic/1", ServiceDomainError::Format),
            ("é/1", ServiceDomainError::Format),
            ("a/", ServiceDomainError::Length),
            ("", ServiceDomainError::Length),
        ] {
            assert_eq!(ServiceDomain::parse(bad), Err(error), "{bad}");
        }
        let long = format!("{}/1", "a".repeat(MAX_SERVICE_DOMAIN_LEN));
        assert_eq!(ServiceDomain::parse(&long), Err(ServiceDomainError::Length));
    }

    #[test]
    fn a_listing_signature_holds_for_its_domain_message_and_key_only() {
        let listing = domain("epic-listing/1");
        let signature = sign_listing_message(&listing, b"card", &secret(1)).unwrap();
        assert!(listing_message_verifies(
            &public(1),
            &listing,
            b"card",
            &signature
        ));
        assert!(!listing_message_verifies(
            &public(2),
            &listing,
            b"card",
            &signature
        ));
        assert!(!listing_message_verifies(
            &public(1),
            &listing,
            b"cart",
            &signature
        ));
        assert!(!listing_message_verifies(
            &public(1),
            &domain("epic-payreq/1"),
            b"card",
            &signature
        ));
        // The length prefix keeps domain and message apart.
        let short = sign_listing_message(&domain("a/1"), b"2card", &secret(1)).unwrap();
        let long = sign_listing_message(&domain("a/12"), b"card", &secret(1)).unwrap();
        assert_ne!(short, long);
        assert!(!listing_message_verifies(
            &public(1),
            &domain("a/12"),
            b"card",
            &short
        ));
    }

    #[test]
    fn listing_address_and_text_signatures_never_stand_in_for_each_other() {
        let listing = domain("epic-listing/1");
        let text = "challenge";
        let as_listing = sign_listing_message(&listing, text.as_bytes(), &secret(1)).unwrap();
        let as_address = sign_address_message(text.as_bytes(), &secret(1)).unwrap();
        let as_text = sign_text(text, &secret(1)).unwrap();
        assert!(verify_address_message(text.as_bytes(), &as_listing, &public(1)).is_err());
        assert!(verify_text(text, &as_listing, &public(1)).is_err());
        assert!(!listing_message_verifies(
            &public(1),
            &listing,
            text.as_bytes(),
            &as_address
        ));
        assert!(!listing_message_verifies(
            &public(1),
            &listing,
            text.as_bytes(),
            &as_text
        ));
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
