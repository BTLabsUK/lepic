// SPDX-License-Identifier: Apache-2.0
//! Keys of the LEPIC namespace: the keys LEPIC adds that `epic-wallet` has no use for, each the
//! keyed BLAKE2b-256 of the seed over its own versioned label and a fixed-width context. Nothing
//! here sits on a BIP32 path, so no key of this module can equal an output or address key.
//!
//! Each key has one function and one label here; nothing else derives them.

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_keychain::Seed;
use zeroize::Zeroizing;

use crate::error::WalletError;

/// The key of a listing address: context `service_key (33) || generation (u32 BE) || counter (u8)`,
/// the counter from 0 up to the first output that is a valid secp256k1 key.
pub const LISTING_KEY_LABEL: &[u8] = b"lepic-wallet listing key v1";

/// The Ed25519 key that signs a device-link hello: no context. Every install of one phrase
/// derives the same key, so a valid signature proves the same phrase.
pub const DEVICE_LINK_KEY_LABEL: &[u8] = b"lepic-wallet device link key v1";

/// The Ed25519 seed of the wallet's onion service (ADR 0044): no context. It is off the
/// payment-proof key, so the Epicbox and payment-proof addresses do not give the onion.
pub const ONION_KEY_LABEL: &[u8] = b"lepic-wallet onion key v1";

/// The Ed25519 seed of the certificate key of `serve`'s owner TLS listener (ADR 0050): no
/// context. A restore from the phrase gives the same key, so clients keep their pin.
pub const API_TLS_KEY_LABEL: &[u8] = b"lepic-wallet api tls v1";

/// What device-link signatures are made over: this tag, then the transcript.
pub const DEVICE_LINK_TAG: &[u8] = b"lepic/device-link/v1";

/// A listing of this wallet with a name service: the service's key and the generation of the
/// listing, raised after each leave so a new listing gets a new key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Listing {
    service_key: PublicKey,
    generation: u32,
}

impl Listing {
    pub fn new(service_key: PublicKey, generation: u32) -> Self {
        Self {
            service_key,
            generation,
        }
    }

    /// Fails with [`WalletError::InvalidListing`] unless `service_key` is a compressed secp256k1 key.
    pub fn from_bytes(service_key: &[u8], generation: u32) -> Result<Self, WalletError> {
        if service_key.len() != 33 {
            return Err(WalletError::InvalidListing);
        }
        let service_key =
            PublicKey::from_bytes(service_key).map_err(|_| WalletError::InvalidListing)?;
        Ok(Self::new(service_key, generation))
    }

    /// [`Self::from_bytes`] of `service_key` written as 66 hex digits.
    pub fn from_hex(service_key: &str, generation: u32) -> Result<Self, WalletError> {
        let bytes = lepic_crypto::hex::decode_array::<33>(service_key)
            .map_err(|_| WalletError::InvalidListing)?;
        Self::from_bytes(&bytes, generation)
    }

    pub fn service_key(&self) -> &PublicKey {
        &self.service_key
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub(crate) fn to_stored(self) -> lepic_store::ReceiveListing {
        lepic_store::ReceiveListing {
            service_key: self.service_key.to_bytes(),
            generation: self.generation,
        }
    }

    /// The listing `stored` names; a stored service key that is no curve point is damage,
    /// reported as such rather than read as no listing.
    pub(crate) fn from_stored(
        stored: &lepic_store::ReceiveListing,
    ) -> Result<Self, lepic_store::StoreError> {
        PublicKey::from_bytes(&stored.service_key)
            .map(|service_key| Self::new(service_key, stored.generation))
            .map_err(|_| lepic_store::StoreError::Corrupt {
                record: lepic_store::Record::Transaction,
                field: "receive listing",
            })
    }
}

/// BLAKE2b-256 keyed by the seed over `label` and then each part of `context`.
fn namespace_hash(
    seed: &Seed,
    label: &[u8],
    context: &[&[u8]],
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let mut mac =
        <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).map_err(|_| {
            WalletError::StoredSeed(lepic_keychain::MnemonicError::EntropyLength {
                actual: seed.expose_bytes().len(),
            })
        })?;
    mac.update(label);
    for part in context {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    mac.finalize_into((&mut *out).into());
    Ok(out)
}

/// The secret key of `listing`'s address.
pub(crate) fn listing_key(seed: &Seed, listing: &Listing) -> Result<SecretKey, WalletError> {
    let service_key = listing.service_key.to_bytes();
    let generation = listing.generation.to_be_bytes();
    for counter in 0..=u8::MAX {
        let bytes = namespace_hash(
            seed,
            LISTING_KEY_LABEL,
            &[&service_key, &generation, &[counter]],
        )?;
        if let Ok(key) = SecretKey::from_array(*bytes) {
            return Ok(key);
        }
    }
    Err(WalletError::InvalidListing)
}

/// The device-link key of the wallet of `seed`.
pub(crate) fn device_link_key(seed: &Seed) -> Result<SigningKey, WalletError> {
    let bytes = namespace_hash(seed, DEVICE_LINK_KEY_LABEL, &[])?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// The seed of the onion key of the wallet of `seed`.
pub(crate) fn onion_seed(seed: &Seed) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    namespace_hash(seed, ONION_KEY_LABEL, &[])
}

/// The seed of the owner TLS certificate key of the wallet of `seed`.
pub(crate) fn api_tls_seed(seed: &Seed) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    namespace_hash(seed, API_TLS_KEY_LABEL, &[])
}

fn device_link_message(transcript: &[u8]) -> Vec<u8> {
    [DEVICE_LINK_TAG, transcript].concat()
}

/// The device-link signature of `transcript` by the wallet of `seed`.
pub(crate) fn device_link_sign(seed: &Seed, transcript: &[u8]) -> Result<[u8; 64], WalletError> {
    Ok(device_link_key(seed)?
        .sign(&device_link_message(transcript))
        .to_bytes())
}

/// Whether `signature` is the device-link signature of `transcript` by `key`.
pub fn device_link_verifies(key: &VerifyingKey, transcript: &[u8], signature: &[u8]) -> bool {
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(&device_link_message(transcript), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and panic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn seed(byte: u8) -> Seed {
        Seed::from_entropy(&[byte; 32]).unwrap()
    }

    fn service_key(byte: u8) -> PublicKey {
        PublicKey::from_secret_key(&SecretKey::from_array([byte; 32]).unwrap()).unwrap()
    }

    #[test]
    fn a_stored_listing_reads_back_and_a_damaged_service_key_is_reported() {
        let listing = Listing::new(service_key(9), 3);
        assert_eq!(Listing::from_stored(&listing.to_stored()).unwrap(), listing);
        let damaged = lepic_store::ReceiveListing {
            service_key: [0; 33],
            generation: 3,
        };
        assert!(matches!(
            Listing::from_stored(&damaged),
            Err(lepic_store::StoreError::Corrupt {
                field: "receive listing",
                ..
            })
        ));
    }

    #[test]
    fn a_listing_key_is_the_keyed_hash_of_its_label_and_context() {
        let listing = Listing::new(service_key(9), 3);
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(&[1; 32]).unwrap();
        mac.update(b"lepic-wallet listing key v1");
        mac.update(&service_key(9).to_bytes());
        mac.update(&[0, 0, 0, 3]);
        mac.update(&[0]);
        let expected: [u8; 32] = mac.finalize_fixed().into();
        assert_eq!(
            listing_key(&seed(1), &listing).unwrap().expose_bytes(),
            &expected
        );
    }

    #[test]
    fn listing_keys_differ_by_seed_service_and_generation() {
        let key = |seed_byte, key_byte, generation| {
            *listing_key(
                &seed(seed_byte),
                &Listing::new(service_key(key_byte), generation),
            )
            .unwrap()
            .expose_bytes()
        };
        let base = key(1, 9, 0);
        assert_eq!(base, key(1, 9, 0));
        assert_ne!(base, key(2, 9, 0));
        assert_ne!(base, key(1, 8, 0));
        assert_ne!(base, key(1, 9, 1));
    }

    #[test]
    fn a_listing_needs_a_compressed_curve_point() {
        assert!(Listing::from_bytes(&service_key(9).to_bytes(), 0).is_ok());
        assert!(matches!(
            Listing::from_bytes(&[2; 32], 0),
            Err(WalletError::InvalidListing)
        ));
        let mut off_curve = [0u8; 33];
        off_curve[0] = 2;
        off_curve[32] = 7;
        assert!(Listing::from_bytes(&off_curve, 0).is_err());
    }

    #[test]
    fn device_link_signatures_verify_only_for_the_same_phrase_and_transcript() {
        let signature = device_link_sign(&seed(1), b"hello").unwrap();
        let own = device_link_key(&seed(1)).unwrap().verifying_key();
        let other = device_link_key(&seed(2)).unwrap().verifying_key();
        assert!(device_link_verifies(&own, b"hello", &signature));
        assert!(!device_link_verifies(&own, b"hellp", &signature));
        assert!(!device_link_verifies(&other, b"hello", &signature));
        assert!(!device_link_verifies(&own, b"hello", &signature[..63]));
        // The tag is part of what is signed: the bare transcript does not verify.
        let bare = device_link_key(&seed(1)).unwrap().sign(b"hello").to_bytes();
        assert!(!device_link_verifies(&own, b"hello", &bare));
    }

    #[test]
    fn the_device_link_key_is_the_keyed_hash_of_its_label() {
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(&[1; 32]).unwrap();
        mac.update(b"lepic-wallet device link key v1");
        let expected: [u8; 32] = mac.finalize_fixed().into();
        assert_eq!(device_link_key(&seed(1)).unwrap().to_bytes(), expected);
    }

    #[test]
    fn the_onion_seed_is_the_keyed_hash_of_its_label() {
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(&[1; 32]).unwrap();
        mac.update(b"lepic-wallet onion key v1");
        let expected: [u8; 32] = mac.finalize_fixed().into();
        assert_eq!(*onion_seed(&seed(1)).unwrap(), expected);
        assert_ne!(*onion_seed(&seed(2)).unwrap(), expected);
    }

    #[test]
    fn the_api_tls_seed_is_the_keyed_hash_of_its_label() {
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(&[1; 32]).unwrap();
        mac.update(b"lepic-wallet api tls v1");
        let expected: [u8; 32] = mac.finalize_fixed().into();
        assert_eq!(*api_tls_seed(&seed(1)).unwrap(), expected);
        assert_ne!(*api_tls_seed(&seed(2)).unwrap(), expected);
    }
}
