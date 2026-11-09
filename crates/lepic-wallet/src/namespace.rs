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
use lepic_contact::{EncSecretKey, Network};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_keychain::Seed;
use sha2::{Digest, Sha256};
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

/// The X25519 key that opens envelopes sealed to one address of an account: context
/// `account (u32 BE) || net || kind`, 6 bytes ([`SealKeyKind`]).
pub const SEAL_KEY_LABEL: &[u8] = b"lepic-wallet seal key v1";

/// The Ed25519 seed of the proof key in an account's epic1 address: context
/// `account (u32 BE) || net`, 5 bytes. It signs the payment proofs of slates that came to the
/// epic1, as the onion key does for slates that came over the onion (ADR 0044).
pub const EPIC1_PROOF_KEY_LABEL: &[u8] = b"lepic-wallet epic1 proof key v1";

/// The throwaway Epicbox mailbox for the answer to one slate: context
/// `account (u32 BE) || net || slate_id (16) || counter (u8)`, 22 bytes.
pub const REPLY_MAILBOX_LABEL: &[u8] = b"lepic-wallet reply mailbox v1";

/// The Epicbox `from` key of the posts of one slate to another party's mailbox: context
/// `account (u32 BE) || net || slate_id (16) || role || counter (u8)`, 23 bytes ([`PostRole`]).
pub const POST_KEY_LABEL: &[u8] = b"lepic-wallet post key v1";

/// The Epicbox mailbox an epic1 link names: context
/// `account (u32 BE) || net || kind || n (u32 BE) || counter (u8)`, 11 bytes ([`LinkMailbox`]).
pub const LINK_MAILBOX_LABEL: &[u8] = b"lepic-wallet link mailbox v1";

/// What a check code hashes: this tag, then the receiver's public excess (33 bytes, compressed).
pub const CHECK_CODE_TAG: &[u8] = b"epic-check/1";

/// Which address of an account a seal key opens envelopes for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SealKeyKind {
    /// The account's epic1 address.
    Epic1,
    /// The onion listener.
    Onion,
    /// The plain web listener.
    Web,
}

impl SealKeyKind {
    /// The byte of the derivation context.
    pub fn byte(self) -> u8 {
        match self {
            Self::Epic1 => 0x00,
            Self::Onion => 0x01,
            Self::Web => 0x02,
        }
    }
}

/// Which side of a slate a post key posts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostRole {
    /// The party that started the slate.
    Initiator,
    /// The party that answers it.
    Responder,
}

impl PostRole {
    /// The byte of the derivation context.
    pub fn byte(self) -> u8 {
        match self {
            Self::Initiator => 0x00,
            Self::Responder => 0x01,
        }
    }
}

/// One link mailbox of an account: a code shown on screen (`n` 0 to 49, a new one per receive
/// session or share, used in turn) or a printed code (`n` 0 to 31, fixed per code). The two
/// kinds have index spaces of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkMailbox {
    kind: u8,
    n: u32,
}

impl LinkMailbox {
    /// How many on-screen link mailboxes an account has.
    pub const ON_SCREEN: u32 = 50;
    /// How many printed link mailboxes an account has.
    pub const PRINTED: u32 = 32;

    /// The on-screen mailbox `n`, or `None` past [`Self::ON_SCREEN`].
    pub fn on_screen(n: u32) -> Option<Self> {
        (n < Self::ON_SCREEN).then_some(Self { kind: 0x00, n })
    }

    /// The printed mailbox `n`, or `None` past [`Self::PRINTED`].
    pub fn printed(n: u32) -> Option<Self> {
        (n < Self::PRINTED).then_some(Self { kind: 0x01, n })
    }

    /// The kind byte of the derivation context: 00 on screen, 01 printed.
    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn n(&self) -> u32 {
        self.n
    }
}

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

/// The first valid secp256k1 key of `label` and `context`, followed by a counter from 0 up.
fn first_valid_key(seed: &Seed, label: &[u8], context: &[&[u8]]) -> Result<SecretKey, WalletError> {
    for counter in 0..=u8::MAX {
        let counter = [counter];
        let parts: Vec<&[u8]> = context.iter().copied().chain([&counter[..]]).collect();
        let bytes = namespace_hash(seed, label, &parts)?;
        if let Ok(key) = SecretKey::from_array(*bytes) {
            return Ok(key);
        }
    }
    Err(WalletError::NoValidKey)
}

/// The seal key of `kind` for `account` on `network`; its public key is X25519 of the secret
/// and the base point. Not used by the engine yet.
pub fn seal_key(
    seed: &Seed,
    account: u32,
    network: Network,
    kind: SealKeyKind,
) -> Result<EncSecretKey, WalletError> {
    let bytes = namespace_hash(
        seed,
        SEAL_KEY_LABEL,
        &[&account.to_be_bytes(), &[network.byte()], &[kind.byte()]],
    )?;
    Ok(EncSecretKey::from_bytes(*bytes))
}

/// The epic1 proof key of `account` on `network`. Not used by the engine yet.
pub fn epic1_proof_key(
    seed: &Seed,
    account: u32,
    network: Network,
) -> Result<SigningKey, WalletError> {
    let bytes = namespace_hash(
        seed,
        EPIC1_PROOF_KEY_LABEL,
        &[&account.to_be_bytes(), &[network.byte()]],
    )?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// The reply mailbox key of `account` on `network` for the slate `slate_id`.
pub fn reply_mailbox_key(
    seed: &Seed,
    account: u32,
    network: Network,
    slate_id: &[u8; 16],
) -> Result<SecretKey, WalletError> {
    first_valid_key(
        seed,
        REPLY_MAILBOX_LABEL,
        &[&account.to_be_bytes(), &[network.byte()], slate_id],
    )
}

/// The post key of `account` on `network` for the slate `slate_id` in `role`.
pub fn post_key(
    seed: &Seed,
    account: u32,
    network: Network,
    slate_id: &[u8; 16],
    role: PostRole,
) -> Result<SecretKey, WalletError> {
    first_valid_key(
        seed,
        POST_KEY_LABEL,
        &[
            &account.to_be_bytes(),
            &[network.byte()],
            slate_id,
            &[role.byte()],
        ],
    )
}

/// The key of `mailbox` of `account` on `network`. Not used by the engine yet.
pub fn link_mailbox_key(
    seed: &Seed,
    account: u32,
    network: Network,
    mailbox: LinkMailbox,
) -> Result<SecretKey, WalletError> {
    first_valid_key(
        seed,
        LINK_MAILBOX_LABEL,
        &[
            &account.to_be_bytes(),
            &[network.byte()],
            &[mailbox.kind],
            &mailbox.n.to_be_bytes(),
        ],
    )
}

/// The four-digit check code of an answer: the first 4 bytes of
/// `SHA-256("epic-check/1" || excess)`, big-endian, modulo 10,000, with leading zeros. `excess`
/// is the 33-byte public excess of the party that answered: the payer's in an I2, the
/// receiver's in an S2.
pub fn check_code(excess: &PublicKey) -> String {
    let digest = Sha256::new()
        .chain_update(CHECK_CODE_TAG)
        .chain_update(excess.to_bytes())
        .finalize();
    let first = digest.first_chunk::<4>().copied().unwrap_or_default();
    format!("{:04}", u32::from_be_bytes(first) % 10_000)
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

    fn keyed(label: &[u8], context: &[&[u8]]) -> [u8; 32] {
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(&[1; 32]).unwrap();
        mac.update(label);
        for part in context {
            mac.update(part);
        }
        mac.finalize_fixed().into()
    }

    #[test]
    fn a_seal_key_is_the_keyed_hash_of_its_label_and_context() {
        let key = seal_key(&seed(1), 7, Network::Floonet, SealKeyKind::Onion).unwrap();
        let expected = keyed(b"lepic-wallet seal key v1", &[&[0, 0, 0, 7], &[1], &[1]]);
        assert_eq!(
            key.public_key(),
            EncSecretKey::from_bytes(expected).public_key()
        );
        let public = |account, network, kind| {
            *seal_key(&seed(1), account, network, kind)
                .unwrap()
                .public_key()
                .as_bytes()
        };
        let base = public(0, Network::Mainnet, SealKeyKind::Epic1);
        assert_ne!(base, public(1, Network::Mainnet, SealKeyKind::Epic1));
        assert_ne!(base, public(0, Network::Floonet, SealKeyKind::Epic1));
        assert_ne!(base, public(0, Network::Mainnet, SealKeyKind::Onion));
        assert_ne!(base, public(0, Network::Mainnet, SealKeyKind::Web));
    }

    #[test]
    fn the_epic1_proof_key_is_the_keyed_hash_of_its_label_and_context() {
        let key = epic1_proof_key(&seed(1), 2, Network::Mainnet).unwrap();
        let expected = keyed(b"lepic-wallet epic1 proof key v1", &[&[0, 0, 0, 2], &[0]]);
        assert_eq!(key.to_bytes(), expected);
        assert_ne!(
            epic1_proof_key(&seed(1), 2, Network::Floonet)
                .unwrap()
                .to_bytes(),
            expected
        );
    }

    #[test]
    fn mailbox_keys_are_the_keyed_hash_of_their_label_and_context() {
        let slate_id = [0x5a; 16];
        let reply = reply_mailbox_key(&seed(1), 1, Network::Floonet, &slate_id).unwrap();
        let expected = keyed(
            b"lepic-wallet reply mailbox v1",
            &[&[0, 0, 0, 1], &[1], &slate_id, &[0]],
        );
        assert_eq!(reply.expose_bytes(), &expected);

        let post = post_key(
            &seed(1),
            1,
            Network::Floonet,
            &slate_id,
            PostRole::Responder,
        )
        .unwrap();
        let expected = keyed(
            b"lepic-wallet post key v1",
            &[&[0, 0, 0, 1], &[1], &slate_id, &[1], &[0]],
        );
        assert_eq!(post.expose_bytes(), &expected);

        let printed = LinkMailbox::printed(31).unwrap();
        let link = link_mailbox_key(&seed(1), 1, Network::Floonet, printed).unwrap();
        let expected = keyed(
            b"lepic-wallet link mailbox v1",
            &[&[0, 0, 0, 1], &[1], &[1], &[0, 0, 0, 31], &[0]],
        );
        assert_eq!(link.expose_bytes(), &expected);
    }

    #[test]
    fn link_mailboxes_have_their_own_index_spaces() {
        assert!(LinkMailbox::on_screen(49).is_some());
        assert!(LinkMailbox::on_screen(50).is_none());
        assert!(LinkMailbox::printed(31).is_some());
        assert!(LinkMailbox::printed(32).is_none());
        let key = |mailbox| {
            *link_mailbox_key(&seed(1), 0, Network::Mainnet, mailbox)
                .unwrap()
                .expose_bytes()
        };
        assert_ne!(
            key(LinkMailbox::on_screen(3).unwrap()),
            key(LinkMailbox::printed(3).unwrap())
        );
    }

    #[test]
    fn post_keys_differ_by_role() {
        let key = |role| {
            *post_key(&seed(1), 0, Network::Mainnet, &[1; 16], role)
                .unwrap()
                .expose_bytes()
        };
        assert_ne!(key(PostRole::Initiator), key(PostRole::Responder));
    }

    #[test]
    fn a_check_code_is_four_digits_of_the_tagged_hash() {
        let excess = service_key(9);
        let digest = Sha256::new()
            .chain_update(b"epic-check/1")
            .chain_update(excess.to_bytes())
            .finalize();
        let number = u32::from_be_bytes(*digest.first_chunk::<4>().unwrap());
        let code = check_code(&excess);
        assert_eq!(code.len(), 4);
        assert_eq!(code.parse::<u32>().unwrap(), number % 10_000);
    }
}
