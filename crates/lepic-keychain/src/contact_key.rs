//! The contact-identity keys of RFC 0002 sections 2.1 to 2.3, and the pairing mailbox keys of
//! section 8.1.
//!
//! Everything here is derived from one 32-byte [`ContactRoot`] that depends only on the seed, the
//! account and the network, plus a contact's slot (and, for its mailbox, a random salt) or the
//! slate id. Slots are numbered so a restored wallet can find its keys for a contact again
//! ([`ContactRoot::find_slot`]). The pairing mailbox keys are not seed-derived: they come from a
//! code the pairing parties share.

use std::fmt;

use blake2::Blake2b256;
use blake2::digest::{FixedOutput, Update};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use lepic_crypto::{CryptoError, PublicKey, SecretKey};
use lepic_primitives::params::Network;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::{Zeroize, Zeroizing};

use crate::identifier::Identifier;
use crate::keychain::{Keychain, KeychainError, SwitchCommitment};

const ROOT_SALT: &[u8] = b"epic-contact/1";
const MAILBOX_SALT: &[u8] = b"epic-pair/1 mailbox";
const KEY_CHECK_DOMAIN: &[u8] = b"epic-pair/1 keycheck";

/// The depth of an account's own path `m/<a>/0`.
const ACCOUNT_DEPTH: u8 = 2;

/// The second path component of the contact-identity branch.
const CONTACT_BRANCH: u32 = 2;

/// A slot is any u32. A wallet keeps its slots below `SLOT_COUNT`, the range the slot searches
/// cover, and refuses new pairings once it used them all; a service never searches and may use
/// the whole range.
pub const SLOT_COUNT: u32 = 65_536;

/// Length of the random salt of a contact's mailbox key.
pub const BOX_SALT_LEN: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContactKeyError {
    #[error("key derivation failed")]
    Derivation,
    #[error("no valid secp256k1 key within 256 counter values")]
    NoValidKey,
    #[error("key operation failed")]
    Crypto(#[from] CryptoError),
    #[error("account key derivation failed")]
    Keychain(#[from] KeychainError),
}

/// The path `m/<a>/2/0` of the contact-identity root key under the account at `parent`, which
/// must be the account's own path `m/<a>/0`.
pub fn contact_identity_key_id(parent: &Identifier) -> Result<Identifier, KeychainError> {
    let depth = parent.depth();
    let mut components = parent.components();
    if depth != ACCOUNT_DEPTH || components.get(1) != Some(&0) {
        return Err(KeychainError::NotAnAccountPath { depth });
    }
    if let Some(branch) = components.get_mut(1) {
        *branch = CONTACT_BRANCH;
    }
    if let Some(slot) = components.get_mut(usize::from(depth)) {
        *slot = 0;
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(KeychainError::NotAnAccountPath { depth })?;
    Identifier::new(child_depth, components).map_err(|_| KeychainError::NotAnAccountPath { depth })
}

const fn network_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Floonet => 1,
    }
}

impl Keychain {
    /// The contact-identity root of the account at `parent` on `network` (RFC 0002 2.1).
    pub fn contact_root(
        &self,
        parent: &Identifier,
        network: Network,
    ) -> Result<ContactRoot, ContactKeyError> {
        let id = contact_identity_key_id(parent)?;
        let raw = self.derive_key(0, &id, SwitchCommitment::None)?;
        ContactRoot::from_raw(raw.expose_bytes(), network)
    }
}

/// The 32-byte contact-identity root. Wiped on drop and never printed.
pub struct ContactRoot(Zeroizing<[u8; 32]>);

impl ContactRoot {
    /// The root for a raw account key `raw` (the plain BIP32 output at `m/<a>/2/0`) on `network`:
    /// `HKDF(salt = "epic-contact/1", ikm = BLAKE2b-256(raw), info = "root" || net)`. This is the
    /// step [`Keychain::contact_root`] performs after deriving `raw`, exposed so other
    /// implementations can be checked against it from a raw key alone.
    pub fn from_raw(raw: &[u8; 32], network: Network) -> Result<Self, ContactKeyError> {
        let mut state = Blake2b256::default();
        state.update(raw);
        let mut hashed = state.finalize_fixed();
        let hkdf = Hkdf::<Sha256>::new(Some(ROOT_SALT), &hashed);
        hashed.as_mut_slice().zeroize();
        let mut root = Zeroizing::new([0u8; 32]);
        hkdf.expand(
            &[b"root".as_slice(), &[network_byte(network)]].concat(),
            root.as_mut(),
        )
        .map_err(|_| ContactKeyError::Derivation)?;
        Ok(Self(root))
    }

    /// The raw root. Callers must not log it or copy it into memory that is not wiped.
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn expand(&self, parts: &[&[u8]], out: &mut [u8; 32]) -> Result<(), ContactKeyError> {
        let hkdf =
            Hkdf::<Sha256>::from_prk(self.0.as_slice()).map_err(|_| ContactKeyError::Derivation)?;
        hkdf.expand(&parts.concat(), out)
            .map_err(|_| ContactKeyError::Derivation)
    }

    /// The keys for the contact in `slot`, with its mailbox salt `box_salt` (RFC 0002 2.2).
    pub fn contact_keys(
        &self,
        slot: u32,
        box_salt: [u8; BOX_SALT_LEN],
    ) -> Result<ContactKeys, ContactKeyError> {
        let slot_bytes = slot.to_be_bytes();
        let mut enc_sk = Zeroizing::new([0u8; 32]);
        self.expand(&[b"enc", &slot_bytes], &mut enc_sk)?;
        let mut sig_seed = Zeroizing::new([0u8; 32]);
        self.expand(&[b"sig", &slot_bytes], &mut sig_seed)?;
        let sig_sk = SigningKey::from_bytes(&sig_seed);
        let hint_key = self.hint_key(slot)?;
        let box_sk = first_valid_key(
            |ctr, out| self.expand(&[b"box", &slot_bytes, &box_salt, &[ctr]], out),
            |bytes| SecretKey::from_bytes(bytes).ok(),
        )?;
        let box_pk = PublicKey::from_secret_key(&box_sk)?;
        Ok(ContactKeys {
            enc_sk,
            sig_sk,
            hint_key,
            box_sk,
            box_pk,
        })
    }

    /// The hint key of `slot` alone: one HMAC, so a restore can scan every slot (RFC 0002 2.5).
    pub fn hint_key(&self, slot: u32) -> Result<Zeroizing<[u8; 32]>, ContactKeyError> {
        let mut hint_key = Zeroizing::new([0u8; 32]);
        self.expand(&[b"hint", &slot.to_be_bytes()], &mut hint_key)?;
        Ok(hint_key)
    }

    /// The slot whose keys a contact card holds for us, found from the card's hint key and
    /// confirmed by its enc and sig keys (RFC 0002 2.5). `None` means the card was made by
    /// another seed, account or network.
    pub fn find_slot(
        &self,
        card_hint_key: &[u8; 32],
        card_enc_pk: &[u8; 32],
        card_sig_pk: &[u8; 32],
    ) -> Result<Option<u32>, ContactKeyError> {
        let hkdf =
            Hkdf::<Sha256>::from_prk(self.0.as_slice()).map_err(|_| ContactKeyError::Derivation)?;
        let mut hint_key = Zeroizing::new([0u8; 32]);
        for slot in 0..SLOT_COUNT {
            hkdf.expand(
                &[b"hint".as_slice(), &slot.to_be_bytes()].concat(),
                hint_key.as_mut(),
            )
            .map_err(|_| ContactKeyError::Derivation)?;
            if !equal_in_constant_time(&hint_key, card_hint_key) {
                continue;
            }
            let slot_bytes = slot.to_be_bytes();
            let mut enc_sk = Zeroizing::new([0u8; 32]);
            self.expand(&[b"enc", &slot_bytes], &mut enc_sk)?;
            let mut sig_seed = Zeroizing::new([0u8; 32]);
            self.expand(&[b"sig", &slot_bytes], &mut sig_seed)?;
            if x25519(*enc_sk, X25519_BASEPOINT_BYTES) == *card_enc_pk
                && SigningKey::from_bytes(&sig_seed).verifying_key().to_bytes() == *card_sig_pk
            {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// The slot below [`SLOT_COUNT`] whose hint key gives the key check `tag` for the new
    /// pairing's sig keys `n_y` (ours) and `n_x` (RFC 0002 7.8 step 2). `None` means no slot of
    /// this seed, account and network made the card the check names.
    pub fn find_slot_by_tag(
        &self,
        tag: &[u8; 32],
        n_y: &[u8; 32],
        n_x: &[u8; 32],
    ) -> Result<Option<u32>, ContactKeyError> {
        let hkdf =
            Hkdf::<Sha256>::from_prk(self.0.as_slice()).map_err(|_| ContactKeyError::Derivation)?;
        let mut hint_key = Zeroizing::new([0u8; 32]);
        for slot in 0..SLOT_COUNT {
            hkdf.expand(
                &[b"hint".as_slice(), &slot.to_be_bytes()].concat(),
                hint_key.as_mut(),
            )
            .map_err(|_| ContactKeyError::Derivation)?;
            if equal_in_constant_time(&key_check_tag(&hint_key, n_y, n_x), tag) {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// The X25519 secret of the one-time reply key for the slate `slate_id` (RFC 0002 2.3).
    pub fn reply_key(&self, slate_id: [u8; 16]) -> Result<ReplyKey, ContactKeyError> {
        let mut key = Zeroizing::new([0u8; 32]);
        self.expand(&[b"reply", &slate_id], &mut key)?;
        Ok(ReplyKey(key))
    }
}

impl fmt::Debug for ContactRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContactRoot([redacted])")
    }
}

/// The X25519 secret of a one-time reply key. Wiped on drop and never printed.
pub struct ReplyKey(Zeroizing<[u8; 32]>);

impl ReplyKey {
    /// The secret bytes, to be used as an X25519 private key. Callers must not log them or copy
    /// them into memory that is not wiped.
    pub fn expose_x25519_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReplyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplyKey([redacted])")
    }
}

/// Compares derived key bytes without stopping at the first difference.
fn equal_in_constant_time(ours: &[u8; 32], theirs: &[u8; 32]) -> bool {
    ours.iter()
        .zip(theirs)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// `H("epic-pair/1 keycheck" || hint_key || nY || nX)` (RFC 0002 7.8): names the old slot whose
/// card had `hint_key` without revealing it, bound to the new pairing's sig keys `n_y` (of the
/// side that may hold the slot) and `n_x`.
pub fn key_check_tag(hint_key: &[u8; 32], n_y: &[u8; 32], n_x: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    Sha256::new()
        .chain_update(KEY_CHECK_DOMAIN)
        .chain_update(hint_key)
        .chain_update(n_y)
        .chain_update(n_x)
        .finalize()
        .into()
}

/// The keys of one pairing record. Wiped on drop and never printed.
pub struct ContactKeys {
    enc_sk: Zeroizing<[u8; 32]>,
    sig_sk: SigningKey,
    hint_key: Zeroizing<[u8; 32]>,
    box_sk: SecretKey,
    box_pk: PublicKey,
}

impl ContactKeys {
    /// The X25519 secret bytes. Callers must not log them or copy them into memory that is not
    /// wiped.
    pub fn expose_enc_secret(&self) -> &[u8; 32] {
        &self.enc_sk
    }

    /// The X25519 public key the contact seals to.
    pub fn enc_public_key(&self) -> [u8; 32] {
        x25519(*self.enc_sk, X25519_BASEPOINT_BYTES)
    }

    /// The Ed25519 signing key.
    pub fn expose_signing_key(&self) -> &SigningKey {
        &self.sig_sk
    }

    pub fn sig_public_key(&self) -> [u8; 32] {
        self.sig_sk.verifying_key().to_bytes()
    }

    /// The key that tags envelopes from this contact.
    pub fn expose_hint_key(&self) -> &[u8; 32] {
        &self.hint_key
    }

    pub fn expose_box_secret(&self) -> &SecretKey {
        &self.box_sk
    }

    pub fn box_public_key(&self) -> &PublicKey {
        &self.box_pk
    }
}

impl fmt::Debug for ContactKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContactKeys([redacted])")
    }
}

/// The mailbox key pair of a pairing (RFC 0002 8.1): the key messages are read at and the key
/// they are posted from.
pub fn pairing_mailbox_keys(
    seed: [u8; 16],
    network: Network,
) -> Result<(SecretKey, SecretKey), ContactKeyError> {
    let net = network_byte(network);
    let hkdf = Hkdf::<Sha256>::new(Some(MAILBOX_SALT), &seed);
    let derive = |label: &[u8]| {
        first_valid_key(
            |ctr, out| {
                hkdf.expand(&[label, &[net, ctr]].concat(), out)
                    .map_err(|_| ContactKeyError::Derivation)
            },
            |bytes| SecretKey::from_bytes(bytes).ok(),
        )
    };
    Ok((derive(b"box")?, derive(b"from")?))
}

/// The first output for `ctr` from 0 up that `accept` turns into a key.
fn first_valid_key<K>(
    mut derive: impl FnMut(u8, &mut [u8; 32]) -> Result<(), ContactKeyError>,
    accept: impl Fn(&[u8; 32]) -> Option<K>,
) -> Result<K, ContactKeyError> {
    for ctr in 0..=u8::MAX {
        let mut bytes = Zeroizing::new([0u8; 32]);
        derive(ctr, &mut bytes)?;
        if let Some(key) = accept(&bytes) {
            return Ok(key);
        }
    }
    Err(ContactKeyError::NoValidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_path_of_default_account() {
        let parent = Identifier::new(2, [0, 0, 0, 0]).unwrap();
        let id = contact_identity_key_id(&parent).unwrap();
        assert_eq!(id, Identifier::new(3, [0, 2, 0, 0]).unwrap());
        assert_eq!(id.to_bip32_path(), "m/0/2/0");
    }

    #[test]
    fn refuses_a_parent_that_is_not_an_account_path() {
        for (depth, components) in [
            (0, [0, 0, 0, 0]),
            (1, [0, 0, 0, 0]),
            (2, [0, 1, 0, 0]),
            (2, [0, 2, 0, 0]),
            (3, [0, 0, 0, 0]),
            (4, [0, 0, 0, 0]),
        ] {
            let parent = Identifier::new(depth, components).unwrap();
            assert_eq!(
                contact_identity_key_id(&parent),
                Err(KeychainError::NotAnAccountPath { depth }),
                "{components:?} at depth {depth}"
            );
        }
    }

    #[test]
    fn contact_path_of_another_account() {
        let parent = Identifier::new(2, [7, 0, 0, 0]).unwrap();
        assert_eq!(
            contact_identity_key_id(&parent).unwrap().to_bip32_path(),
            "m/7/2/0"
        );
    }

    #[test]
    fn counter_loop_takes_first_accepted_output() {
        let mut seen = Vec::new();
        let key = first_valid_key(
            |ctr, out| {
                seen.push(ctr);
                *out = [ctr; 32];
                Ok(())
            },
            |bytes| (bytes[0] == 3).then_some(bytes[0]),
        );
        assert_eq!(key, Ok(3));
        assert_eq!(seen, [0, 1, 2, 3]);
    }

    /// The pairing kit's `synthetic_order` vector: with the curve order replaced by the `ctr = 00`
    /// output, that output is out of range and the loop must take `ctr = 01`.
    #[test]
    fn counter_loop_matches_the_kits_injected_order_vector() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/pairing/mailbox_keys.json"
        ))
        .unwrap();
        let vectors = document["vectors"].as_array().unwrap();
        let synthetic: Vec<_> = vectors
            .iter()
            .filter(|vector| vector["kind"] == "synthetic_order")
            .collect();
        assert!(!synthetic.is_empty());
        let unhex = |value: &serde_json::Value| -> Vec<u8> {
            let text = value.as_str().unwrap();
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        };
        for vector in synthetic {
            let seed = unhex(&vector["seed"]);
            let order: [u8; 32] = unhex(&vector["order"]).try_into().unwrap();
            let net = u8::try_from(vector["net"].as_u64().unwrap()).unwrap();
            let hkdf = Hkdf::<Sha256>::new(Some(MAILBOX_SALT), &seed);
            let mut last_ctr = None;
            let key = first_valid_key(
                |ctr, out| {
                    last_ctr = Some(ctr);
                    hkdf.expand(&[b"box".as_slice(), &[net, ctr]].concat(), out)
                        .map_err(|_| ContactKeyError::Derivation)
                },
                |bytes| (*bytes != [0; 32] && *bytes < order).then_some(*bytes),
            )
            .unwrap();
            assert_eq!(key.to_vec(), unhex(&vector["pbox_sk"]));
            assert_eq!(last_ctr.map(u64::from), vector["pbox_ctr"].as_u64());
        }
    }

    #[test]
    fn counter_loop_gives_up_after_256_values() {
        let key = first_valid_key(|_, _| Ok(()), |_| None::<u8>);
        assert_eq!(key, Err(ContactKeyError::NoValidKey));
    }

    #[test]
    fn counter_loop_passes_up_derivation_errors() {
        let key = first_valid_key(|_, _| Err(ContactKeyError::Derivation), |_| Some(0u8));
        assert_eq!(key, Err(ContactKeyError::Derivation));
    }
}
