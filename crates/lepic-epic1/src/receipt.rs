// SPDX-License-Identifier: Apache-2.0
//! The receipt of a payment to an epic1 address: a Schnorr signature by a key tweaked from the
//! address's delivery key, over the payment's facts (`docs/protocols/epic1-receipt.md`).
//!
//! - receipt key: `R = D + t·G`, `t = SHA-256("lepic-epic1-receipt-key/1" || D)` read big-endian,
//!   where `D` is the 33-byte compressed delivery key the address carries. The payee signs with
//!   `r = d + t`. A `t` of zero or not below the curve order makes no key; no such key is known.
//! - message: `"lepic-epic1-receipt/1" || net (1) || D (33) || amount (u64 BE) ||
//!   kernel excess (33) || slate id (16) || payer key (33)`, signed as its SHA-256.
//! - signature: the single-signer aggsig Schnorr signature of the node's secp256k1-zkp, with `R`
//!   in its challenge, `e = SHA-256(x(K) || R || SHA-256(message))` for the nonce point `K`, and
//!   `K` with a square Y. The nonce is `SHA-256("lepic-epic1-receipt-nonce/1" || r ||
//!   SHA-256(message))`, so the same facts give the same signature.

use lepic_crypto::aggsig;
use lepic_crypto::{Message, PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha256};

use crate::Network;

/// The tag the tweak hashes before the delivery key.
pub const KEY_TAG: &[u8] = b"lepic-epic1-receipt-key/1";
/// The tag the signed message starts with.
pub const MESSAGE_TAG: &[u8] = b"lepic-epic1-receipt/1";
/// The tag the nonce hashes before the receipt secret.
pub const NONCE_TAG: &[u8] = b"lepic-epic1-receipt-nonce/1";
/// Bytes of the signed message.
pub const MESSAGE_LEN: usize = 21 + 1 + 33 + 8 + 33 + 16 + 33;
/// Bytes of the receipt signature, in the compact form.
pub const SIGNATURE_LEN: usize = 64;

/// Why a receipt cannot be made or does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    /// The tweak is zero or not below the curve order, or the sum is the point at infinity.
    #[error("the delivery key makes no receipt key")]
    NoKey,
    /// The secret given to sign with is not the delivery key's.
    #[error("the secret is not the delivery key's")]
    WrongSecret,
    /// The signature does not parse or does not verify for these facts.
    #[error("the receipt signature does not verify")]
    BadSignature,
}

/// What a receipt signs: the payment as both sides know it once the payee has answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptFacts {
    pub network: Network,
    /// The delivery key of the address paid.
    pub delivery_key: PublicKey,
    /// The amount, in base units.
    pub amount: u64,
    /// The kernel excess, a 33-byte Pedersen commitment.
    pub kernel_excess: [u8; 33],
    pub slate_id: [u8; 16],
    /// The payer's one-time key for this payment.
    pub payer_key: PublicKey,
}

/// The network byte of the contact formats: 0 mainnet, 1 floonet.
#[must_use]
pub fn net_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Floonet => 1,
    }
}

/// The tweak `t` of `delivery_key`.
///
/// # Errors
///
/// [`ReceiptError::NoKey`] when the hash is zero or not below the curve order.
pub fn tweak(delivery_key: &PublicKey) -> Result<SecretKey, ReceiptError> {
    let hash: [u8; 32] = Sha256::new()
        .chain_update(KEY_TAG)
        .chain_update(delivery_key.to_bytes())
        .finalize()
        .into();
    SecretKey::from_array(hash).map_err(|_| ReceiptError::NoKey)
}

/// The receipt key `R = D + t·G` of `delivery_key`: what a receipt verifies against.
///
/// # Errors
///
/// [`ReceiptError::NoKey`].
pub fn receipt_key(delivery_key: &PublicKey) -> Result<PublicKey, ReceiptError> {
    let tweak =
        PublicKey::from_secret_key(&tweak(delivery_key)?).map_err(|_| ReceiptError::NoKey)?;
    PublicKey::sum(&[*delivery_key, tweak]).map_err(|_| ReceiptError::NoKey)
}

/// The receipt secret `r = d + t` of the delivery secret `delivery_secret`.
///
/// # Errors
///
/// [`ReceiptError::NoKey`].
pub fn receipt_secret(delivery_secret: &SecretKey) -> Result<SecretKey, ReceiptError> {
    let delivery_key =
        PublicKey::from_secret_key(delivery_secret).map_err(|_| ReceiptError::NoKey)?;
    let tweak = tweak(&delivery_key)?;
    SecretKey::sum(&[delivery_secret.clone(), tweak], &[]).map_err(|_| ReceiptError::NoKey)
}

/// The message bytes a receipt for `facts` signs.
#[must_use]
pub fn message(facts: &ReceiptFacts) -> [u8; MESSAGE_LEN] {
    let mut out = [0u8; MESSAGE_LEN];
    let bytes = [
        MESSAGE_TAG,
        &[net_byte(facts.network)],
        &facts.delivery_key.to_bytes(),
        &facts.amount.to_be_bytes(),
        &facts.kernel_excess,
        &facts.slate_id,
        &facts.payer_key.to_bytes(),
    ]
    .concat();
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = byte;
    }
    out
}

/// The SHA-256 of [`message`], the 32 bytes the signature is over.
#[must_use]
pub fn digest(facts: &ReceiptFacts) -> [u8; 32] {
    Sha256::digest(message(facts)).into()
}

/// The receipt nonce for the receipt secret `secret` and the digest `digest`.
fn nonce(secret: &SecretKey, digest: &[u8; 32]) -> Result<SecretKey, ReceiptError> {
    let hash: [u8; 32] = Sha256::new()
        .chain_update(NONCE_TAG)
        .chain_update(secret.expose_bytes())
        .chain_update(digest)
        .finalize()
        .into();
    SecretKey::from_array(hash).map_err(|_| ReceiptError::NoKey)
}

/// The receipt for `facts`, signed with the delivery secret of `facts.delivery_key`.
///
/// # Errors
///
/// [`ReceiptError::WrongSecret`] when `delivery_secret` is not the delivery key's, and
/// [`ReceiptError::NoKey`].
pub fn sign(
    facts: &ReceiptFacts,
    delivery_secret: &SecretKey,
) -> Result<[u8; SIGNATURE_LEN], ReceiptError> {
    let public = PublicKey::from_secret_key(delivery_secret).map_err(|_| ReceiptError::NoKey)?;
    if public != facts.delivery_key {
        return Err(ReceiptError::WrongSecret);
    }
    let secret = receipt_secret(delivery_secret)?;
    let key = PublicKey::from_secret_key(&secret).map_err(|_| ReceiptError::NoKey)?;
    let digest = digest(facts);
    let nonce = nonce(&secret, &digest)?;
    let signature = aggsig::sign_single(&Message::from(digest), &secret, &nonce, Some(&key))
        .map_err(|_| ReceiptError::NoKey)?;
    Ok(signature.to_compact())
}

/// Checks `signature` as the receipt for `facts`.
///
/// # Errors
///
/// [`ReceiptError::BadSignature`] when it does not verify, [`ReceiptError::NoKey`] when the
/// delivery key makes no receipt key.
pub fn verify(facts: &ReceiptFacts, signature: &[u8; SIGNATURE_LEN]) -> Result<(), ReceiptError> {
    let key = receipt_key(&facts.delivery_key)?;
    let signature = Signature::from_compact(signature).map_err(|_| ReceiptError::BadSignature)?;
    aggsig::verify_completed_sig(&signature, &key, Some(&key), &Message::from(digest(facts)))
        .map_err(|_| ReceiptError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn facts() -> (SecretKey, ReceiptFacts) {
        let delivery = secret(0x21);
        let facts = ReceiptFacts {
            network: Network::Floonet,
            delivery_key: PublicKey::from_secret_key(&delivery).unwrap(),
            amount: 150_000_000,
            kernel_excess: {
                let mut excess = [0x5a; 33];
                excess[0] = 0x09;
                excess
            },
            slate_id: [0x7c; 16],
            payer_key: PublicKey::from_secret_key(&secret(0x33)).unwrap(),
        };
        (delivery, facts)
    }

    #[test]
    fn receipt_secret_matches_receipt_key() {
        let (delivery, facts) = facts();
        let key = PublicKey::from_secret_key(&receipt_secret(&delivery).unwrap()).unwrap();
        assert_eq!(key, receipt_key(&facts.delivery_key).unwrap());
        assert_ne!(key, facts.delivery_key);
    }

    #[test]
    fn signs_and_verifies_the_same_every_time() {
        let (delivery, facts) = facts();
        let first = sign(&facts, &delivery).unwrap();
        assert_eq!(first, sign(&facts, &delivery).unwrap());
        verify(&facts, &first).unwrap();
    }

    #[test]
    fn every_fact_is_signed() {
        type Change = Box<dyn Fn(&mut ReceiptFacts)>;
        let (delivery, facts) = facts();
        let signature = sign(&facts, &delivery).unwrap();
        let other = PublicKey::from_secret_key(&secret(0x44)).unwrap();
        let changes: [Change; 6] = [
            Box::new(|f| f.network = Network::Mainnet),
            Box::new(|f| f.amount += 1),
            Box::new(|f| f.kernel_excess[5] ^= 1),
            Box::new(|f| f.slate_id[0] ^= 1),
            Box::new(move |f| f.payer_key = other),
            Box::new(move |f| f.delivery_key = other),
        ];
        for change in changes {
            let mut changed = facts.clone();
            change(&mut changed);
            assert_eq!(
                verify(&changed, &signature),
                Err(ReceiptError::BadSignature)
            );
        }
    }

    #[test]
    fn a_changed_signature_fails() {
        let (delivery, facts) = facts();
        let mut signature = sign(&facts, &delivery).unwrap();
        signature[40] ^= 1;
        assert_eq!(verify(&facts, &signature), Err(ReceiptError::BadSignature));
    }

    /// A signature by the untweaked delivery key does not pass as a receipt.
    #[test]
    fn the_delivery_key_alone_does_not_sign() {
        let (delivery, facts) = facts();
        let digest = Message::from(digest(&facts));
        let plain =
            aggsig::sign_single(&digest, &delivery, &secret(0x55), Some(&facts.delivery_key))
                .unwrap();
        assert_eq!(
            verify(&facts, &plain.to_compact()),
            Err(ReceiptError::BadSignature)
        );
    }

    #[test]
    fn refuses_another_secret() {
        let (_, facts) = facts();
        assert_eq!(sign(&facts, &secret(0x22)), Err(ReceiptError::WrongSecret));
    }
}
