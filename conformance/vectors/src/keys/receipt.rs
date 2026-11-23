// SPDX-License-Identifier: Apache-2.0
//! The receipt of a payment to an epic1 address (`docs/protocols/epic1-receipt.md`), written here
//! from its description with the node's secp256k1-zkp and `ring`'s SHA-256, sharing nothing with
//! the product crate:
//!
//! - tweak `t = SHA-256("lepic-epic1-receipt-key/1" || D)`, receipt key `R = D + t·G`, receipt
//!   secret `r = d + t`;
//! - message `"lepic-epic1-receipt/1" || net || D (33) || amount (u64 BE) || kernel excess (33)
//!   || slate id (16) || payer key (33)`, signed as its SHA-256;
//! - nonce `k = SHA-256("lepic-epic1-receipt-nonce/1" || r || SHA-256(message))`;
//! - signature: aggsig `sign_single` by `r` with nonce `k` and `R` as the challenge key, in the
//!   compact form.
//!
//! The refused cases are signatures a verifier must turn down: a flipped bit, a changed fact, a
//! signature by the untweaked delivery key, and one whose challenge leaves `R` out.

use epic_util::secp::aggsig;
use epic_util::secp::key::{PublicKey, SecretKey};
use epic_util::secp::{ContextFlag, Message, Secp256k1, Signature};
use serde::Serialize;

use super::epic1::{SEAL_KEYS, address_text};
use super::namespace::sha256;
use super::{AREA, Inconsistent, KeysPins, Network};
use crate::{Error, Rendered, hex, render};

const KEY_TAG: &[u8] = b"lepic-epic1-receipt-key/1";
const MESSAGE_TAG: &[u8] = b"lepic-epic1-receipt/1";
const NONCE_TAG: &[u8] = b"lepic-epic1-receipt-nonce/1";

/// The delivery secrets of the addresses paid.
const DELIVERY_SECRETS: [[u8; 32]; 2] = [[0x21; 32], [0x42; 32]];

/// One payment's facts other than the address: amount, the blinding factor whose commitment to
/// zero stands for the kernel excess, the slate id and the payer's secret.
struct Payment {
    amount: u64,
    excess_blind: [u8; 32],
    slate_id: [u8; 16],
    payer_secret: [u8; 32],
}

const PAYMENTS: [Payment; 2] = [
    Payment {
        amount: 1,
        excess_blind: [0x61; 32],
        slate_id: [0x00; 16],
        payer_secret: [0x71; 32],
    },
    Payment {
        amount: 150_000_000,
        excess_blind: [0x62; 32],
        slate_id: [0x5a; 16],
        payer_secret: [0x72; 32],
    },
];

#[derive(Serialize)]
struct Inputs {
    key_tag: &'static str,
    message_tag: &'static str,
    nonce_tag: &'static str,
    note: &'static str,
}

/// One receipt, from the facts to the signature.
#[derive(Serialize)]
struct Case {
    network: &'static str,
    net: u8,
    /// The epic1 address paid, from the first seal key and the delivery key.
    address: String,
    delivery_secret: String,
    delivery_key: String,
    amount: u64,
    kernel_excess: String,
    slate_id: String,
    payer_key: String,
    tweak: String,
    receipt_secret: String,
    receipt_key: String,
    message: String,
    digest: String,
    nonce: String,
    signature: String,
}

/// A signature over the facts of the first case that must not verify.
#[derive(Serialize)]
struct RefusedCase {
    name: &'static str,
    network: &'static str,
    delivery_key: String,
    amount: u64,
    kernel_excess: String,
    slate_id: String,
    payer_key: String,
    signature: String,
}

#[derive(Serialize)]
struct Expected {
    cases: Vec<Case>,
    refused: Vec<RefusedCase>,
}

fn net_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Floonet => 1,
    }
}

fn secret(secp: &Secp256k1, bytes: &[u8]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(secp, bytes).map_err(Error::reference("receipt secret"))
}

fn public(secp: &Secp256k1, key: &SecretKey) -> Result<PublicKey, Error> {
    PublicKey::from_secret_key(secp, key).map_err(Error::reference("receipt public key"))
}

fn compressed(secp: &Secp256k1, key: &PublicKey) -> Vec<u8> {
    key.serialize_vec(secp, true).to_vec()
}

/// The facts a receipt signs, as bytes.
#[derive(Clone)]
struct Facts {
    network: Network,
    delivery_key: Vec<u8>,
    amount: u64,
    kernel_excess: Vec<u8>,
    slate_id: [u8; 16],
    payer_key: Vec<u8>,
}

impl Facts {
    fn message(&self) -> Vec<u8> {
        [
            MESSAGE_TAG,
            &[net_byte(self.network)],
            &self.delivery_key,
            &self.amount.to_be_bytes(),
            &self.kernel_excess,
            &self.slate_id,
            &self.payer_key,
        ]
        .concat()
    }

    fn digest(&self) -> [u8; 32] {
        sha256(&[&self.message()])
    }

    fn refused(&self, name: &'static str, signature: &[u8]) -> RefusedCase {
        RefusedCase {
            name,
            network: self.network.name(),
            delivery_key: hex(&self.delivery_key),
            amount: self.amount,
            kernel_excess: hex(&self.kernel_excess),
            slate_id: hex(self.slate_id),
            payer_key: hex(&self.payer_key),
            signature: hex(signature),
        }
    }
}

/// The receipt key and secret of the delivery secret `delivery`, and the tweak.
fn receipt_keys(
    secp: &Secp256k1,
    delivery: &SecretKey,
) -> Result<(SecretKey, SecretKey, PublicKey), Error> {
    let delivery_key = public(secp, delivery)?;
    let tweak = secret(secp, &sha256(&[KEY_TAG, &compressed(secp, &delivery_key)]))?;
    let mut receipt_secret = delivery.clone();
    receipt_secret
        .add_assign(secp, &tweak)
        .map_err(Error::reference("receipt secret"))?;
    let mut receipt_key = delivery_key;
    receipt_key
        .add_exp_assign(secp, &tweak)
        .map_err(Error::reference("receipt key"))?;
    if public(secp, &receipt_secret)? != receipt_key {
        return Err(Error::reference("receipt key")(Inconsistent(
            "r·G is not D + t·G",
        )));
    }
    Ok((tweak, receipt_secret, receipt_key))
}

fn sign(
    secp: &Secp256k1,
    digest: &[u8; 32],
    key: &SecretKey,
    nonce: &SecretKey,
    challenge_key: Option<&PublicKey>,
) -> Result<Signature, Error> {
    let msg = Message::from_slice(digest).map_err(Error::reference("receipt message"))?;
    aggsig::sign_single(
        secp,
        &msg,
        key,
        Some(nonce),
        None,
        None,
        challenge_key,
        None,
    )
    .map_err(Error::reference("receipt signature"))
}

fn verifies(secp: &Secp256k1, signature: &[u8], facts: &Facts, key: &PublicKey) -> bool {
    let (Ok(signature), Ok(msg)) = (
        Signature::from_compact(secp, signature),
        Message::from_slice(&facts.digest()),
    ) else {
        return false;
    };
    aggsig::verify_single(secp, &signature, &msg, None, key, Some(key), None, false)
}

fn cases(secp: &Secp256k1) -> Result<(Vec<Case>, Vec<RefusedCase>), Error> {
    let mut cases = Vec::new();
    let mut refused = Vec::new();
    for delivery_bytes in &DELIVERY_SECRETS {
        let delivery = secret(secp, delivery_bytes)?;
        let delivery_key = compressed(secp, &public(secp, &delivery)?);
        let (tweak, receipt_secret, receipt_key) = receipt_keys(secp, &delivery)?;
        for network in Network::ALL {
            for payment in &PAYMENTS {
                let excess = secp
                    .commit(0, secret(secp, &payment.excess_blind)?)
                    .map_err(Error::reference("kernel excess"))?;
                let facts = Facts {
                    network,
                    delivery_key: delivery_key.clone(),
                    amount: payment.amount,
                    kernel_excess: excess.0.to_vec(),
                    slate_id: payment.slate_id,
                    payer_key: compressed(
                        secp,
                        &public(secp, &secret(secp, &payment.payer_secret)?)?,
                    ),
                };
                let digest = facts.digest();
                let nonce_bytes = sha256(&[NONCE_TAG, &receipt_secret.0, &digest]);
                let nonce = secret(secp, &nonce_bytes)?;
                let signature = sign(secp, &digest, &receipt_secret, &nonce, Some(&receipt_key))?
                    .serialize_compact(secp);
                if !verifies(secp, &signature, &facts, &receipt_key) {
                    return Err(Error::reference("receipt")(Inconsistent(
                        "the receipt does not verify",
                    )));
                }
                if refused.is_empty() {
                    refused =
                        refused_cases(secp, &facts, &signature, &delivery, &nonce, &receipt_key)?;
                }
                cases.push(Case {
                    network: network.name(),
                    net: net_byte(network),
                    address: address_text(network, 1, SEAL_KEYS[0].1, &hex(&delivery_key)),
                    delivery_secret: hex(delivery_bytes),
                    delivery_key: hex(&delivery_key),
                    amount: payment.amount,
                    kernel_excess: hex(&facts.kernel_excess),
                    slate_id: hex(payment.slate_id),
                    payer_key: hex(&facts.payer_key),
                    tweak: hex(tweak.0),
                    receipt_secret: hex(receipt_secret.0),
                    receipt_key: hex(compressed(secp, &receipt_key)),
                    message: hex(facts.message()),
                    digest: hex(digest),
                    nonce: hex(nonce_bytes),
                    signature: hex(signature),
                });
            }
        }
    }
    Ok((cases, refused))
}

/// Signatures over `facts` that must not verify as its receipt.
fn refused_cases(
    secp: &Secp256k1,
    facts: &Facts,
    signature: &[u8; 64],
    delivery: &SecretKey,
    nonce: &SecretKey,
    receipt_key: &PublicKey,
) -> Result<Vec<RefusedCase>, Error> {
    let receipt_secret = receipt_keys(secp, delivery)?.1;
    let digest = facts.digest();
    let mut flipped = *signature;
    flipped[40] ^= 1;
    let delivery_key = public(secp, delivery)?;
    let untweaked =
        sign(secp, &digest, delivery, nonce, Some(&delivery_key))?.serialize_compact(secp);
    let no_key = sign(secp, &digest, &receipt_secret, nonce, None)?.serialize_compact(secp);
    let changed = Facts {
        amount: facts.amount + 1,
        ..facts.clone()
    };
    let cases = vec![
        facts.refused("flipped_bit", &flipped),
        changed.refused("amount_changed", signature),
        facts.refused("untweaked_delivery_key", &untweaked),
        facts.refused("key_not_in_challenge", &no_key),
    ];
    for case in &cases {
        let check = Facts {
            amount: case.amount,
            ..facts.clone()
        };
        let bytes = super::namespace::unhex(&case.signature);
        if verifies(secp, &bytes, &check, receipt_key) {
            return Err(Error::reference("refused receipt")(Inconsistent(
                "a refused receipt verifies",
            )));
        }
    }
    Ok(cases)
}

pub(super) fn generate(pins: &KeysPins<'_>) -> Result<Vec<Rendered>, Error> {
    // `Commit` signs, verifies and commits; `Full` has no generators for the kernel excess.
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let (cases, refused) = cases(&secp)?;
    Ok(vec![render(
        AREA,
        "epic1_receipts",
        &pins.wallet,
        Inputs {
            key_tag: "lepic-epic1-receipt-key/1",
            message_tag: "lepic-epic1-receipt/1",
            nonce_tag: "lepic-epic1-receipt-nonce/1",
            note: "addresses from the first seal key of epic1_addresses; the kernel excess is the commitment to zero of a fixed blinding factor; the refused cases change the first case",
        },
        Expected { cases, refused },
    )?])
}
