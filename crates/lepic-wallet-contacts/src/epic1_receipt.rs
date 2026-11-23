// SPDX-License-Identifier: Apache-2.0
//! The receipt of a payment to an epic1 address (`docs/protocols/epic1-receipt.md`): what the
//! payer asks for in its S1 (tag 84, the payer key), what the payee signs into its S2 (tag 85),
//! and the receipt file the payer keeps and exports.
//!
//! The payee signs with the receipt secret of its delivery key; the payer checks the signature
//! against the address it paid, the amount, the kernel excess and the slate id of the S2, and
//! the payer key it derives again for the slate. A receipt that holds is stored under
//! [`receipt_key`] for good: it outlives the payment's record.

use lepic_crypto::{Commitment, PublicKey, SecretKey};
use lepic_epic1::Epic1Address;
use lepic_epic1::receipt::{self, ReceiptFacts, SIGNATURE_LEN};
use lepic_node::{NodeApi, NodeError};
use lepic_primitives::amount::Height;
use lepic_slate::model::{Slate, SlateId};
use serde::{Deserialize, Serialize};

use crate::hex;

/// The media type of a receipt file.
pub const RECEIPT_MEDIA_TYPE: &str = "application/vnd.lepic.receipt+json";
/// The `type` of a receipt file.
pub const RECEIPT_TYPE: &str = "lepic-epic1-receipt";
/// The `version` of a receipt file this release writes and reads.
pub const RECEIPT_VERSION: u32 = 1;
/// The longest receipt file read, in bytes: a receipt is well under 1 KiB.
pub const MAX_RECEIPT_LEN: usize = 4096;

/// The settings key of the receipts this wallet holds.
const RECEIPT_PREFIX: &str = "epic1.receipt.";

/// The settings key of the receipt of the payment `slate_id`.
pub(crate) fn receipt_key(slate_id: SlateId) -> String {
    format!("{RECEIPT_PREFIX}{slate_id}")
}

/// The receipt of a payment to an epic1 address, as a file: the facts the payee signed and its
/// signature. Anyone holding it checks it with [`Epic1Receipt::check`], with no wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epic1Receipt {
    /// Always [`RECEIPT_TYPE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// Always [`RECEIPT_VERSION`].
    pub version: u32,
    /// `mainnet` or `floonet`.
    pub network: String,
    /// The epic1 address paid.
    pub address: String,
    /// The amount paid, in base units.
    pub amount: u64,
    /// The kernel excess of the transaction, 33 bytes as hex.
    pub kernel_excess: String,
    /// The slate id, hyphenated.
    pub slate_id: String,
    /// The payer's one-time key for this payment, 33 bytes as hex.
    pub payer_key: String,
    /// The payee's signature, 64 bytes as hex.
    pub signature: String,
}

/// What a check of a receipt file says, with no node asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptVerdict {
    /// The address's payee signed these facts.
    Valid,
    /// The file reads, and the signature does not hold for its facts.
    BadSignature,
    /// The file is not a receipt this release reads: not JSON of the receipt's fields, another
    /// type or version, a field that does not decode, or a network the address is not on.
    Malformed,
    /// The receipt is for another network than the one asked for.
    WrongNetwork,
}

/// What the node says of a receipt's kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptOnChain {
    /// The node's chain holds the kernel, at this height.
    OnChain { height: Height },
    /// The node's chain holds no kernel with this excess.
    NotOnChain,
}

/// Why a payer refuses an S2's receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiptFault {
    /// The S2 carries none.
    Missing,
    /// The S2 carries one that does not hold for the payment.
    Invalid,
}

fn network_name(network: lepic_epic1::Network) -> &'static str {
    match network {
        lepic_epic1::Network::Mainnet => "mainnet",
        lepic_epic1::Network::Floonet => "floonet",
    }
}

/// The kernel excess of an answered slate: the sum of the two participants' public excesses,
/// as the kernel commits it. `None` for a slate with fewer than two participants.
pub(crate) fn answered_excess(slate: &Slate) -> Option<[u8; 33]> {
    let keys: Vec<PublicKey> = slate
        .participants()
        .map(|(_, participant)| participant.public_blind_excess)
        .collect();
    if keys.len() < 2 {
        return None;
    }
    let sum = PublicKey::sum(&keys).ok()?;
    Commitment::from_public_key(&sum)
        .ok()
        .map(|excess| *excess.as_bytes())
}

/// The facts of the answered `slate` of a payment to `address` with the payer key `payer_key`.
fn facts_of(address: &Epic1Address, slate: &Slate, payer_key: PublicKey) -> Option<ReceiptFacts> {
    Some(ReceiptFacts {
        network: address.network(),
        delivery_key: *address.delivery_key(),
        amount: slate.amount().value(),
        kernel_excess: answered_excess(slate)?,
        slate_id: *slate.id().as_bytes(),
        payer_key,
    })
}

/// The payee's receipt for the answered `slate` of a payment to `address`, whose delivery secret
/// is `delivery`, for the payer key `ask` the S1 carried. `None` when the ask is not a key or the
/// slate has no kernel excess yet: the payment goes on with no receipt.
pub(crate) fn sign_receipt(
    address: &Epic1Address,
    delivery: &SecretKey,
    slate: &Slate,
    ask: &[u8; 33],
) -> Option<[u8; SIGNATURE_LEN]> {
    let payer_key = PublicKey::from_bytes(ask).ok()?;
    let facts = facts_of(address, slate, payer_key)?;
    receipt::sign(&facts, delivery).ok()
}

/// Checks the receipt `signature` an S2 carried for the payment of `slate` to `address`, with the
/// payer key `payer_key` this wallet asked with. Returns the receipt file to keep.
pub(crate) fn check_answer(
    address: &Epic1Address,
    slate: &Slate,
    payer_key: PublicKey,
    signature: Option<&[u8; SIGNATURE_LEN]>,
) -> Result<Epic1Receipt, ReceiptFault> {
    let signature = signature.ok_or(ReceiptFault::Missing)?;
    let facts = facts_of(address, slate, payer_key).ok_or(ReceiptFault::Invalid)?;
    receipt::verify(&facts, signature).map_err(|_| ReceiptFault::Invalid)?;
    Ok(Epic1Receipt::new(address, &facts, signature))
}

impl Epic1Receipt {
    fn new(address: &Epic1Address, facts: &ReceiptFacts, signature: &[u8; SIGNATURE_LEN]) -> Self {
        Self {
            kind: RECEIPT_TYPE.to_owned(),
            version: RECEIPT_VERSION,
            network: network_name(address.network()).to_owned(),
            address: address.encode(),
            amount: facts.amount,
            kernel_excess: hex::encode(&facts.kernel_excess),
            slate_id: SlateId::from_bytes(facts.slate_id).to_string(),
            payer_key: hex::encode(&facts.payer_key.to_bytes()),
            signature: hex::encode(signature),
        }
    }

    /// Reads a receipt file. `None` when it is not one: too long, not JSON of the receipt's
    /// fields, or another type or version.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_RECEIPT_LEN {
            return None;
        }
        let receipt: Self = serde_json::from_str(text).ok()?;
        (receipt.kind == RECEIPT_TYPE && receipt.version == RECEIPT_VERSION).then_some(receipt)
    }

    /// The receipt as the text of its file.
    #[must_use]
    pub fn to_text(&self) -> String {
        // A struct of strings and numbers always serializes.
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// The facts the receipt signs and its signature, when every field decodes and the network
    /// is the address's.
    fn decoded(&self) -> Option<(ReceiptFacts, [u8; SIGNATURE_LEN])> {
        if self.kind != RECEIPT_TYPE || self.version != RECEIPT_VERSION {
            return None;
        }
        let address = Epic1Address::decode_any(&self.address).ok()?;
        if network_name(address.network()) != self.network {
            return None;
        }
        let slate_id = SlateId::parse(&self.slate_id).ok()?;
        let facts = ReceiptFacts {
            network: address.network(),
            delivery_key: *address.delivery_key(),
            amount: self.amount,
            kernel_excess: decode_array(&self.kernel_excess)?,
            slate_id: *slate_id.as_bytes(),
            payer_key: PublicKey::from_bytes(&decode_array::<33>(&self.payer_key)?).ok()?,
        };
        Some((facts, decode_array(&self.signature)?))
    }

    /// Checks the receipt for `network`, or for its own network when `None`.
    #[must_use]
    pub fn check(&self, network: Option<lepic_epic1::Network>) -> ReceiptVerdict {
        let Some((facts, signature)) = self.decoded() else {
            return ReceiptVerdict::Malformed;
        };
        if network.is_some_and(|network| network != facts.network) {
            return ReceiptVerdict::WrongNetwork;
        }
        match receipt::verify(&facts, &signature) {
            Ok(()) => ReceiptVerdict::Valid,
            Err(_) => ReceiptVerdict::BadSignature,
        }
    }

    /// The kernel excess as a commitment, when it decodes.
    #[must_use]
    pub fn excess(&self) -> Option<Commitment> {
        Commitment::from_bytes(&decode_array::<33>(&self.kernel_excess)?).ok()
    }

    /// Asks `node` whether its chain holds the receipt's kernel. `None` when the excess does not
    /// decode.
    ///
    /// # Errors
    ///
    /// The node's error when it cannot be asked.
    pub async fn on_chain<N: NodeApi>(
        &self,
        node: &N,
    ) -> Result<Option<ReceiptOnChain>, NodeError> {
        let Some(excess) = self.excess() else {
            return Ok(None);
        };
        Ok(Some(match node.get_kernel(&excess, None, None).await? {
            Some(kernel) => ReceiptOnChain::OnChain {
                height: kernel.height,
            },
            None => ReceiptOnChain::NotOnChain,
        }))
    }
}

fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    hex::decode_array(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    /// A receipt over made-up facts, signed by the delivery secret `0x21…`.
    fn receipt() -> Epic1Receipt {
        let delivery = secret(0x21);
        let seal = lepic_seal::EncSecretKey::from_bytes([0x11; 32]).public_key();
        let address = Epic1Address::new(
            lepic_epic1::Network::Floonet,
            seal,
            PublicKey::from_secret_key(&delivery).unwrap(),
        );
        let facts = ReceiptFacts {
            network: lepic_epic1::Network::Floonet,
            delivery_key: *address.delivery_key(),
            amount: 150_000_000,
            kernel_excess: *Commitment::commit(0, &secret(0x61)).unwrap().as_bytes(),
            slate_id: [0x5a; 16],
            payer_key: PublicKey::from_secret_key(&secret(0x72)).unwrap(),
        };
        let signature = receipt::sign(&facts, &delivery).unwrap();
        Epic1Receipt::new(&address, &facts, &signature)
    }

    #[test]
    fn a_receipt_file_reads_back_and_holds() {
        let receipt = receipt();
        let read = Epic1Receipt::parse(&receipt.to_text()).unwrap();
        assert_eq!(read, receipt);
        assert_eq!(read.check(None), ReceiptVerdict::Valid);
        assert_eq!(
            read.check(Some(lepic_epic1::Network::Floonet)),
            ReceiptVerdict::Valid
        );
        assert!(read.excess().is_some());
    }

    #[test]
    fn a_changed_fact_fails_the_signature() {
        let mut receipt = receipt();
        receipt.amount += 1;
        assert_eq!(receipt.check(None), ReceiptVerdict::BadSignature);
    }

    #[test]
    fn another_network_is_refused() {
        assert_eq!(
            receipt().check(Some(lepic_epic1::Network::Mainnet)),
            ReceiptVerdict::WrongNetwork
        );
    }

    #[test]
    fn what_does_not_decode_is_malformed() {
        let changes: [fn(&mut Epic1Receipt); 5] = [
            |r| r.network = "mainnet".to_owned(),
            |r| r.kernel_excess.truncate(10),
            |r| r.payer_key = "00".repeat(33),
            |r| r.signature.push_str("00"),
            |r| r.slate_id = "not an id".to_owned(),
        ];
        for change in changes {
            let mut receipt = receipt();
            change(&mut receipt);
            assert_eq!(receipt.check(None), ReceiptVerdict::Malformed);
        }
    }

    #[test]
    fn another_type_or_an_unknown_field_does_not_read() {
        let text = receipt().to_text();
        assert!(Epic1Receipt::parse(&text.replace(RECEIPT_TYPE, "other")).is_none());
        assert!(Epic1Receipt::parse(&text.replace("\"version\": 1", "\"version\": 2")).is_none());
        assert!(Epic1Receipt::parse(&text.replacen('{', "{\"extra\":1,", 1)).is_none());
        assert!(Epic1Receipt::parse("not json").is_none());
    }
}
