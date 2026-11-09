// SPDX-License-Identifier: Apache-2.0
//! The `lepic.v1` slate envelope (RFC 0003 5.4 to 5.9): type 0A, sealed to a key of a
//! [`KeyClass`], always padded, with an optional reply mailbox (tag 09). It is the RFC 0002
//! envelope with its own reader: the RFC 0002 reader refuses type 0A and tag 09.

use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::CryptoRng;

use crate::card::ContactCard;
use crate::domain::DomainClaim;
use crate::envelope::{Inner, KeyClass, NATIVE_SLATE, Purpose, seal_inner};
use crate::error::{EncodeError, Malformed};
use crate::hint::{Hint, HintRule};
use crate::keys::EncPublicKey;
use crate::network::Network;
use crate::text::Reference;

const TAG_REPLY_MAILBOX: u8 = 0x09;
/// A compressed secp256k1 key.
const REPLY_MAILBOX_KEY_LEN: usize = 33;
const MAX_RELAY_LEN: usize = 128;

/// The Epicbox mailbox an answer is posted to (tag 09): a compressed secp256k1 key, whose point
/// is checked where it is used, and its relay `domain[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyMailbox {
    key: [u8; REPLY_MAILBOX_KEY_LEN],
    relay: String,
}

impl ReplyMailbox {
    /// The mailbox of `key` on `relay`: the key's prefix is 02 or 03, the relay 1 to 128 bytes
    /// of dot-separated labels of letters, digits and inner hyphens, then an optional port of 1
    /// to 5 digits with a value of 1 to 65,535.
    pub fn new(key: [u8; REPLY_MAILBOX_KEY_LEN], relay: &str) -> Result<Self, Malformed> {
        let invalid = Malformed::FieldValue {
            tag: TAG_REPLY_MAILBOX,
        };
        if !matches!(key.first(), Some(0x02 | 0x03))
            || !(1..=MAX_RELAY_LEN).contains(&relay.len())
            || !valid_relay(relay)
        {
            return Err(invalid);
        }
        Ok(Self {
            key,
            relay: relay.to_owned(),
        })
    }

    /// Reads the value of tag 09.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Malformed> {
        let invalid = Malformed::FieldValue {
            tag: TAG_REPLY_MAILBOX,
        };
        let (key, relay) = bytes
            .split_first_chunk::<REPLY_MAILBOX_KEY_LEN>()
            .ok_or(invalid)?;
        let relay = std::str::from_utf8(relay).map_err(|_| invalid)?;
        Self::new(*key, relay)
    }

    pub fn key(&self) -> &[u8; REPLY_MAILBOX_KEY_LEN] {
        &self.key
    }

    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// The value of tag 09: the key, then the relay.
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.key[..], self.relay.as_bytes()].concat()
    }
}

fn valid_relay(relay: &str) -> bool {
    let (host, port) = match relay.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (relay, None),
    };
    if let Some(port) = port {
        let digits = (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit());
        if !digits
            || !port
                .parse::<u32>()
                .is_ok_and(|port| (1..=65_535).contains(&port))
        {
            return false;
        }
    }
    host.split('.').all(valid_label)
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(first), Some(last)) => {
            first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        }
        _ => false,
    }
}

/// The inner content of a `lepic.v1` slate envelope, without the type, the padding and the
/// signature fields. `Debug` shows the body's length, never its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct TxContent {
    /// The raw `lepic.v1` slate bytes.
    pub body: Vec<u8>,
    /// Where the answer should be sealed, for an anonymous envelope.
    pub reply_key: Option<EncPublicKey>,
    /// Where the answer should be posted; only beside `reply_key`, in an anonymous envelope.
    pub reply_mailbox: Option<ReplyMailbox>,
    pub purpose: Option<Purpose>,
    pub reference: Option<Reference>,
    /// Unix seconds after which the sender stops honouring the message; advisory.
    pub expires: Option<u64>,
    /// The sender's current card for this contact.
    pub card: Option<ContactCard>,
    /// Unix seconds when the sender sealed it.
    pub sent_at: Option<u64>,
    pub address_proof: Option<[u8; 32]>,
    pub features: Option<u32>,
    pub domain: Option<DomainClaim>,
}

impl fmt::Debug for TxContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxContent")
            .field("body_len", &self.body.len())
            .field("reply_key", &self.reply_key)
            .field("reply_mailbox", &self.reply_mailbox)
            .field("purpose", &self.purpose)
            .field("reference", &self.reference.is_some())
            .field("expires", &self.expires)
            .field("card", &self.card)
            .field("sent_at", &self.sent_at)
            .field("address_proof", &self.address_proof.is_some())
            .field("features", &self.features)
            .field("domain", &self.domain)
            .finish()
    }
}

impl TxContent {
    pub fn new(body: Vec<u8>) -> Self {
        Self {
            body,
            reply_key: None,
            reply_mailbox: None,
            purpose: None,
            reference: None,
            expires: None,
            card: None,
            sent_at: None,
            address_proof: None,
            features: None,
            domain: None,
        }
    }
}

/// An opened `lepic.v1` slate envelope. `sender` is set exactly when the envelope was signed
/// and the signature verified with that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOpened {
    pub content: TxContent,
    pub sender: Option<VerifyingKey>,
    /// The length of the padding field's value, when the envelope had one.
    pub padding: Option<usize>,
    /// The length of the inner content, padding included.
    pub inner_len: usize,
}

/// The key a `lepic.v1` slate is sealed to, which sets the `info` and the hint.
#[derive(Debug, Clone, Copy)]
pub enum TxKey<'a> {
    /// A contact or one-time reply key, hinted as RFC 0002 hints.
    Seal(HintRule<'a>),
    /// An epic1 address's seal key; the hint is zero.
    Epic1,
    /// A listener's seal key; the hint is zero.
    Listener,
}

impl TxKey<'_> {
    pub fn class(&self) -> KeyClass {
        match self {
            Self::Seal(_) => KeyClass::Seal,
            Self::Epic1 => KeyClass::Epic1,
            Self::Listener => KeyClass::Listener,
        }
    }
}

/// Seals a `lepic.v1` slate to `recipient`, padded (RFC 0003 5.7). With `signer` it is signed;
/// a reply mailbox needs a reply key and no signer. A body over [`crate::MAX_BODY_LEN`] is
/// [`EncodeError::BodyTooLarge`].
pub fn seal_tx<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    key: TxKey<'_>,
    content: &TxContent,
    signer: Option<&SigningKey>,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let inner = Inner {
        kind: NATIVE_SLATE,
        body: &content.body,
        reply_key: content.reply_key.as_ref(),
        purpose: content.purpose,
        reference: content.reference.as_ref(),
        expires: content.expires,
        card: content.card.as_ref(),
        reply_mailbox: content.reply_mailbox.as_ref(),
        sent_at: content.sent_at,
        address_proof: content.address_proof.as_ref(),
        features: content.features,
        domain: content.domain.as_ref(),
        pad: true,
    };
    seal_inner(
        network,
        recipient,
        key.class(),
        |enc| match key {
            TxKey::Seal(rule) => rule.hint(recipient, enc),
            TxKey::Epic1 | TxKey::Listener => Hint::from_bytes([0; 8]),
        },
        &inner,
        signer,
        None,
        rng,
    )
}
