// SPDX-License-Identifier: Apache-2.0
//! The `lepic.v1` slate envelope (RFC 0003 5.4 to 5.9): type 0A, sealed to a key of a
//! [`KeyClass`], always padded, with an optional reply route (tag 09). It is the RFC 0002
//! envelope with its own reader: the RFC 0002 reader refuses type 0A and tag 09.

use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::CryptoRng;

use crate::card::ContactCard;
use crate::domain::DomainClaim;
use crate::envelope::{Inner, KeyClass, MessageType, NATIVE_SLATE, Purpose, seal_inner};
use crate::error::{EncodeError, Malformed};
use crate::hint::{Hint, HintRule};
use crate::keys::EncPublicKey;
use crate::network::Network;
use crate::text::Reference;

const TAG_REPLY_ROUTE: u8 = 0x09;
/// The method of a reply entry whose value is an Epicbox mailbox key.
const METHOD_EPICBOX: u8 = 0x01;
/// A compressed secp256k1 key.
const EPICBOX_KEY_LEN: usize = 33;

/// One way to reach the sender with the answer: a method and its value of up to 255 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyEntry {
    pub method: u8,
    pub value: Vec<u8>,
}

/// Where the answer goes (tag 09): `count || count × (method || len || value)`. Method 01
/// `epicbox` holds a one-time reply mailbox key; the payee posts the answer on the relay it
/// read the payment from. A reader keeps entries of methods it does not know and skips them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRoute {
    pub entries: Vec<ReplyEntry>,
}

impl ReplyRoute {
    /// A route of one `epicbox` entry, the mailbox `key`.
    pub fn epicbox(key: [u8; EPICBOX_KEY_LEN]) -> Self {
        Self {
            entries: vec![ReplyEntry {
                method: METHOD_EPICBOX,
                value: key.to_vec(),
            }],
        }
    }

    /// The key of the first `epicbox` entry.
    pub fn epicbox_key(&self) -> Option<[u8; EPICBOX_KEY_LEN]> {
        self.entries
            .iter()
            .find(|entry| entry.method == METHOD_EPICBOX)
            .and_then(|entry| entry.value.as_slice().try_into().ok())
    }

    /// Reads the value of tag 09. A count of 0, an entry that runs past the value, an
    /// `epicbox` value that is not a 33-byte key with prefix 02 or 03, or bytes left over is
    /// [`Malformed::FieldValue`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Malformed> {
        let invalid = Malformed::FieldValue {
            tag: TAG_REPLY_ROUTE,
        };
        let (&count, mut rest) = bytes.split_first().ok_or(invalid)?;
        if count == 0 {
            return Err(invalid);
        }
        let mut entries = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (&[method, len], after) = rest.split_first_chunk::<2>().ok_or(invalid)?;
            let (value, after) = after.split_at_checked(usize::from(len)).ok_or(invalid)?;
            if method == METHOD_EPICBOX && !epicbox_key_ok(value) {
                return Err(invalid);
            }
            entries.push(ReplyEntry {
                method,
                value: value.to_vec(),
            });
            rest = after;
        }
        if !rest.is_empty() {
            return Err(invalid);
        }
        Ok(Self { entries })
    }

    /// The value of tag 09. An empty route, more than 255 entries, a value over 255 bytes or
    /// an `epicbox` value that is not a 33-byte key with prefix 02 or 03 is
    /// [`EncodeError::ReplyRoute`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let count = u8::try_from(self.entries.len())
            .ok()
            .filter(|count| *count > 0)
            .ok_or(EncodeError::ReplyRoute)?;
        let mut out = vec![count];
        for entry in &self.entries {
            let len = u8::try_from(entry.value.len()).map_err(|_| EncodeError::ReplyRoute)?;
            if entry.method == METHOD_EPICBOX && !epicbox_key_ok(&entry.value) {
                return Err(EncodeError::ReplyRoute);
            }
            out.extend_from_slice(&[entry.method, len]);
            out.extend_from_slice(&entry.value);
        }
        Ok(out)
    }
}

/// A compressed secp256k1 key by its length and prefix; the point is checked where it is used.
fn epicbox_key_ok(value: &[u8]) -> bool {
    value.len() == EPICBOX_KEY_LEN && matches!(value.first(), Some(0x02 | 0x03))
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
    pub reply_route: Option<ReplyRoute>,
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
    /// The payer's one-time key, asking the payee of an epic1 payment for a receipt (S1).
    pub receipt_ask: Option<[u8; 33]>,
    /// The payee's receipt signature for an epic1 payment (S2).
    pub receipt: Option<[u8; 64]>,
}

impl fmt::Debug for TxContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxContent")
            .field("body_len", &self.body.len())
            .field("reply_key", &self.reply_key)
            .field("reply_route", &self.reply_route)
            .field("purpose", &self.purpose)
            .field("reference", &self.reference.is_some())
            .field("expires", &self.expires)
            .field("card", &self.card)
            .field("sent_at", &self.sent_at)
            .field("address_proof", &self.address_proof.is_some())
            .field("features", &self.features)
            .field("domain", &self.domain)
            .field("receipt_ask", &self.receipt_ask.is_some())
            .field("receipt", &self.receipt.is_some())
            .finish()
    }
}

impl TxContent {
    pub fn new(body: Vec<u8>) -> Self {
        Self {
            body,
            reply_key: None,
            reply_route: None,
            purpose: None,
            reference: None,
            expires: None,
            card: None,
            sent_at: None,
            address_proof: None,
            features: None,
            domain: None,
            receipt_ask: None,
            receipt: None,
        }
    }
}

/// What an envelope opened by a `lepic.v1` reader carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    /// A `lepic.v1` slate, type [`NATIVE_SLATE`].
    Slate,
    /// A notice about a payment the address took, type 02 (RFC 0003 5.9); only
    /// [`crate::SealedEnvelope::open_epic1`] reads one.
    Notice,
}

/// An opened `lepic.v1` slate envelope, or a notice at an epic1 address. `sender` is set
/// exactly when the envelope was signed and the signature verified with that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOpened {
    pub kind: TxKind,
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
    /// An Epicbox payments address's seal key; the hint is zero.
    Epicbox,
}

impl TxKey<'_> {
    pub fn class(&self) -> KeyClass {
        match self {
            Self::Seal(_) => KeyClass::Seal,
            Self::Epic1 => KeyClass::Epic1,
            Self::Listener => KeyClass::Listener,
            Self::Epicbox => KeyClass::Epicbox,
        }
    }
}

/// Seals a `lepic.v1` slate to `recipient`, padded (RFC 0003 5.7). With `signer` it is signed;
/// a reply route needs a reply key and no signer. A body over [`crate::MAX_BODY_LEN`] is
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
        reply_route: content.reply_route.as_ref(),
        sent_at: content.sent_at,
        address_proof: content.address_proof.as_ref(),
        features: content.features,
        domain: content.domain.as_ref(),
        receipt_ask: content.receipt_ask.as_ref(),
        receipt: content.receipt.as_ref(),
        pad: true,
    };
    seal_inner(
        network,
        recipient,
        key.class(),
        |enc| match key {
            TxKey::Seal(rule) => rule.hint(recipient, enc),
            TxKey::Epic1 | TxKey::Listener | TxKey::Epicbox => Hint::from_bytes([0; 8]),
        },
        &inner,
        signer,
        None,
        rng,
    )
}

/// Seals a notice `body` about a payment to the epic1 address key `recipient` (RFC 0003 5.9):
/// type 02, anonymous, hint zero, padded as a slate is, with no other field. A body over
/// [`crate::MAX_BODY_LEN`] is [`EncodeError::BodyTooLarge`].
pub fn seal_epic1_notice<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    body: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let inner = Inner::new(MessageType::Notice.byte(), body, true);
    seal_inner(
        network,
        recipient,
        KeyClass::Epic1,
        |_| Hint::from_bytes([0; 8]),
        &inner,
        None,
        None,
        rng,
    )
}
