//! The self-signed contact card (RFC 0002 section 6) and its `epiccash://contact/1/` link.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{DecodeError, EncodeError, Malformed};
use crate::hash::sha256;
use crate::hint::HintRule;
use crate::keys::{EncPublicKey, HintKey, sig_key};
use crate::link::{LinkKind, decode_link, encode_link};
use crate::network::Network;
use crate::text::{ContactName, MailboxAddress, RelayHost};
use crate::tlv::{Fields, Writer, check_format};

/// Every field at its largest is about 600 bytes; the bound leaves room for extension fields.
pub const MAX_CARD_LEN: usize = 1024;
pub const CARD_FORMAT: u8 = 1;

const SIGNATURE_DOMAIN: &[u8] = b"epic-card/1";

const TAG_FORMAT: u8 = 0x01;
const TAG_NETWORK: u8 = 0x02;
const TAG_KIND: u8 = 0x03;
const TAG_NAME: u8 = 0x04;
const TAG_ENC_KEY: u8 = 0x05;
const TAG_SIG_KEY: u8 = 0x06;
const TAG_HINT_KEY: u8 = 0x07;
const TAG_MAILBOX: u8 = 0x08;
const TAG_PAYMENTS_ADDRESS: u8 = 0x09;
const TAG_HOME_ONION: u8 = 0x0a;
const TAG_CAPS: u8 = 0x0b;
const TAG_MAX_ENVELOPE_VERSION: u8 = 0x0c;
const TAG_SEQ: u8 = 0x0d;
const TAG_SIGNATURE: u8 = 0x0e;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactKind {
    Person,
    Shop,
    Exchange,
}

impl ContactKind {
    pub(crate) fn byte(self) -> u8 {
        match self {
            Self::Person => 0x01,
            Self::Shop => 0x02,
            Self::Exchange => 0x03,
        }
    }

    pub(crate) fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x01 => Self::Person,
            0x02 => Self::Shop,
            0x03 => Self::Exchange,
            _ => return None,
        })
    }
}

/// What a card's owner can do; bits not defined here must be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities(u16);

impl Capabilities {
    pub const OPENS_SEALED_FILES: Self = Self(1 << 0);
    pub const PAYS_INVOICES: Self = Self(1 << 1);
    pub const ISSUES_INVOICES: Self = Self(1 << 2);
    /// A service inbox that asks for the fixed hint (RFC 0002 3.2).
    pub const FIXED_HINT: Self = Self(1 << 3);
    pub const SENDS_WITHDRAWALS: Self = Self(1 << 4);

    const KNOWN: u16 = 0b1_1111;

    pub fn from_bits(bits: u16) -> Option<Self> {
        (bits & !Self::KNOWN == 0).then_some(Self(bits))
    }

    pub fn bits(self) -> u16 {
        self.0
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The content of a card, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardFields {
    pub kind: ContactKind,
    pub name: ContactName,
    pub enc_key: EncPublicKey,
    pub sig_key: VerifyingKey,
    pub hint_key: HintKey,
    /// Where this contact delivers to the owner.
    pub mailbox: MailboxAddress,
    /// The owner's ordinary Epicbox address for plain sends; never used for the relationship.
    pub payments_address: Option<MailboxAddress>,
    pub home_onion: Option<RelayHost>,
    pub caps: Capabilities,
    /// The highest envelope version the owner reads.
    pub max_envelope_version: u8,
    /// Raised on every change; a card replaces a stored one only with a higher value.
    pub seq: u32,
}

/// A card whose self-signature verified, with the exact bytes it was read from or written as.
/// `Debug` shows no keys or addresses, only the kind, `seq` and length.
#[derive(Clone, PartialEq, Eq)]
pub struct ContactCard {
    network: Network,
    fields: CardFields,
    bytes: Vec<u8>,
}

impl fmt::Debug for ContactCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactCard")
            .field("network", &self.network)
            .field("kind", &self.fields.kind)
            .field("seq", &self.fields.seq)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl ContactCard {
    /// Encodes and signs `fields` with `key`, which must be the card's sig key.
    pub fn sign(
        network: Network,
        fields: CardFields,
        key: &SigningKey,
    ) -> Result<Self, EncodeError> {
        if key.verifying_key() != fields.sig_key {
            return Err(EncodeError::SigningKeyMismatch);
        }
        let mut writer = Writer::default();
        writer.field(TAG_FORMAT, &[CARD_FORMAT])?;
        writer.field(TAG_NETWORK, &[network.byte()])?;
        writer.field(TAG_KIND, &[fields.kind.byte()])?;
        writer.field(TAG_NAME, fields.name.as_str().as_bytes())?;
        writer.field(TAG_ENC_KEY, fields.enc_key.as_bytes())?;
        writer.field(TAG_SIG_KEY, fields.sig_key.as_bytes())?;
        writer.field(TAG_HINT_KEY, fields.hint_key.as_bytes())?;
        writer.field(TAG_MAILBOX, fields.mailbox.as_str().as_bytes())?;
        writer.optional(
            TAG_PAYMENTS_ADDRESS,
            fields
                .payments_address
                .as_ref()
                .map(|address| address.as_str().as_bytes()),
        )?;
        writer.optional(
            TAG_HOME_ONION,
            fields
                .home_onion
                .as_ref()
                .map(|onion| onion.as_str().as_bytes()),
        )?;
        writer.field(TAG_CAPS, &fields.caps.bits().to_be_bytes())?;
        writer.field(TAG_MAX_ENVELOPE_VERSION, &[fields.max_envelope_version])?;
        writer.field(TAG_SEQ, &fields.seq.to_be_bytes())?;
        let signature = key.sign(&signing_input(writer.as_bytes()));
        writer.field(TAG_SIGNATURE, &signature.to_bytes())?;
        let bytes = writer.into_bytes();
        if bytes.len() > MAX_CARD_LEN {
            return Err(EncodeError::Oversized {
                limit: MAX_CARD_LEN,
                found: bytes.len(),
            });
        }
        Ok(Self {
            network,
            fields,
            bytes,
        })
    }

    /// Reads a card and verifies its self-signature with the sig key it carries.
    pub fn decode(bytes: &[u8], network: Network) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_CARD_LEN {
            return Err(DecodeError::Oversized {
                limit: MAX_CARD_LEN,
                found: bytes.len(),
            });
        }
        check_format(bytes, TAG_FORMAT, CARD_FORMAT)?;
        let fields = Fields::parse(bytes, TAG_SEQ, Some(TAG_SIGNATURE))?;
        if fields.require_u8(TAG_FORMAT)? != CARD_FORMAT {
            return Err(Malformed::FieldValue { tag: TAG_FORMAT }.into());
        }
        network.expect_byte(fields.require_u8(TAG_NETWORK)?)?;
        let value = |tag| Malformed::FieldValue { tag };
        let kind = ContactKind::from_byte(fields.require_u8(TAG_KIND)?).ok_or(value(TAG_KIND))?;
        let name = ContactName::try_from(fields.require(TAG_NAME)?).map_err(|_| value(TAG_NAME))?;
        let enc_key = EncPublicKey::from_bytes(fields.require_array(TAG_ENC_KEY)?)
            .map_err(|_| value(TAG_ENC_KEY))?;
        let sig_key = sig_key(&fields.require_array(TAG_SIG_KEY)?)?;
        let hint_key = HintKey::from_bytes(fields.require_array(TAG_HINT_KEY)?);
        let mailbox = MailboxAddress::try_from(fields.require(TAG_MAILBOX)?)
            .map_err(|_| value(TAG_MAILBOX))?;
        let payments_address = fields
            .get(TAG_PAYMENTS_ADDRESS)
            .map(|bytes| MailboxAddress::try_from(bytes).map_err(|_| value(TAG_PAYMENTS_ADDRESS)))
            .transpose()?;
        let home_onion = fields
            .get(TAG_HOME_ONION)
            .map(|bytes| RelayHost::try_from(bytes).map_err(|_| value(TAG_HOME_ONION)))
            .transpose()?;
        let caps = Capabilities::from_bits(fields.require_u16(TAG_CAPS)?).ok_or(value(TAG_CAPS))?;
        let max_envelope_version = fields.require_u8(TAG_MAX_ENVELOPE_VERSION)?;
        if max_envelope_version == 0 {
            return Err(value(TAG_MAX_ENVELOPE_VERSION).into());
        }
        let seq = fields.require_u32(TAG_SEQ)?;
        let signature = fields
            .signature()
            .ok_or(Malformed::MissingField { tag: TAG_SIGNATURE })?;
        let signature = <[u8; 64]>::try_from(signature)
            .map_err(|_| Malformed::FieldLength { tag: TAG_SIGNATURE })?;
        let signature = Signature::from_bytes(&signature);
        sig_key
            .verify_strict(&signing_input(fields.signed_prefix()), &signature)
            .map_err(|_| DecodeError::BadSignature)?;
        Ok(Self {
            network,
            fields: CardFields {
                kind,
                name,
                enc_key,
                sig_key,
                hint_key,
                mailbox,
                payments_address,
                home_onion,
                caps,
                max_envelope_version,
                seq,
            },
            bytes: bytes.to_vec(),
        })
    }

    pub fn from_link(text: &str, network: Network) -> Result<Self, DecodeError> {
        Self::decode(
            &decode_link(text, LinkKind::Contact, MAX_CARD_LEN)?,
            network,
        )
    }

    pub fn to_link(&self) -> String {
        encode_link(LinkKind::Contact, &self.bytes)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn fields(&self) -> &CardFields {
        &self.fields
    }

    pub fn enc_key(&self) -> &EncPublicKey {
        &self.fields.enc_key
    }

    pub fn sig_key(&self) -> &VerifyingKey {
        &self.fields.sig_key
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `H(card)`, as the commitment and the SAS use it.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.bytes])
    }

    /// The hint this card's owner asks senders for.
    pub fn hint_rule(&self) -> HintRule<'_> {
        if self.fields.caps.contains(Capabilities::FIXED_HINT) {
            HintRule::FixedContact(&self.fields.hint_key)
        } else {
            HintRule::Contact(&self.fields.hint_key)
        }
    }
}

fn signing_input(fields: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len().saturating_add(fields.len()));
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(fields);
    input
}
