// SPDX-License-Identifier: Apache-2.0
//! The sealed envelope (RFC 0002 section 3): HPKE base mode to the recipient's X25519 key,
//! optionally signed with the sender's Ed25519 key for this contact. The signature is tag 0xFF,
//! so optional fields from 0x80 up sit before it and are signed too. Slate envelopes carry the
//! padding field 0xFE (RFC 0003 5.7) before the signature, so they are signed with it.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, PskBundle, Serializable};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::card::ContactCard;
use crate::domain::DomainClaim;
use crate::error::{DecodeError, EncodeError, Malformed};
use crate::hint::{Hint, HintRule};
use crate::keys::{EncPublicKey, EncSecretKey, sig_key};
use crate::network::Network;
use crate::psk::{PSK_ID, PresharedKey, SUITE_PSK};
use crate::text::Reference;
use crate::tlv::{Fields, TAG_PADDING, Writer};
use crate::tx::{ReplyMailbox, TxContent, TxOpened};

pub const MAGIC: [u8; 4] = [0x89, 0x45, 0x53, 0x45];
/// The highest envelope version this crate reads and the one it writes.
pub const ENVELOPE_VERSION: u8 = 1;
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode.
pub const SUITE: u8 = 1;
pub const MAX_ENVELOPE_LEN: usize = 1024 * 1024;

/// The most bytes a body holds: a field's `u16` length. The binding size of a sealed slate.
pub const MAX_BODY_LEN: usize = 65_535;
/// The least inner content a padded envelope carries (RFC 0003 5.7).
pub const PADDING_FLOOR: usize = 768;

pub const HEADER_LEN: usize = 16;
const ENC_LEN: usize = 32;
const AEAD_TAG_LEN: usize = 16;
const MIN_ENVELOPE_LEN: usize = HEADER_LEN + ENC_LEN + AEAD_TAG_LEN;
const FIELD_HEADER_LEN: usize = 3;
const SIGNATURE_FIELD_LEN: usize = FIELD_HEADER_LEN + 64;

const INFO_DOMAIN: &[u8] = b"epic-seal/1";
const TX_INFO_DOMAIN: &[u8] = b"epic-tx/1";
const SIGNATURE_DOMAIN: &[u8] = b"epic-seal/1 sig";

const TAG_TYPE: u8 = 0x01;
const TAG_BODY: u8 = 0x02;
const TAG_REPLY_KEY: u8 = 0x03;
const TAG_PURPOSE: u8 = 0x04;
const TAG_REFERENCE: u8 = 0x05;
const TAG_EXPIRES: u8 = 0x06;
const TAG_CARD: u8 = 0x07;
const TAG_SENDER_KEY: u8 = 0x08;
/// The reply mailbox of a `lepic.v1` slate (RFC 0003 5.6); unknown to the RFC 0002 reader.
const TAG_REPLY_MAILBOX: u8 = 0x09;
/// An extension, so readers that predate it skip it; signed like every field before 0xFF. A
/// value that is not eight bytes is skipped like any extension this reader does not know.
const TAG_SENT_AT: u8 = 0x80;
/// The address proof of a pairing envelope, a 32-byte MAC; skipped when it has another length.
const TAG_ADDRESS_PROOF: u8 = 0x81;
/// The feature bits the sender claims, a big-endian `u32`, unknown bits kept; skipped when it
/// is not four bytes.
const TAG_FEATURES: u8 = 0x82;
/// The sender's domain claim (RFC 0002 6.3): `issued_at (8) || signature (64) || domain`; skipped
/// when it is shorter or its domain is not a valid name.
const TAG_DOMAIN: u8 = 0x83;
const TAG_SIGNATURE: u8 = 0xff;

type SealKem = X25519HkdfSha256;

/// The type byte of a `lepic.v1` slate (RFC 0003 5.6). Only [`SealedEnvelope::open_tx`] reads
/// it; the RFC 0002 reader refuses it.
pub const NATIVE_SLATE: u8 = 0x0a;

/// Which kind of key an envelope is sealed to, which sets the HPKE `info` (RFC 0003 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyClass {
    /// A contact, one-time reply or pairing key: `"epic-seal/1" || net || suite`.
    Seal,
    /// The seal key of an epic1 address: `"epic-tx/1" || net || suite || 00`.
    Epic1,
    /// The seal key of a listener, onion or web: `"epic-tx/1" || net || suite || 01`.
    Listener,
    /// The seal key of an Epicbox payments address: `"epic-tx/1" || net || suite || 02`.
    Epicbox,
}

impl KeyClass {
    /// The HPKE `info` of this class on `network` with `suite`.
    pub fn info(self, network: Network, suite: u8) -> Vec<u8> {
        let mut info = Vec::with_capacity(INFO_DOMAIN.len().saturating_add(3));
        match self {
            Self::Seal => {
                info.extend_from_slice(INFO_DOMAIN);
                info.extend_from_slice(&[network.byte(), suite]);
            }
            Self::Epic1 => {
                info.extend_from_slice(TX_INFO_DOMAIN);
                info.extend_from_slice(&[network.byte(), suite, 0x00]);
            }
            Self::Listener => {
                info.extend_from_slice(TX_INFO_DOMAIN);
                info.extend_from_slice(&[network.byte(), suite, 0x01]);
            }
            Self::Epicbox => {
                info.extend_from_slice(TX_INFO_DOMAIN);
                info.extend_from_slice(&[network.byte(), suite, 0x02]);
            }
        }
        info
    }
}

/// Padmé (RFC 0003 5.7): `length` rounded up so that only its top bits vary.
pub fn padme(length: usize) -> usize {
    if length < 2 {
        return length;
    }
    let exponent = length.ilog2();
    let shift = exponent.saturating_sub(exponent.ilog2().saturating_add(1));
    let mask = usize::MAX
        .checked_shr(usize::BITS.saturating_sub(shift))
        .unwrap_or(0);
    length.saturating_add(mask) & !mask
}

/// The padded length of inner content of `length` bytes: Padmé, at least [`PADDING_FLOOR`].
pub fn pad_target(length: usize) -> usize {
    padme(length).max(PADDING_FLOOR)
}

/// What the body of an envelope is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// A slate as V3 JSON.
    Slate,
    /// A notice as JSON, in the ADR 0016 shape.
    Notice,
    PairingReply,
    PairingConfirm,
    ContactUpdate,
    /// Asks whether the recipient can take back the keys of an older pairing (RFC 0002 7.8).
    KeyCheck,
    KeyCheckAnswer,
    /// Bytes the host app sends its paired counterpart; LEPIC never reads them. Its byte
    /// leaves the next free values to RFC 0002, whose kit refuses 0x08 as unknown.
    AppPayload,
    /// Asks a paired contact to answer with its current card in a contact update (RFC 0002
    /// 8.5). Signed, with an empty body. Byte 0x09: the kit refuses 0x08 as unknown.
    ContactCheck,
}

impl MessageType {
    pub fn byte(self) -> u8 {
        match self {
            Self::Slate => 0x01,
            Self::Notice => 0x02,
            Self::PairingReply => 0x03,
            Self::PairingConfirm => 0x04,
            Self::ContactUpdate => 0x05,
            Self::KeyCheck => 0x06,
            Self::KeyCheckAnswer => 0x07,
            Self::AppPayload => 0x40,
            Self::ContactCheck => 0x09,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x01 => Self::Slate,
            0x02 => Self::Notice,
            0x03 => Self::PairingReply,
            0x04 => Self::PairingConfirm,
            0x05 => Self::ContactUpdate,
            0x06 => Self::KeyCheck,
            0x07 => Self::KeyCheckAnswer,
            0x40 => Self::AppPayload,
            0x09 => Self::ContactCheck,
            _ => return None,
        })
    }
}

/// Why the sender sends this message; shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Payment,
    /// An invoice from a service.
    DepositRequest,
    Withdrawal,
    Refund,
    /// A request between people.
    Request,
}

impl Purpose {
    fn byte(self) -> u8 {
        match self {
            Self::Payment => 0x01,
            Self::DepositRequest => 0x02,
            Self::Withdrawal => 0x03,
            Self::Refund => 0x04,
            Self::Request => 0x05,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x01 => Self::Payment,
            0x02 => Self::DepositRequest,
            0x03 => Self::Withdrawal,
            0x04 => Self::Refund,
            0x05 => Self::Request,
            _ => return None,
        })
    }
}

/// The inner content of an envelope, without the signature fields. `Debug` shows the body's
/// length, never its bytes: a pairing reply's body holds the invite's code.
#[derive(Clone, PartialEq, Eq)]
pub struct Content {
    pub kind: MessageType,
    pub body: Vec<u8>,
    /// Where the answer should be sealed, for an anonymous envelope.
    pub reply_key: Option<EncPublicKey>,
    pub purpose: Option<Purpose>,
    pub reference: Option<Reference>,
    /// Unix seconds after which the sender stops honouring the message; advisory.
    pub expires: Option<u64>,
    /// The sender's current card for this contact.
    pub card: Option<ContactCard>,
    /// Unix seconds when the sender sealed it, so a recipient can refuse an old envelope that
    /// arrives again; signed with the rest of a signed envelope.
    pub sent_at: Option<u64>,
    /// The sender's address proof for this pairing, carried beside its card.
    pub address_proof: Option<[u8; 32]>,
    /// The feature bits the sender claims; a claim, never a reason to skip a check.
    pub features: Option<u32>,
    /// The domain the sender claims to speak for, signed by its domain key; a claim until the
    /// host checks the domain's file (ADR 0043).
    pub domain: Option<DomainClaim>,
}

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Content")
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .field("reply_key", &self.reply_key)
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

impl Content {
    pub fn new(kind: MessageType, body: Vec<u8>) -> Self {
        Self {
            kind,
            body,
            reply_key: None,
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

/// An opened envelope. `sender` is set exactly when the envelope was signed and the signature
/// verified with that key; the caller still checks it is the contact's recorded key. Which types
/// must be signed or anonymous is checked above the envelope, by the openers of each type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub content: Content,
    pub sender: Option<VerifyingKey>,
}

fn header(network: Network, suite: u8, hint: &Hint) -> [u8; HEADER_LEN] {
    let [m0, m1, m2, m3] = MAGIC;
    let [h0, h1, h2, h3, h4, h5, h6, h7] = *hint.as_bytes();
    [
        m0,
        m1,
        m2,
        m3,
        ENVELOPE_VERSION,
        network.byte(),
        suite,
        0x00,
        h0,
        h1,
        h2,
        h3,
        h4,
        h5,
        h6,
        h7,
    ]
}

fn signing_input(header: &[u8; HEADER_LEN], recipient: &EncPublicKey, fields: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        SIGNATURE_DOMAIN
            .len()
            .saturating_add(HEADER_LEN)
            .saturating_add(32)
            .saturating_add(fields.len()),
    );
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(header);
    input.extend_from_slice(recipient.as_bytes());
    input.extend_from_slice(fields);
    input
}

/// Seals `content` to `recipient`. With `signer` the envelope is signed (tags 08 and FF), and a
/// card in it must carry the signer's key; without, it is anonymous. Encapsulation randomness
/// comes from `rng`. A slate goes out as RFC 0002 wrote it, with no padding field; see
/// [`seal_padded`].
pub fn seal<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_with(
        network, recipient, hint_rule, content, signer, None, false, rng,
    )
}

/// Seals as [`seal`] does, and pads a slate (type 01) as RFC 0003 5.7 says. A host calls it
/// with native slates on and [`seal`] with them off, so that the bytes with them off stay those
/// of a build without them. Readers take both. Any other type is sealed as by [`seal`].
pub fn seal_padded<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_with(
        network, recipient, hint_rule, content, signer, None, true, rng,
    )
}

/// Seals as [`seal`] does, in HPKE PSK mode under `psk`, with suite
/// [`crate::SUITE_PSK`]: only a holder of `psk` opens it, with
/// [`SealedEnvelope::open_psk`].
pub fn seal_psk<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    psk: &(impl PresharedKey + ?Sized),
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_with(
        network,
        recipient,
        hint_rule,
        content,
        signer,
        Some(psk.psk_bytes()),
        false,
        rng,
    )
}

/// Seals as [`seal_psk`] does, and pads a slate as [`seal_padded`] does.
pub fn seal_psk_padded<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    psk: &(impl PresharedKey + ?Sized),
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_with(
        network,
        recipient,
        hint_rule,
        content,
        signer,
        Some(psk.psk_bytes()),
        true,
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_with<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    psk: Option<&[u8; 32]>,
    pad_slate: bool,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let inner = Inner {
        kind: content.kind.byte(),
        body: &content.body,
        reply_key: content.reply_key.as_ref(),
        purpose: content.purpose,
        reference: content.reference.as_ref(),
        expires: content.expires,
        card: content.card.as_ref(),
        reply_mailbox: None,
        sent_at: content.sent_at,
        address_proof: content.address_proof.as_ref(),
        features: content.features,
        domain: content.domain.as_ref(),
        pad: pad_slate && content.kind == MessageType::Slate,
    };
    seal_inner(
        network,
        recipient,
        KeyClass::Seal,
        |enc| hint_rule.hint(recipient, enc),
        &inner,
        signer,
        psk,
        rng,
    )
}

/// The fields of inner content to seal, borrowed from a [`Content`] or a
/// [`crate::TxContent`].
pub(crate) struct Inner<'c> {
    pub kind: u8,
    pub body: &'c [u8],
    pub reply_key: Option<&'c EncPublicKey>,
    pub purpose: Option<Purpose>,
    pub reference: Option<&'c Reference>,
    pub expires: Option<u64>,
    pub card: Option<&'c ContactCard>,
    pub reply_mailbox: Option<&'c ReplyMailbox>,
    pub sent_at: Option<u64>,
    pub address_proof: Option<&'c [u8; 32]>,
    pub features: Option<u32>,
    pub domain: Option<&'c DomainClaim>,
    /// Whether to write the padding field: for a `0A` slate envelope always, for a type 01 one
    /// when the host asks for it.
    pub pad: bool,
}

/// Seals `inner` to `recipient` with the `info` of `class` and the hint `hint` computes from
/// `enc`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_inner<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    class: KeyClass,
    hint: impl FnOnce(&[u8; ENC_LEN]) -> Hint,
    inner: &Inner<'_>,
    signer: Option<&SigningKey>,
    psk: Option<&[u8; 32]>,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    if inner.body.len() > MAX_BODY_LEN {
        return Err(EncodeError::BodyTooLarge {
            limit: MAX_BODY_LEN,
            found: inner.body.len(),
        });
    }
    if inner.reply_mailbox.is_some() && (inner.reply_key.is_none() || signer.is_some()) {
        return Err(EncodeError::ReplyMailbox);
    }
    if let Some(card) = inner.card {
        if card.network() != network {
            return Err(EncodeError::WrongNetwork);
        }
        if signer.is_some_and(|signer| signer.verifying_key() != *card.sig_key()) {
            return Err(EncodeError::SigningKeyMismatch);
        }
    }
    let public = <SealKem as Kem>::PublicKey::from_bytes(recipient.as_bytes())
        .map_err(|_| EncodeError::Encapsulation)?;
    let (mode, suite) = match psk {
        None => (OpModeS::Base, SUITE),
        Some(psk) => (
            OpModeS::Psk(PskBundle::new(psk, PSK_ID).map_err(|_| EncodeError::Encapsulation)?),
            SUITE_PSK,
        ),
    };
    let (encapped, mut context) = hpke::setup_sender_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        SealKem,
    >(&mode, &public, &class.info(network, suite), rng)
    .map_err(|_| EncodeError::Encapsulation)?;
    let enc: [u8; ENC_LEN] = encapped
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| EncodeError::Encapsulation)?;
    let header = header(network, suite, &hint(&enc));
    let inner = Zeroizing::new(encode_inner(inner, &header, recipient, signer)?);
    let ciphertext = context
        .seal(&inner, &header)
        .map_err(|_| EncodeError::Encryption)?;

    let length = MIN_ENVELOPE_LEN
        .saturating_add(ciphertext.len())
        .saturating_sub(AEAD_TAG_LEN);
    if length > MAX_ENVELOPE_LEN {
        return Err(EncodeError::Oversized {
            limit: MAX_ENVELOPE_LEN,
            found: length,
        });
    }
    let mut envelope = Vec::with_capacity(length);
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&enc);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn encode_inner(
    inner: &Inner<'_>,
    header: &[u8; HEADER_LEN],
    recipient: &EncPublicKey,
    signer: Option<&SigningKey>,
) -> Result<Vec<u8>, EncodeError> {
    let mut writer = Writer::default();
    writer.field(TAG_TYPE, &[inner.kind])?;
    writer.field(TAG_BODY, inner.body)?;
    writer.optional(
        TAG_REPLY_KEY,
        inner.reply_key.map(|key| &key.as_bytes()[..]),
    )?;
    writer.optional(
        TAG_PURPOSE,
        inner
            .purpose
            .map(|purpose| [purpose.byte()])
            .as_ref()
            .map(|byte| &byte[..]),
    )?;
    writer.optional(
        TAG_REFERENCE,
        inner
            .reference
            .map(|reference| reference.as_str().as_bytes()),
    )?;
    writer.optional(
        TAG_EXPIRES,
        inner
            .expires
            .map(u64::to_be_bytes)
            .as_ref()
            .map(|bytes| &bytes[..]),
    )?;
    writer.optional(TAG_CARD, inner.card.map(ContactCard::as_bytes))?;
    if let Some(signer) = signer {
        writer.field(TAG_SENDER_KEY, signer.verifying_key().as_bytes())?;
    }
    writer.optional(
        TAG_REPLY_MAILBOX,
        inner.reply_mailbox.map(ReplyMailbox::to_bytes).as_deref(),
    )?;
    writer.optional(
        TAG_SENT_AT,
        inner
            .sent_at
            .map(u64::to_be_bytes)
            .as_ref()
            .map(|bytes| &bytes[..]),
    )?;
    writer.optional(
        TAG_ADDRESS_PROOF,
        inner.address_proof.map(|proof| &proof[..]),
    )?;
    writer.optional(
        TAG_FEATURES,
        inner
            .features
            .map(u32::to_be_bytes)
            .as_ref()
            .map(|bytes| &bytes[..]),
    )?;
    writer.optional(
        TAG_DOMAIN,
        inner.domain.map(DomainClaim::to_bytes).as_deref(),
    )?;
    if inner.pad {
        // L counts every field, the padding field's header and the signature field to come.
        let length = writer
            .as_bytes()
            .len()
            .saturating_add(FIELD_HEADER_LEN)
            .saturating_add(if signer.is_some() {
                SIGNATURE_FIELD_LEN
            } else {
                0
            });
        writer.field(
            TAG_PADDING,
            &vec![0; pad_target(length).saturating_sub(length)],
        )?;
    }
    if let Some(signer) = signer {
        let signature = signer.sign(&signing_input(header, recipient, writer.as_bytes()));
        writer.field(TAG_SIGNATURE, &signature.to_bytes())?;
    }
    Ok(writer.into_bytes())
}

/// A decoded envelope whose header was checked; the ciphertext is still sealed.
#[derive(Debug, Clone, Copy)]
pub struct SealedEnvelope<'a> {
    network: Network,
    suite: u8,
    header: &'a [u8; HEADER_LEN],
    hint: Hint,
    enc: &'a [u8; ENC_LEN],
    ciphertext: &'a [u8],
}

impl<'a> SealedEnvelope<'a> {
    /// Checks the bounds and the header: magic, version, network, suite and flags, in that
    /// order. `enc` is split after the suite, whose KEM sets its length.
    pub fn decode(bytes: &'a [u8], network: Network) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_ENVELOPE_LEN {
            return Err(DecodeError::Oversized {
                limit: MAX_ENVELOPE_LEN,
                found: bytes.len(),
            });
        }
        if bytes.len() < MIN_ENVELOPE_LEN {
            return Err(Malformed::Truncated.into());
        }
        let (header, rest) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(Malformed::Truncated)?;
        let [
            m0,
            m1,
            m2,
            m3,
            version,
            net,
            suite,
            flags,
            h0,
            h1,
            h2,
            h3,
            h4,
            h5,
            h6,
            h7,
        ] = *header;
        if [m0, m1, m2, m3] != MAGIC {
            return Err(Malformed::Magic.into());
        }
        if version > ENVELOPE_VERSION {
            return Err(DecodeError::NewerVersion { found: version });
        }
        if version != ENVELOPE_VERSION {
            return Err(Malformed::Version { found: version }.into());
        }
        network.expect_byte(net)?;
        if suite != SUITE && suite != SUITE_PSK {
            return Err(DecodeError::UnsupportedSuite { suite });
        }
        if flags != 0 {
            return Err(Malformed::Flags { flags }.into());
        }
        // Both suites use DHKEM(X25519), whose `enc` is 32 bytes.
        let (enc, ciphertext) = rest
            .split_first_chunk::<ENC_LEN>()
            .ok_or(Malformed::Truncated)?;
        if ciphertext.len() < AEAD_TAG_LEN {
            return Err(Malformed::Truncated.into());
        }
        Ok(Self {
            network,
            suite,
            header,
            hint: Hint::from_bytes([h0, h1, h2, h3, h4, h5, h6, h7]),
            enc,
            ciphertext,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn hint(&self) -> Hint {
        self.hint
    }

    /// The HPKE encapsulated key, from which the recipient computes candidate hints.
    pub fn enc(&self) -> &[u8; ENC_LEN] {
        self.enc
    }

    /// Opens with one candidate key for a contact whose recorded sig key is `expected`: a valid
    /// signature by another key is [`DecodeError::KeyChanged`] (RFC 0002 3.4). An anonymous
    /// envelope opens with no sender; whether its type may be anonymous is the caller's check.
    pub fn open_from(
        &self,
        key: &EncSecretKey,
        expected: &VerifyingKey,
    ) -> Result<Opened, DecodeError> {
        let opened = self.open(key)?;
        if opened
            .sender
            .as_ref()
            .is_some_and(|sender| sender != expected)
        {
            return Err(DecodeError::KeyChanged);
        }
        Ok(opened)
    }

    /// Opens with one candidate key. Any failure of HPKE is [`DecodeError::CannotOpen`], whatever
    /// step failed; content that opens but is malformed or badly signed has its own error. An
    /// envelope of a private pairing ([`crate::SUITE_PSK`]) never opens here.
    pub fn open(&self, key: &EncSecretKey) -> Result<Opened, DecodeError> {
        if self.suite != SUITE {
            return Err(DecodeError::CannotOpen);
        }
        let inner = self.open_bytes(key, &OpModeR::Base, KeyClass::Seal)?;
        decode_content(&inner, self.network, self.header, &key.public_key())
    }

    /// Opens a `lepic.v1` slate (type [`NATIVE_SLATE`]) with one candidate key of `class`. Its
    /// errors are those of [`Self::open`]; content of any other type is refused.
    pub fn open_tx(&self, key: &EncSecretKey, class: KeyClass) -> Result<TxOpened, DecodeError> {
        if self.suite != SUITE {
            return Err(DecodeError::CannotOpen);
        }
        let inner = self.open_bytes(key, &OpModeR::Base, class)?;
        decode_tx_content(&inner, self.network, self.header, &key.public_key())
    }

    /// Opens an envelope of a private pairing with one candidate key and the pairing's `psk`.
    /// A base-mode envelope never opens here, so nobody without the key writes to the pairing.
    pub fn open_psk(
        &self,
        key: &EncSecretKey,
        psk: &(impl PresharedKey + ?Sized),
    ) -> Result<Opened, DecodeError> {
        if self.suite != SUITE_PSK {
            return Err(DecodeError::CannotOpen);
        }
        let bundle =
            PskBundle::new(psk.psk_bytes(), PSK_ID).map_err(|_| DecodeError::CannotOpen)?;
        let inner = self.open_bytes(key, &OpModeR::Psk(bundle), KeyClass::Seal)?;
        decode_content(&inner, self.network, self.header, &key.public_key())
    }

    /// [`Self::open_psk`] for a pairing whose recorded sig key is `expected`, as
    /// [`Self::open_from`] checks it.
    pub fn open_from_psk(
        &self,
        key: &EncSecretKey,
        expected: &VerifyingKey,
        psk: &(impl PresharedKey + ?Sized),
    ) -> Result<Opened, DecodeError> {
        let opened = self.open_psk(key, psk)?;
        if opened
            .sender
            .as_ref()
            .is_some_and(|sender| sender != expected)
        {
            return Err(DecodeError::KeyChanged);
        }
        Ok(opened)
    }

    fn open_bytes(
        &self,
        key: &EncSecretKey,
        mode: &OpModeR<'_, SealKem>,
        class: KeyClass,
    ) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
        let secret = <SealKem as Kem>::PrivateKey::from_bytes(key.expose_bytes())
            .map_err(|_| DecodeError::CannotOpen)?;
        let encapped = <SealKem as Kem>::EncappedKey::from_bytes(self.enc)
            .map_err(|_| DecodeError::CannotOpen)?;
        Ok(Zeroizing::new(
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, SealKem>(
                mode,
                &secret,
                &encapped,
                &class.info(self.network, self.suite),
                self.ciphertext,
                self.header,
            )
            .map_err(|_| DecodeError::CannotOpen)?,
        ))
    }

    /// Whether the envelope was sealed for a private pairing.
    pub fn is_private(&self) -> bool {
        self.suite == SUITE_PSK
    }
}

/// The inner fields of an envelope with `header`, sealed to `recipient`, as [`SealedEnvelope::open`]
/// reads them once HPKE has opened the ciphertext: the TLV fields, the card, and the signature.
/// The pure decode entry point for fuzzing; callers open envelopes with [`SealedEnvelope::open`].
pub fn decode_content(
    bytes: &[u8],
    network: Network,
    header: &[u8; HEADER_LEN],
    recipient: &EncPublicKey,
) -> Result<Opened, DecodeError> {
    let decoded = decode_inner(bytes, network, header, recipient, Reader::Rfc0002)?;
    let kind =
        MessageType::from_byte(decoded.kind).ok_or(Malformed::FieldValue { tag: TAG_TYPE })?;
    Ok(Opened {
        content: Content {
            kind,
            body: decoded.body,
            reply_key: decoded.reply_key,
            purpose: decoded.purpose,
            reference: decoded.reference,
            expires: decoded.expires,
            card: decoded.card,
            sent_at: decoded.sent_at,
            address_proof: decoded.address_proof,
            features: decoded.features,
            domain: decoded.domain,
        },
        sender: decoded.sender,
    })
}

/// The inner fields of a `lepic.v1` slate envelope, as [`SealedEnvelope::open_tx`] reads them;
/// the pure decode entry point for fuzzing. Returns the content, the verified sender, and the
/// length of the padding field when there is one.
pub fn decode_tx_content(
    bytes: &[u8],
    network: Network,
    header: &[u8; HEADER_LEN],
    recipient: &EncPublicKey,
) -> Result<TxOpened, DecodeError> {
    let decoded = decode_inner(bytes, network, header, recipient, Reader::Tx)?;
    Ok(TxOpened {
        content: TxContent {
            body: decoded.body,
            reply_key: decoded.reply_key,
            reply_mailbox: decoded.reply_mailbox,
            purpose: decoded.purpose,
            reference: decoded.reference,
            expires: decoded.expires,
            card: decoded.card,
            sent_at: decoded.sent_at,
            address_proof: decoded.address_proof,
            features: decoded.features,
            domain: decoded.domain,
        },
        sender: decoded.sender,
        padding: decoded.padding,
        inner_len: bytes.len(),
    })
}

/// Which reader decodes inner content.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// RFC 0002: the types of [`MessageType`]; tag 09 is unknown.
    Rfc0002,
    /// RFC 0003: type [`NATIVE_SLATE`] only, with tag 09.
    Tx,
}

struct Decoded {
    kind: u8,
    body: Vec<u8>,
    reply_key: Option<EncPublicKey>,
    purpose: Option<Purpose>,
    reference: Option<Reference>,
    expires: Option<u64>,
    card: Option<ContactCard>,
    reply_mailbox: Option<ReplyMailbox>,
    sent_at: Option<u64>,
    address_proof: Option<[u8; 32]>,
    features: Option<u32>,
    domain: Option<DomainClaim>,
    padding: Option<usize>,
    sender: Option<VerifyingKey>,
}

/// Refuses a type the reader does not know, and tag 09 outside type 0A.
fn check_kind(fields: &Fields<'_>, kind: u8, reader: Reader) -> Result<(), DecodeError> {
    let known = MessageType::from_byte(kind).is_some();
    match reader {
        Reader::Rfc0002 if !known => return Err(Malformed::FieldValue { tag: TAG_TYPE }.into()),
        Reader::Rfc0002 => {}
        Reader::Tx => {
            if !known && kind != NATIVE_SLATE {
                return Err(Malformed::FieldValue { tag: TAG_TYPE }.into());
            }
            // Tag 09 belongs to type 0A alone; in any other type it is the unknown tag every
            // RFC 0002 reader refuses.
            if kind != NATIVE_SLATE && fields.get(TAG_REPLY_MAILBOX).is_some() {
                return Err(Malformed::UnknownField {
                    tag: TAG_REPLY_MAILBOX,
                }
                .into());
            }
            if kind != NATIVE_SLATE {
                return Err(Malformed::FieldValue { tag: TAG_TYPE }.into());
            }
        }
    }
    Ok(())
}

/// The reply mailbox, valid only beside a reply key in an anonymous envelope.
fn reply_mailbox(
    fields: &Fields<'_>,
    has_reply_key: bool,
) -> Result<Option<ReplyMailbox>, Malformed> {
    let Some(bytes) = fields.get(TAG_REPLY_MAILBOX) else {
        return Ok(None);
    };
    if !has_reply_key || fields.signature().is_some() {
        return Err(Malformed::FieldValue {
            tag: TAG_REPLY_MAILBOX,
        });
    }
    ReplyMailbox::from_bytes(bytes).map(Some)
}

/// The length of the padding field, whose bytes must all be zero.
fn padding_len(fields: &Fields<'_>) -> Result<Option<usize>, Malformed> {
    fields
        .padding()
        .map(|value| {
            if value.iter().any(|byte| *byte != 0) {
                Err(Malformed::FieldValue { tag: TAG_PADDING })
            } else {
                Ok(value.len())
            }
        })
        .transpose()
}

fn decode_inner(
    bytes: &[u8],
    network: Network,
    header: &[u8; HEADER_LEN],
    recipient: &EncPublicKey,
    reader: Reader,
) -> Result<Decoded, DecodeError> {
    let last_known = match reader {
        Reader::Rfc0002 => TAG_SENDER_KEY,
        Reader::Tx => TAG_REPLY_MAILBOX,
    };
    let fields = Fields::parse(bytes, last_known, Some(TAG_SIGNATURE))?;
    let kind = fields.require_u8(TAG_TYPE)?;
    check_kind(&fields, kind, reader)?;
    let body = fields.require(TAG_BODY)?.to_vec();
    let reply_key = fields
        .optional_array(TAG_REPLY_KEY)?
        .map(|bytes| {
            EncPublicKey::from_bytes(bytes)
                .map_err(|_| Malformed::FieldValue { tag: TAG_REPLY_KEY })
        })
        .transpose()?;
    let purpose = fields
        .optional_u8(TAG_PURPOSE)?
        .map(|byte| Purpose::from_byte(byte).ok_or(Malformed::FieldValue { tag: TAG_PURPOSE }))
        .transpose()?;
    let reference = fields
        .get(TAG_REFERENCE)
        .map(|bytes| {
            Reference::try_from(bytes).map_err(|_| Malformed::FieldValue { tag: TAG_REFERENCE })
        })
        .transpose()?;
    let expires = fields.optional_u64(TAG_EXPIRES)?;
    let card = fields
        .get(TAG_CARD)
        .map(|bytes| ContactCard::decode(bytes, network))
        .transpose()?;
    let reply_mailbox = reply_mailbox(&fields, reply_key.is_some())?;
    let sent_at = fields
        .extension(TAG_SENT_AT)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_be_bytes);
    let address_proof = fields
        .extension(TAG_ADDRESS_PROOF)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let features = fields
        .extension(TAG_FEATURES)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes);
    let domain = fields
        .extension(TAG_DOMAIN)
        .and_then(|bytes| DomainClaim::from_bytes(bytes).ok());
    let padding = padding_len(&fields)?;

    let sender = match (
        fields.optional_array::<32>(TAG_SENDER_KEY)?,
        fields
            .signature()
            .map(|value| {
                <[u8; 64]>::try_from(value)
                    .map_err(|_| Malformed::FieldLength { tag: TAG_SIGNATURE })
            })
            .transpose()?,
    ) {
        // A sender key without a signature proves nothing, so the envelope counts as anonymous.
        (None | Some(_), None) => None,
        (None, Some(_)) => {
            return Err(Malformed::MissingField {
                tag: TAG_SENDER_KEY,
            }
            .into());
        }
        (Some(key), Some(signature)) => {
            let key = sig_key(&key)?;
            let input = signing_input(header, recipient, fields.signed_prefix());
            key.verify_strict(&input, &Signature::from_bytes(&signature))
                .map_err(|_| DecodeError::BadSignature)?;
            Some(key)
        }
    };
    if let (Some(card), Some(sender)) = (&card, &sender)
        && card.sig_key() != sender
    {
        return Err(Malformed::FieldValue { tag: TAG_CARD }.into());
    }

    Ok(Decoded {
        kind,
        body,
        reply_key,
        purpose,
        reference,
        expires,
        card,
        reply_mailbox,
        sent_at,
        address_proof,
        features,
        domain,
        padding,
        sender,
    })
}
