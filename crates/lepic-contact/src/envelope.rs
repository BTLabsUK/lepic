// SPDX-License-Identifier: Apache-2.0
//! The sealed envelope (RFC 0002 section 3): HPKE base mode to the recipient's X25519 key,
//! optionally signed with the sender's Ed25519 key for this contact. The signature is tag 0xFF,
//! so optional fields from 0x80 up sit before it and are signed too.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, PskBundle, Serializable};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::card::ContactCard;
use crate::error::{DecodeError, EncodeError, Malformed};
use crate::hint::{Hint, HintRule};
use crate::keys::{EncPublicKey, EncSecretKey, sig_key};
use crate::network::Network;
use crate::private::{ChannelKey, PSK_ID, SUITE_PSK};
use crate::text::Reference;
use crate::tlv::{Fields, Writer};

pub const MAGIC: [u8; 4] = [0x89, 0x45, 0x53, 0x45];
/// The highest envelope version this crate reads and the one it writes.
pub const ENVELOPE_VERSION: u8 = 1;
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode.
pub const SUITE: u8 = 1;
pub const MAX_ENVELOPE_LEN: usize = 1024 * 1024;

pub const HEADER_LEN: usize = 16;
const ENC_LEN: usize = 32;
const AEAD_TAG_LEN: usize = 16;
const MIN_ENVELOPE_LEN: usize = HEADER_LEN + ENC_LEN + AEAD_TAG_LEN;

const INFO_DOMAIN: &[u8] = b"epic-seal/1";
const SIGNATURE_DOMAIN: &[u8] = b"epic-seal/1 sig";

const TAG_TYPE: u8 = 0x01;
const TAG_BODY: u8 = 0x02;
const TAG_REPLY_KEY: u8 = 0x03;
const TAG_PURPOSE: u8 = 0x04;
const TAG_REFERENCE: u8 = 0x05;
const TAG_EXPIRES: u8 = 0x06;
const TAG_CARD: u8 = 0x07;
const TAG_SENDER_KEY: u8 = 0x08;
/// An extension, so readers that predate it skip it; signed like every field before 0xFF. A
/// value that is not eight bytes is skipped like any extension this reader does not know.
const TAG_SENT_AT: u8 = 0x80;
/// The address proof of a pairing envelope, a 32-byte MAC; skipped when it has another length.
const TAG_ADDRESS_PROOF: u8 = 0x81;
/// The feature bits the sender claims, a big-endian `u32`, unknown bits kept; skipped when it
/// is not four bytes.
const TAG_FEATURES: u8 = 0x82;
const TAG_SIGNATURE: u8 = 0xff;

type SealKem = X25519HkdfSha256;

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
}

impl MessageType {
    pub(crate) fn byte(self) -> u8 {
        match self {
            Self::Slate => 0x01,
            Self::Notice => 0x02,
            Self::PairingReply => 0x03,
            Self::PairingConfirm => 0x04,
            Self::ContactUpdate => 0x05,
            Self::KeyCheck => 0x06,
            Self::KeyCheckAnswer => 0x07,
            Self::AppPayload => 0x40,
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

fn info(network: Network, suite: u8) -> [u8; 13] {
    let mut info = [0u8; 13];
    let (domain, rest) = info.split_at_mut(INFO_DOMAIN.len());
    domain.copy_from_slice(INFO_DOMAIN);
    if let [net, suite_byte] = rest {
        *net = network.byte();
        *suite_byte = suite;
    }
    info
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
/// comes from `rng`.
pub fn seal<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_with(network, recipient, hint_rule, content, signer, None, rng)
}

/// Seals as [`seal`] does, in HPKE PSK mode under `psk`, with suite
/// [`crate::private::SUITE_PSK`]: only a holder of `psk` opens it, with
/// [`SealedEnvelope::open_psk`].
pub fn seal_psk<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    psk: &ChannelKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_with(
        network,
        recipient,
        hint_rule,
        content,
        signer,
        Some(psk),
        rng,
    )
}

fn seal_with<R: CryptoRng>(
    network: Network,
    recipient: &EncPublicKey,
    hint_rule: HintRule<'_>,
    content: &Content,
    signer: Option<&SigningKey>,
    psk: Option<&ChannelKey>,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    if let Some(card) = &content.card {
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
            OpModeS::Psk(
                PskBundle::new(psk.expose_bytes(), PSK_ID)
                    .map_err(|_| EncodeError::Encapsulation)?,
            ),
            SUITE_PSK,
        ),
    };
    let (encapped, mut context) = hpke::setup_sender_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        SealKem,
    >(&mode, &public, &info(network, suite), rng)
    .map_err(|_| EncodeError::Encapsulation)?;
    let enc: [u8; ENC_LEN] = encapped
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| EncodeError::Encapsulation)?;
    let header = header(network, suite, &hint_rule.hint(recipient, &enc));
    let inner = Zeroizing::new(encode_content(content, &header, recipient, signer)?);
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

fn encode_content(
    content: &Content,
    header: &[u8; HEADER_LEN],
    recipient: &EncPublicKey,
    signer: Option<&SigningKey>,
) -> Result<Vec<u8>, EncodeError> {
    let mut writer = Writer::default();
    writer.field(TAG_TYPE, &[content.kind.byte()])?;
    writer.field(TAG_BODY, &content.body)?;
    writer.optional(
        TAG_REPLY_KEY,
        content.reply_key.as_ref().map(|key| &key.as_bytes()[..]),
    )?;
    writer.optional(
        TAG_PURPOSE,
        content
            .purpose
            .map(|purpose| [purpose.byte()])
            .as_ref()
            .map(|byte| &byte[..]),
    )?;
    writer.optional(
        TAG_REFERENCE,
        content
            .reference
            .as_ref()
            .map(|reference| reference.as_str().as_bytes()),
    )?;
    writer.optional(
        TAG_EXPIRES,
        content
            .expires
            .map(u64::to_be_bytes)
            .as_ref()
            .map(|bytes| &bytes[..]),
    )?;
    writer.optional(TAG_CARD, content.card.as_ref().map(ContactCard::as_bytes))?;
    if let Some(signer) = signer {
        writer.field(TAG_SENDER_KEY, signer.verifying_key().as_bytes())?;
    }
    writer.optional(
        TAG_SENT_AT,
        content
            .sent_at
            .map(u64::to_be_bytes)
            .as_ref()
            .map(|bytes| &bytes[..]),
    )?;
    writer.optional(
        TAG_ADDRESS_PROOF,
        content.address_proof.as_ref().map(|proof| &proof[..]),
    )?;
    writer.optional(
        TAG_FEATURES,
        content
            .features
            .map(u32::to_be_bytes)
            .as_ref()
            .map(|bytes| &bytes[..]),
    )?;
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
    /// Checks the bounds and the header: version, network, suite and flags, in that order.
    pub fn decode(bytes: &'a [u8], network: Network) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_ENVELOPE_LEN {
            return Err(DecodeError::Oversized {
                limit: MAX_ENVELOPE_LEN,
                found: bytes.len(),
            });
        }
        let (header, rest) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(Malformed::Truncated)?;
        let (enc, ciphertext) = rest
            .split_first_chunk::<ENC_LEN>()
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
    /// envelope of a private pairing ([`crate::private::SUITE_PSK`]) never opens here.
    pub fn open(&self, key: &EncSecretKey) -> Result<Opened, DecodeError> {
        if self.suite != SUITE {
            return Err(DecodeError::CannotOpen);
        }
        self.open_mode(key, &OpModeR::Base)
    }

    /// Opens an envelope of a private pairing with one candidate key and the pairing's `psk`.
    /// A base-mode envelope never opens here, so nobody without the key writes to the pairing.
    pub fn open_psk(&self, key: &EncSecretKey, psk: &ChannelKey) -> Result<Opened, DecodeError> {
        if self.suite != SUITE_PSK {
            return Err(DecodeError::CannotOpen);
        }
        let bundle =
            PskBundle::new(psk.expose_bytes(), PSK_ID).map_err(|_| DecodeError::CannotOpen)?;
        self.open_mode(key, &OpModeR::Psk(bundle))
    }

    /// [`Self::open_psk`] for a pairing whose recorded sig key is `expected`, as
    /// [`Self::open_from`] checks it.
    pub fn open_from_psk(
        &self,
        key: &EncSecretKey,
        expected: &VerifyingKey,
        psk: &ChannelKey,
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

    fn open_mode(
        &self,
        key: &EncSecretKey,
        mode: &OpModeR<'_, SealKem>,
    ) -> Result<Opened, DecodeError> {
        let secret = <SealKem as Kem>::PrivateKey::from_bytes(key.expose_bytes())
            .map_err(|_| DecodeError::CannotOpen)?;
        let encapped = <SealKem as Kem>::EncappedKey::from_bytes(self.enc)
            .map_err(|_| DecodeError::CannotOpen)?;
        let inner = Zeroizing::new(
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, SealKem>(
                mode,
                &secret,
                &encapped,
                &info(self.network, self.suite),
                self.ciphertext,
                self.header,
            )
            .map_err(|_| DecodeError::CannotOpen)?,
        );
        decode_content(&inner, self.network, self.header, &key.public_key())
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
    let fields = Fields::parse(bytes, TAG_SENDER_KEY, Some(TAG_SIGNATURE))?;
    let kind = MessageType::from_byte(fields.require_u8(TAG_TYPE)?)
        .ok_or(Malformed::FieldValue { tag: TAG_TYPE })?;
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

    Ok(Opened {
        content: Content {
            kind,
            body,
            reply_key,
            purpose,
            reference,
            expires,
            card,
            sent_at,
            address_proof,
            features,
        },
        sender,
    })
}
