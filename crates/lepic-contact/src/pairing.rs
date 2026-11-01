// SPDX-License-Identifier: Apache-2.0
//! Pairing secrets and the reply and confirm messages (RFC 0002 7.1 to 7.3).

use std::fmt;

use ed25519_dalek::SigningKey;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::card::ContactCard;
use crate::envelope::{Content, MessageType, Opened, SealedEnvelope, seal, seal_psk};
use crate::error::{DecodeError, EncodeError, Malformed};
use crate::hash::{first8, sha256};
use crate::hint::HintRule;
use crate::invite::Invite;
use crate::keys::EncSecretKey;
use crate::link::{LinkKind, decode_link, encode_link};
use crate::network::Network;
use crate::private::ChannelKey;

const ID_DOMAIN: &[u8] = b"epic-pair/1 id";
const COMMIT_DOMAIN: &[u8] = b"epic-pair/1 commit";

/// A reply or confirm envelope is a card and a few fixed fields; this bounds its link.
pub const MAX_PAIRING_ENVELOPE_LEN: usize = 4096;

macro_rules! secret_bytes {
    ($name:ident, $len:literal) => {
        #[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $len]);

        impl $name {
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub fn expose_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_bytes!(PairingCode, 16);
secret_bytes!(Nonce, 16);
secret_bytes!(ConfirmCode, 16);

impl Nonce {
    /// The nonce both sides use for an in-person pairing.
    pub fn zero() -> Self {
        Self([0; 16])
    }
}

/// `H("epic-pair/1 id" || code)[0..8]`: names an invite and is the hint of its replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InviteId([u8; 8]);

impl InviteId {
    pub fn from_code(code: &PairingCode) -> Self {
        Self(first8(&sha256(&[ID_DOMAIN, code.expose_bytes()])))
    }

    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

/// `H("epic-pair/1 commit" || nA || H(cardA))`: binds the inviter to its nonce and card before
/// the invitee chooses its own nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment([u8; 32]);

impl Commitment {
    pub fn new(nonce: &Nonce, card: &ContactCard) -> Self {
        Self(sha256(&[
            COMMIT_DOMAIN,
            nonce.expose_bytes(),
            &card.digest(),
        ]))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The invitee's answer: `code || nB || rc || cardB`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyBody {
    pub code: PairingCode,
    pub nonce: Nonce,
    /// Derives the confirm mailbox.
    pub confirm_code: ConfirmCode,
    pub card: ContactCard,
}

impl ReplyBody {
    /// The body bytes, which hold the invite's code and so are wiped on drop.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let card = self.card.as_bytes();
        let mut bytes = Zeroizing::new(Vec::with_capacity(card.len().saturating_add(48)));
        bytes.extend_from_slice(self.code.expose_bytes());
        bytes.extend_from_slice(self.nonce.expose_bytes());
        bytes.extend_from_slice(self.confirm_code.expose_bytes());
        bytes.extend_from_slice(card);
        bytes
    }

    pub fn decode(bytes: &[u8], network: Network) -> Result<Self, DecodeError> {
        let (code, rest) = bytes.split_first_chunk().ok_or(Malformed::Truncated)?;
        let (nonce, rest) = rest.split_first_chunk().ok_or(Malformed::Truncated)?;
        let (confirm_code, card) = rest.split_first_chunk().ok_or(Malformed::Truncated)?;
        Ok(Self {
            code: PairingCode::from_bytes(*code),
            nonce: Nonce::from_bytes(*nonce),
            confirm_code: ConfirmCode::from_bytes(*confirm_code),
            card: ContactCard::decode(card, network)?,
        })
    }
}

const STATUS_ACCEPTED: u8 = 0x01;

/// What a reply, confirm or contact update carries beside its body, as signed (or, for a
/// reply, sealed) envelope extensions: the sender's address proof and the features it claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PairingExtras {
    pub address_proof: Option<[u8; 32]>,
    pub features: Option<u32>,
}

impl PairingExtras {
    pub(crate) fn of(content: &Content) -> Self {
        Self {
            address_proof: content.address_proof,
            features: content.features,
        }
    }

    pub(crate) fn apply(&self, content: &mut Content) {
        content.address_proof = self.address_proof;
        content.features = self.features;
    }
}

/// Why the inviter did not accept a reply (RFC 0002 7.3). A refusal is advisory: it carries no
/// key or nonce of the inviter, and nothing is stored or trusted because of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    AlreadyUsed,
    Expired,
    CancelledByInviter,
}

impl Refusal {
    fn byte(self) -> u8 {
        match self {
            Self::AlreadyUsed => 0x02,
            Self::Expired => 0x03,
            Self::CancelledByInviter => 0x04,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x02 => Self::AlreadyUsed,
            0x03 => Self::Expired,
            0x04 => Self::CancelledByInviter,
            _ => return None,
        })
    }
}

/// The inviter's accepted confirm: `nA || cardA || 01`, with `cardA` the exact card the invite
/// committed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmBody {
    pub nonce: Nonce,
    pub card: ContactCard,
}

impl ConfirmBody {
    pub fn encode(&self) -> Vec<u8> {
        let card = self.card.as_bytes();
        let mut bytes = Vec::with_capacity(card.len().saturating_add(17));
        bytes.extend_from_slice(self.nonce.expose_bytes());
        bytes.extend_from_slice(card);
        bytes.push(STATUS_ACCEPTED);
        bytes
    }

    /// The invitee's check: the revealed nonce and card match the invite's commitment, and the
    /// card's enc key is the one the reply was sealed to. A mismatch means the invite was changed
    /// on the way.
    pub fn matches_invite(&self, invite: &Invite) -> bool {
        Commitment::new(&self.nonce, &self.card) == invite.fields().commit
            && self.card.enc_key() == &invite.fields().enc_key
    }
}

/// An opened confirm: accepted (signed, with the inviter's nonce and card) or refused
/// (anonymous, one status byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    Accepted(Box<ConfirmBody>),
    Refused(Refusal),
}

impl Confirm {
    /// A one-byte body is a refusal; anything longer is an accepted confirm ending in `01`.
    /// Whether the envelope was signed as its kind needs is [`open_confirm`]'s check.
    pub fn decode(bytes: &[u8], network: Network) -> Result<Self, DecodeError> {
        if let [status] = bytes {
            return Refusal::from_byte(*status)
                .map(Self::Refused)
                .ok_or_else(|| Malformed::Body.into());
        }
        let (nonce, rest) = bytes.split_first_chunk().ok_or(Malformed::Body)?;
        let (status, card) = rest.split_last().ok_or(Malformed::Body)?;
        if *status != STATUS_ACCEPTED || card.is_empty() {
            return Err(Malformed::Body.into());
        }
        Ok(Self::Accepted(Box::new(ConfirmBody {
            nonce: Nonce::from_bytes(*nonce),
            card: ContactCard::decode(card, network)?,
        })))
    }
}

/// Seals the invitee's reply to the invite's enc key: anonymous, hinted with the invite id.
pub fn seal_reply<R: CryptoRng>(
    invite: &Invite,
    body: &ReplyBody,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_reply_with(invite, body, &PairingExtras::default(), rng)
}

/// [`seal_reply`] with `extras` beside the body.
pub fn seal_reply_with<R: CryptoRng>(
    invite: &Invite,
    body: &ReplyBody,
    extras: &PairingExtras,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let network = invite.network();
    if body.card.network() != network {
        return Err(EncodeError::WrongNetwork);
    }
    let mut content = Content::new(MessageType::PairingReply, body.encode().to_vec());
    extras.apply(&mut content);
    let sealed = seal(
        network,
        &invite.fields().enc_key,
        HintRule::Invite(invite.id()),
        &content,
        None,
        rng,
    );
    content.body.zeroize();
    sealed
}

/// Opens a pairing reply with the invite's enc key. A reply is anonymous; a signed one is refused.
pub fn open_reply(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
) -> Result<ReplyBody, DecodeError> {
    open_reply_with(envelope, key).map(|(body, _)| body)
}

/// [`open_reply`], with what the reply carries beside its body.
pub fn open_reply_with(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
) -> Result<(ReplyBody, PairingExtras), DecodeError> {
    let opened = envelope.open(key)?;
    let extras = PairingExtras::of(&opened.content);
    let signed = opened.sender.is_some();
    let body = Zeroizing::new(expect_type(opened, MessageType::PairingReply)?);
    if signed {
        return Err(Malformed::Signed {
            kind: MessageType::PairingReply.byte(),
        }
        .into());
    }
    Ok((ReplyBody::decode(&body, envelope.network())?, extras))
}

/// Seals the inviter's accepted confirm to the invitee's card, signed with the inviter's sig key
/// for this contact, which must be the key in `body.card`.
pub fn seal_confirm<R: CryptoRng>(
    invitee: &ContactCard,
    body: &ConfirmBody,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_confirm_with(invitee, body, signer, None, &PairingExtras::default(), rng)
}

/// [`seal_confirm`] with `extras` beside the body, signed with it.
pub fn seal_confirm_with_extras<R: CryptoRng>(
    invitee: &ContactCard,
    body: &ConfirmBody,
    signer: &SigningKey,
    extras: &PairingExtras,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_confirm_with(invitee, body, signer, None, extras, rng)
}

/// [`seal_confirm`] for a private pairing, sealed under its channel key.
pub fn seal_private_confirm<R: CryptoRng>(
    invitee: &ContactCard,
    body: &ConfirmBody,
    signer: &SigningKey,
    channel: &ChannelKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_confirm_with(
        invitee,
        body,
        signer,
        Some(channel),
        &PairingExtras::default(),
        rng,
    )
}

fn seal_confirm_with<R: CryptoRng>(
    invitee: &ContactCard,
    body: &ConfirmBody,
    signer: &SigningKey,
    channel: Option<&ChannelKey>,
    extras: &PairingExtras,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let network = invitee.network();
    if body.card.network() != network {
        return Err(EncodeError::WrongNetwork);
    }
    if signer.verifying_key() != *body.card.sig_key() {
        return Err(EncodeError::SigningKeyMismatch);
    }
    let mut content = Content::new(MessageType::PairingConfirm, body.encode());
    extras.apply(&mut content);
    match channel {
        None => seal(
            network,
            invitee.enc_key(),
            invitee.hint_rule(),
            &content,
            Some(signer),
            rng,
        ),
        Some(channel) => seal_psk(
            network,
            invitee.enc_key(),
            invitee.hint_rule(),
            &content,
            Some(signer),
            channel,
            rng,
        ),
    }
}

/// Seals a refusal to the replier's card: anonymous, one status byte, nothing of the inviter's.
pub fn seal_refusal<R: CryptoRng>(
    invitee: &ContactCard,
    refusal: Refusal,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let content = Content::new(MessageType::PairingConfirm, vec![refusal.byte()]);
    seal(
        invitee.network(),
        invitee.enc_key(),
        invitee.hint_rule(),
        &content,
        None,
        rng,
    )
}

/// [`seal_refusal`] for a private pairing, sealed under its channel key.
pub fn seal_private_refusal<R: CryptoRng>(
    invitee: &ContactCard,
    refusal: Refusal,
    channel: &ChannelKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let content = Content::new(MessageType::PairingConfirm, vec![refusal.byte()]);
    seal_psk(
        invitee.network(),
        invitee.enc_key(),
        invitee.hint_rule(),
        &content,
        None,
        channel,
        rng,
    )
}

/// Opens a pairing confirm with the invitee's enc key for this contact. An accepted confirm must
/// be signed by the sig key of the card it carries, and the caller still checks
/// [`ConfirmBody::matches_invite`]; a refusal must be anonymous. A signed refusal and an
/// anonymous acceptance are malformed.
pub fn open_confirm(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
) -> Result<Confirm, DecodeError> {
    check_confirm(envelope, envelope.open(key)?)
}

/// [`open_confirm`], with what the confirm carries beside its body.
pub fn open_confirm_with(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
) -> Result<(Confirm, PairingExtras), DecodeError> {
    let opened = envelope.open(key)?;
    let extras = PairingExtras::of(&opened.content);
    Ok((check_confirm(envelope, opened)?, extras))
}

/// [`open_confirm`] for a private pairing, with its channel key.
pub fn open_private_confirm(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    channel: &ChannelKey,
) -> Result<Confirm, DecodeError> {
    check_confirm(envelope, envelope.open_psk(key, channel)?)
}

fn check_confirm(envelope: &SealedEnvelope<'_>, opened: Opened) -> Result<Confirm, DecodeError> {
    let sender = opened.sender;
    let confirm = Confirm::decode(
        &expect_type(opened, MessageType::PairingConfirm)?,
        envelope.network(),
    )?;
    let kind = MessageType::PairingConfirm.byte();
    match (&confirm, sender) {
        (Confirm::Accepted(body), Some(sender)) if sender == *body.card.sig_key() => Ok(confirm),
        (Confirm::Accepted(_), Some(_)) => Err(DecodeError::BadSignature),
        (Confirm::Accepted(_), None) => Err(Malformed::Unsigned { kind }.into()),
        (Confirm::Refused(_), None) => Ok(confirm),
        (Confirm::Refused(_), Some(_)) => Err(Malformed::Signed { kind }.into()),
    }
}

fn expect_type(opened: Opened, kind: MessageType) -> Result<Vec<u8>, DecodeError> {
    if opened.content.kind != kind {
        return Err(Malformed::FieldValue { tag: 0x01 }.into());
    }
    Ok(opened.content.body)
}

/// `epiccash://pair-reply/1/...` or `epiccash://pair-confirm/1/...` for an envelope sent by hand.
pub fn pairing_envelope_link(kind: PairingLink, envelope: &[u8]) -> String {
    encode_link(kind.link_kind(), envelope)
}

/// The envelope bytes in a hand-sent pairing link.
pub fn pairing_envelope_from_link(text: &str, kind: PairingLink) -> Result<Vec<u8>, DecodeError> {
    decode_link(text, kind.link_kind(), MAX_PAIRING_ENVELOPE_LEN)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingLink {
    Reply,
    Confirm,
}

impl PairingLink {
    fn link_kind(self) -> LinkKind {
        match self {
            Self::Reply => LinkKind::PairReply,
            Self::Confirm => LinkKind::PairConfirm,
        }
    }
}
