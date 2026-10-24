//! Re-pairing after a restore (RFC 0002 7.8): the key check (type 06), its answer (type 07), and
//! the contact update (type 05, 8.5) that hands a contact an old pairing's new card. All three are
//! signed: 06 and 07 by the new pairing's peer key, 05 by the key recorded for the pairing.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::CryptoRng;

use crate::card::ContactCard;
use crate::envelope::{Content, MessageType, SealedEnvelope, seal};
use crate::error::{DecodeError, EncodeError, Malformed};
use crate::keys::EncSecretKey;
use crate::network::Network;

/// The body of a key check: the card the recipient gave the sender for an older pairing, and the
/// sender's own current card for that older pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCheckBody {
    pub recipient_old_card: ContactCard,
    pub sender_old_card: ContactCard,
}

impl KeyCheckBody {
    /// `u16 length || recipient_old_card || sender_old_card`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let first = self.recipient_old_card.as_bytes();
        let second = self.sender_old_card.as_bytes();
        let length =
            u16::try_from(first.len()).map_err(|_| EncodeError::FieldTooLong { tag: 0x02 })?;
        let mut bytes =
            Vec::with_capacity(first.len().saturating_add(second.len()).saturating_add(2));
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(first);
        bytes.extend_from_slice(second);
        Ok(bytes)
    }

    /// Both cards must be present, decode and verify.
    pub fn decode(bytes: &[u8], network: Network) -> Result<Self, DecodeError> {
        let (length, rest) = bytes.split_first_chunk::<2>().ok_or(Malformed::Body)?;
        let length = usize::from(u16::from_be_bytes(*length));
        if length == 0 || rest.len() <= length {
            return Err(Malformed::Body.into());
        }
        let (first, second) = rest.split_at(length);
        let card = |bytes| ContactCard::decode(bytes, network).map_err(|_| Malformed::Body);
        Ok(Self {
            recipient_old_card: card(first)?,
            sender_old_card: card(second)?,
        })
    }
}

/// The answer to a key check whose old slot was not found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheckStatus {
    /// The old card was not made by this wallet's seed.
    NotThisWallet,
}

impl KeyCheckStatus {
    fn byte(self) -> u8 {
        match self {
            Self::NotThisWallet => 0x01,
        }
    }

    fn from_body(body: &[u8]) -> Option<Self> {
        match body {
            [0x01] => Some(Self::NotThisWallet),
            _ => None,
        }
    }
}

/// Seals a key check to the new pairing's peer card, signed with our key of the new pairing.
pub fn seal_key_check<R: CryptoRng>(
    recipient: &ContactCard,
    body: &KeyCheckBody,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_signed(
        recipient,
        MessageType::KeyCheck,
        body.encode()?,
        signer,
        rng,
    )
}

/// Opens a key check, which must be signed by `new_peer`, the peer key of the new pairing.
pub fn open_key_check(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    new_peer: &VerifyingKey,
) -> Result<KeyCheckBody, DecodeError> {
    let body = open_signed(envelope, key, MessageType::KeyCheck, new_peer)?;
    KeyCheckBody::decode(&body, envelope.network())
}

/// Seals the answer to a key check to the new pairing's peer card, signed with our key of the new
/// pairing.
pub fn seal_key_check_answer<R: CryptoRng>(
    recipient: &ContactCard,
    status: KeyCheckStatus,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_signed(
        recipient,
        MessageType::KeyCheckAnswer,
        vec![status.byte()],
        signer,
        rng,
    )
}

/// Opens the answer to a key check, which must be signed by `new_peer`.
pub fn open_key_check_answer(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    new_peer: &VerifyingKey,
) -> Result<KeyCheckStatus, DecodeError> {
    let body = open_signed(envelope, key, MessageType::KeyCheckAnswer, new_peer)?;
    KeyCheckStatus::from_body(&body).ok_or_else(|| Malformed::Body.into())
}

/// Seals our new card for a pairing to the peer's card of that pairing, signed with our key of
/// the pairing, which the card must carry.
pub fn seal_contact_update<R: CryptoRng>(
    recipient: &ContactCard,
    card: &ContactCard,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    if card.network() != recipient.network() {
        return Err(EncodeError::WrongNetwork);
    }
    if signer.verifying_key() != *card.sig_key() {
        return Err(EncodeError::SigningKeyMismatch);
    }
    seal_signed(
        recipient,
        MessageType::ContactUpdate,
        card.as_bytes().to_vec(),
        signer,
        rng,
    )
}

/// Opens a contact update signed by `recorded_peer`, whose card carries that key. Whether its
/// `seq` is above the stored card's is the caller's check (RFC 0002 8.5).
pub fn open_contact_update(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    recorded_peer: &VerifyingKey,
) -> Result<ContactCard, DecodeError> {
    let body = open_signed(envelope, key, MessageType::ContactUpdate, recorded_peer)?;
    let card = ContactCard::decode(&body, envelope.network()).map_err(|_| Malformed::Body)?;
    if card.sig_key() != recorded_peer {
        return Err(Malformed::Body.into());
    }
    Ok(card)
}

fn seal_signed<R: CryptoRng>(
    recipient: &ContactCard,
    kind: MessageType,
    body: Vec<u8>,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal(
        recipient.network(),
        recipient.enc_key(),
        recipient.hint_rule(),
        &Content::new(kind, body),
        Some(signer),
        rng,
    )
}

/// The body of an envelope of `kind` signed by `sender`. A valid signature by another key is
/// [`DecodeError::KeyChanged`]; an unsigned envelope is malformed for these types.
fn open_signed(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    kind: MessageType,
    sender: &VerifyingKey,
) -> Result<Vec<u8>, DecodeError> {
    let opened = envelope.open_from(key, sender)?;
    if opened.sender.is_none() {
        return Err(Malformed::Unsigned { kind: kind.byte() }.into());
    }
    if opened.content.kind != kind {
        return Err(Malformed::FieldValue { tag: 0x01 }.into());
    }
    Ok(opened.content.body)
}
