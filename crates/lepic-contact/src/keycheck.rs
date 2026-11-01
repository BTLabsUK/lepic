// SPDX-License-Identifier: Apache-2.0
//! Re-pairing after a restore (RFC 0002 7.8): the key check (type 06), its answers (type 07: not
//! found, found, restored), and the contact update (type 05, 8.5).
//!
//! Every 06 and 07 travels over the new pairing: sealed to the peer's new key and signed by the
//! sender's new key. X holds the old record and asks; Y may hold the old slot. `n_x` and `n_y`
//! are the new pairing's sig keys of X and Y. A found or restored answer carries a proof by a key
//! the other side already held for the old pairing, over the envelope it answers and both new
//! keys, so neither side adopts a card from a party that has not shown it holds the old key.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRng;

use crate::card::ContactCard;
use crate::envelope::{Content, MessageType, SealedEnvelope, seal};
use crate::error::{DecodeError, EncodeError, Malformed};
use crate::hash::sha256;
use crate::keys::{EncSecretKey, HintKey};
use crate::network::Network;
use crate::pairing::PairingExtras;

const TAG_DOMAIN: &[u8] = b"epic-pair/1 keycheck";
const FOUND_DOMAIN: &[u8] = b"epic-pair/1 keycheck found";
const RESTORED_DOMAIN: &[u8] = b"epic-pair/1 keycheck restored";

const STATUS_NOT_FOUND: u8 = 0x01;
const STATUS_FOUND: u8 = 0x02;
const STATUS_RESTORED: u8 = 0x03;

const PROOF_LEN: usize = 64;

/// `H("epic-pair/1 keycheck" || hint_key || nY || nX)`: names the old card whose hint key is
/// `hint_key` to the side that made it, and to nobody else, for this new pairing only.
pub fn key_check_tag(hint_key: &HintKey, n_y: &VerifyingKey, n_x: &VerifyingKey) -> [u8; 32] {
    sha256(&[
        TAG_DOMAIN,
        hint_key.as_bytes(),
        n_y.as_bytes(),
        n_x.as_bytes(),
    ])
}

/// The body of a key check: `seq (u32) || tag (32)`, with `seq` the seq of the card Y gave X
/// for the old pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCheck {
    pub seq: u32,
    pub tag: [u8; 32],
}

impl KeyCheck {
    pub fn encode(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        let (seq, tag) = bytes.split_at_mut(4);
        seq.copy_from_slice(&self.seq.to_be_bytes());
        tag.copy_from_slice(&self.tag);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; 36] = bytes.try_into().map_err(|_| Malformed::Body)?;
        let (seq, tag) = bytes.split_first_chunk::<4>().ok_or(Malformed::Body)?;
        Ok(Self {
            seq: u32::from_be_bytes(*seq),
            tag: tag.try_into().map_err(|_| Malformed::Body)?,
        })
    }
}

/// A card and the proof by the old key that comes with it in a found or restored answer.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyCheckProof {
    card: Vec<u8>,
    proof: [u8; PROOF_LEN],
}

impl KeyCheckProof {
    /// The card bytes as received; they are decoded only when the answer is accepted.
    pub fn card_bytes(&self) -> &[u8] {
        &self.card
    }

    pub fn proof(&self) -> &[u8; PROOF_LEN] {
        &self.proof
    }
}

impl std::fmt::Debug for KeyCheckProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCheckProof")
            .field("card_len", &self.card.len())
            .finish_non_exhaustive()
    }
}

/// A 07 decoded but not yet judged: [`accept_found`] and [`accept_restored`] check the proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCheckAnswer {
    /// The checked card was not made by Y's seed (body `01`).
    NotFound,
    /// Y's refreshed card for the old slot and its proof by the old slot key (body `02 || ...`).
    Found(KeyCheckProof),
    /// X's card for the old record and its proof by X's old key (body `03 || ...`).
    Restored(KeyCheckProof),
}

impl KeyCheckAnswer {
    /// `01`, or `02`/`03 || u16 length || card || proof (64)`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let (status, carried) = match self {
            Self::NotFound => return Ok(vec![STATUS_NOT_FOUND]),
            Self::Found(carried) => (STATUS_FOUND, carried),
            Self::Restored(carried) => (STATUS_RESTORED, carried),
        };
        let length = u16::try_from(carried.card.len())
            .map_err(|_| EncodeError::FieldTooLong { tag: 0x02 })?;
        let mut bytes = Vec::with_capacity(carried.card.len().saturating_add(3 + PROOF_LEN));
        bytes.push(status);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&carried.card);
        bytes.extend_from_slice(&carried.proof);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (status, rest) = bytes.split_first().ok_or(Malformed::Body)?;
        let wrap = match *status {
            STATUS_NOT_FOUND if rest.is_empty() => return Ok(Self::NotFound),
            STATUS_FOUND => Self::Found,
            STATUS_RESTORED => Self::Restored,
            _ => return Err(Malformed::Body.into()),
        };
        let (length, rest) = rest.split_first_chunk::<2>().ok_or(Malformed::Body)?;
        let length = usize::from(u16::from_be_bytes(*length));
        if length == 0 || rest.len() != length.saturating_add(PROOF_LEN) {
            return Err(Malformed::Body.into());
        }
        let (card, proof) = rest.split_at_checked(length).ok_or(Malformed::Body)?;
        Ok(wrap(KeyCheckProof {
            card: card.to_vec(),
            proof: proof.try_into().map_err(|_| Malformed::Body)?,
        }))
    }
}

/// `"epic-pair/1 keycheck found" || H(06 envelope) || nY || nX || H(card)`.
fn found_message(
    check_envelope: &[u8],
    n_y: &VerifyingKey,
    n_x: &VerifyingKey,
    card: &[u8],
) -> Vec<u8> {
    proof_message(FOUND_DOMAIN, check_envelope, n_y, n_x, card)
}

/// `"epic-pair/1 keycheck restored" || H(found envelope) || nX || nY || H(card)`.
fn restored_message(
    found_envelope: &[u8],
    n_x: &VerifyingKey,
    n_y: &VerifyingKey,
    card: &[u8],
) -> Vec<u8> {
    proof_message(RESTORED_DOMAIN, found_envelope, n_x, n_y, card)
}

fn proof_message(
    domain: &[u8],
    answered: &[u8],
    first: &VerifyingKey,
    second: &VerifyingKey,
    card: &[u8],
) -> Vec<u8> {
    [
        domain,
        &sha256(&[answered]),
        first.as_bytes(),
        second.as_bytes(),
        &sha256(&[card]),
    ]
    .concat()
}

/// X's side, step 1: the check for the old record whose peer card is `old_peer_card`, sealed to
/// the new pairing's peer card and signed with our key of the new pairing.
pub fn seal_key_check<R: CryptoRng>(
    new_peer_card: &ContactCard,
    old_peer_card: &ContactCard,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    let check = KeyCheck {
        seq: old_peer_card.fields().seq,
        tag: key_check_tag(
            &old_peer_card.fields().hint_key,
            new_peer_card.sig_key(),
            &signer.verifying_key(),
        ),
    };
    seal_signed(
        new_peer_card,
        MessageType::KeyCheck,
        check.encode().to_vec(),
        signer,
        rng,
    )
}

/// Y's side: opens a key check, which must be signed by `new_peer` (nX).
pub fn open_key_check(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    new_peer: &VerifyingKey,
) -> Result<KeyCheck, DecodeError> {
    let body = open_signed(envelope, key, MessageType::KeyCheck, new_peer)?;
    KeyCheck::decode(&body)
}

/// Y's side, step 2: no slot or record matched the tag.
pub fn seal_not_found<R: CryptoRng>(
    new_peer_card: &ContactCard,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_answer(new_peer_card, &KeyCheckAnswer::NotFound, signer, rng)
}

/// Y's side, step 3: `refreshed` is Y's card for the found slot (seq above the checked one),
/// signed by `old_slot_signer`, which also makes the proof over `check_envelope`, the 06 bytes
/// as received.
pub fn seal_found<R: CryptoRng>(
    new_peer_card: &ContactCard,
    signer: &SigningKey,
    check_envelope: &[u8],
    refreshed: &ContactCard,
    old_slot_signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    if refreshed.network() != new_peer_card.network() {
        return Err(EncodeError::WrongNetwork);
    }
    if old_slot_signer.verifying_key() != *refreshed.sig_key() {
        return Err(EncodeError::SigningKeyMismatch);
    }
    let message = found_message(
        check_envelope,
        &signer.verifying_key(),
        new_peer_card.sig_key(),
        refreshed.as_bytes(),
    );
    let answer = KeyCheckAnswer::Found(KeyCheckProof {
        card: refreshed.as_bytes().to_vec(),
        proof: old_slot_signer.sign(&message).to_bytes(),
    });
    seal_answer(new_peer_card, &answer, signer, rng)
}

/// X's side, step 5: `old_card` is X's own card for the old record, signed by `old_signer`, which
/// also makes the proof over `found_envelope`, the found answer's bytes as received.
pub fn seal_restored<R: CryptoRng>(
    new_peer_card: &ContactCard,
    signer: &SigningKey,
    found_envelope: &[u8],
    old_card: &ContactCard,
    old_signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    if old_card.network() != new_peer_card.network() {
        return Err(EncodeError::WrongNetwork);
    }
    if old_signer.verifying_key() != *old_card.sig_key() {
        return Err(EncodeError::SigningKeyMismatch);
    }
    let message = restored_message(
        found_envelope,
        &signer.verifying_key(),
        new_peer_card.sig_key(),
        old_card.as_bytes(),
    );
    let answer = KeyCheckAnswer::Restored(KeyCheckProof {
        card: old_card.as_bytes().to_vec(),
        proof: old_signer.sign(&message).to_bytes(),
    });
    seal_answer(new_peer_card, &answer, signer, rng)
}

/// Either side: opens a 07 signed by `new_peer`, the new pairing's peer key. Its proof is not yet
/// checked.
pub fn open_key_check_answer(
    envelope: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    new_peer: &VerifyingKey,
) -> Result<KeyCheckAnswer, DecodeError> {
    let body = open_signed(envelope, key, MessageType::KeyCheckAnswer, new_peer)?;
    KeyCheckAnswer::decode(&body)
}

/// X's side, step 4: a found answer to the check `check_envelope` (the 06 bytes as sent) over
/// the new pairing with peer key `new_peer` (nY) and our key `own_new` (nX). The refreshed card
/// must have the enc, sig and hint keys of `stored_old_card`, a higher seq, and a proof by its sig
/// key. Returns the refreshed card; any failure is [`DecodeError::KeyCheckNotProven`] or
/// malformed. Only the caller knows whether this answers its open check, once, within 24 hours.
pub fn accept_found(
    answer: &KeyCheckAnswer,
    check_envelope: &[u8],
    new_peer: &VerifyingKey,
    own_new: &VerifyingKey,
    stored_old_card: &ContactCard,
) -> Result<ContactCard, DecodeError> {
    let KeyCheckAnswer::Found(carried) = answer else {
        return Err(DecodeError::KeyCheckNotProven);
    };
    let card = answer_card(carried, stored_old_card.network())?;
    let (old, new) = (stored_old_card.fields(), card.fields());
    if new.enc_key != old.enc_key
        || new.sig_key != old.sig_key
        || new.hint_key != old.hint_key
        || new.seq <= old.seq
    {
        return Err(DecodeError::KeyCheckNotProven);
    }
    let message = found_message(check_envelope, new_peer, own_new, &carried.card);
    verify_proof(stored_old_card.sig_key(), &message, &carried.proof)?;
    Ok(card)
}

/// Y's side, step 6: a restored answer to our found answer `found_envelope` (its bytes as sent)
/// over the new pairing with peer key `new_peer` (nX) and our key `own_new` (nY). X's old card
/// must decode, and the proof verify with its sig key. Returns X's old card.
pub fn accept_restored(
    answer: &KeyCheckAnswer,
    found_envelope: &[u8],
    new_peer: &VerifyingKey,
    own_new: &VerifyingKey,
    network: Network,
) -> Result<ContactCard, DecodeError> {
    let KeyCheckAnswer::Restored(carried) = answer else {
        return Err(DecodeError::KeyCheckNotProven);
    };
    let card = answer_card(carried, network)?;
    let message = restored_message(found_envelope, new_peer, own_new, &carried.card);
    verify_proof(card.sig_key(), &message, &carried.proof)?;
    Ok(card)
}

/// The card of a found or restored answer. A weak sig key keeps its own error; anything else
/// wrong with the card is a malformed answer.
fn answer_card(carried: &KeyCheckProof, network: Network) -> Result<ContactCard, DecodeError> {
    ContactCard::decode(&carried.card, network).map_err(|error| match error {
        DecodeError::WeakSigKey => error,
        _ => Malformed::Body.into(),
    })
}

fn verify_proof(
    key: &VerifyingKey,
    message: &[u8],
    proof: &[u8; PROOF_LEN],
) -> Result<(), DecodeError> {
    key.verify_strict(message, &Signature::from_bytes(proof))
        .map_err(|_| DecodeError::KeyCheckNotProven)
}

/// Seals our new card for a pairing to the peer's card of that pairing, signed with our key of
/// the pairing, which the card must carry.
pub fn seal_contact_update<R: CryptoRng>(
    recipient: &ContactCard,
    card: &ContactCard,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_contact_update_with(recipient, card, signer, &PairingExtras::default(), rng)
}

/// [`seal_contact_update`] with `extras` beside the card, signed with it.
pub fn seal_contact_update_with<R: CryptoRng>(
    recipient: &ContactCard,
    card: &ContactCard,
    signer: &SigningKey,
    extras: &PairingExtras,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    if card.network() != recipient.network() {
        return Err(EncodeError::WrongNetwork);
    }
    if signer.verifying_key() != *card.sig_key() {
        return Err(EncodeError::SigningKeyMismatch);
    }
    let mut content = Content::new(MessageType::ContactUpdate, card.as_bytes().to_vec());
    extras.apply(&mut content);
    seal(
        recipient.network(),
        recipient.enc_key(),
        recipient.hint_rule(),
        &content,
        Some(signer),
        rng,
    )
}

/// Opens a contact update signed by `recorded_peer`, whose card carries that key. Whether its
/// `seq` is above the stored card's is the caller's check (RFC 0002 8.5). An update never
/// completes a key check: only [`accept_found`] does.
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

fn seal_answer<R: CryptoRng>(
    recipient: &ContactCard,
    answer: &KeyCheckAnswer,
    signer: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, EncodeError> {
    seal_signed(
        recipient,
        MessageType::KeyCheckAnswer,
        answer.encode()?,
        signer,
        rng,
    )
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
