// SPDX-License-Identifier: Apache-2.0
//! Native slates between paired contacts (RFC 0003, ADR 0052 step 6): `lepic.v1` in a type `0A`
//! envelope through the contacts' mailboxes.
//!
//! The engine keeps storing V3 JSON; the format changes only at the edge. A slate goes native
//! when the host sets [`lepic_wallet::config::WalletConfig::native_direct`] and the contact's
//! pairing features claim [`NATIVE_SLATES`], and never through a private pairing; an answer
//! takes the format of its request. A native proposal carries no inputs or outputs and a native
//! answer leaves out the initiator's message, so an answer is completed from the request this
//! wallet stored before the engine sees it.

use lepic_contact::{
    ContactCard, Content, DecodeError, EncSecretKey, KeyClass, MessageType, Opened, SealedEnvelope,
    SigningKey, TxContent, TxKey, TxOpened, VerifyingKey, seal_tx,
};
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_native_slate::{NativeSlate, Tail};
use lepic_primitives::params::Network;
use lepic_slate::codec::{EncodeContext, MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{ContactRecord, SlateStage, WalletStore};
use lepic_transport::marker::features::NATIVE_SLATES;
use lepic_wallet::receive::legacy_codecs;

use lepic_node::NodeApi;
use lepic_wallet::ports::{SecretVault, StoreOpener};
use uuid::Uuid;

use super::{ContactError, LockedRng};
use crate::ContactBook;

/// Whether a new slate to the contact of `record` goes native: the host sends native slates and
/// the contact claims to take them, through a base pairing.
pub(crate) fn wants_native(native_direct: bool, record: &ContactRecord) -> bool {
    native_direct
        && record.facts.peer_features & NATIVE_SLATES != 0
        && !super::private::is_private(record)
}

/// The `lepic.v1` bytes of a slate stored as V3 JSON.
fn native_body(network: Network, v3: &[u8]) -> Result<Vec<u8>, ContactError> {
    let slate = legacy_codecs(network)
        .map_err(ContactError::Receive)?
        .decode(&WireSlate::binary(MediaType::JSON, v3.to_vec()))
        .map_err(|_| ContactError::NotASlate)?;
    let native = NativeSlate::new(slate, Tail::empty()).map_err(|_| ContactError::NotASlate)?;
    Ok(native.encode(network))
}

/// `content`, a slate as V3 JSON, sealed to `card` as `lepic.v1` in a type `0A` envelope and
/// signed. A body over [`lepic_contact::MAX_BODY_LEN`] is [`ContactError::Encode`] with
/// [`lepic_contact::EncodeError::BodyTooLarge`] (RFC 0003 5.17).
pub(crate) fn seal_native(
    network: Network,
    card: &ContactCard,
    content: Content,
    signer: &SigningKey,
    rng: &mut LockedRng<'_>,
) -> Result<Vec<u8>, ContactError> {
    let tx = TxContent {
        body: native_body(network, &content.body)?,
        reply_key: content.reply_key,
        reply_mailbox: None,
        purpose: content.purpose,
        reference: content.reference,
        expires: content.expires,
        card: content.card,
        sent_at: content.sent_at,
        address_proof: content.address_proof,
        features: content.features,
        domain: content.domain,
    };
    seal_tx(
        super::keys::contact_network(network),
        card.enc_key(),
        TxKey::Seal(card.hint_rule()),
        &tx,
        Some(signer),
        rng,
    )
    .map_err(ContactError::Encode)
}

fn opened_of(opened: TxOpened) -> Opened {
    let content = opened.content;
    Opened {
        content: Content {
            kind: MessageType::Slate,
            body: content.body,
            reply_key: content.reply_key,
            purpose: content.purpose,
            reference: content.reference,
            expires: content.expires,
            card: content.card,
            sent_at: content.sent_at,
            address_proof: content.address_proof,
            features: content.features,
            domain: content.domain,
        },
        sender: opened.sender,
    }
}

/// Opens a base envelope with `key`, of type `0A` as well as the types of RFC 0002. The flag
/// says the body is a `lepic.v1` slate.
pub(crate) fn open_any(
    sealed: &SealedEnvelope<'_>,
    key: &EncSecretKey,
) -> Result<(Opened, bool), DecodeError> {
    match sealed.open(key) {
        Ok(opened) => Ok((opened, false)),
        // The types of RFC 0002 do not include 0A; only then is it tried as a native slate.
        Err(DecodeError::Malformed(_)) => sealed
            .open_tx(key, KeyClass::Seal)
            .map(|opened| (opened_of(opened), true)),
        Err(error) => Err(error),
    }
}

/// [`open_any`] for an envelope that must not be signed by another key than `expected`, as
/// [`SealedEnvelope::open_from`] opens one.
pub(crate) fn open_any_from(
    sealed: &SealedEnvelope<'_>,
    key: &EncSecretKey,
    expected: &VerifyingKey,
) -> Result<(Opened, bool), DecodeError> {
    let (opened, native) = open_any(sealed, key)?;
    if opened
        .sender
        .as_ref()
        .is_some_and(|sender| sender != expected)
    {
        return Err(DecodeError::KeyChanged);
    }
    Ok((opened, native))
}

/// A `lepic.v1` body decoded for `network`, refused when its tail holds a record a slate inside
/// an envelope never carries (RFC 0003 5.10).
pub(crate) fn decode_native(network: Network, body: &[u8]) -> Option<Slate> {
    let (slate, tail) = NativeSlate::decode(network, body).ok()?.into_parts();
    if tail.reply_key().is_some() || tail.reply_mailbox().is_some() {
        return None;
    }
    Some(slate)
}

/// The V3 JSON of a native slate: a proposal as it came, an answer completed from `request`,
/// the stored V3 JSON of the proposal it answers. The answer takes the request's inputs and
/// outputs and the initiator's message; an entry the answer repeats must be identical to the
/// stored one. `None` when the answer does not fit its request.
pub(crate) fn v3_of_native(
    network: Network,
    slate: Slate,
    request: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let codecs = legacy_codecs(network).ok()?;
    let slate = match (slate.stage(), request) {
        (Stage::S1 | Stage::I1, None) => slate,
        (Stage::S2 | Stage::I2, Some(request)) => {
            let request = codecs
                .decode(&WireSlate::binary(MediaType::JSON, request.to_vec()))
                .ok()?;
            completed(slate, &request)?
        }
        _ => return None,
    };
    let context = EncodeContext {
        block_header_version: network.params().block_header_version(slate.height()),
    };
    let wire = codecs.encode(LEGACY_V3_JSON, &slate, &context)?.ok()?;
    Some(wire.as_bytes().to_vec())
}

/// `answer` with the body and the initiator's message of `request`.
fn completed(answer: Slate, request: &Slate) -> Option<Slate> {
    let initiator = answer.flow().initiator();
    let message = request.participant(initiator)?.message.clone();
    let mut parts = answer.into_parts();
    let mut inputs = request.inputs().to_vec();
    for input in parts.inputs {
        match inputs
            .iter()
            .find(|held| held.commitment == input.commitment)
        {
            Some(held) if *held != input => return None,
            Some(_) => {}
            None => inputs.push(input),
        }
    }
    let mut outputs = request.outputs().to_vec();
    for output in parts.outputs {
        match outputs
            .iter()
            .find(|held| held.commitment == output.commitment)
        {
            Some(held) if *held != output => return None,
            Some(_) => {}
            None => outputs.push(output),
        }
    }
    parts.inputs = inputs;
    parts.outputs = outputs;
    let participant = match initiator {
        Role::Sender => parts.sender.as_mut(),
        Role::Receiver => parts.receiver.as_mut(),
    }?;
    participant.message = message;
    // The request's version info, which the stored stages of the slate share.
    parts.origin = request.origin().copied();
    Slate::from_parts(parts).ok()
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The V3 JSON of a `lepic.v1` body that came in an envelope, an answer completed from the
    /// request this wallet stored under its slate id. `None` for a body that does not decode,
    /// or an answer to no stored request or one it does not fit.
    pub(crate) async fn v3_of_native(&self, body: &[u8]) -> Result<Option<Vec<u8>>, ContactError> {
        let network = self.wallet.config().network;
        let Some(slate) = decode_native(network, body) else {
            return Ok(None);
        };
        let request_stage = match slate.stage() {
            Stage::S2 => SlateStage::Standard1,
            Stage::I2 => SlateStage::Invoice1,
            _ => return Ok(v3_of_native(network, slate, None)),
        };
        let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
        let session = self.wallet.session()?;
        let request = self
            .contact_work(move |_, _| {
                Ok(session
                    .store
                    .read(|repos| repos.slate(slate_id, request_stage))?)
            })
            .await?;
        Ok(request.and_then(|request: lepic_store::StoredSlate| {
            v3_of_native(network, slate, Some(&request.bytes))
        }))
    }
}
