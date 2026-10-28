// Portions Copyright 2019 The Epic Developers
// Ported from EpicCash/epic-wallet libwallet/src/api_impl/foreign.rs,
// libwallet/src/internal/tx.rs, libwallet/src/internal/selection.rs, libwallet/src/slate.rs
// (Apache-2.0); see NOTICE and upstream.toml.

//! A repeated S1: the relay hands a message out again when the app was suspended after storing
//! S2 and before acknowledging, and a user receives the same file again when the reply file was
//! lost. The receiver answers it with the S2 it stored, never a new one, so each inbound slate
//! stays idempotent on `(slate_id, stage)`.

use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{Repositories, SlateStage, StoreError, TxDirection, TxId, TxState};
use uuid::Uuid;

use super::{ReceiveError, Received, legacy_codecs};

/// The S2 this wallet stored when it received a slate, and the state its transaction is in now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredReply {
    pub(crate) tx_id: TxId,
    pub(crate) state: TxState,
    pub(crate) codec: String,
    pub(crate) bytes: Vec<u8>,
}

/// The stored S2 of the incoming transaction for `slate_id`, or `None` when this wallet has not
/// received that slate.
pub(crate) fn stored_reply(
    repos: &dyn Repositories,
    slate_id: SlateId,
) -> Result<Option<StoredReply>, StoreError> {
    let uuid = Uuid::from_bytes(*slate_id.as_bytes());
    let Some(transaction) = repos.transaction_by_slate(uuid, TxDirection::Incoming)? else {
        return Ok(None);
    };
    Ok(repos
        .slate(uuid, SlateStage::Standard2)?
        .map(|slate| StoredReply {
            tx_id: transaction.id,
            state: transaction.entry.state,
            codec: slate.codec,
            bytes: slate.bytes,
        }))
}

/// The stored S2 as a slate, decoded with the codec that wrote it.
pub(crate) fn decode_reply(network: Network, reply: &StoredReply) -> Result<Slate, ReceiveError> {
    let codecs = legacy_codecs(network)?;
    let codec = codecs
        .ids()
        .find(|id| id.as_str() == reply.codec)
        .and_then(|id| codecs.get(id))
        .ok_or(ReceiveError::Decode(DecodeError::UnknownFormat))?;
    codec
        .decode(&WireSlate::binary(MediaType::JSON, reply.bytes.clone()))
        .map_err(ReceiveError::Decode)
}

/// The stored S2 again, when this wallet received `proposal` before, or `None` when it has not
/// received its slate id. A different S1 under that id is refused, and so is one whose
/// transaction was cancelled or expired: cancelling released the output the reply pays to.
pub(crate) fn answer_again(
    repos: &dyn Repositories,
    network: Network,
    proposal: &Slate,
) -> Result<Option<Received>, ReceiveError> {
    let slate_id = proposal.id();
    let uuid = Uuid::from_bytes(*slate_id.as_bytes());
    let Some(transaction) = repos.transaction_by_slate(uuid, TxDirection::Incoming)? else {
        return Ok(None);
    };
    let refused = ReceiveError::AlreadyReceived {
        slate_id,
        tx_id: transaction.id,
    };
    let Some(stored) = stored_reply(repos, slate_id)? else {
        return Err(refused);
    };
    if matches!(stored.state, TxState::Cancelled | TxState::Expired) {
        return Err(refused);
    }
    let slate = decode_reply(network, &stored)?;
    if !answers(&slate, proposal) {
        return Err(refused);
    }
    let reply = match String::from_utf8(stored.bytes) {
        Ok(text) => WireSlate::text(MediaType::JSON, text),
        Err(error) => WireSlate::binary(MediaType::JSON, error.into_bytes()),
    };
    Ok(Some(Received {
        tx_id: stored.tx_id,
        slate,
        reply,
        repeated: true,
    }))
}

/// Whether `reply` is the S2 this wallet built from `proposal`: everything the sender proposed is
/// in it unchanged, plus exactly one output. Another S1 that reuses the slate id fails this and
/// stays refused. A proposal without an offset gets one drawn on receipt, so its offset is not
/// compared.
pub(crate) fn answers(reply: &Slate, proposal: &Slate) -> bool {
    let offset_kept = proposal.offset().is_zero() || reply.offset() == proposal.offset();
    let outputs_kept = reply.outputs().len() == proposal.outputs().len().saturating_add(1)
        && proposal
            .outputs()
            .iter()
            .all(|output| reply.outputs().contains(output));
    let proof_kept = match (reply.payment_proof(), proposal.payment_proof()) {
        (None, None) => true,
        (Some(reply), Some(proposal)) => {
            reply.sender_address == proposal.sender_address
                && reply.receiver_address == proposal.receiver_address
        }
        _ => false,
    };
    reply.stage() == Stage::S2
        && proposal.stage() == Stage::S1
        && reply.id() == proposal.id()
        && reply.amount() == proposal.amount()
        && reply.fee() == proposal.fee()
        && reply.height() == proposal.height()
        && reply.lock() == proposal.lock()
        && reply.ttl_cutoff_height() == proposal.ttl_cutoff_height()
        && reply.inputs() == proposal.inputs()
        && reply.participant(Role::Sender) == proposal.participant(Role::Sender)
        && offset_kept
        && outputs_kept
        && proof_kept
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and index (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use jiff::Timestamp;
    use lepic_primitives::amount::{Amount, Fee};
    use lepic_slate::codec::Codec;
    use lepic_slate::codec::legacy::v3_json::{LEGACY_V3_JSON, V3JsonCodec};
    use lepic_store::{
        AccountIndex, CONTEXT_KEY_LEN, ContextKey, MemoryStore, StoredSlate, TransactionEntry,
        TxState, WalletStore,
    };
    use serde_json::Value;

    use super::*;
    use crate::account::ensure_default_account;

    const S1: &str = include_str!(
        "../../../../testdata/vectors/slates/send_file_ttl_payment_proof_messages_s1_v3.json"
    );
    const S2: &str = include_str!(
        "../../../../testdata/vectors/slates/send_file_ttl_payment_proof_messages_s2_v3.json"
    );
    const OTHER_S1: &str =
        include_str!("../../../../testdata/vectors/slates/send_file_plain_s1_v3.json");

    fn vector_json(vector: &str) -> String {
        let vector: Value = serde_json::from_str(vector).unwrap();
        vector["expected"]["json"].as_str().unwrap().to_owned()
    }

    fn decode(json: &str) -> Slate {
        V3JsonCodec::new(Network::Floonet.params().default_base_fee())
            .decode(&WireSlate::text(MediaType::JSON, json.to_owned()))
            .unwrap()
    }

    fn with_field(json: &str, key: &str, value: &str) -> String {
        let mut slate: Value = serde_json::from_str(json).unwrap();
        slate[key] = Value::String(value.to_owned());
        slate.to_string()
    }

    #[test]
    fn the_g03_s2_answers_its_own_s1() {
        assert!(answers(
            &decode(&vector_json(S2)),
            &decode(&vector_json(S1))
        ));
    }

    #[test]
    fn a_different_s1_under_the_same_id_is_not_answered() {
        let reply = decode(&vector_json(S2));
        let proposal = vector_json(S1);
        for (key, value) in [
            ("amount", "1"),
            ("height", "3"),
            ("ttl_cutoff_height", "99"),
        ] {
            let changed = decode(&with_field(&proposal, key, value));
            assert!(!answers(&reply, &changed), "{key}");
        }
        let mut other = vector_json(OTHER_S1);
        other = with_field(&other, "id", &reply.id().to_string());
        assert!(!answers(&reply, &decode(&other)));
        assert!(!answers(&reply, &reply));
    }

    #[test]
    fn stored_reply_is_found_by_slate_id_and_decodes() {
        let store = MemoryStore::new(ContextKey::from_bytes([3; CONTEXT_KEY_LEN]));
        let reply_json = vector_json(S2);
        let slate = decode(&reply_json);
        let uuid = Uuid::from_bytes(*slate.id().as_bytes());
        let at = Timestamp::from_second(1_790_000_000).unwrap();
        let tx_id = store
            .write(|repos| {
                ensure_default_account(repos)?;
                let tx_id = repos.insert_transaction(&TransactionEntry {
                    account: AccountIndex(0),
                    direction: TxDirection::Incoming,
                    state: TxState::Received,
                    slate_id: Some(uuid),
                    transport: None,
                    amount_credited: slate.amount(),
                    amount_debited: Amount::ZERO,
                    fee: None::<Fee>,
                    created_at: at,
                    updated_at: at,
                })?;
                repos.insert_slate(&StoredSlate {
                    slate_id: uuid,
                    stage: SlateStage::Standard2,
                    codec: LEGACY_V3_JSON.as_str().to_owned(),
                    bytes: reply_json.clone().into_bytes(),
                })?;
                Ok::<_, crate::WalletError>(tx_id)
            })
            .unwrap();

        let stored = store
            .read(|repos| stored_reply(repos, slate.id()))
            .unwrap()
            .unwrap();
        assert_eq!(stored.tx_id, tx_id);
        assert_eq!(stored.bytes, reply_json.as_bytes());
        assert_eq!(decode_reply(Network::Floonet, &stored).unwrap(), slate);

        let unknown = SlateId::from_bytes([9; 16]);
        assert_eq!(
            store.read(|repos| stored_reply(repos, unknown)).unwrap(),
            None
        );
    }

    #[test]
    fn a_reply_under_an_unknown_codec_is_a_typed_error() {
        let reply = StoredReply {
            tx_id: TxId(1),
            state: TxState::Received,
            codec: "unknown".to_owned(),
            bytes: Vec::new(),
        };
        assert!(matches!(
            decode_reply(Network::Floonet, &reply),
            Err(ReceiveError::Decode(DecodeError::UnknownFormat))
        ));
    }
}
