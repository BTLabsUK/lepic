//! Finalizing: a LEPIC sender finalizes the S2 a LEPIC receiver returned, stores S3, drops its
//! private context and posts the transaction; a reply that does not answer the S1, or whose
//! signatures do not verify, is refused with nothing stored; finalizing and posting again are
//! harmless.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use lepic_keychain::{ExtKeyVersion, Identifier, Keychain};
use lepic_node::Propagation;
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::{Amount, Height};
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::error::{DecodeError, SlateError};
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_slate::stage::Stage;
use lepic_store::{SlateStage, TxId, TxState};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::event::TransactionState;
use lepic_wallet::finalize::{FinalizeError, SlateField};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Event, WalletError};
use receive_harness::{Receiver, json, vector};
use send_support::{ACCOUNT, PEER, Sender, TIP, uuid};
use serde_json::Value;
use support::LOOPBACK;

const AMOUNT: u64 = 100_000_000;

/// The receiver of the G-03 cases.
const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

fn request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

fn receiver_address() -> ProofAddress {
    let key = Keychain::from_mnemonic(RECEIVER_MNEMONIC, ExtKeyVersion::FLOONET)
        .unwrap()
        .payment_proof_key(&Identifier::new(2, [0, 0, 0, 0]).unwrap(), 0)
        .unwrap();
    ProofAddress::from_bytes(key.public_key()).unwrap()
}

/// A sent transaction and the S2 a LEPIC receiver answered it with.
struct Exchange {
    sender: Sender,
    tx_id: TxId,
    slate_id: SlateId,
    s1: WireSlate,
    s2: WireSlate,
}

fn exchange(request: SendRequest, receiver_message: Option<&str>) -> Exchange {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            request,
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let (s1, _) = sender.received().unwrap();
    let s2 = reply(&s1, receiver_message);
    Exchange {
        sender,
        tx_id: sent.tx_id,
        slate_id: sent.slate_id,
        s1,
        s2,
    }
}

/// The S2 a fresh LEPIC receiver returns for `s1`.
fn reply(s1: &WireSlate, message: Option<&str>) -> WireSlate {
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    receiver
        .receive(FILE, s1.as_text().unwrap(), message)
        .unwrap()
        .reply
}

impl Exchange {
    fn finalize(&self, s2: &WireSlate) -> Result<lepic_wallet::Finalized, FinalizeError> {
        self.sender
            .harness
            .block_on(self.sender.wallet.finalize(LOOPBACK, s2, Propagation::Stem))
    }

    fn post(&self, tx_id: TxId) -> Result<(), FinalizeError> {
        self.sender
            .harness
            .block_on(self.sender.wallet.post(tx_id, Propagation::Fluff))
    }

    fn state(&self) -> TxState {
        self.sender.transactions()[0].entry.state
    }

    fn has_s3(&self) -> bool {
        self.sender
            .read(|repos| repos.slate(uuid(self.slate_id), SlateStage::Standard3))
            .is_some()
    }

    fn pushed(&self) -> usize {
        self.sender.harness.node.pushed_transactions().len()
    }

    /// Nothing of a finalize was stored: the transaction still waits for its S2.
    fn assert_untouched(&self) {
        assert_eq!(self.state(), TxState::Sent);
        assert!(self.sender.has_sender_context(uuid(self.slate_id)));
        assert!(!self.has_s3());
        assert_eq!(self.pushed(), 0);
    }
}

/// `s2` with its JSON changed by `change`.
fn tampered(s2: &WireSlate, change: impl FnOnce(&mut Value)) -> WireSlate {
    let mut slate: Value = serde_json::from_str(s2.as_text().unwrap()).unwrap();
    change(&mut slate);
    WireSlate::text(MediaType::JSON, slate.to_string())
}

fn receiver_entry(slate: &mut Value) -> &mut Value {
    slate["participant_data"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|participant| participant["id"] == "1" || participant["id"] == 1)
        .unwrap()
}

/// Replaces a string-encoded number with another one, in whichever form the shape uses.
fn replace_number(field: &mut Value, value: u64) {
    *field = match field {
        Value::String(_) => Value::String(value.to_string()),
        _ => Value::from(value),
    };
}

fn transaction_events(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
) -> Vec<(TxState, TxState)> {
    let mut changes = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transaction(TransactionState { from, to, .. }) = event {
            changes.push((from, to));
        }
    }
    changes
}

#[test]
fn finalize_stores_s3_drops_the_context_and_posts_the_transaction() {
    let exchange = exchange(request(), Some("thanks"));
    let mut events = exchange.sender.wallet.subscribe();

    let finalized = exchange.finalize(&exchange.s2).unwrap();

    assert_eq!(finalized.tx_id, exchange.tx_id);
    assert_eq!(finalized.slate.id(), exchange.slate_id);
    assert_eq!(finalized.slate.stage(), Stage::S3);
    finalized.transaction.validate().unwrap();
    assert_eq!(
        exchange.sender.harness.node.pushed_transactions(),
        vec![finalized.transaction.clone()]
    );
    assert_eq!(exchange.state(), TxState::Posted);
    assert!(!exchange.sender.has_sender_context(uuid(exchange.slate_id)));
    let stored = exchange
        .sender
        .read(|repos| repos.slate(uuid(exchange.slate_id), SlateStage::Standard3))
        .unwrap();
    assert_eq!(stored.codec, LEGACY_V3_JSON.as_str());
    assert_eq!(
        transaction_events(&mut events),
        vec![
            (TxState::Sent, TxState::Finalized),
            (TxState::Finalized, TxState::Posted)
        ]
    );
}

#[test]
fn finalize_verifies_and_keeps_a_requested_payment_proof() {
    let exchange = exchange(
        SendRequest {
            payment_proof_recipient: Some(receiver_address()),
            ..request()
        },
        None,
    );
    let finalized = exchange.finalize(&exchange.s2).unwrap();
    let proof = finalized.slate.payment_proof().unwrap();
    assert_eq!(proof.receiver_address, receiver_address());
    assert!(proof.receiver_signature.is_some());
    assert_eq!(exchange.state(), TxState::Posted);
}

#[test]
fn finalizing_the_same_s2_again_changes_nothing() {
    let exchange = exchange(request(), None);
    let first = exchange.finalize(&exchange.s2).unwrap();
    let mut events = exchange.sender.wallet.subscribe();

    let second = exchange.finalize(&exchange.s2).unwrap();

    assert_eq!(second, first);
    assert_eq!(exchange.pushed(), 1);
    assert_eq!(exchange.state(), TxState::Posted);
    assert!(transaction_events(&mut events).is_empty());
}

#[test]
fn another_s2_for_a_finalized_slate_is_refused() {
    let exchange = exchange(request(), None);
    exchange.finalize(&exchange.s2).unwrap();
    let other = reply(&exchange.s1, Some("a different reply"));

    let error = exchange.finalize(&other).unwrap_err();

    assert!(
        matches!(
            error,
            FinalizeError::AlreadyFinalized { slate_id, tx_id }
                if slate_id == exchange.slate_id && tx_id == exchange.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(exchange.pushed(), 1);
}

#[test]
fn a_failed_post_leaves_the_transaction_finalized_until_it_is_posted_again() {
    let exchange = exchange(request(), None);
    exchange
        .sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);

    let error = exchange.finalize(&exchange.s2).unwrap_err();

    assert!(
        matches!(error, FinalizeError::NotPosted { tx_id, .. } if tx_id == exchange.tx_id),
        "{error:?}"
    );
    assert_eq!(exchange.state(), TxState::Finalized);
    assert!(exchange.has_s3());
    assert!(!exchange.sender.has_sender_context(uuid(exchange.slate_id)));
    assert_eq!(exchange.pushed(), 0);

    exchange.post(exchange.tx_id).unwrap();
    assert_eq!(exchange.state(), TxState::Posted);
    assert_eq!(exchange.pushed(), 1);

    // Posting a posted transaction sends it again and stores nothing new.
    let mut events = exchange.sender.wallet.subscribe();
    exchange.post(exchange.tx_id).unwrap();
    assert_eq!(exchange.state(), TxState::Posted);
    let pushed = exchange.sender.harness.node.pushed_transactions();
    assert_eq!(pushed.len(), 2);
    assert_eq!(pushed[0], pushed[1]);
    assert!(transaction_events(&mut events).is_empty());
}

#[test]
fn finalizing_again_after_a_failed_post_posts() {
    let exchange = exchange(request(), None);
    exchange
        .sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    exchange.finalize(&exchange.s2).unwrap_err();

    exchange.finalize(&exchange.s2).unwrap();

    assert_eq!(exchange.state(), TxState::Posted);
    assert_eq!(exchange.pushed(), 1);
}

#[test]
fn a_reply_with_a_changed_amount_is_refused() {
    let exchange = exchange(request(), None);
    let changed = tampered(&exchange.s2, |slate| {
        replace_number(&mut slate["amount"], AMOUNT + 1);
    });

    let error = exchange.finalize(&changed).unwrap_err();

    assert!(
        matches!(
            error,
            FinalizeError::Mismatch {
                field: SlateField::Amount
            }
        ),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn a_wrong_receiver_partial_signature_is_refused() {
    let exchange = exchange(request(), Some("signed"));
    // The receiver's message signature is a valid signature, but not over the kernel.
    let forged = tampered(&exchange.s2, |slate| {
        let receiver = receiver_entry(slate);
        receiver["part_sig"] = receiver["message_sig"].clone();
    });

    let error = exchange.finalize(&forged).unwrap_err();

    assert!(
        matches!(error, FinalizeError::ReceiverSignature(_)),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn a_receiver_message_that_does_not_match_its_signature_is_refused() {
    let exchange = exchange(request(), Some("signed"));
    let forged = tampered(&exchange.s2, |slate| {
        receiver_entry(slate)["message"] = Value::String("changed".to_owned());
    });

    let error = exchange.finalize(&forged).unwrap_err();

    assert!(
        matches!(error, FinalizeError::MessageSignature(_)),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn a_reply_without_the_requested_payment_proof_is_refused() {
    let exchange = exchange(
        SendRequest {
            payment_proof_recipient: Some(receiver_address()),
            ..request()
        },
        None,
    );
    let dropped = tampered(&exchange.s2, |slate| slate["payment_proof"] = Value::Null);

    let error = exchange.finalize(&dropped).unwrap_err();

    assert!(
        matches!(error, FinalizeError::MissingPaymentProof),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn a_payment_proof_without_a_receiver_signature_is_refused() {
    let exchange = exchange(
        SendRequest {
            payment_proof_recipient: Some(receiver_address()),
            ..request()
        },
        None,
    );
    let unsigned = tampered(&exchange.s2, |slate| {
        slate["payment_proof"]["receiver_signature"] = Value::Null;
    });

    let error = exchange.finalize(&unsigned).unwrap_err();

    assert!(
        matches!(
            error,
            FinalizeError::Decode(DecodeError::Model(SlateError::MissingProofSignature {
                stage: Stage::S2
            }))
        ),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn a_wrong_payment_proof_signature_is_refused() {
    let exchange = exchange(
        SendRequest {
            payment_proof_recipient: Some(receiver_address()),
            ..request()
        },
        None,
    );
    let forged = tampered(&exchange.s2, |slate| {
        let signature = &mut slate["payment_proof"]["receiver_signature"];
        let mut hex = signature.as_str().unwrap().to_owned();
        let flipped = if hex.starts_with('0') { "1" } else { "0" };
        hex.replace_range(0..1, flipped);
        *signature = Value::String(hex);
    });

    let error = exchange.finalize(&forged).unwrap_err();

    assert!(
        matches!(error, FinalizeError::PaymentProofSignature),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn a_slate_past_its_ttl_is_not_finalized() {
    let exchange = exchange(
        SendRequest {
            ttl_blocks: Some(2),
            ..request()
        },
        None,
    );
    exchange
        .sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 2));

    let error = exchange.finalize(&exchange.s2).unwrap_err();

    assert!(
        matches!(error, FinalizeError::Expired { cutoff, tip }
            if cutoff == Height::new(TIP + 2) && tip == Height::new(TIP + 2)),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn an_s1_or_a_reply_to_another_wallet_is_refused() {
    let exchange = exchange(request(), None);

    let error = exchange.finalize(&exchange.s1).unwrap_err();
    assert!(
        matches!(error, FinalizeError::WrongStage { stage: Stage::S1 }),
        "{error:?}"
    );

    let foreign = vector("send_file_plain_s2_file");
    let foreign = WireSlate::text(MediaType::JSON, json(&foreign));
    let error = exchange.finalize(&foreign).unwrap_err();
    assert!(
        matches!(error, FinalizeError::UnknownSlate { .. }),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn only_a_finalized_or_posted_transaction_is_posted() {
    let exchange = exchange(request(), None);

    let error = exchange.post(exchange.tx_id).unwrap_err();
    assert!(
        matches!(
            error,
            FinalizeError::NotPostable {
                state: TxState::Sent,
                ..
            }
        ),
        "{error:?}"
    );

    let error = exchange.post(TxId(99)).unwrap_err();
    assert!(
        matches!(
            error,
            FinalizeError::Wallet(WalletError::UnknownTransaction(TxId(99)))
        ),
        "{error:?}"
    );
    exchange.assert_untouched();
}

#[test]
fn a_cancelled_transaction_is_neither_finalized_nor_posted() {
    let exchange = exchange(request(), None);
    exchange
        .sender
        .harness
        .block_on(exchange.sender.wallet.cancel(exchange.tx_id))
        .unwrap();

    let error = exchange.finalize(&exchange.s2).unwrap_err();
    assert!(
        matches!(
            error,
            FinalizeError::NotFinalizable {
                state: TxState::Cancelled,
                ..
            }
        ),
        "{error:?}"
    );
    let error = exchange.post(exchange.tx_id).unwrap_err();
    assert!(
        matches!(
            error,
            FinalizeError::NotPostable {
                state: TxState::Cancelled,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(exchange.pushed(), 0);
}
