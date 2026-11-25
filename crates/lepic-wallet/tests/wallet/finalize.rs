// SPDX-License-Identifier: Apache-2.0
//! Finalizing: a LEPIC sender finalizes the S2 a LEPIC receiver returned, stores S3, drops its
//! private context and posts the transaction; a reply that does not answer the S1, or whose
//! signatures do not verify, is refused with nothing stored; finalizing and posting again are
//! harmless.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use crate::receive_harness;
use crate::send_support;
use crate::support;

use lepic_crypto::aggsig::calculate_partial_sig;
use lepic_crypto::{PublicKey, SecretKey};
use lepic_keychain::{Identifier, Keychain};
use lepic_legacy_slate::v2_json::V2JsonCodec;
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_node::Propagation;
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_primitives::validate::ValidationError;
use lepic_slate::codec::{Codec, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, SlateError};
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{SlateStage, TxId, TxState, WalletStore};
use lepic_transport::file::FILE;
use lepic_transport::transport::{Destination, Location};
use lepic_wallet::event::TransactionState;
use lepic_wallet::finalize::{FinalizeError, Posted, SlateField};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Event, ProofKey, ReceiveError, ReceiveRequest, WalletError};
use receive_harness::{Receiver, json, vector};
use send_support::{ACCOUNT, PEER, Sender, TIP, V2Only, legacy_codecs, uuid};
use serde_json::Value;
use std::sync::Arc;
use support::both_stores;

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
    let key = Keychain::from_mnemonic(RECEIVER_MNEMONIC, Network::Floonet)
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
    exchange_with(Sender::new(), request, receiver_message)
}

fn exchange_with(sender: Sender, request: SendRequest, receiver_message: Option<&str>) -> Exchange {
    exchange_replying(sender, request, |s1| reply(s1, receiver_message))
}

/// A sent transaction and the S2 `reply` answers its S1 with.
fn exchange_replying(
    sender: Sender,
    request: SendRequest,
    reply: impl FnOnce(&WireSlate) -> WireSlate,
) -> Exchange {
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            &sender.harness.method(),
            request,
            Delivery::Deliver {
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let (s1, _) = sender.received().unwrap();
    let s2 = reply(&s1);
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
        self.sender.harness.block_on(self.sender.wallet.finalize(
            &self.sender.harness.method(),
            s2,
            Propagation::Stem,
        ))
    }

    fn post(&self, tx_id: TxId) -> Result<Posted, FinalizeError> {
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

both_stores!(finalize_stores_s3_drops_the_context_and_posts_the_transaction);
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

both_stores!(finalize_verifies_and_keeps_a_requested_payment_proof);
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

/// The receiver's onion as a payment-proof address (ADR 0044).
fn receiver_onion_address() -> ProofAddress {
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    ProofAddress::from_bytes(*receiver.wallet.onion_key().unwrap().public_key()).unwrap()
}

/// What `receiver` answers `s1` with, its payment proof signed with `proof_key`.
fn receive_signed_with(
    receiver: &Receiver,
    s1: &WireSlate,
    proof_key: ProofKey,
) -> Result<WireSlate, ReceiveError> {
    receiver
        .receive_with(
            FILE,
            s1.as_text().unwrap(),
            ReceiveRequest {
                proof_key,
                ..ReceiveRequest::default()
            },
        )
        .map(|received| received.reply)
}

both_stores!(a_payment_proof_asked_for_the_onion_is_signed_with_the_onion_key_and_verifies);
fn a_payment_proof_asked_for_the_onion_is_signed_with_the_onion_key_and_verifies() {
    assert_ne!(receiver_onion_address(), receiver_address());
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    let exchange = exchange_replying(
        Sender::new(),
        SendRequest {
            payment_proof_recipient: Some(receiver_onion_address()),
            ..request()
        },
        |s1| receive_signed_with(&receiver, s1, ProofKey::Onion).unwrap(),
    );
    let finalized = exchange.finalize(&exchange.s2).unwrap();
    let proof = finalized.slate.payment_proof().unwrap();
    assert_eq!(proof.receiver_address, receiver_onion_address());
    assert!(proof.receiver_signature.is_some());
    assert_eq!(exchange.state(), TxState::Posted);
}

both_stores!(a_proof_key_signs_only_for_its_own_address);
fn a_proof_key_signs_only_for_its_own_address() {
    // Each key refuses the other's address, so a slate sent to one address cannot learn that
    // the other belongs to the same wallet.
    for (recipient, proof_key) in [
        (receiver_address(), ProofKey::Onion),
        (receiver_onion_address(), ProofKey::Payments),
    ] {
        let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
        exchange_replying(
            Sender::new(),
            SendRequest {
                payment_proof_recipient: Some(recipient),
                ..request()
            },
            |s1| {
                let error = receive_signed_with(&receiver, s1, proof_key).unwrap_err();
                assert!(
                    matches!(error, ReceiveError::ForeignProofAddress),
                    "{proof_key:?}: {error:?}"
                );
                s1.clone()
            },
        );
        assert_eq!(receiver.transaction_count(), 0);
    }
}

both_stores!(finalizing_the_same_s2_again_changes_nothing);
fn finalizing_the_same_s2_again_changes_nothing() {
    let exchange = exchange(request(), None);
    let first = exchange.finalize(&exchange.s2).unwrap();
    let mut events = exchange.sender.wallet.subscribe();

    let second = exchange.finalize(&exchange.s2).unwrap();

    assert!(first.pushed && !second.pushed);
    assert_eq!(
        lepic_wallet::Finalized {
            pushed: true,
            ..second
        },
        first
    );
    assert_eq!(exchange.pushed(), 1);
    assert_eq!(exchange.state(), TxState::Posted);
    assert!(transaction_events(&mut events).is_empty());
}

both_stores!(finalizing_the_same_s2_after_confirmation_changes_nothing);
fn finalizing_the_same_s2_after_confirmation_changes_nothing() {
    let exchange = exchange(request(), None);
    let first = exchange.finalize(&exchange.s2).unwrap();
    exchange
        .sender
        .store
        .write(|repos| {
            let mut entry = repos.transaction(exchange.tx_id)?.unwrap();
            entry.state = TxState::Confirmed;
            repos.update_transaction(exchange.tx_id, &entry)
        })
        .unwrap();
    let mut events = exchange.sender.wallet.subscribe();

    let second = exchange.finalize(&exchange.s2).unwrap();

    assert!(first.pushed && !second.pushed);
    assert_eq!(
        lepic_wallet::Finalized {
            pushed: true,
            ..second
        },
        first
    );
    assert_eq!(exchange.pushed(), 1);
    assert_eq!(exchange.state(), TxState::Confirmed);
    assert!(transaction_events(&mut events).is_empty());
    let other = reply(&exchange.s1, Some("a different reply"));
    assert!(matches!(
        exchange.finalize(&other).unwrap_err(),
        FinalizeError::AlreadyFinalized { .. }
    ));
}

both_stores!(another_s2_for_a_finalized_slate_is_refused);
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

both_stores!(a_failed_post_leaves_the_transaction_finalized_until_it_is_posted_again);
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

both_stores!(a_repeated_failed_post_raises_not_posted_once_and_a_good_post_does_not);
fn a_repeated_failed_post_raises_not_posted_once_and_a_good_post_does_not() {
    let exchange = exchange(request(), None);
    let mut events = exchange.sender.wallet.subscribe();
    let node = &exchange.sender.harness.node;
    node.fail_next("push_transaction", MockFailure::Unreachable);

    exchange.finalize(&exchange.s2).unwrap_err();
    node.fail_next("push_transaction", MockFailure::Unreachable);
    exchange.post(exchange.tx_id).unwrap_err();
    exchange.post(exchange.tx_id).unwrap();

    let mut raised = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let lepic_wallet::Event::NotPosted(not_posted) = event {
            raised.push(not_posted);
        }
    }
    // The second failure is the same as the first, so it tells the host nothing new.
    assert_eq!(raised.len(), 1, "{raised:?}");
    for not_posted in &raised {
        assert_eq!(not_posted.tx_id, exchange.tx_id);
        assert_eq!(not_posted.slate_id, exchange.slate_id);
        assert!(!not_posted.reason.is_empty());
    }
}

both_stores!(finalizing_again_after_a_failed_post_posts);
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

both_stores!(a_reply_with_a_changed_amount_is_refused);
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

fn proof_exchange() -> Exchange {
    exchange(
        SendRequest {
            payment_proof_recipient: Some(receiver_address()),
            ..request()
        },
        None,
    )
}

/// A reply that changes a field only the sender sets names that field, and nothing is stored.
fn assert_reply_change_is_a_mismatch(
    exchange: &Exchange,
    field: SlateField,
    change: impl FnOnce(&mut Value),
) {
    let error = exchange
        .finalize(&tampered(&exchange.s2, change))
        .unwrap_err();
    assert!(
        matches!(&error, FinalizeError::Mismatch { field: got } if *got == field),
        "{field}: {error:?}"
    );
    exchange.assert_untouched();
}

both_stores!(a_reply_with_a_changed_fee_is_refused);
fn a_reply_with_a_changed_fee_is_refused() {
    let exchange = exchange(request(), None);
    assert_reply_change_is_a_mismatch(&exchange, SlateField::Fee, |slate| {
        let fee: u64 = slate["fee"].as_str().unwrap().parse().unwrap();
        replace_number(&mut slate["fee"], fee + 1);
        replace_number(&mut slate["tx"]["body"]["kernels"][0]["fee"], fee + 1);
    });
}

both_stores!(a_reply_with_a_changed_lock_height_is_refused);
fn a_reply_with_a_changed_lock_height_is_refused() {
    let exchange = exchange(request(), None);
    assert_reply_change_is_a_mismatch(&exchange, SlateField::Lock, |slate| {
        slate["tx"]["body"]["kernels"][0]["features"] = Value::from("HeightLocked");
        replace_number(&mut slate["tx"]["body"]["kernels"][0]["lock_height"], 3);
        replace_number(&mut slate["lock_height"], 3);
    });
}

both_stores!(a_reply_with_other_inputs_is_refused);
fn a_reply_with_other_inputs_is_refused() {
    let exchange = exchange(request(), None);
    assert_reply_change_is_a_mismatch(&exchange, SlateField::Inputs, |slate| {
        slate["tx"]["body"]["inputs"].as_array_mut().unwrap().pop();
    });
}

both_stores!(a_reply_with_another_payment_proof_address_is_refused);
fn a_reply_with_another_payment_proof_address_is_refused() {
    // The two addresses swap places: both are valid keys, so the reply decodes.
    let exchange = proof_exchange();
    assert_reply_change_is_a_mismatch(&exchange, SlateField::PaymentProof, |slate| {
        let proof = &mut slate["payment_proof"];
        let sender = proof["sender_address"].clone();
        let receiver = proof["receiver_address"].clone();
        proof["sender_address"] = receiver;
        proof["receiver_address"] = sender;
    });
}

both_stores!(a_reply_whose_private_context_is_gone_is_refused);
fn a_reply_whose_private_context_is_gone_is_refused() {
    let exchange = exchange(request(), None);
    exchange
        .sender
        .store
        .write(|repos| repos.delete_context(uuid(exchange.slate_id), lepic_store::ParticipantId(0)))
        .unwrap();

    let error = exchange.finalize(&exchange.s2).unwrap_err();

    assert!(
        matches!(&error, FinalizeError::MissingContext { slate_id } if *slate_id == exchange.slate_id),
        "{error:?}"
    );
    assert_eq!(exchange.state(), TxState::Sent);
    assert!(!exchange.has_s3());
    assert_eq!(exchange.pushed(), 0);
}

both_stores!(a_wrong_receiver_partial_signature_is_refused);
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

both_stores!(a_receiver_message_that_does_not_match_its_signature_is_refused);
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

both_stores!(a_receiver_output_whose_range_proof_does_not_verify_is_refused);
fn a_receiver_output_whose_range_proof_does_not_verify_is_refused() {
    let exchange = exchange(request(), None);
    let receiver_commitment = exchange.sender.read(|repos| {
        let sent = repos.outputs(ACCOUNT, None)?;
        let s2 = legacy_codecs().decode(&exchange.s2).unwrap();
        Ok(s2
            .outputs()
            .iter()
            .find(|output| {
                !sent
                    .iter()
                    .any(|own| own.id.commitment == output.commitment)
            })
            .unwrap()
            .commitment
            .to_hex())
    });
    let broken = tampered(&exchange.s2, |slate| {
        let output = slate["tx"]["body"]["outputs"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|output| output["commit"] == receiver_commitment.as_str())
            .unwrap();
        let mut proof = output["proof"].as_str().unwrap().to_owned();
        let flipped = if proof.ends_with('0') { "1" } else { "0" };
        proof.replace_range(proof.len() - 1.., flipped);
        output["proof"] = Value::String(proof);
    });

    let error = exchange.finalize(&broken).unwrap_err();

    assert!(
        matches!(
            error,
            FinalizeError::InvalidTransaction(ValidationError::RangeProof(_))
        ),
        "{error:?}"
    );
    exchange.assert_untouched();
}

both_stores!(a_receiver_excess_that_does_not_match_its_output_is_refused);
fn a_receiver_excess_that_does_not_match_its_output_is_refused() {
    let exchange = exchange(request(), None);
    let s2 = legacy_codecs().decode(&exchange.s2).unwrap();
    let sender = s2.participant(Role::Sender).unwrap();
    // The receiver drew its nonce from the harness RNG, which repeats the byte 1.
    let receiver_nonce = SecretKey::from_array([1; 32]).unwrap();
    assert_eq!(
        s2.participant(Role::Receiver).unwrap().public_nonce,
        PublicKey::from_secret_key(&receiver_nonce).unwrap()
    );
    // Another key, with a partial signature that verifies for it, but not the key of the
    // receiver's output: only the kernel check of the final transaction can tell.
    let other_key = SecretKey::from_array([7; 32]).unwrap();
    let other_excess = PublicKey::from_secret_key(&other_key).unwrap();
    let nonce_sum = PublicKey::sum(&[
        sender.public_nonce,
        PublicKey::from_secret_key(&receiver_nonce).unwrap(),
    ])
    .unwrap();
    let excess_sum = PublicKey::sum(&[sender.public_blind_excess, other_excess]).unwrap();
    let signature = calculate_partial_sig(
        &other_key,
        &receiver_nonce,
        &nonce_sum,
        Some(&excess_sum),
        &s2.kernel_features().signature_message(),
    )
    .unwrap();
    let forged = tampered(&exchange.s2, |slate| {
        let receiver = receiver_entry(slate);
        receiver["public_blind_excess"] = Value::String(other_excess.to_hex());
        receiver["part_sig"] = Value::String(signature.to_compact_hex());
    });

    let error = exchange.finalize(&forged).unwrap_err();

    assert!(
        matches!(
            error,
            FinalizeError::InvalidTransaction(
                ValidationError::KernelSignature { .. } | ValidationError::KernelSum(_)
            )
        ),
        "{error:?}"
    );
    exchange.assert_untouched();
}

both_stores!(a_reply_without_the_requested_payment_proof_is_refused);
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

both_stores!(a_payment_proof_without_a_receiver_signature_is_refused);
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

both_stores!(a_wrong_payment_proof_signature_is_refused);
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

both_stores!(a_slate_past_its_ttl_is_not_finalized);
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

fn set_tip(exchange: &Exchange, height: u64) {
    exchange
        .sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(height));
}

fn is_expired_at(error: &FinalizeError, at: u64) -> bool {
    matches!(error, FinalizeError::Expired { cutoff, tip }
        if *cutoff == Height::new(TIP + 2) && *tip == Height::new(at))
}

both_stores!(a_send_past_its_local_cutoff_is_not_finalized_though_its_v2_slate_has_no_ttl);
fn a_send_past_its_local_cutoff_is_not_finalized_though_its_v2_slate_has_no_ttl() {
    let exchange = exchange_with(
        Sender::with_policy(Arc::new(V2Only)),
        SendRequest {
            local_ttl_blocks: Some(2),
            ..request()
        },
        None,
    );
    assert!(!exchange.s1.as_text().unwrap().contains("ttl_cutoff_height"));
    // The reply in the V2 shape, as a legacy Epicbox peer returns it.
    let s2 = legacy_codecs().decode(&exchange.s2).unwrap();
    assert_eq!(s2.ttl_cutoff_height(), None);
    let s2 = V2JsonCodec::new(Network::Floonet.params().default_base_fee())
        .encode(
            &s2,
            &EncodeContext {
                block_header_version: 6,
            },
        )
        .unwrap();

    set_tip(&exchange, TIP + 2);
    let error = exchange.finalize(&s2).unwrap_err();
    assert!(is_expired_at(&error, TIP + 2), "{error:?}");
    exchange.assert_untouched();

    set_tip(&exchange, TIP + 1);
    exchange.finalize(&s2).unwrap();
    assert_eq!(exchange.state(), TxState::Posted);
}

both_stores!(a_finalized_send_past_its_local_cutoff_is_not_pushed_again);
fn a_finalized_send_past_its_local_cutoff_is_not_pushed_again() {
    let exchange = exchange(
        SendRequest {
            local_ttl_blocks: Some(2),
            ..request()
        },
        None,
    );
    exchange
        .sender
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    exchange.finalize(&exchange.s2).unwrap_err();
    assert_eq!(exchange.state(), TxState::Finalized);

    set_tip(&exchange, TIP + 2);
    let error = exchange.post(exchange.tx_id).unwrap_err();
    assert!(is_expired_at(&error, TIP + 2), "{error:?}");
    let error = exchange.finalize(&exchange.s2).unwrap_err();
    assert!(is_expired_at(&error, TIP + 2), "{error:?}");
    assert_eq!(exchange.state(), TxState::Finalized);
    assert_eq!(exchange.pushed(), 0);

    set_tip(&exchange, TIP + 1);
    exchange.post(exchange.tx_id).unwrap();
    assert_eq!(exchange.state(), TxState::Posted);
    assert_eq!(exchange.pushed(), 1);

    set_tip(&exchange, TIP + 3);
    let error = exchange.post(exchange.tx_id).unwrap_err();
    assert!(is_expired_at(&error, TIP + 3), "{error:?}");
    assert_eq!(exchange.state(), TxState::Posted);
    assert_eq!(exchange.pushed(), 1);
}

both_stores!(the_earlier_of_the_slate_ttl_and_the_local_cutoff_applies);
fn the_earlier_of_the_slate_ttl_and_the_local_cutoff_applies() {
    for (ttl_blocks, local_ttl_blocks) in [(5, 2), (2, 5)] {
        let exchange = exchange(
            SendRequest {
                ttl_blocks: Some(ttl_blocks),
                local_ttl_blocks: Some(local_ttl_blocks),
                ..request()
            },
            None,
        );
        set_tip(&exchange, TIP + 2);

        let error = exchange.finalize(&exchange.s2).unwrap_err();

        assert!(is_expired_at(&error, TIP + 2), "{error:?}");
        exchange.assert_untouched();
    }
}

both_stores!(an_s1_or_a_reply_to_another_wallet_is_refused);
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

both_stores!(only_a_finalized_or_posted_transaction_is_posted);
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

both_stores!(a_cancelled_transaction_is_neither_finalized_nor_posted);
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

both_stores!(fee_error_text_carries_no_amounts);
fn fee_error_text_carries_no_amounts() {
    let text = FinalizeError::FeeBelowMinimum {
        fee: lepic_primitives::amount::Fee::new(123_456_789),
        minimum: lepic_primitives::amount::Fee::new(987_654_321),
    }
    .to_string();
    assert!(
        !text.contains("123456789") && !text.contains("987654321"),
        "{text}"
    );
}

/// The paid send of `exchange`, finalized and posted, its kernel mined three blocks below the
/// tip, then refreshed.
fn mine_the_payment(exchange: &Exchange) {
    exchange.finalize(&exchange.s2).unwrap();
    let kernel = exchange.sender.harness.node.pushed_transactions()[0].kernels()[0];
    exchange.sender.harness.node.update_chain(|chain| {
        chain.tip.height = Height::new(TIP + 3);
        chain.kernels.push(lepic_node::LocatedKernel {
            kernel,
            height: Height::new(TIP + 1),
            mmr_index: 99,
        });
    });
    exchange
        .sender
        .harness
        .block_on(exchange.sender.wallet.refresh())
        .unwrap();
}

both_stores!(an_s1_under_the_id_of_a_payment_made_is_refused);
fn an_s1_under_the_id_of_a_payment_made_is_refused() {
    // The peer was paid under this slate id. It builds an S1 of its own under the same id, so
    // that the incoming payment would read the old payment's slates and confirm off its kernel.
    let exchange = exchange(request(), None);
    mine_the_payment(&exchange);
    let other = Sender::new();
    other
        .harness
        .block_on(other.wallet.send(
            &other.harness.method(),
            SendRequest {
                slate_id: Some(exchange.slate_id),
                ..SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(7 * AMOUNT))
                }
            },
            Delivery::Deliver {
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let (fake_s1, _) = other.received().unwrap();

    let error = exchange
        .sender
        .harness
        .block_on(exchange.sender.wallet.receive(
            &exchange.sender.harness.method(),
            &fake_s1,
            ReceiveRequest::default(),
        ))
        .unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::AlreadyReceived { slate_id, tx_id }
                if slate_id == exchange.slate_id && tx_id == exchange.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(exchange.sender.transactions().len(), 1);
}

both_stores!(an_incoming_payment_never_confirms_off_a_send_under_its_slate_id);
fn an_incoming_payment_never_confirms_off_a_send_under_its_slate_id() {
    // An incoming entry under the slate id of a mined send, as a receipt from before receives
    // were refused under such an id: its own output confirms it, never the send's kernel.
    let exchange = exchange(request(), None);
    mine_the_payment(&exchange);
    let now = support::fixed_time();
    let incoming = exchange
        .sender
        .store
        .write(|repos| {
            repos.insert_transaction(&lepic_store::TransactionEntry {
                account: ACCOUNT,
                direction: lepic_store::TxDirection::Incoming,
                state: TxState::Received,
                slate_id: Some(uuid(exchange.slate_id)),
                transport: Some(FILE.as_str().to_owned()),
                amount_credited: Amount::new(7 * AMOUNT),
                amount_debited: Amount::ZERO,
                fee: None,
                created_at: now,
                updated_at: now,
            })
        })
        .unwrap();

    exchange
        .sender
        .harness
        .block_on(exchange.sender.wallet.refresh())
        .unwrap();

    let stored = exchange
        .sender
        .read(|repos| repos.transaction(incoming))
        .unwrap();
    assert_eq!(stored.state, TxState::Received);
}

both_stores!(the_wallet_receives_its_own_s1);
fn the_wallet_receives_its_own_s1() {
    // A payment to the wallet's own address comes back as its own S1 under the id of its send.
    let exchange = exchange(request(), None);

    let received = exchange
        .sender
        .harness
        .block_on(exchange.sender.wallet.receive(
            &exchange.sender.harness.method(),
            &exchange.s1,
            ReceiveRequest::default(),
        ))
        .unwrap();

    assert_ne!(received.tx_id, exchange.tx_id);
    assert_eq!(exchange.sender.transactions().len(), 2);
}

both_stores!(the_wallet_refuses_its_own_s1_after_cancelling_the_send);
fn the_wallet_refuses_its_own_s1_after_cancelling_the_send() {
    let exchange = exchange(request(), None);
    let sender = &exchange.sender;
    sender
        .harness
        .block_on(sender.wallet.cancel(exchange.tx_id))
        .unwrap();

    let error = sender
        .harness
        .block_on(sender.wallet.receive(
            &sender.harness.method(),
            &exchange.s1,
            ReceiveRequest::default(),
        ))
        .unwrap_err();

    assert!(
        matches!(error, ReceiveError::AlreadyReceived { tx_id, .. } if tx_id == exchange.tx_id),
        "{error:?}"
    );
    assert_eq!(sender.transactions().len(), 1);
}

both_stores!(the_wallet_takes_its_own_epic1_payment_at_its_epic1_address);
/// An epic1 payment is stored as an export; when the wallet pays its own epic1 link, the install
/// that sent it may be the one that collects its S1 at the epic1 address, and answers it.
fn the_wallet_takes_its_own_epic1_payment_at_its_epic1_address() {
    let sender = Sender::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send.slate");
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            &support::file(),
            request(),
            Delivery::Export {
                to: Location::File(path.clone()),
            },
        ))
        .unwrap();
    let s1 = WireSlate::text(MediaType::JSON, std::fs::read_to_string(&path).unwrap());

    let received = sender
        .harness
        .block_on(sender.wallet.receive(
            &support::file(),
            &s1,
            ReceiveRequest {
                proof_key: ProofKey::Epic1 { index: 0 },
                ..ReceiveRequest::default()
            },
        ))
        .unwrap();

    assert_ne!(received.tx_id, sent.tx_id);
    assert!(!received.repeated);
    assert_eq!(sender.transactions().len(), 2);
}

both_stores!(the_wallet_refuses_the_file_of_its_own_exported_send);
fn the_wallet_refuses_the_file_of_its_own_exported_send() {
    let sender = Sender::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send.slate");
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            &support::file(),
            request(),
            Delivery::Export {
                to: Location::File(path.clone()),
            },
        ))
        .unwrap();
    let s1 = WireSlate::text(MediaType::JSON, std::fs::read_to_string(&path).unwrap());

    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .receive(&support::file(), &s1, ReceiveRequest::default()),
        )
        .unwrap_err();

    assert!(
        matches!(error, ReceiveError::AlreadyReceived { tx_id, .. } if tx_id == sent.tx_id),
        "{error:?}"
    );
    assert_eq!(sender.transactions().len(), 1);
}

/// The paid send of `exchange` mined at `height`: its funding spent, its change and its kernel
/// on the chain, the tip at `height`.
fn mine_the_send_at(exchange: &Exchange, height: u64) {
    let sender = &exchange.sender;
    let kernel = sender.harness.node.pushed_transactions()[0].kernels()[0];
    let (funding, change) = funding_and_change(sender);
    sender.harness.node.update_chain(|chain| {
        for held in &mut chain.outputs {
            if held.commitment == funding.id.commitment {
                held.spent = true;
            }
        }
        support::mine_output(
            chain,
            lepic_node::mock::ChainOutput {
                commitment: change.id.commitment,
                features: change.id.features,
                proof: support::some_proof(),
                height: Height::new(height),
                mmr_index: 50,
                spent: false,
            },
        );
        chain.kernels.push(lepic_node::LocatedKernel {
            kernel,
            height: Height::new(height),
            mmr_index: 99,
        });
        chain.tip.height = Height::new(height);
    });
}

/// The sender's funding output and the change of its only send.
fn funding_and_change(sender: &Sender) -> (lepic_store::OutputRecord, lepic_store::OutputRecord) {
    let outputs = sender.outputs();
    let funding = outputs
        .iter()
        .find(|output| output.amount == Amount::new(send_support::FUNDING))
        .unwrap()
        .clone();
    let change = outputs
        .iter()
        .find(|output| output.id != funding.id)
        .unwrap()
        .clone();
    (funding, change)
}

both_stores!(a_payment_a_reorganisation_takes_off_the_chain_is_posted_again);
fn a_payment_a_reorganisation_takes_off_the_chain_is_posted_again() {
    let exchange = exchange(request(), None);
    exchange.finalize(&exchange.s2).unwrap();
    let sender = &exchange.sender;
    mine_the_send_at(&exchange, TIP + 1);
    sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert_eq!(state(sender, exchange.tx_id), TxState::Confirmed);
    let entries = sender.transactions().len();
    let pushes = sender.harness.node.pushed_transactions().len();
    let mut events = sender.wallet.subscribe();

    // Another branch replaces the block, past the blocks a posted send waits before it is pushed
    // again: the funding is unspent again, and neither the change nor the kernel exists.
    let (funding, change) = funding_and_change(sender);
    sender.harness.node.update_chain(|chain| {
        chain
            .outputs
            .retain(|held| held.commitment != change.id.commitment);
        for held in &mut chain.outputs {
            held.spent = false;
        }
        chain.kernels.clear();
        chain.tip.height = Height::new(TIP + 12);
    });
    sender.harness.block_on(sender.wallet.refresh()).unwrap();

    assert_eq!(state(sender, exchange.tx_id), TxState::Posted);
    assert_eq!(
        sender.read(|repos| repos.confirmed_height(exchange.tx_id)),
        None
    );
    let (funding_now, change_now) = funding_and_change(sender);
    assert_eq!(funding_now.status, lepic_store::OutputStatus::Locked);
    assert_eq!(change_now.status, lepic_store::OutputStatus::Unconfirmed);
    assert_eq!(change_now.mmr_index, None);
    assert_eq!(funding_now.id, funding.id);
    // The change is not taken for another wallet's spend.
    assert_eq!(sender.transactions().len(), entries);
    assert_eq!(
        sender.harness.node.pushed_transactions().len(),
        pushes + 1,
        "the reopened payment is pushed again"
    );
    let events: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok()).collect();
    assert!(
        events.contains(&Event::Transaction(TransactionState {
            tx_id: exchange.tx_id,
            from: TxState::Confirmed,
            to: TxState::Posted,
        })),
        "{events:?}"
    );

    // Mined again on the new branch, it is confirmed at its new height.
    mine_the_send_at(&exchange, TIP + 13);
    sender.harness.block_on(sender.wallet.refresh()).unwrap();

    assert_eq!(state(sender, exchange.tx_id), TxState::Confirmed);
    assert_eq!(
        sender.read(|repos| repos.confirmed_height(exchange.tx_id)),
        Some(Height::new(TIP + 13))
    );
    assert_eq!(sender.transactions().len(), entries);
}

both_stores!(a_confirmation_past_the_recheck_window_costs_no_kernel_lookup);
fn a_confirmation_past_the_recheck_window_costs_no_kernel_lookup() {
    let exchange = exchange(request(), None);
    exchange.finalize(&exchange.s2).unwrap();
    let sender = &exchange.sender;
    mine_the_send_at(&exchange, TIP + 1);
    sender.harness.block_on(sender.wallet.refresh()).unwrap();
    let (_, change) = funding_and_change(sender);
    // The change is spent, so no output of the payment shows it on chain any more.
    let spend_change = |tip: u64| {
        sender.harness.node.update_chain(|chain| {
            for held in &mut chain.outputs {
                if held.commitment == change.id.commitment {
                    held.spent = true;
                }
            }
            chain.tip.height = Height::new(tip);
        });
    };
    let kernel_lookups = || {
        sender
            .harness
            .node
            .calls()
            .iter()
            .filter(|call| *call == "get_kernel")
            .count()
    };

    let last_recheck = TIP + lepic_wallet::refresh::CONFIRMATION_RECHECK_BLOCKS;
    spend_change(last_recheck);
    let before = kernel_lookups();
    sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert_eq!(kernel_lookups(), before + 1, "checked on its last block");
    assert_eq!(state(sender, exchange.tx_id), TxState::Confirmed);

    spend_change(last_recheck + 1);
    let before = kernel_lookups();
    sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert_eq!(kernel_lookups(), before, "checked past the window");
    assert_eq!(state(sender, exchange.tx_id), TxState::Confirmed);
}

fn state(sender: &Sender, tx_id: TxId) -> TxState {
    sender.read(|repos| repos.transaction(tx_id)).unwrap().state
}
