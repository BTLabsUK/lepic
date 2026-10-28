//! Receive (S1 to S2): what it stores and the slates it rejects.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod support;

use lepic_keychain::{Identifier, Keychain, SwitchCommitment};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, OutputStatus, ParticipantId, SlateStage, StoreError, TxDirection, TxState,
    WalletStore,
};
use lepic_transport::file::FILE;
use lepic_transport::transport::TransportId;
use lepic_wallet::chain::SLATE_LEAD_BLOCKS;
use lepic_wallet::event::{AnsweredSlate, ReceivedTransaction};
use lepic_wallet::{Event, ReceiveError, WalletError};
use receive_harness::*;
use serde_json::Value;
use support::both_stores;
use support::fixed_time;
use uuid::Uuid;

both_stores!(received_slate_is_stored_with_its_output_and_reply_but_no_signing_keys);
fn received_slate_is_stored_with_its_output_and_reply_but_no_signing_keys() {
    let case = "send_file_payment_proof";
    let (s1, transport) = delivered_s1(case);
    let s2 = vector(&format!("{case}_s2_v3"));
    let receiver = Receiver::new(&receiver_mnemonic(&s2), slate_height(&s1));
    let start = receiver
        .store()
        .read(|repos| repos.account(AccountIndex(0)))
        .unwrap()
        .unwrap()
        .next_child;
    let received = receiver.receive(transport, &json(&s1), None).unwrap();
    let slate_id = Uuid::from_bytes(*received.slate.id().as_bytes());
    let amount = received.slate.amount();

    let key_id = Identifier::new(3, [0, 0, start, 0]).unwrap();
    let keychain = Keychain::from_seed(&receiver.seed, Network::Floonet).unwrap();
    let commitment = keychain
        .commit(amount.value(), &key_id, SwitchCommitment::Regular)
        .unwrap();

    receiver
        .store()
        .read(|repos| {
            let stored = repos
                .transaction_by_slate(slate_id, TxDirection::Incoming)?
                .unwrap();
            assert_eq!(stored.id, received.tx_id);
            assert_eq!(stored.entry.state, TxState::Received);
            assert_eq!(stored.entry.amount_credited, amount);
            assert_eq!(stored.entry.amount_debited, Amount::ZERO);
            assert_eq!(stored.entry.transport.as_deref(), Some("file"));
            assert_eq!(stored.entry.created_at, fixed_time());

            let outputs = repos.outputs_of_transaction(received.tx_id)?;
            assert_eq!(outputs.len(), 1);
            let output = &outputs[0];
            assert_eq!(output.commitment(), commitment.as_bytes());
            assert_eq!(output.key_id.0, key_id.to_bytes());
            assert_eq!(output.status, OutputStatus::Unconfirmed);
            assert_eq!(output.amount, amount);
            assert_eq!(output.height, received.slate.height());

            // The receiver never signs this kernel again, so its signing keys are not kept.
            assert!(repos.context(slate_id, ParticipantId(1))?.is_none());

            let reply = repos.slate(slate_id, SlateStage::Standard2)?.unwrap();
            assert_eq!(reply.bytes, received.reply.as_bytes());
            assert_eq!(reply.codec, "legacy-v3");
            assert_eq!(
                repos.account(AccountIndex(0))?.unwrap().next_child,
                start + 1
            );
            Ok::<_, StoreError>(())
        })
        .unwrap();
}

both_stores!(a_received_slate_announces_the_transaction_it_created);
fn a_received_slate_announces_the_transaction_it_created() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let mut events = receiver.wallet.subscribe();

    let received = receiver.receive(transport, &json(&s1), None).unwrap();

    let announced: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok()).collect();
    assert_eq!(
        announced,
        [Event::Received(ReceivedTransaction {
            tx_id: received.tx_id,
            account: AccountIndex(0),
            amount: received.slate.amount(),
            transport,
        })]
    );
}

both_stores!(a_repeated_slate_announces_only_that_it_was_answered_again);
fn a_repeated_slate_announces_only_that_it_was_answered_again() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let received = receiver.receive(transport, &json(&s1), None).unwrap();
    let mut events = receiver.wallet.subscribe();

    let again = receiver.receive(FILE, &json(&s1), None).unwrap();

    assert!(again.repeated);
    let announced: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok()).collect();
    assert_eq!(
        announced,
        [Event::AnsweredAgain(AnsweredSlate {
            tx_id: received.tx_id,
            slate_id: received.slate.id(),
            transport: FILE,
        })]
    );
}

both_stores!(a_slate_missing_a_field_states_the_cause_once);
fn a_slate_missing_a_field_states_the_cause_once() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let mut slate: Value = serde_json::from_str(&json(&s1)).unwrap();
    slate.as_object_mut().unwrap().remove("amount");

    let error = receiver
        .receive(transport, &slate.to_string(), None)
        .unwrap_err();

    assert!(matches!(error, ReceiveError::Decode(_)), "{error:?}");
    let chain = lepic_telemetry::ErrorChain(&error).to_string();
    assert_eq!(chain.matches("is missing").count(), 1, "{chain}");
    let mut layer: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(parent) = layer {
        if let Some(cause) = parent.source() {
            assert!(
                !parent.to_string().contains(&cause.to_string()),
                "{parent} repeats {cause}"
            );
        }
        layer = parent.source();
    }
}

both_stores!(a_repeated_slate_is_answered_with_the_stored_reply_and_stores_nothing);
fn a_repeated_slate_is_answered_with_the_stored_reply_and_stores_nothing() {
    // Over either method: the slate id, not the transport, identifies the payment.
    for case in ["send_file_plain", "send_epicbox_plain"] {
        let (s1, transport) = delivered_s1(case);
        let receiver = Receiver::new(
            &receiver_mnemonic(&vector(&format!("{case}_s2_v3"))),
            slate_height(&s1),
        );
        let first = receiver.receive(transport, &json(&s1), None).unwrap();
        let next_child = receiver.next_child();
        let node_calls = receiver.node.calls();

        let again = receiver
            .receive(transport, &json(&s1), Some("a different message"))
            .unwrap();

        assert!(!first.repeated, "{case}");
        assert!(again.repeated, "{case}");
        assert_eq!(again.tx_id, first.tx_id, "{case}");
        assert_eq!(again.slate.id(), first.slate.id(), "{case}");
        assert_eq!(again.reply.as_bytes(), first.reply.as_bytes(), "{case}");
        assert_eq!(receiver.transaction_count(), 1, "{case}");
        assert_eq!(receiver.next_child(), next_child, "{case}");
        assert_eq!(receiver.node.calls(), node_calls, "{case}");
    }
}

both_stores!(a_different_slate_under_a_received_id_is_refused);
fn a_different_slate_under_a_received_id_is_refused() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let first = receiver.receive(transport, &json(&s1), None).unwrap();
    assert!(
        receiver
            .receive(transport, &json(&s1), None)
            .unwrap()
            .repeated
    );
    let mut changed: Value = serde_json::from_str(&json(&s1)).unwrap();
    changed["amount"] = Value::String("1".to_owned());

    let error = receiver
        .receive(transport, &changed.to_string(), None)
        .unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::AlreadyReceived { slate_id, tx_id }
                if slate_id == first.slate.id() && tx_id == first.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(receiver.transaction_count(), 1);
}

both_stores!(two_receives_of_one_slate_at_once_store_it_once);
fn two_receives_of_one_slate_at_once_store_it_once() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let mut events = receiver.wallet.subscribe();

    let (a, b) = receiver.receive_twice_at_once(transport, &json(&s1));

    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.tx_id, b.tx_id);
    assert_ne!(a.repeated, b.repeated);
    assert_eq!(a.reply.as_bytes(), b.reply.as_bytes());
    assert_eq!(receiver.transaction_count(), 1);
    let announced: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok()).collect();
    assert_eq!(announced.len(), 2, "{announced:?}");
    assert!(announced.iter().any(|event| matches!(
        event,
        Event::Received(ReceivedTransaction { tx_id, .. }) if *tx_id == a.tx_id
    )));
    assert!(announced.contains(&Event::AnsweredAgain(AnsweredSlate {
        tx_id: a.tx_id,
        slate_id: a.slate.id(),
        transport,
    })));
}

both_stores!(an_expired_receive_is_not_answered_again);
fn an_expired_receive_is_not_answered_again() {
    let case = "send_file_ttl";
    let (s1, transport) = delivered_s1(case);
    let slate: Value = serde_json::from_str(&json(&s1)).unwrap();
    let cutoff: u64 = text(&slate["ttl_cutoff_height"]).parse().unwrap();
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector(&format!("{case}_s2_v3"))),
        cutoff - 1,
    );
    let first = receiver.receive(transport, &json(&s1), None).unwrap();
    receiver.refresh_at(cutoff);
    let state = receiver
        .store()
        .read(|repos| Ok::<_, StoreError>(repos.transaction(first.tx_id)?.unwrap().state))
        .unwrap();
    assert_eq!(state, TxState::Expired);
    let next_child = receiver.next_child();

    let error = receiver.receive(transport, &json(&s1), None).unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::AlreadyReceived { tx_id, .. } if tx_id == first.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(receiver.next_child(), next_child);
}

both_stores!(a_cancelled_receive_is_not_answered_again);
fn a_cancelled_receive_is_not_answered_again() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let first = receiver.receive(transport, &json(&s1), None).unwrap();
    assert!(
        receiver
            .receive(transport, &json(&s1), None)
            .unwrap()
            .repeated
    );
    receiver.cancel(first.tx_id);

    let error = receiver.receive(transport, &json(&s1), None).unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::AlreadyReceived { tx_id, .. } if tx_id == first.tx_id
        ),
        "{error:?}"
    );
}

both_stores!(rejects_a_slate_whose_ttl_the_tip_has_reached);
fn rejects_a_slate_whose_ttl_the_tip_has_reached() {
    let case = "send_file_ttl";
    let (s1, transport) = delivered_s1(case);
    let slate: Value = serde_json::from_str(&json(&s1)).unwrap();
    let cutoff: u64 = text(&slate["ttl_cutoff_height"]).parse().unwrap();
    let mnemonic = receiver_mnemonic(&vector(&format!("{case}_s2_v3")));

    for tip in [cutoff, cutoff + 1] {
        let receiver = Receiver::new(&mnemonic, tip);
        let error = receiver.receive(transport, &json(&s1), None).unwrap_err();
        assert!(
            matches!(
                error,
                ReceiveError::Expired { cutoff: at, tip: seen }
                    if at == Height::new(cutoff) && seen == Height::new(tip)
            ),
            "{error:?}"
        );
        assert_eq!(receiver.transaction_count(), 0);
    }
    let receiver = Receiver::new(&mnemonic, cutoff - 1);
    receiver.receive(transport, &json(&s1), None).unwrap();
}

/// The JSON of `s1` with its height set to `height`, in the type the vector writes it in.
fn s1_at_height(s1: &Value, height: u64) -> String {
    let mut slate: Value = serde_json::from_str(&json(s1)).unwrap();
    slate["height"] = match slate["height"] {
        Value::String(_) => Value::String(height.to_string()),
        _ => Value::from(height),
    };
    slate.to_string()
}

both_stores!(rejects_a_slate_created_far_above_the_tip_and_stores_nothing);
fn rejects_a_slate_created_far_above_the_tip_and_stores_nothing() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let tip = slate_height(&s1);
    let receiver = Receiver::new(&receiver_mnemonic(&vector("send_file_plain_s2_v3")), tip);
    let far = 1_000_000_000_000;

    let error = receiver
        .receive(transport, &s1_at_height(&s1, far), None)
        .unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::AheadOfTip { height, limit }
                if height == Height::new(far) && limit > Height::new(tip)
        ),
        "{error:?}"
    );
    assert_eq!(receiver.transaction_count(), 0);
}

both_stores!(receives_a_slate_created_above_a_lagging_node_tip);
fn receives_a_slate_created_above_a_lagging_node_tip() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let tip = slate_height(&s1);
    let mnemonic = receiver_mnemonic(&vector("send_file_plain_s2_v3"));

    // The sender's node is ahead of this wallet's, which lags by more than a few blocks.
    let receiver = Receiver::new(&mnemonic, tip);
    receiver
        .receive(
            transport,
            &s1_at_height(&s1, tip + 10 * SLATE_LEAD_BLOCKS),
            None,
        )
        .unwrap();
    assert_eq!(receiver.transaction_count(), 1);
}

both_stores!(rejects_a_slate_that_pays_nothing);
fn rejects_a_slate_that_pays_nothing() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let mut slate: Value = serde_json::from_str(&json(&s1)).unwrap();
    slate["amount"] = Value::String("0".to_owned());
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );

    let error = receiver
        .receive(transport, &slate.to_string(), None)
        .unwrap_err();

    assert!(matches!(error, ReceiveError::ZeroAmount), "{error:?}");
    assert_eq!(receiver.transaction_count(), 0);
}

both_stores!(a_restored_wallet_receives_only_after_its_restore_scan);
fn a_restored_wallet_receives_only_after_its_restore_scan() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::restored_without_scan(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );

    let error = receiver.receive(transport, &json(&s1), None).unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::Wallet(WalletError::RestoreScanRequired)
        ),
        "{error:?}"
    );
    assert_eq!(receiver.transaction_count(), 0);
    receiver.complete_restore_scan();
    receiver.receive(transport, &json(&s1), None).unwrap();
}

both_stores!(rejects_malformed_participant_data);
fn rejects_malformed_participant_data() {
    let receiver = Receiver::new(&receiver_mnemonic(&vector("send_file_plain_s2_v3")), 10);
    for name in [
        "malformed_duplicate_participant_id",
        "malformed_public_blind_excess_not_a_point",
        "malformed_part_sig_not_hex",
        "malformed_num_participants_zero",
    ] {
        let malformed = vector(name);
        let error = receiver
            .receive(FILE, text(&malformed["inputs"]["json"]), None)
            .unwrap_err();
        assert!(
            matches!(error, ReceiveError::Decode(_)),
            "{name}: {error:?}"
        );
    }
    assert_eq!(receiver.transaction_count(), 0);
}

both_stores!(rejects_a_sender_message_whose_signature_does_not_match);
fn rejects_a_sender_message_whose_signature_does_not_match() {
    let case = "send_file_messages";
    let (s1, transport) = delivered_s1(case);
    let original = json(&s1);
    let mut slate: Value = serde_json::from_str(&original).unwrap();
    let message = text(&slate["participant_data"][0]["message"]).to_owned();
    slate["participant_data"][0]["message"] = Value::String(format!("{message}!"));
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector(&format!("{case}_s2_v3"))),
        slate_height(&s1),
    );

    let error = receiver
        .receive(transport, &slate.to_string(), None)
        .unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::MessageSignature {
                role: Role::Sender,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(receiver.transaction_count(), 0);
    receiver.receive(transport, &original, None).unwrap();
}

both_stores!(rejects_a_payment_proof_for_another_receiver_address);
fn rejects_a_payment_proof_for_another_receiver_address() {
    let case = "send_file_payment_proof";
    let (s1, transport) = delivered_s1(case);
    let mut slate: Value = serde_json::from_str(&json(&s1)).unwrap();
    let sender_address = slate["payment_proof"]["sender_address"].clone();
    slate["payment_proof"]["receiver_address"] = sender_address;
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector(&format!("{case}_s2_v3"))),
        slate_height(&s1),
    );

    let error = receiver
        .receive(transport, &slate.to_string(), None)
        .unwrap_err();

    assert!(
        matches!(error, ReceiveError::ForeignProofAddress),
        "{error:?}"
    );
    assert_eq!(receiver.transaction_count(), 0);
}

both_stores!(rejects_slates_past_s1);
fn rejects_slates_past_s1() {
    let receiver = Receiver::new(&receiver_mnemonic(&vector("send_file_plain_s2_v3")), 10);
    for (name, stage) in [
        ("send_file_plain_s2_file", Stage::S2),
        ("send_file_plain_s3_file", Stage::S3),
        ("invoice_file_plain_i1_file", Stage::I1),
    ] {
        let error = receiver
            .receive(FILE, &json(&vector(name)), None)
            .unwrap_err();
        assert!(
            matches!(error, ReceiveError::WrongStage { stage: found } if found == stage),
            "{name}: {error:?}"
        );
    }
    assert_eq!(receiver.transaction_count(), 0);
}

both_stores!(rejects_an_unknown_transport_and_a_locked_wallet);
fn rejects_an_unknown_transport_and_a_locked_wallet() {
    let (s1, _) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let unknown = TransportId::new("carrier-pigeon");
    let error = receiver.receive(unknown, &json(&s1), None).unwrap_err();
    assert!(
        matches!(error, ReceiveError::UnknownTransport { transport } if transport == unknown),
        "{error:?}"
    );

    receiver.wallet.lock();
    let error = receiver.receive(FILE, &json(&s1), None).unwrap_err();
    assert!(
        matches!(error, ReceiveError::Wallet(WalletError::Locked)),
        "{error:?}"
    );
}

both_stores!(receiver_message_is_cut_to_256_bytes_and_signed);
fn receiver_message_is_cut_to_256_bytes_and_signed() {
    let case = "send_file_long_messages";
    let (s1, transport) = delivered_s1(case);
    let s2 = vector(&format!("{case}_s2_v3"));
    let long = responder_message(&s2).unwrap();
    assert!(long.len() > 256, "the case must carry a long message");
    let receiver = Receiver::new(&receiver_mnemonic(&s2), slate_height(&s1));

    let received = receiver
        .receive(transport, &json(&s1), Some(&long))
        .unwrap();

    let receiver_data = received.slate.participant(Role::Receiver).unwrap();
    let message = receiver_data.message.as_ref().unwrap();
    assert_eq!(message.text().len(), 256);
    assert!(long.starts_with(message.text()));
}

both_stores!(fee_error_text_carries_no_amounts);
fn fee_error_text_carries_no_amounts() {
    let text = ReceiveError::FeeBelowMinimum {
        fee: lepic_primitives::amount::Fee::new(123_456_789),
        minimum: lepic_primitives::amount::Fee::new(987_654_321),
    }
    .to_string();
    assert!(
        !text.contains("123456789") && !text.contains("987654321"),
        "{text}"
    );
}
