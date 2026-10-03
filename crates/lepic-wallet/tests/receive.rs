//! Receive (S1 to S2): what it stores and the slates it rejects.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod support;

use lepic_keychain::{ExtKeyVersion, Identifier, Keychain, SwitchCommitment};
use lepic_primitives::amount::{Amount, Height};
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, OutputStatus, ParticipantId, SlateStage, StoreError, TxDirection, TxState,
    WalletStore,
};
use lepic_transport::file::FILE;
use lepic_transport::transport::TransportId;
use lepic_wallet::{ReceiveError, WalletError};
use receive_harness::*;
use serde_json::Value;
use support::fixed_time;
use uuid::Uuid;

#[test]
fn received_slate_is_stored_with_its_output_context_and_reply() {
    let case = "send_file_payment_proof";
    let (s1, transport) = delivered_s1(case);
    let s2 = vector(&format!("{case}_s2_v3"));
    let receiver = Receiver::new(&receiver_mnemonic(&s2), slate_height(&s1));
    let received = receiver.receive(transport, &json(&s1), None).unwrap();
    let slate_id = Uuid::from_bytes(*received.slate.id().as_bytes());
    let amount = received.slate.amount();

    let key_id = Identifier::new(3, [0, 0, 0, 0]).unwrap();
    let keychain = Keychain::from_seed(&receiver.seed, ExtKeyVersion::FLOONET).unwrap();
    let commitment = keychain
        .commit(amount.value(), &key_id, SwitchCommitment::Regular)
        .unwrap();
    let blinding = keychain
        .derive_key(amount.value(), &key_id, SwitchCommitment::Regular)
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

            let context = repos.context(slate_id, ParticipantId(1))?.unwrap();
            let mut expected = vec![1];
            expected.extend_from_slice(blinding.expose_bytes());
            expected.extend_from_slice(&[1; 32]);
            assert_eq!(context.expose(), expected.as_slice());

            let reply = repos.slate(slate_id, SlateStage::Standard2)?.unwrap();
            assert_eq!(reply.bytes, received.reply.as_bytes());
            assert_eq!(reply.codec, "legacy-v3");
            assert_eq!(repos.account(AccountIndex(0))?.unwrap().next_child, 1);
            Ok::<_, StoreError>(())
        })
        .unwrap();
}

#[test]
fn rejects_a_slate_id_already_received() {
    let (s1, transport) = delivered_s1("send_file_plain");
    let receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_file_plain_s2_v3")),
        slate_height(&s1),
    );
    let first = receiver.receive(transport, &json(&s1), None).unwrap();

    let error = receiver.receive(transport, &json(&s1), None).unwrap_err();

    assert!(
        matches!(
            error,
            ReceiveError::AlreadyReceived { slate_id, tx_id }
                if slate_id == first.slate.id() && tx_id == first.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(receiver.transaction_count(), 1);
    // Also over another method: the slate id, not the transport, identifies the payment.
    let epicbox_s1 = vector("send_epicbox_plain_s1_epicbox");
    let epicbox_receiver = Receiver::new(
        &receiver_mnemonic(&vector("send_epicbox_plain_s2_v3")),
        slate_height(&epicbox_s1),
    );
    epicbox_receiver
        .receive(EPICBOX, &json(&epicbox_s1), None)
        .unwrap();
    let error = epicbox_receiver
        .receive(EPICBOX, &json(&epicbox_s1), None)
        .unwrap_err();
    assert!(
        matches!(error, ReceiveError::AlreadyReceived { .. }),
        "{error:?}"
    );
}

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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
