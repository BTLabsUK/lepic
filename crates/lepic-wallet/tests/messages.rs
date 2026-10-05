//! Participant messages in the transaction details: each party sees the messages of the latest
//! stored stage whose signatures verify, a sender's message is cut on a character boundary
//! before it is signed, and a message that does not verify is left out.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_slate::codec::WireSlate;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::model::MAX_MESSAGE_LEN;
use lepic_slate::role::Role;
use lepic_store::{SlateStage, StoredSlate, TxId, WalletStore};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::details::SlateMessage;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use receive_harness::Receiver;
use send_support::{ACCOUNT, PEER, Sender, TIP};
use serde_json::Value;
use support::LOOPBACK;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

fn request(message: &str) -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        message: Some(message.to_owned()),
        ..SendRequest::new(ACCOUNT, Amount::new(100_000_000))
    }
}

fn message(role: Role, text: &str) -> SlateMessage {
    SlateMessage {
        role,
        text: text.to_owned(),
    }
}

/// A sender that sent `text` and the S1 it sent.
fn sent(text: &str) -> (Sender, TxId, WireSlate) {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            request(text),
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let (s1, _) = sender.received().unwrap();
    (sender, sent.tx_id, s1)
}

fn sender_messages(sender: &Sender, tx_id: TxId) -> Vec<SlateMessage> {
    sender
        .harness
        .block_on(sender.wallet.transaction_details(tx_id))
        .unwrap()
        .messages
}

fn receiver_messages(receiver: &Receiver, tx_id: TxId) -> Vec<SlateMessage> {
    receiver
        .block_on(receiver.wallet.transaction_details(tx_id))
        .unwrap()
        .messages
}

#[test]
fn a_long_message_is_cut_on_a_character_boundary_and_verifies() {
    // Three bytes each, so the byte limit falls inside a character.
    let long = "€".repeat(100);
    assert!(long.len() > MAX_MESSAGE_LEN);
    let cut = "€".repeat(MAX_MESSAGE_LEN / 3);

    let (sender, tx_id, s1) = sent(&long);

    assert_eq!(
        sender_messages(&sender, tx_id),
        [message(Role::Sender, &cut)]
    );
    // The receiver refuses an S1 whose message does not verify.
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    let received = receiver.receive(FILE, s1.as_text().unwrap(), None).unwrap();
    assert_eq!(
        receiver_messages(&receiver, received.tx_id),
        [message(Role::Sender, &cut)]
    );
}

#[test]
fn the_receiver_sees_both_messages_after_a_file_receive() {
    let (_sender, _, s1) = sent("for the pizza");
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);

    let received = receiver
        .receive(FILE, s1.as_text().unwrap(), Some("got it"))
        .unwrap();

    assert_eq!(
        receiver_messages(&receiver, received.tx_id),
        [
            message(Role::Sender, "for the pizza"),
            message(Role::Receiver, "got it"),
        ]
    );
}

#[test]
fn the_sender_sees_both_messages_after_finalize() {
    let (sender, tx_id, s1) = sent("for the pizza");
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    let s2 = receiver
        .receive(FILE, s1.as_text().unwrap(), Some("got it"))
        .unwrap()
        .reply;
    assert_eq!(
        sender_messages(&sender, tx_id),
        [message(Role::Sender, "for the pizza")]
    );

    sender
        .harness
        .block_on(sender.wallet.finalize(LOOPBACK, &s2, Propagation::Fluff))
        .unwrap();

    assert_eq!(
        sender_messages(&sender, tx_id),
        [
            message(Role::Sender, "for the pizza"),
            message(Role::Receiver, "got it"),
        ]
    );
}

#[test]
fn a_message_whose_signature_does_not_verify_is_not_shown() {
    let (sender, tx_id, s1) = sent("for the pizza");
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    let s2 = receiver
        .receive(FILE, s1.as_text().unwrap(), Some("got it"))
        .unwrap()
        .reply;
    let mut forged: Value = serde_json::from_str(s2.as_text().unwrap()).unwrap();
    for participant in forged["participant_data"].as_array_mut().unwrap() {
        if participant["message"] == "got it" {
            participant["message"] = Value::from("changed");
        }
    }
    let slate_id = sender.transactions()[0].entry.slate_id.unwrap();
    sender
        .store
        .write(|repos| {
            repos.insert_slate(&StoredSlate {
                slate_id,
                stage: SlateStage::Standard2,
                codec: LEGACY_V3_JSON.as_str().to_owned(),
                bytes: forged.to_string().into_bytes(),
            })
        })
        .unwrap();

    assert_eq!(
        sender_messages(&sender, tx_id),
        [message(Role::Sender, "for the pizza")]
    );
}

#[test]
fn a_send_without_a_message_shows_none() {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            SendRequest {
                message: None,
                ..request("")
            },
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();

    assert!(sender_messages(&sender, sent.tx_id).is_empty());
}

#[test]
fn a_message_is_shown_without_control_or_bidirectional_characters() {
    let (sender, tx_id, s1) = sent("pay \u{202E}evil\u{2069}\nnow");
    // The signed text keeps every character; only what the host sees loses them.
    let signed: Value = serde_json::from_str(s1.as_text().unwrap()).unwrap();
    assert_eq!(
        signed["participant_data"][0]["message"],
        "pay \u{202E}evil\u{2069}\nnow"
    );

    assert_eq!(
        sender_messages(&sender, tx_id),
        [message(Role::Sender, "pay evilnow")]
    );
}
