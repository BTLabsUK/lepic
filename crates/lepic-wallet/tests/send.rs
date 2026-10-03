//! Sending: the S1 is stored with its inputs locked before it is delivered, a slate the
//! transport cannot carry is refused with nothing stored, and a failed delivery can be retried.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod send_support;
mod support;

use std::sync::Arc;

use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::error::{EncodeError, Unrepresentable};
use lepic_slate::model::ProofAddress;
use lepic_slate::stage::Stage;
use lepic_store::{OutboxStatus, OutputStatus, SlateStage, TxDirection, TxState};
use lepic_transport::error::TransportError;
use lepic_transport::file::{FILE, FileTransport};
use lepic_transport::transport::{Destination, Location};
use lepic_wallet::WalletError;
use lepic_wallet::selection::{SelectionError, SelectionStrategy};
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use send_support::{
    ACCOUNT, FUNDING, NEXT_CHILD, PEER, SEND_FILE_PLAIN_S1, Sender, TIP, V2Only, uuid,
};
use support::LOOPBACK;

/// `send_file_plain`: 1 EPIC from the funding output, with one change output.
const AMOUNT: u64 = 100_000_000;
const FEE: u64 = 800_000;

fn request(amount: u64) -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(amount))
    }
}

fn to(destination: &str) -> Delivery {
    Delivery::Deliver {
        transport: LOOPBACK,
        to: Destination::new(destination.to_owned()),
    }
}

/// A valid ed25519 point to stand for a receiver's payment proof address.
fn receiver_address() -> ProofAddress {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    ProofAddress::from_bytes(bytes).unwrap()
}

#[test]
fn send_stores_the_s1_with_its_inputs_locked_and_delivers_it() {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(AMOUNT), to(PEER)))
        .unwrap();
    assert_eq!(sent.amount, Amount::new(AMOUNT));
    assert_eq!(sent.fee.value(), FEE);

    let (_, delivered) = sender.received().unwrap();
    assert_eq!(delivered.id(), sent.slate_id);
    assert_eq!(delivered.stage(), Stage::S1);
    assert_eq!(delivered.height(), Height::new(TIP));
    // Inputs, change and its proof derive from keys alone, so they equal upstream's S1 for the
    // same wallet and amount; only the id, offset, excess and nonce are random.
    let upstream: serde_json::Value = serde_json::from_str(
        serde_json::from_str::<serde_json::Value>(SEND_FILE_PLAIN_S1).unwrap()["expected"]["json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let body = &upstream["tx"]["body"];
    assert_eq!(delivered.inputs().len(), 1);
    assert_eq!(
        delivered.inputs()[0].commitment.to_hex(),
        body["inputs"][0]["commit"].as_str().unwrap()
    );
    assert_eq!(delivered.outputs().len(), 1);
    assert_eq!(
        delivered.outputs()[0].commitment.to_hex(),
        body["outputs"][0]["commit"].as_str().unwrap()
    );
    assert_eq!(
        delivered.outputs()[0].proof.to_hex(),
        body["outputs"][0]["proof"].as_str().unwrap()
    );

    let transactions = sender.transactions();
    assert_eq!(transactions.len(), 1);
    let tx = &transactions[0];
    assert_eq!(tx.id, sent.tx_id);
    assert_eq!(tx.entry.direction, TxDirection::Outgoing);
    assert_eq!(tx.entry.state, TxState::Sent);
    assert_eq!(tx.entry.slate_id, Some(uuid(sent.slate_id)));
    assert_eq!(tx.entry.transport.as_deref(), Some(LOOPBACK.as_str()));
    assert_eq!(tx.entry.amount_debited, Amount::new(FUNDING));
    assert_eq!(
        tx.entry.amount_credited,
        Amount::new(FUNDING - AMOUNT - FEE)
    );

    let outputs = sender.outputs();
    let input = outputs
        .iter()
        .find(|output| output.id.features == OutputFeatures::Coinbase)
        .unwrap();
    assert_eq!(input.status, OutputStatus::Locked);
    assert_eq!(input.tx, Some(sent.tx_id));
    let change = outputs
        .iter()
        .find(|output| output.status == OutputStatus::Unconfirmed)
        .unwrap();
    assert_eq!(change.amount, Amount::new(FUNDING - AMOUNT - FEE));
    assert_eq!(change.tx, Some(sent.tx_id));
    assert_eq!(change.id.commitment, delivered.outputs()[0].commitment);
    assert_eq!(sender.next_child(), NEXT_CHILD + 1);

    assert!(sender.has_sender_context(uuid(sent.slate_id)));
    let stored = sender
        .read(|repos| repos.slate(uuid(sent.slate_id), SlateStage::Standard1))
        .unwrap();
    assert_eq!(stored.codec, LEGACY_V3_JSON.as_str());
    let delivered_outbox = sender.outbox(OutboxStatus::Delivered);
    assert_eq!(delivered_outbox.len(), 1);
    assert_eq!(delivered_outbox[0].entry.attempts, 1);
    assert_eq!(delivered_outbox[0].entry.destination, PEER);
    assert!(sender.outbox(OutboxStatus::Pending).is_empty());
}

#[test]
fn send_writes_a_v2_file_unless_the_slate_needs_v3() {
    let sender = Sender::new();
    sender.fund(1, FUNDING);
    let plain = sender
        .harness
        .block_on(sender.wallet.send(request(AMOUNT), to(PEER)))
        .unwrap();
    let (wire, slate) = sender.received().unwrap();
    assert_eq!(slate.id(), plain.slate_id);
    assert!(wire.as_text().unwrap().starts_with(
        r#"{"version_info":{"version":2,"orig_version":2,"block_header_version":6},"#
    ));

    let with_ttl = SendRequest {
        ttl_blocks: Some(30),
        message: Some("x".repeat(300)),
        ..request(AMOUNT)
    };
    let sent = sender
        .harness
        .block_on(sender.wallet.send(with_ttl, to(PEER)))
        .unwrap();
    let (wire, slate) = sender.received().unwrap();
    assert_eq!(slate.id(), sent.slate_id);
    assert_eq!(slate.ttl_cutoff_height(), Some(Height::new(TIP + 30)));
    let message = slate
        .participant(lepic_slate::role::Role::Sender)
        .unwrap()
        .message
        .as_ref()
        .unwrap();
    assert_eq!(message.text(), "x".repeat(256));
    assert!(wire.as_text().unwrap().starts_with(
        r#"{"version_info":{"version":3,"orig_version":3,"block_header_version":6},"#
    ));
}

#[test]
fn send_exports_the_s1_to_a_file() {
    let sender = Sender::with_transports(vec![Box::new(FileTransport::new())]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send.slate");
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            request(AMOUNT),
            Delivery::Export {
                transport: FILE,
                to: Location::File(path.clone()),
            },
        ))
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(&sent.slate_id.to_string()));
    assert_eq!(
        sender.transactions()[0].entry.transport.as_deref(),
        Some("file")
    );
    assert!(sender.outbox(OutboxStatus::Pending).is_empty());
    assert!(sender.outbox(OutboxStatus::Delivered).is_empty());
}

#[test]
fn refuses_a_payment_proof_the_transport_cannot_carry_before_storing_anything() {
    let sender = Sender::with_policy(Arc::new(V2Only));
    let outputs_before = sender.outputs();
    for request in [
        SendRequest {
            payment_proof_recipient: Some(receiver_address()),
            ..request(AMOUNT)
        },
        SendRequest {
            ttl_blocks: Some(30),
            ..request(AMOUNT)
        },
    ] {
        let error = sender
            .harness
            .block_on(sender.wallet.send(request, to(PEER)))
            .unwrap_err();
        assert!(
            matches!(
                error,
                SendError::Unrepresentable(EncodeError::Unrepresentable {
                    what: Unrepresentable::PaymentProof | Unrepresentable::TimeToLive,
                    ..
                })
            ),
            "{error:?}"
        );
    }
    assert!(sender.transactions().is_empty());
    assert_eq!(sender.outputs(), outputs_before);
    assert_eq!(sender.next_child(), NEXT_CHILD);
    assert!(sender.outbox(OutboxStatus::Pending).is_empty());
    assert!(sender.received().is_none());

    // Without TTL or payment proof the V2 shape carries the slate.
    sender
        .harness
        .block_on(sender.wallet.send(request(AMOUNT), to(PEER)))
        .unwrap();
    let (wire, _) = sender.received().unwrap();
    assert!(wire.as_text().unwrap().starts_with(
        r#"{"version_info":{"version":3,"orig_version":3,"block_header_version":6},"#
    ));
}

#[test]
fn refuses_a_send_the_outputs_cannot_cover_before_storing_anything() {
    let sender = Sender::new();
    let error = sender
        .harness
        .block_on(sender.wallet.send(request(FUNDING), to(PEER)))
        .unwrap_err();
    assert!(
        matches!(
            error,
            SendError::Selection(SelectionError::NotEnoughFunds { .. })
        ),
        "{error:?}"
    );
    assert!(sender.transactions().is_empty());
    assert_eq!(sender.next_child(), NEXT_CHILD);
}

#[test]
fn refuses_a_transport_that_is_not_registered_or_cannot_deliver() {
    let sender = Sender::new();
    let unknown = sender
        .harness
        .block_on(sender.wallet.send(
            request(AMOUNT),
            Delivery::Deliver {
                transport: FILE,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap_err();
    assert!(
        matches!(
            unknown,
            SendError::UnknownTransport { transport } if transport == FILE
        ),
        "{unknown:?}"
    );
    let cannot_export = sender
        .harness
        .block_on(sender.wallet.send(
            request(AMOUNT),
            Delivery::Export {
                transport: LOOPBACK,
                to: Location::File("unused".into()),
            },
        ))
        .unwrap_err();
    assert!(
        matches!(cannot_export, SendError::CannotExport { .. }),
        "{cannot_export:?}"
    );
    assert!(sender.transactions().is_empty());
}

#[test]
fn a_failed_delivery_leaves_the_transaction_waiting_and_resend_delivers_it() {
    let sender = Sender::new();
    let error = sender
        .harness
        .block_on(sender.wallet.send(request(AMOUNT), to("nobody")))
        .unwrap_err();
    let SendError::Undelivered {
        tx_id,
        slate_id,
        source: TransportError::UnknownDestination { .. },
    } = error
    else {
        panic!("{error:?}");
    };
    let tx = &sender.transactions()[0];
    assert_eq!((tx.id, tx.entry.state), (tx_id, TxState::Sent));
    assert!(
        sender
            .outputs()
            .iter()
            .any(|output| output.status == OutputStatus::Locked && output.tx == Some(tx_id))
    );
    assert!(sender.has_sender_context(uuid(slate_id)));
    let pending = sender.outbox(OutboxStatus::Pending);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].entry.attempts, 1);
    assert!(sender.received().is_none());

    // The same destination again counts another attempt on the same outbox entry.
    let again = sender
        .harness
        .block_on(sender.wallet.resend(tx_id, to("nobody")))
        .unwrap_err();
    assert!(matches!(again, SendError::Undelivered { .. }));
    let pending = sender.outbox(OutboxStatus::Pending);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].entry.attempts, 2);

    sender
        .harness
        .block_on(sender.wallet.resend(tx_id, to(PEER)))
        .unwrap();
    let (_, delivered) = sender.received().unwrap();
    assert_eq!(delivered.id(), slate_id);
    assert_eq!(delivered.stage(), Stage::S1);
    assert_eq!(delivered.amount(), Amount::new(AMOUNT));
    assert_eq!(sender.outbox(OutboxStatus::Delivered).len(), 1);
    assert!(sender.outbox(OutboxStatus::Pending).is_empty());
    assert_eq!(sender.transactions().len(), 1);
}

#[test]
fn resend_refuses_a_transaction_that_is_not_waiting_for_delivery() {
    let sender = Sender::new();
    let unknown = sender
        .harness
        .block_on(sender.wallet.resend(lepic_store::TxId(9), to(PEER)))
        .unwrap_err();
    assert!(
        matches!(
            unknown,
            SendError::Wallet(WalletError::UnknownTransaction(lepic_store::TxId(9)))
        ),
        "{unknown:?}"
    );

    let sent = sender
        .harness
        .block_on(sender.wallet.send(request(AMOUNT), to(PEER)))
        .unwrap();
    sender
        .harness
        .block_on(sender.wallet.cancel(sent.tx_id))
        .unwrap();
    let cancelled = sender
        .harness
        .block_on(sender.wallet.resend(sent.tx_id, to(PEER)))
        .unwrap_err();
    assert!(
        matches!(
            cancelled,
            SendError::NotResendable { tx_id } if tx_id == sent.tx_id
        ),
        "{cancelled:?}"
    );
}

#[test]
fn send_needs_an_unlocked_wallet() {
    let sender = Sender::new();
    sender.wallet.lock();
    let error = sender
        .harness
        .block_on(sender.wallet.send(request(AMOUNT), to(PEER)))
        .unwrap_err();
    assert!(
        matches!(error, SendError::Wallet(WalletError::Locked)),
        "{error:?}"
    );
}
