// SPDX-License-Identifier: Apache-2.0
//! Sending: the S1 is stored with its inputs locked before it is delivered, a slate the
//! transport cannot carry is refused with nothing stored, and a failed delivery can be retried.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod send_support;
mod support;

use std::sync::{Arc, Mutex};

use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_slate::codec::WireSlate;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::error::{EncodeError, Unrepresentable};
use lepic_slate::model::{ProofAddress, SlateId};
use lepic_slate::stage::Stage;
use lepic_store::{OutboxStatus, OutputStatus, SlateStage, TxDirection, TxState, WalletStore};
use lepic_transport::error::TransportError;
use lepic_transport::file::FILE;
use lepic_transport::method::{Carries, Method};
use lepic_transport::policy::FormatPolicy;
use lepic_transport::transport::{
    BoxFuture, Destination, Location, Outbound, Transport, TransportId,
};
use lepic_wallet::WalletError;
use lepic_wallet::selection::{SelectionError, SelectionStrategy};
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use send_support::{
    ACCOUNT, FUNDING, NEXT_CHILD, PEER, SEND_FILE_PLAIN_S1, Sender, TIP, V2Only, uuid,
};
use support::both_stores;
use support::{LOOPBACK, TestStore};

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
        to: Destination::new(destination.to_owned()),
    }
}

/// A valid ed25519 point of large order (the base point) to stand for a receiver's payment proof
/// address.
fn receiver_address() -> ProofAddress {
    let mut bytes = [0x66u8; 32];
    bytes[0] = 0x58;
    ProofAddress::from_bytes(bytes).unwrap()
}

both_stores!(send_stores_the_s1_with_its_inputs_locked_and_delivers_it);
fn send_stores_the_s1_with_its_inputs_locked_and_delivers_it() {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to(PEER)),
        )
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

both_stores!(send_writes_a_v3_file_with_header_three_with_or_without_ttl);
fn send_writes_a_v3_file_with_header_three_with_or_without_ttl() {
    let sender = Sender::new();
    sender.fund(1, FUNDING);
    let plain = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to(PEER)),
        )
        .unwrap();
    let (wire, slate) = sender.received().unwrap();
    assert_eq!(slate.id(), plain.slate_id);
    let text = wire.as_text().unwrap();
    assert!(text.starts_with(
        r#"{"version_info":{"version":3,"orig_version":3,"block_header_version":6},"#
    ));
    assert!(text.contains(r#""ttl_cutoff_height":null"#));
    assert!(text.contains(r#""payment_proof":null"#));

    let with_ttl = SendRequest {
        ttl_blocks: Some(30),
        message: Some("x".repeat(300)),
        ..request(AMOUNT)
    };
    let sent = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), with_ttl, to(PEER)),
        )
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

both_stores!(send_exports_the_s1_to_a_file);
fn send_exports_the_s1_to_a_file() {
    let sender = Sender::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("send.slate");
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            &crate::support::file(),
            request(AMOUNT),
            Delivery::Export {
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

both_stores!(refuses_a_payment_proof_the_transport_cannot_carry_before_storing_anything);
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
            .block_on(
                sender
                    .wallet
                    .send(&sender.harness.method(), request, to(PEER)),
            )
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
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to(PEER)),
        )
        .unwrap();
    let (wire, _) = sender.received().unwrap();
    assert!(wire.as_text().unwrap().starts_with(
        r#"{"version_info":{"version":2,"orig_version":3,"block_header_version":6},"#
    ));
}

both_stores!(a_send_with_change_waits_for_the_restore_scan_of_a_rebuilt_database);
fn a_send_with_change_waits_for_the_restore_scan_of_a_rebuilt_database() {
    let sender = Sender::new();
    // As after a restore whose scan from genesis stopped part way: the funding output is
    // stored, the change key counter may still be behind keys in use on chain.
    sender
        .store
        .write(|repos| repos.put_setting("wallet.restore_scan_required", "true"))
        .unwrap();

    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to(PEER)),
        )
        .unwrap_err();

    assert!(
        matches!(error, SendError::Wallet(WalletError::RestoreScanRequired)),
        "{error:?}"
    );
    assert!(sender.transactions().is_empty());
    assert_eq!(sender.next_child(), NEXT_CHILD);
    assert!(sender.received().is_none());
}

both_stores!(a_send_with_a_given_slate_id_is_made_once);
fn a_send_with_a_given_slate_id_is_made_once() {
    let sender = Sender::new();
    let slate_id = SlateId::from_random_bytes([7; 16]);
    let once = SendRequest {
        slate_id: Some(slate_id),
        ..request(AMOUNT)
    };
    let sent = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), once.clone(), to(PEER)),
        )
        .unwrap();
    assert_eq!(sent.slate_id, slate_id);
    assert_eq!(sender.received().unwrap().1.id(), slate_id);

    // The funding output is locked by now, so only a check made before selection names the
    // first send instead of failing for funds.
    let error = sender
        .harness
        .block_on(sender.wallet.send(&sender.harness.method(), once, to(PEER)))
        .unwrap_err();
    assert!(
        matches!(
            error,
            SendError::SlateIdTaken { slate_id: taken, sent: Some(tx_id) }
                if taken == slate_id && tx_id == sent.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(sender.transactions().len(), 1);
    assert_eq!(sender.next_child(), NEXT_CHILD + 1);
    assert_eq!(sender.outbox(OutboxStatus::Delivered).len(), 1);
}

both_stores!(refuses_a_send_the_outputs_cannot_cover_before_storing_anything);
fn refuses_a_send_the_outputs_cannot_cover_before_storing_anything() {
    let sender = Sender::new();
    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(FUNDING), to(PEER)),
        )
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

both_stores!(refuses_a_method_that_cannot_deliver_or_cannot_export);
fn refuses_a_method_that_cannot_deliver_or_cannot_export() {
    let sender = Sender::new();
    let cannot_deliver = sender
        .harness
        .block_on(sender.wallet.send(
            &crate::support::file(),
            request(AMOUNT),
            Delivery::Deliver {
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap_err();
    assert!(
        matches!(
            cannot_deliver,
            SendError::CannotDeliver { transport } if transport == FILE
        ),
        "{cannot_deliver:?}"
    );
    let cannot_export = sender
        .harness
        .block_on(sender.wallet.send(
            &sender.harness.method(),
            request(AMOUNT),
            Delivery::Export {
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

both_stores!(a_failed_delivery_leaves_the_transaction_waiting_and_resend_delivers_it);
fn a_failed_delivery_leaves_the_transaction_waiting_and_resend_delivers_it() {
    let sender = Sender::new();
    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to("nobody")),
        )
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
        .block_on(
            sender
                .wallet
                .resend(&sender.harness.method(), tx_id, to("nobody")),
        )
        .unwrap_err();
    assert!(matches!(again, SendError::Undelivered { .. }));
    let pending = sender.outbox(OutboxStatus::Pending);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].entry.attempts, 2);

    sender
        .harness
        .block_on(
            sender
                .wallet
                .resend(&sender.harness.method(), tx_id, to(PEER)),
        )
        .unwrap();
    let (_, delivered) = sender.received().unwrap();
    assert_eq!(delivered.id(), slate_id);
    assert_eq!(delivered.stage(), Stage::S1);
    assert_eq!(delivered.amount(), Amount::new(AMOUNT));
    assert_eq!(sender.outbox(OutboxStatus::Delivered).len(), 1);
    assert!(sender.outbox(OutboxStatus::Pending).is_empty());
    assert_eq!(sender.transactions().len(), 1);
}

both_stores!(a_send_is_undelivered_while_every_attempt_failed);
fn a_send_is_undelivered_while_every_attempt_failed() {
    let sender = Sender::new();
    let undelivered = |tx_id| {
        sender
            .harness
            .block_on(sender.wallet.transaction_details(tx_id))
            .unwrap()
            .undelivered
    };
    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to("nobody")),
        )
        .unwrap_err();
    let SendError::Undelivered { tx_id, .. } = error else {
        panic!("{error:?}");
    };
    assert!(undelivered(tx_id));

    sender
        .harness
        .block_on(
            sender
                .wallet
                .resend(&sender.harness.method(), tx_id, to(PEER)),
        )
        .unwrap();
    assert!(!undelivered(tx_id));

    let other = Sender::new();
    let delivered = other
        .harness
        .block_on(
            other
                .wallet
                .send(&other.harness.method(), request(AMOUNT), to(PEER)),
        )
        .unwrap();
    let details = other
        .harness
        .block_on(other.wallet.transaction_details(delivered.tx_id))
        .unwrap();
    assert!(!details.undelivered);
}

both_stores!(resend_refuses_a_transaction_that_is_not_waiting_for_delivery);
fn resend_refuses_a_transaction_that_is_not_waiting_for_delivery() {
    let sender = Sender::new();
    let unknown = sender
        .harness
        .block_on(
            sender
                .wallet
                .resend(&sender.harness.method(), lepic_store::TxId(9), to(PEER)),
        )
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
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to(PEER)),
        )
        .unwrap();
    sender
        .harness
        .block_on(sender.wallet.cancel(sent.tx_id))
        .unwrap();
    let cancelled = sender
        .harness
        .block_on(
            sender
                .wallet
                .resend(&sender.harness.method(), sent.tx_id, to(PEER)),
        )
        .unwrap_err();
    assert!(
        matches!(
            cancelled,
            SendError::NotResendable { tx_id } if tx_id == sent.tx_id
        ),
        "{cancelled:?}"
    );
}

both_stores!(send_needs_an_unlocked_wallet);
fn send_needs_an_unlocked_wallet() {
    let sender = Sender::new();
    sender.wallet.lock();
    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request(AMOUNT), to(PEER)),
        )
        .unwrap_err();
    assert!(
        matches!(error, SendError::Wallet(WalletError::Locked)),
        "{error:?}"
    );
}

/// What a delivering transport saw in the sender's store while it delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenAtDelivery {
    input: OutputStatus,
    state: TxState,
    s1_stored: bool,
    outbox_pending: usize,
}

/// A transport that, when asked to deliver, reads the sender's store instead of sending.
struct Observer {
    store: Arc<Mutex<Option<TestStore>>>,
    seen: Arc<Mutex<Option<SeenAtDelivery>>>,
}

const OBSERVER: TransportId = TransportId::new("observer");

impl Transport for Observer {
    fn id(&self) -> TransportId {
        OBSERVER
    }

    fn policy(&self) -> &dyn FormatPolicy {
        &lepic_transport::file::FilePolicy
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }
}

impl Method for Observer {
    fn carries(&self) -> Carries {
        Carries::default()
    }

    fn notice_lengths(&self) -> &'static [usize] {
        &[]
    }
}

impl Outbound for Observer {
    fn deliver<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let seen = self
                .store
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .read(|repos| {
                    let tx = repos.transactions(ACCOUNT)?.remove(0);
                    let input = repos
                        .outputs(ACCOUNT, None)?
                        .into_iter()
                        .find(|output| output.id.features == OutputFeatures::Coinbase)
                        .unwrap();
                    Ok::<_, lepic_store::StoreError>(SeenAtDelivery {
                        input: input.status,
                        state: tx.entry.state,
                        s1_stored: repos
                            .slate(tx.entry.slate_id.unwrap(), SlateStage::Standard1)?
                            .is_some(),
                        outbox_pending: repos.outbox(OutboxStatus::Pending)?.len(),
                    })
                })
                .unwrap();
            *self.seen.lock().unwrap() = Some(seen);
            Ok(())
        })
    }
}

both_stores!(inputs_are_locked_and_the_s1_stored_before_the_transport_is_called);
fn inputs_are_locked_and_the_s1_stored_before_the_transport_is_called() {
    let store = Arc::new(Mutex::new(None));
    let seen = Arc::new(Mutex::new(None));
    let sender = Sender::new();
    let observer: Arc<dyn Method> = Arc::new(Observer {
        store: Arc::clone(&store),
        seen: Arc::clone(&seen),
    });
    *store.lock().unwrap() = Some(
        lepic_wallet::StoreOpener::open(
            &sender.harness.stores,
            &sender.harness.data_dir,
            lepic_store::StoreKeys::from_bytes([0; 32], [0; 32]),
            &lepic_store::StoreKey::from_bytes([0; 32]),
        )
        .unwrap(),
    );
    sender
        .harness
        .block_on(sender.wallet.send(
            &observer,
            request(AMOUNT),
            Delivery::Deliver {
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().clone(),
        Some(SeenAtDelivery {
            input: OutputStatus::Locked,
            state: TxState::Sent,
            s1_stored: true,
            outbox_pending: 1,
        })
    );
}
