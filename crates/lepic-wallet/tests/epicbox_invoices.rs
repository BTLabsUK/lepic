//! Invoices over Epicbox between two LEPIC wallets on the mock relay: the payer pays or
//! declines a parked invoice, the issuer finalizes and posts the payment, recognises an invoice
//! a stock wallet sent back, and both sides expire what was left unpaid.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use lepic_epicbox::marker::v3::carries_lepic_marker;
use lepic_epicbox::{EpicboxClient, TRANSPORT_ID};
use lepic_node::Propagation;
use lepic_primitives::amount::{Amount, Height};
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, EncodeContext};
use lepic_slate::stage::Stage;
use lepic_store::{
    OutputStatus, PeerSupport, PendingInvoiceStatus, SlateStage, TxDirection, TxState,
};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::Event;
use lepic_wallet::details::TxFlow;
use lepic_wallet::epicbox_invoice::{InvoiceExpiry, PeerInvoiceSupport};
use lepic_wallet::event::BouncedInvoice;
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet::invoice::{INVOICE_TTL_MARGIN_BLOCKS, InvoiceError, PayRequest};
use lepic_wallet::selection::SelectionOptions;
use lepic_wallet::send::{Delivery, SendError};
use lepic_wallet::slate::{CodecRegistry, V2JsonCodec};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, FUNDING, TIP, World, pay_request};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn uuid(slate_id: lepic_slate::model::SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn codecs() -> CodecRegistry {
    let base_fee = lepic_primitives::params::Network::Floonet
        .params()
        .default_base_fee();
    let mut codecs = CodecRegistry::new();
    codecs
        .register(Box::new(V3JsonCodec::new(base_fee)))
        .unwrap();
    codecs
        .register(Box::new(V2JsonCodec::new(base_fee)))
        .unwrap();
    codecs
}

#[test]
fn a_parked_invoice_waits_for_the_user_and_pays_nothing() {
    let world = World::new();
    let issued = world.issue(Some("order 17"));

    let parked = world.read_parked(&world.payer, issued.slate_id);
    assert_eq!(parked.status, PendingInvoiceStatus::Parked);
    assert_eq!(parked.sender_address, world.issuer.address.to_string());
    let pending = world
        .payer
        .wallet
        .pending_invoices(InvoiceExpiry::default())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].slate_id, issued.slate_id);
    assert_eq!(pending[0].amount.value(), AMOUNT);
    assert_eq!(pending[0].message.as_deref(), Some("order 17"));
    assert_eq!(pending[0].sender, world.issuer.address);
    assert_eq!(
        pending[0].expires_at,
        pending[0].received_at.checked_add(DAY).unwrap()
    );
    // Parking pays nothing.
    assert!(
        world
            .payer
            .read(|repos| repos.transactions(world::ACCOUNT))
            .is_empty()
    );
}

#[test]
fn the_invoice_goes_out_as_v3_with_the_marker() {
    let world = World::new();
    let peer = world.peer_client(7);
    world.issue_to(peer.address(), None);
    let wire = world.block_on(async {
        let subscription = peer.drain().unwrap();
        let envelope = world
            .within(subscription.next_envelope())
            .await
            .unwrap()
            .unwrap();
        let wire = envelope.wire().clone();
        subscription
            .acknowledge(envelope.ack_token())
            .await
            .unwrap();
        subscription.stop().await.unwrap();
        wire
    });
    let slate = V3JsonCodec::new(
        lepic_primitives::params::Network::Floonet
            .params()
            .default_base_fee(),
    )
    .decode(&wire)
    .unwrap();
    assert_eq!(slate.stage(), Stage::I1);
    assert!(carries_lepic_marker(&wire));
}

#[test]
fn a_paid_invoice_is_finalized_and_posted_by_the_issuer() {
    let world = World::new();
    let mut events = world.issuer.wallet.subscribe();
    let issued = world.issue(None);

    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap();
    assert_eq!(paid.slate.stage(), Stage::I2);
    assert!(carries_lepic_marker(&paid.reply));
    assert_eq!(
        paid.slate.ttl_cutoff_height(),
        Some(Height::new(TIP + 1440))
    );
    assert_eq!(
        world.read_parked(&world.payer, issued.slate_id).status,
        PendingInvoiceStatus::Paid
    );
    // Paid invoices are no longer offered.
    assert!(
        world
            .payer
            .wallet
            .pending_invoices(InvoiceExpiry::default())
            .unwrap()
            .is_empty()
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 1);

    let summary = world
        .block_on(world.issuer.wallet.epicbox_drain(&world.issuer.epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            finalized: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(world.node.pushed_transactions().len(), 1);
    let issued_tx = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(issued.slate_id), TxDirection::Incoming));
    assert_eq!(issued_tx.unwrap().entry.state, TxState::Posted);
    let finalized: Vec<_> = std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::InvoiceFinalized(finalized) => Some((finalized.tx_id, finalized.slate_id)),
            _ => None,
        })
        .collect();
    assert_eq!(finalized, vec![(issued.tx_id, issued.slate_id)]);
}

#[test]
fn an_issued_and_a_paid_invoice_are_invoices_on_both_sides() {
    let world = World::new();
    let issued = world.issue(None);
    let flow = |wallet: &world::PartyWallet, tx_id| {
        let details = world.block_on(wallet.transaction_details(tx_id)).unwrap();
        (details.transaction.entry.direction, details.flow)
    };
    assert_eq!(
        flow(&world.issuer.wallet, issued.tx_id),
        (TxDirection::Incoming, TxFlow::Invoice)
    );
    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap();
    assert_eq!(
        flow(&world.payer.wallet, paid.tx_id),
        (TxDirection::Outgoing, TxFlow::Invoice)
    );
    world
        .block_on(world.issuer.wallet.epicbox_drain(&world.issuer.epicbox))
        .unwrap();
    assert_eq!(
        flow(&world.issuer.wallet, issued.tx_id),
        (TxDirection::Incoming, TxFlow::Invoice)
    );
}

#[test]
fn a_payer_is_known_to_run_lepic_after_its_marked_payment() {
    let world = World::new();
    let payer = world.payer.address.to_string();
    let capability = || world.issuer.wallet.peer_capability(&payer).unwrap();
    assert_eq!(capability(), PeerInvoiceSupport::Unknown);
    let issued = world.issue(None);
    world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap();
    assert_eq!(capability(), PeerInvoiceSupport::Unknown);

    world
        .block_on(world.issuer.wallet.epicbox_drain(&world.issuer.epicbox))
        .unwrap();

    assert_eq!(capability(), PeerInvoiceSupport::Lepic);
    assert!(matches!(
        world.issuer.wallet.peer_capability("not an address"),
        Err(InboxError::Address(_))
    ));
}

/// The I1 `stock` received, as a stock listener posts it back: as it parsed it, without the
/// marker.
fn echoed_i1(world: &World, stock: &EpicboxClient) -> String {
    world.block_on(async {
        let subscription = stock.drain().unwrap();
        let envelope = world
            .within(subscription.next_envelope())
            .await
            .unwrap()
            .unwrap();
        subscription
            .acknowledge(envelope.ack_token())
            .await
            .unwrap();
        subscription.stop().await.unwrap();
        let slate = codecs().decode(envelope.wire()).unwrap();
        let unmarked = V3JsonCodec::new(
            lepic_primitives::params::Network::Floonet
                .params()
                .default_base_fee(),
        )
        .encode(
            &slate,
            &EncodeContext {
                block_header_version: 6,
            },
        )
        .unwrap();
        unmarked.as_text().unwrap().to_owned()
    })
}

fn bounce_events(events: &mut Receiver<Event>) -> Vec<BouncedInvoice> {
    std::iter::from_fn(|| events.try_recv().ok())
        .filter_map(|event| match event {
            Event::InvoiceBounced(bounced) => Some(bounced),
            _ => None,
        })
        .collect()
}

#[test]
fn an_invoice_sent_back_unchanged_marks_the_peer_as_not_paying_invoices() {
    let world = World::new();
    let stock = world.peer_client(7);
    let issued = world.issue_to(stock.address(), None);
    let bounced = echoed_i1(&world, &stock);
    world.post(7, &world.issuer.address, &bounced, 1);
    let mut events = world.issuer.wallet.subscribe();
    let capability = || {
        world
            .issuer
            .wallet
            .peer_capability(&stock.address().to_string())
            .unwrap()
    };
    assert_eq!(capability(), PeerInvoiceSupport::Unknown);

    let summary = world
        .block_on(world.issuer.wallet.epicbox_drain(&world.issuer.epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            bounced: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(
        bounce_events(&mut events),
        vec![BouncedInvoice {
            tx_id: issued.tx_id,
            slate_id: issued.slate_id,
            peer: stock.address().clone(),
        }]
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    let key = stock.address().key_text();
    let capability = world
        .issuer
        .read(|repos| repos.peer_capability(&key))
        .unwrap();
    assert_eq!(capability.support, PeerSupport::NoInvoices);
    assert_eq!(
        world
            .issuer
            .wallet
            .peer_capability(&stock.address().to_string())
            .unwrap(),
        PeerInvoiceSupport::NoInvoices
    );
    // The invoice itself waits for its expiry.
    let issued_tx = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(issued.slate_id), TxDirection::Incoming));
    assert_eq!(issued_tx.unwrap().entry.state, TxState::Received);
}

#[test]
fn a_listener_names_the_invoice_a_peer_sent_back() {
    let world = World::new();
    let stock = world.peer_client(7);
    let issued = world.issue_to(stock.address(), None);
    let bounced = echoed_i1(&world, &stock);
    world.post(7, &world.issuer.address, &bounced, 1);
    let mut events = world.issuer.wallet.subscribe();
    let handle = ListenHandle::new();

    let summary = world.block_on(async {
        let listen = world
            .issuer
            .wallet
            .epicbox_listen(&world.issuer.epicbox, &handle);
        let script = async {
            world
                .within(
                    world
                        .relay
                        .wait_until(|relay| relay.pending(&world.issuer.address) == 0),
                )
                .await;
            handle.stop();
        };
        tokio::join!(listen, script).0
    });

    assert_eq!(summary.unwrap().bounced, 1);
    assert_eq!(
        bounce_events(&mut events),
        vec![BouncedInvoice {
            tx_id: issued.tx_id,
            slate_id: issued.slate_id,
            peer: stock.address().clone(),
        }]
    );
}

#[test]
fn an_i1_from_another_key_is_not_taken_for_a_bounce() {
    let world = World::new();
    let stock = world.peer_client(7);
    world.issue_to(stock.address(), None);
    let i1 = world.block_on(async {
        let subscription = stock.drain().unwrap();
        let envelope = world
            .within(subscription.next_envelope())
            .await
            .unwrap()
            .unwrap();
        subscription
            .acknowledge(envelope.ack_token())
            .await
            .unwrap();
        subscription.stop().await.unwrap();
        envelope.wire().as_text().unwrap().to_owned()
    });
    world.post(8, &world.issuer.address, &i1, 1);

    let summary = world
        .block_on(world.issuer.wallet.epicbox_drain(&world.issuer.epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    let key = World::address_of(8).key_text();
    assert!(
        world
            .issuer
            .read(|repos| repos.peer_capability(&key))
            .is_none()
    );
}

#[test]
fn expiry_deletes_parked_invoices_cancels_issued_ones_and_refuses_late_payments() {
    let world = World::new();
    let expiry = InvoiceExpiry::default();
    // One invoice the payer pays late, one it never answers.
    let late = world.issue(None);
    let ignored = world.issue(None);
    let before = world.issuer.wallet.balance(world::ACCOUNT).unwrap();
    assert_eq!(before.awaiting_finalization, Amount::ZERO);
    assert_eq!(before.total, Amount::ZERO);
    let mut payer_events = world.payer.wallet.subscribe();
    let mut issuer_events = world.issuer.wallet.subscribe();

    world.payer.clock.advance(DAY + Duration::from_secs(1));
    world.issuer.clock.advance(DAY + Duration::from_secs(1));
    // The payer pays the first before its own sweep; the issuer sweeps before it reads it.
    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(late.slate_id, pay_request()),
        )
        .unwrap();
    let payer_sweep = world
        .block_on(world.payer.wallet.sweep_invoices(expiry))
        .unwrap();
    let issuer_sweep = world
        .block_on(world.issuer.wallet.sweep_invoices(expiry))
        .unwrap();

    assert_eq!(payer_sweep.deleted, vec![ignored.slate_id]);
    assert!(payer_sweep.cancelled.is_empty());
    assert!(
        world
            .payer
            .read(|repos| repos.pending_invoice(uuid(ignored.slate_id)))
            .is_none()
    );
    // A paid invoice is never deleted.
    assert_eq!(
        world.read_parked(&world.payer, late.slate_id).status,
        PendingInvoiceStatus::Paid
    );
    let mut cancelled = issuer_sweep.cancelled.clone();
    cancelled.sort_by_key(|tx_id| tx_id.0);
    let mut expected = vec![late.tx_id, ignored.tx_id];
    expected.sort_by_key(|tx_id| tx_id.0);
    assert_eq!(cancelled, expected);
    for issued in [&late, &ignored] {
        let state = world
            .issuer
            .read(|repos| repos.transaction(issued.tx_id))
            .unwrap()
            .state;
        assert_eq!(state, TxState::Cancelled);
    }
    // Neither invoice counted before the sweep, and nothing of them counts after it.
    let balance = world.issuer.wallet.balance(world::ACCOUNT).unwrap();
    assert_eq!(balance.awaiting_finalization, Amount::ZERO);
    assert_eq!(balance.total, Amount::ZERO);
    let expired = |events: &mut tokio::sync::broadcast::Receiver<Event>| {
        std::iter::from_fn(|| events.try_recv().ok())
            .filter(|event| matches!(event, Event::InvoiceExpired(_)))
            .count()
    };
    assert_eq!(expired(&mut payer_events), 1);
    assert_eq!(expired(&mut issuer_events), 2);

    let summary = world
        .block_on(world.issuer.wallet.epicbox_drain(&world.issuer.epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert!(world.node.pushed_transactions().is_empty());
    assert!(
        world
            .issuer
            .read(|repos| repos.slate(uuid(paid.slate.id()), SlateStage::Invoice3))
            .is_none()
    );
}

#[test]
fn a_payment_past_its_ttl_is_offered_for_cancel_and_not_expired_by_refresh() {
    let world = World::new();
    let issued = world.issue(None);
    let paid = world
        .block_on(world.payer.wallet.pay_parked_invoice(
            issued.slate_id,
            PayRequest {
                ttl_blocks: Some(2),
                ..pay_request()
            },
        ))
        .unwrap();
    // It is offered from the issuer's margin past its cutoff, not before.
    let offered_at = TIP + 2 + INVOICE_TTL_MARGIN_BLOCKS;
    world
        .node
        .update_chain(|chain| chain.tip.height = Height::new(offered_at - 1));
    world.block_on(world.payer.wallet.refresh()).unwrap();
    let sweep = world
        .block_on(world.payer.wallet.sweep_invoices(InvoiceExpiry::default()))
        .unwrap();
    assert!(sweep.cancellable.is_empty(), "{sweep:?}");

    world
        .node
        .update_chain(|chain| chain.tip.height = Height::new(offered_at));
    world.block_on(world.payer.wallet.refresh()).unwrap();

    let sweep = world
        .block_on(world.payer.wallet.sweep_invoices(InvoiceExpiry::default()))
        .unwrap();

    assert_eq!(sweep.cancellable, vec![paid.tx_id]);
    let state = world
        .payer
        .read(|repos| repos.transaction(paid.tx_id))
        .unwrap()
        .state;
    assert_eq!(state, TxState::Sent);
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();
}

#[test]
fn a_stored_payment_is_delivered_again_after_a_failed_delivery() {
    let world = World::new();
    let issued = world.issue(None);
    world.relay.set_refusing(true);

    let error = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap_err();
    let InvoiceError::PaymentUndelivered {
        tx_id, slate_id, ..
    } = error
    else {
        panic!("unexpected error {error:?}");
    };
    assert_eq!(slate_id, issued.slate_id);
    world.relay.set_refusing(false);
    assert_eq!(world.relay.pending(&world.issuer.address), 0);

    // Only the address the issuer was allowed under takes the payment.
    let elsewhere = World::address_of(8);
    let error = world
        .block_on(world.payer.wallet.resend(
            tx_id,
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(elsewhere.to_string()),
            },
        ))
        .unwrap_err();
    assert!(
        matches!(error, SendError::PayeeMismatch { tx_id: id } if id == tx_id),
        "{error:?}"
    );
    assert_eq!(world.relay.pending(&elsewhere), 0);
    assert_eq!(
        world.payer.read(|repos| repos.counterparty(tx_id)),
        Some(world.issuer.address.to_string())
    );

    world
        .block_on(world.payer.wallet.resend(
            tx_id,
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(world.issuer.address.to_string()),
            },
        ))
        .unwrap();
    let summary = world
        .block_on(world.issuer.wallet.epicbox_drain(&world.issuer.epicbox))
        .unwrap();

    assert_eq!(summary.finalized, 1);
    assert_eq!(world.node.pushed_transactions().len(), 1);
}

#[test]
fn a_declined_invoice_cannot_be_paid() {
    let world = World::new();
    let issued = world.issue(None);

    world
        .block_on(world.payer.wallet.decline_invoice(issued.slate_id))
        .unwrap();

    assert_eq!(
        world.read_parked(&world.payer, issued.slate_id).status,
        PendingInvoiceStatus::Declined
    );
    let error = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap_err();
    assert!(
        matches!(error, InvoiceError::NotParked { slate_id } if slate_id == issued.slate_id),
        "{error:?}"
    );
    assert!(matches!(
        world.block_on(world.payer.wallet.decline_invoice(issued.slate_id)),
        Err(InvoiceError::NotParked { .. })
    ));
}

#[test]
fn the_payments_address_parks_no_invoice() {
    let world = World::new();
    world.issue_to(&world.payer.address, None);

    let summary = world
        .block_on(world.payer.wallet.epicbox_drain(&world.payer.epicbox))
        .unwrap();

    assert_eq!(
        summary,
        InboxSummary {
            rejected: 1,
            ..InboxSummary::default()
        }
    );
    assert_eq!(world.relay.pending(&world.payer.address), 0);
    assert!(
        world
            .payer
            .read(|repos| repos.pending_invoices())
            .is_empty()
    );
    assert!(
        world
            .payer
            .wallet
            .pending_invoices(InvoiceExpiry::default())
            .unwrap()
            .is_empty()
    );
    assert!(
        world
            .payer
            .read(|repos| repos.transactions(world::ACCOUNT))
            .is_empty()
    );
}

impl World {
    fn read_parked(
        &self,
        party: &world::Party,
        slate_id: lepic_slate::model::SlateId,
    ) -> lepic_store::PendingInvoice {
        party
            .read(|repos| repos.pending_invoice(uuid(slate_id)))
            .unwrap()
    }
}

#[test]
fn a_cancelled_payment_has_exactly_its_inputs_spent_to_the_payer_itself() {
    let world = World::new();
    // A second output the payer holds, which the self-send must leave alone.
    world.payer.fund(9, 2 * FUNDING);
    let issued = world.issue(None);
    let paid = world
        .block_on(
            world
                .payer
                .wallet
                .pay_parked_invoice(issued.slate_id, pay_request()),
        )
        .unwrap();
    let locked = |world: &World| -> Vec<_> {
        world
            .payer
            .read(|repos| repos.outputs(ACCOUNT, None))
            .into_iter()
            .filter(|output| output.status == OutputStatus::Locked)
            .map(|output| output.id.commitment)
            .collect()
    };
    let inputs = locked(&world);
    assert_eq!(inputs.len(), 1);
    world
        .block_on(world.payer.wallet.cancel(paid.tx_id))
        .unwrap();
    assert!(locked(&world).is_empty());

    // The issuer still holds the signed I2; spending its inputs elsewhere voids it.
    let sent = world
        .block_on(world.payer.wallet.spend_outputs_to_self(
            SelectionOptions {
                minimum_confirmations: 1,
                ..SelectionOptions::new(ACCOUNT)
            },
            inputs.clone(),
            Propagation::Fluff,
        ))
        .unwrap();

    let spent: Vec<_> = sent
        .selection
        .inputs
        .iter()
        .map(|input| input.id.commitment)
        .collect();
    assert_eq!(spent, inputs);
    assert!(sent.selection.change.is_empty());
    assert_eq!(locked(&world), inputs, "the other output stays unspent");
    let pushed = world.node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    let pushed_inputs: Vec<_> = pushed[0]
        .inputs()
        .iter()
        .map(|input| input.commitment)
        .collect();
    assert_eq!(pushed_inputs, inputs);
}

#[test]
fn expiry_cancels_an_invoice_issued_by_file_and_left_unpaid() {
    let world = World::new();
    let issued = world
        .block_on(world.issuer.wallet.issue_invoice(
            lepic_wallet::invoice::InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
                ttl_blocks: None,
            },
            Delivery::Export {
                transport: lepic_transport::file::FILE,
                to: lepic_transport::transport::Location::File(
                    tempfile::tempdir().unwrap().keep().join("i1.tx"),
                ),
            },
        ))
        .unwrap();
    let expiry = InvoiceExpiry::default();
    assert!(
        world
            .block_on(world.issuer.wallet.sweep_invoices(expiry))
            .unwrap()
            .cancelled
            .is_empty()
    );

    world.issuer.clock.advance(DAY + Duration::from_secs(1));
    let sweep = world
        .block_on(world.issuer.wallet.sweep_invoices(expiry))
        .unwrap();
    assert_eq!(sweep.cancelled, vec![issued.tx_id]);
    assert_eq!(
        world
            .issuer
            .read(|repos| repos.transaction(issued.tx_id))
            .unwrap()
            .state,
        TxState::Cancelled
    );
}
