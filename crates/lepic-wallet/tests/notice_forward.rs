// SPDX-License-Identifier: Apache-2.0
//! Notices for a slate another install holds: an install on the same recovery phrase that does
//! not hold the slate raises `NoticeUnmatched` for its host to pass on, and the install that
//! holds it applies the passed-on notice under the rules of one it received itself.
//!
//! The payer of `World` sends and the issuer receives, through the peer key 7 as in
//! `send_posted.rs`, so the receiver's counterparty is a key the test holds. The issuer's twin
//! is the install that does not hold the payment.

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

use lepic_crypto::Commitment;
use lepic_epicbox::{EpicboxAddress, TRANSPORT_ID};
use lepic_primitives::amount::Amount;
use lepic_slate::model::SlateId;
use lepic_store::{TxDirection, TxId};
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::Event;
use lepic_wallet::event::{PostedPayment, UnmatchedNotice};
use lepic_wallet::notice::{Notice, NoticeKind, Payload, classify_text};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;
use world::{ACCOUNT, AMOUNT, Party, World};

const SENDER: u8 = 7;
const STRANGER: u8 = 9;

fn uuid(slate_id: SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}

fn events(receiver: &mut Receiver<Event>) -> Vec<Event> {
    std::iter::from_fn(|| receiver.try_recv().ok())
        .filter(|event| {
            matches!(
                event,
                Event::NoticeUnmatched(_) | Event::PaymentPosted(_) | Event::PaymentCancelled(_)
            )
        })
        .collect()
}

fn drain(world: &World, party: &Party) {
    world
        .block_on(party.wallet.epicbox_drain(&party.epicbox))
        .unwrap();
}

/// Takes the one message waiting for the peer key `byte`.
fn only_message(world: &World, byte: u8) -> String {
    let peer = world.peer_client(byte);
    world.block_on(async {
        let subscription = peer.drain().unwrap();
        let envelope = world
            .within(subscription.next_envelope())
            .await
            .unwrap()
            .unwrap();
        let text = envelope.wire().as_text().unwrap().to_owned();
        subscription
            .acknowledge(envelope.ack_token())
            .await
            .unwrap();
        subscription.stop().await.unwrap();
        text
    })
}

/// A payment the payer sent through [`SENDER`] that the issuer received and answered, then
/// finalized and posted: the issuer's transaction, and the `posted` notice for it.
fn posted_payment(world: &World) -> (TxId, Notice) {
    let sent = world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(World::address_of(SENDER).to_string()),
            },
        ))
        .unwrap();
    let s1 = only_message(world, SENDER);
    world.post(SENDER, &world.issuer.address, &s1, 1);
    drain(world, &world.issuer);
    let s2 = only_message(world, SENDER);
    world.post(SENDER, &world.payer.address, &s2, 1);
    drain(world, &world.payer);
    let text = only_message(world, SENDER);
    let Payload::Notice(notice) = classify_text(&text) else {
        panic!("not a notice: {text}");
    };
    let tx_id = world
        .issuer
        .read(|repos| repos.transaction_by_slate(uuid(sent.slate_id), TxDirection::Incoming))
        .unwrap()
        .id;
    (tx_id, notice)
}

fn sender() -> EpicboxAddress {
    World::address_of(SENDER)
}

fn forward(world: &World, party: &Party, from: &EpicboxAddress, notice: Notice) -> bool {
    world
        .block_on(
            party
                .wallet
                .notice_apply_forwarded(&from.to_string(), notice),
        )
        .unwrap()
}

#[test]
fn an_install_without_the_slate_raises_the_notice_for_its_host_to_pass_on() {
    let world = World::new();
    let twin = world.issuer_twin();
    let (_, notice) = posted_payment(&world);
    let mut twin_events = twin.wallet.subscribe();

    world.post(
        SENDER,
        &world.issuer.address,
        notice.encode().as_text().unwrap(),
        1,
    );
    drain(&world, &twin);

    assert_eq!(
        events(&mut twin_events),
        vec![Event::NoticeUnmatched(UnmatchedNotice {
            notice,
            sender: sender().to_string(),
        })]
    );
    assert_eq!(
        world.relay.pending(&world.issuer.address),
        0,
        "acknowledged"
    );
}

#[test]
fn a_passed_on_notice_is_applied_once_by_the_install_holding_the_slate() {
    let world = World::new();
    let (tx_id, notice) = posted_payment(&world);
    let NoticeKind::Posted { excess } = notice.kind else {
        panic!("{notice:?}");
    };
    let mut issuer_events = world.issuer.wallet.subscribe();

    assert!(forward(&world, &world.issuer, &sender(), notice));
    assert!(forward(&world, &world.issuer, &sender(), notice));

    assert_eq!(
        events(&mut issuer_events),
        vec![Event::PaymentPosted(PostedPayment {
            tx_id,
            slate_id: notice.slate_id,
            excess,
        })],
        "a repeat changes nothing"
    );
}

#[test]
fn a_passed_on_notice_with_another_excess_or_sender_is_refused() {
    let world = World::new();
    let (_, notice) = posted_payment(&world);
    let mut issuer_events = world.issuer.wallet.subscribe();
    let lie = Notice {
        kind: NoticeKind::Posted {
            excess: Commitment::commit_value(1).unwrap(),
        },
        ..notice
    };

    assert!(!forward(&world, &world.issuer, &sender(), lie));
    assert!(!forward(
        &world,
        &world.issuer,
        &World::address_of(STRANGER),
        notice
    ));
    assert!(
        !world
            .block_on(
                world
                    .issuer
                    .wallet
                    .notice_apply_forwarded("not an address", notice)
            )
            .unwrap()
    );

    assert!(events(&mut issuer_events).is_empty());
    let stranger = World::address_of(STRANGER).key_text();
    assert!(world.issuer.peer_kind(&stranger).is_none());
    // The true notice from the true sender is still taken afterwards.
    assert!(forward(&world, &world.issuer, &sender(), notice));
}

#[test]
fn a_passed_on_notice_this_install_does_not_hold_either_is_dropped_and_not_passed_on() {
    let world = World::new();
    let twin = world.issuer_twin();
    let (_, notice) = posted_payment(&world);
    let mut twin_events = twin.wallet.subscribe();

    assert!(!forward(&world, &twin, &sender(), notice));

    assert!(events(&mut twin_events).is_empty());
}

#[test]
fn a_notice_held_here_from_the_wrong_sender_is_not_passed_on() {
    let world = World::new();
    let (_, notice) = posted_payment(&world);
    let mut issuer_events = world.issuer.wallet.subscribe();

    world.post(
        STRANGER,
        &world.issuer.address,
        notice.encode().as_text().unwrap(),
        1,
    );
    drain(&world, &world.issuer);

    assert!(events(&mut issuer_events).is_empty());
}
