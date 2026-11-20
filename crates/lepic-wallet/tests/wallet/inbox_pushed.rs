// SPDX-License-Identifier: Apache-2.0
//! The payments listener reading pushed mail from a mux/1 session: messages that cannot be used
//! are recorded and acknowledged as on a socket, and a relay without mux/1 gets the 3.0.0 listen.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::inbox_world as world;

use lepic_crypto::SecretKey;
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::{MuxOptions, MuxState, Network as RelayNetwork, Nonce, Salt, SignedMessage};
use lepic_methods::epicbox::Epicbox;
use lepic_store::InboxStatus;
use lepic_wallet::event::TransportState;
use lepic_wallet::inbox::{InboxSummary, ListenHandle};
use world::{World, settings, transport_reaches, within};

fn sealed(world: &World, signer: u8, plaintext: &str) -> SignedMessage {
    SignedMessage::seal(
        plaintext,
        &world.receiver_address,
        &SecretKey::from_array([signer; 32]).unwrap(),
        Salt::from([4; 8]),
        Nonce::from([5; 12]),
    )
    .unwrap()
}

#[test]
fn pushed_mail_that_cannot_be_used_is_recorded_and_acknowledged() {
    let world = World::new();
    let mux = MuxMockRelay::new(RelayNetwork::Floonet);
    let epicbox = Epicbox::new(settings(), RelayNetwork::Floonet, mux.connector());
    let address = epicbox.attach_wallet(&world.receiver_wallet).unwrap();
    assert_eq!(address, world.receiver_address);
    let forged = mux.store(&World::address_of(7), &address, &sealed(&world, 8, "{}"));
    let undecodable = mux.store(
        &World::address_of(7),
        &address,
        &sealed(&world, 7, "not a slate"),
    );
    let handle = ListenHandle::new();
    let mut events = world.receiver_wallet.subscribe();

    let summary = world.block_on(async {
        let listen = epicbox.listen_via(
            &world.receiver_wallet,
            &handle,
            "payments",
            MuxOptions::default(),
        );
        let script = async {
            transport_reaches(&mut events, TransportState::Connected).await;
            within(mux.wait_until(|relay| relay.is_acked(&forged) && relay.is_acked(&undecodable)))
                .await;
            // A dropped socket shows as a disconnect, then the session attaches again.
            mux.drop_sockets();
            transport_reaches(&mut events, TransportState::Disconnected).await;
            transport_reaches(&mut events, TransportState::Connected).await;
            handle.stop();
        };
        tokio::join!(listen, script).0
    });

    assert_eq!(
        summary.unwrap(),
        InboxSummary {
            rejected: 1,
            dropped: 1,
            ..InboxSummary::default()
        }
    );
    for msg_id in [&forged, &undecodable] {
        assert_eq!(
            world.receiver.inbox(msg_id).unwrap().status,
            InboxStatus::Rejected
        );
    }
    assert_eq!(world.receiver.transactions(), 0);
    assert_eq!(mux.sockets_made(), 2);
    // The listener let go of its session when it stopped.
    assert!(epicbox.pushed().infos().is_empty());
}

#[test]
fn a_relay_without_mux_gets_the_socket_listen() {
    let world = World::new();
    let msg_id = world.post_to_receiver(7, 8, "{}");
    let handle = ListenHandle::new();

    let summary = world.block_on(async {
        let listen = world.receiver_epicbox.listen_via(
            &world.receiver_wallet,
            &handle,
            "payments",
            MuxOptions::default(),
        );
        let script = async {
            world.until_acknowledged(&world.receiver_address).await;
            handle.stop();
        };
        tokio::join!(listen, script).0
    });

    assert_eq!(summary.unwrap().rejected, 1);
    assert_eq!(
        world.receiver.inbox(&msg_id).unwrap().status,
        InboxStatus::Rejected
    );
    let sessions = world.receiver_epicbox.pushed().infos();
    assert!(
        sessions
            .iter()
            .all(|session| session.state == MuxState::NotOffered || session.state.has_ended()),
        "{sessions:?}"
    );
}

/// Listens on a mux/1 relay that offers `txcancel/1` or not, to a cancellation the relay keeps
/// for a transaction this wallet never had, and returns how many cancellations stay unacked.
fn pushed_cancellation_left(offering_cancel: bool) -> usize {
    let world = World::new();
    let mux = MuxMockRelay::new(RelayNetwork::Floonet);
    mux.offer_cancel(offering_cancel);
    let epicbox = Epicbox::new(settings(), RelayNetwork::Floonet, mux.connector());
    let address = epicbox.attach_wallet(&world.receiver_wallet).unwrap();
    let stranger = World::address_of(7);
    let txid = "0123456789ab4def8123456789abcdef";
    mux.store_with_txid(&stranger, &address, &sealed(&world, 7, "{}"), txid);
    assert!(mux.cancel_as(&stranger, txid));
    assert_eq!(mux.unacked_cancels(&address), 1);
    let handle = ListenHandle::new();
    let mut events = world.receiver_wallet.subscribe();

    world.block_on(async {
        let listen = epicbox.listen_via(
            &world.receiver_wallet,
            &handle,
            "payments",
            MuxOptions::default(),
        );
        let script = async {
            transport_reaches(&mut events, TransportState::Connected).await;
            if offering_cancel {
                within(mux.wait_until(|relay| relay.unacked_cancels(&address) == 0)).await;
            }
            handle.stop();
        };
        tokio::join!(listen, script).0.unwrap();
    });

    assert_eq!(world.receiver.transactions(), 0);
    mux.unacked_cancels(&address)
}

#[test]
fn a_pushed_cancellation_of_no_transaction_here_is_acknowledged() {
    assert_eq!(pushed_cancellation_left(true), 0);
}

#[test]
fn a_session_without_cancel_is_told_of_no_cancellation() {
    assert_eq!(pushed_cancellation_left(false), 1);
}
