// SPDX-License-Identifier: Apache-2.0
//! No message exists only to learn about a peer: what the wallet knows of a key comes from the
//! messages the user's own payments caused, and drains with nothing new to answer send nothing.

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

use lepic_epicbox::TRANSPORT_ID;
use lepic_primitives::amount::Amount;
use lepic_transport::transport::Destination;
use lepic_wallet::peer_compat::PeerKind;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use world::{ACCOUNT, AMOUNT, Party, World};

const POST: &str = "PostSlate";

fn drain(world: &World, party: &Party) {
    world
        .block_on(party.wallet.epicbox_drain(&party.epicbox))
        .unwrap();
}

#[test]
fn idle_drains_send_nothing_to_any_payments_address() {
    let world = World::new();
    // One payment between the two LEPIC wallets, so each knows the other runs LEPIC.
    world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(world.issuer.address.to_string()),
            },
        ))
        .unwrap();
    for _ in 0..3 {
        drain(&world, &world.issuer);
        drain(&world, &world.payer);
    }
    assert_eq!(
        world.issuer.peer_kind(&world.payer.address.key_text()),
        Some(PeerKind::Lepic)
    );
    let posted = world.relay.received(POST);
    assert!(posted > 0);

    // Days of drains with nothing new: nothing is sent to learn or to advertise.
    for _ in 0..5 {
        world
            .issuer
            .clock
            .advance(Duration::from_secs(24 * 60 * 60));
        world.payer.clock.advance(Duration::from_secs(24 * 60 * 60));
        drain(&world, &world.issuer);
        drain(&world, &world.payer);
    }

    assert_eq!(world.relay.received(POST), posted);
    assert_eq!(world.relay.pending(&world.issuer.address), 0);
    assert_eq!(world.relay.pending(&world.payer.address), 0);
}
