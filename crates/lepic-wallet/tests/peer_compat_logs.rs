// SPDX-License-Identifier: Apache-2.0
//! What is learned of peer keys never reaches a log at `info` or above, in its own binary for
//! the reason `lifecycle_logs.rs` gives: a full send between two LEPIC wallets, with the notice
//! that follows and the pruning a host runs, logs neither wallet's key above `debug`.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use lepic_epicbox::TRANSPORT_ID;
use lepic_primitives::amount::Amount;
use lepic_telemetry::{LogLevel, assert_no_secrets, capture};
use lepic_transport::transport::Destination;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use world::{ACCOUNT, AMOUNT, World};

#[test]
fn a_send_with_its_notice_logs_no_peer_key_above_debug() {
    let world = World::new();
    let ((), captured) = capture(|| {
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
        for party in [&world.issuer, &world.payer, &world.issuer] {
            world
                .block_on(party.wallet.epicbox_drain(&party.epicbox))
                .unwrap();
        }
        world
            .issuer
            .wallet
            .forget_peers(Duration::from_secs(180 * 24 * 60 * 60))
            .unwrap();
    });
    // The exchange ran to its notice, so every step that learns about a key was taken.
    assert!(
        captured
            .records
            .iter()
            .any(|record| record.message == "notice received"),
        "{:?}",
        captured.records
    );
    assert!(
        world
            .issuer
            .peer_compat(&world.payer.address.key_text())
            .is_some()
    );

    let shown: Vec<_> = captured
        .records
        .into_iter()
        .filter(|record| record.level <= LogLevel::Info)
        .collect();
    let keys: Vec<String> = [&world.payer, &world.issuer]
        .iter()
        .flat_map(|party| [party.address.key_text(), party.address.to_string()])
        .collect();
    let compressed: Vec<Vec<u8>> = [&world.payer, &world.issuer]
        .iter()
        .map(|party| party.address.public_key().to_bytes().to_vec())
        .collect();
    let mut secrets: Vec<&[u8]> = keys.iter().map(String::as_bytes).collect();
    secrets.extend(compressed.iter().map(Vec::as_slice));
    assert_no_secrets(&shown, &secrets).unwrap();
}
