// SPDX-License-Identifier: Apache-2.0
//! A full send between two LEPIC wallets over Epicbox logs neither wallet's key above `debug`, in
//! a process of its own for the reason `lifecycle_logs.rs` gives.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::epicbox_world as world;

use lepic_primitives::amount::Amount;
use lepic_telemetry::{LogLevel, assert_no_secrets, capture};
use lepic_transport::transport::Destination;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use world::{ACCOUNT, AMOUNT, World};

#[test]
fn a_send_logs_no_peer_key_above_debug() {
    let world = World::new();
    let ((), captured) = capture(|| {
        world
            .block_on(world.payer.wallet.send(
                &world.payer.method,
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    to: Destination::new(world.issuer.address.to_string()),
                },
            ))
            .unwrap();
        for party in [&world.issuer, &world.payer, &world.issuer] {
            world.block_on(party.epicbox.drain(&party.wallet)).unwrap();
        }
    });
    // The exchange ran to its end.
    assert_eq!(world.node.pushed_transactions().len(), 1);

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
