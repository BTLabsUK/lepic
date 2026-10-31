// SPDX-License-Identifier: Apache-2.0
//! A receive and a contact operation on one wallet at the same moment. A receive draws its
//! output's randomness from the shared generator, and sealing a slate for a contact draws inside
//! its store write; both run on the blocking pool. Taken in opposite orders the two locks
//! deadlock both threads, so the race runs under a time limit that fails the test instead of
//! hanging it.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "pairing/helpers.rs"]
mod helpers;
mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::time::Duration;

use lepic_primitives::amount::Amount;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::file::FILE;
use lepic_transport::transport::Location;
use lepic_wallet::ReceiveRequest;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet_contacts::WalletContacts;
use world::{ACCOUNT, AMOUNT, FUNDING, World};

/// Distinct S1s the payer sends, one coin each.
const SLATES: u32 = 6;
/// Receives and seals each side runs; repeats of a received S1 take the same locks.
const ROUNDS: usize = 120;
/// Far longer than the race takes; a deadlock never ends.
const LIMIT: Duration = Duration::from_secs(120);

/// The payer sends `AMOUNT` by file from a coin of its own and returns the S1.
fn payer_s1(world: &World) -> WireSlate {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s1.tx");
    world
        .block_on(world.payer.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Export {
                transport: FILE,
                to: Location::File(path.clone()),
            },
        ))
        .unwrap();
    WireSlate::text(MediaType::JSON, std::fs::read_to_string(&path).unwrap())
}

#[test]
fn a_receive_beside_a_contact_seal_never_deadlocks() {
    let world = World::new();
    let (payer_contact, _) = world.pair_by_link();
    // One coin per S1, above the one the world funds: no send waits on change.
    for child in 1..SLATES {
        world.payer.fund(child, FUNDING);
    }
    let s1s: Vec<WireSlate> = (0..SLATES).map(|_| payer_s1(&world)).collect();
    // A received transaction the issuer can seal its S2 of for the payer.
    let first = world
        .block_on(
            world
                .issuer
                .wallet
                .receive(FILE, &s1s[0], ReceiveRequest::default()),
        )
        .unwrap();

    let raced = world.block_on(async {
        let receives = async {
            for round in 0..ROUNDS {
                let s1 = &s1s[round % s1s.len()];
                world
                    .issuer
                    .wallet
                    .receive(FILE, s1, ReceiveRequest::default())
                    .await
                    .unwrap();
            }
        };
        let seals = async {
            let book = world.issuer.wallet.contact_book();
            for _ in 0..ROUNDS {
                book.contact_seal_slate(payer_contact, first.tx_id, None)
                    .await
                    .unwrap();
            }
        };
        tokio::time::timeout(LIMIT, async { tokio::join!(receives, seals) }).await
    });
    if raced.is_err() {
        // The deadlocked threads never return, and dropping the runtime waits for them.
        std::mem::forget(world);
        panic!("a receive and a contact seal deadlocked on the generator and the store");
    }

    let stored = world.issuer.read(|repos| repos.transactions(ACCOUNT));
    let incoming = stored
        .iter()
        .filter(|stored| stored.entry.slate_id.is_some())
        .count();
    assert_eq!(incoming, SLATES as usize, "each S1 is stored once");
}
