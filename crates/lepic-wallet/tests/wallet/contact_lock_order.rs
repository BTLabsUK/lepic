// SPDX-License-Identifier: Apache-2.0
//! Every path takes the store before the wallet's RNG, as the send path does: a store write that
//! draws from the RNG never waits in a cycle on a call that holds the RNG while it waits for the
//! store. Both run on the blocking pool, so a cycle would stop every later store call of the
//! wallet.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::epicbox_world as world;
use crate::pairing_helpers::relays;

use lepic_primitives::amount::Amount;
use lepic_store::{ContactId, StoreError, WalletStore};
use lepic_transport::transport::Location;
use lepic_wallet::invoice::InvoiceRequest;
use lepic_wallet::send::Delivery;
use lepic_wallet_contacts::{ContactError, WalletContacts};
use rand::SeedableRng;
use rand::rngs::StdRng;
use world::{ACCOUNT, AMOUNT, Party, World};

/// How long each step gets; a lock cycle never finishes.
const PATIENCE: Duration = Duration::from_secs(20);

/// Holds `party`'s store in a write until another write has started, then takes the RNG, as a
/// send's write does; sends on `held` once it holds the store and `"write"` on `done` at the end.
fn hold_store_then_take_rng(
    party: &'static Party,
    held: mpsc::Sender<()>,
    done: mpsc::Sender<&'static str>,
) {
    let session = party.wallet.session().unwrap();
    let before = party.writes();
    std::thread::spawn(move || {
        session
            .store
            .write(|_| {
                held.send(()).unwrap();
                // This write and the other: the other has started and waits for the store.
                let deadline = Instant::now() + PATIENCE;
                while party.writes() < before + 2 && Instant::now() < deadline {
                    std::thread::yield_now();
                }
                drop(party.wallet.ports().rng.lock());
                Ok::<_, StoreError>(())
            })
            .unwrap();
        done.send("write").unwrap();
    });
}

/// Waits for both calls; a cycle leaves both blocked.
fn both_finish(done: &mpsc::Receiver<&'static str>) -> Vec<&'static str> {
    let mut finished = Vec::new();
    for _ in 0..2 {
        match done.recv_timeout(PATIENCE) {
            Ok(which) => finished.push(which),
            Err(_) => panic!("store and RNG locks wait on each other; finished: {finished:?}"),
        }
    }
    finished.sort_unstable();
    finished
}

/// The contact engine queues a payload while another write holds the store. Taking the RNG
/// first and the store second, as the payload once did, left each thread waiting on the other.
#[test]
fn a_contact_write_waits_for_the_store_without_holding_the_rng() {
    // Leaked so the threads can borrow the wallet; a cycle leaves them blocked for good.
    let world: &'static World = Box::leak(Box::new(World::new()));
    let party = &world.issuer;
    let (done_tx, done_rx) = mpsc::channel();
    let (held_tx, held_rx) = mpsc::channel();
    hold_store_then_take_rng(party, held_tx, done_tx.clone());
    held_rx.recv().unwrap();

    std::thread::spawn(move || {
        let posted = world.block_on(party.wallet.contact_book().contact_post_payload(
            &relays(party),
            ContactId([7; 16]),
            vec![1],
        ));
        let unknown = matches!(posted, Err(ContactError::UnknownContact));
        done_tx
            .send(if unknown { "payload" } else { "payload failed" })
            .unwrap();
    });

    assert_eq!(both_finish(&done_rx), ["payload", "write"]);
}

/// An RNG that, once armed, stops in its next draw until the test lets it go, so the test can
/// act while the draw's caller holds the wallet's RNG.
struct PausingRng {
    inner: StdRng,
    armed: Arc<AtomicBool>,
    drawing: mpsc::Sender<()>,
    go: mpsc::Receiver<()>,
}

impl PausingRng {
    fn pause(&mut self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.drawing.send(()).unwrap();
            self.go.recv_timeout(PATIENCE).unwrap();
        }
    }
}

impl rand_core::TryRng for PausingRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.pause();
        self.inner.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.pause();
        self.inner.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.pause();
        self.inner.try_fill_bytes(dst)
    }
}

impl rand_core::TryCryptoRng for PausingRng {}

/// An invoice draws its randomness and then stores itself. The test takes the store while the
/// draw holds the RNG; the invoice's write then waits for the store without holding the RNG.
/// Keeping the RNG's guard until the write ended, as issuing once did, left each thread waiting
/// on the other.
#[test]
fn an_invoice_draws_its_randomness_before_it_waits_for_the_store() {
    let world: &'static World = Box::leak(Box::new(World::new()));
    let party = &world.issuer;
    let armed = Arc::new(AtomicBool::new(false));
    let (drawing_tx, drawing_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    *party.wallet.ports().rng.lock() = Box::new(PausingRng {
        inner: StdRng::seed_from_u64(11),
        armed: Arc::clone(&armed),
        drawing: drawing_tx,
        go: go_rx,
    });
    let (done_tx, done_rx) = mpsc::channel();

    armed.store(true, Ordering::SeqCst);
    let invoice_done = done_tx.clone();
    std::thread::spawn(move || {
        let issued = world.block_on(party.wallet.issue_unsent(
            &crate::support::file(),
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: None,
                ttl_blocks: None,
            },
            Delivery::Export {
                to: Location::File(tempfile::tempdir().unwrap().keep().join("i1.tx")),
            },
        ));
        invoice_done
            .send(if issued.is_ok() {
                "invoice"
            } else {
                "invoice failed"
            })
            .unwrap();
    });
    drawing_rx
        .recv_timeout(PATIENCE)
        .expect("the invoice never drew from the RNG");

    let (held_tx, held_rx) = mpsc::channel();
    hold_store_then_take_rng(party, held_tx, done_tx);
    held_rx
        .recv_timeout(PATIENCE)
        .expect("the invoice drew inside a store write");
    go_tx.send(()).unwrap();

    assert_eq!(both_finish(&done_rx), ["invoice", "write"]);
}
