// SPDX-License-Identifier: Apache-2.0
//! The cost of encryption at rest on one workload: open a new database, write 2,000
//! transactions, refresh them (read all, confirm each, in commits of 100 as
//! a refresh batches them), and open the full database again.
//!
//! `cargo xtask budget` times the plain and the encrypted workload. The ignored comparison runs
//! both several times, alternating, and prints each phase's median and the ratio, for a phone:
//! build this test binary for the target and run it with `--ignored --nocapture`
//! (docs/budgets.md).

// Test code may unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

mod support;

use std::path::Path;
use std::time::{Duration, Instant};

use lepic_primitives::amount::Height;
use lepic_store::{AtRest, STORE_KEY_LEN, SqliteStore, StoreKey, TxId, WalletStore};

use support::{account, context_key, transaction};

const TRANSACTIONS: usize = 2_000;
const BATCH: usize = 100;

#[derive(Debug, Clone, Copy, Default)]
struct Phases {
    create: Duration,
    write: Duration,
    refresh: Duration,
    reopen: Duration,
}

fn open(path: &Path, at_rest: AtRest<'_>) -> SqliteStore {
    SqliteStore::open(path, context_key(1), at_rest).unwrap()
}

fn workload(at_rest: AtRest<'_>) -> Phases {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite3");
    let started = Instant::now();
    let store = open(&path, at_rest);
    let create = started.elapsed();
    let default = account(0, "default").index;
    store
        .write(|repos| repos.put_account(&account(0, "default")))
        .unwrap();

    let started = Instant::now();
    for _ in 0..TRANSACTIONS / BATCH {
        store
            .write(|repos| {
                for _ in 0..BATCH {
                    repos.insert_transaction(&transaction(default, None))?;
                }
                Ok::<_, lepic_store::StoreError>(())
            })
            .unwrap();
    }
    let write = started.elapsed();

    let started = Instant::now();
    let ids: Vec<TxId> = store
        .read(|repos| repos.transactions(default))
        .unwrap()
        .iter()
        .map(|stored| stored.id)
        .collect();
    assert_eq!(ids.len(), TRANSACTIONS);
    for chunk in ids.chunks(BATCH) {
        store
            .write(|repos| {
                for id in chunk {
                    repos.set_confirmed_height(*id, Height::new(1_000))?;
                }
                Ok::<_, lepic_store::StoreError>(())
            })
            .unwrap();
    }
    let refresh = started.elapsed();
    drop(store);

    let started = Instant::now();
    let reopened = open(&path, at_rest);
    let count = reopened
        .read(|repos| repos.transactions(default))
        .unwrap()
        .len();
    let reopen = started.elapsed();
    assert_eq!(count, TRANSACTIONS);
    Phases {
        create,
        write,
        refresh,
        reopen,
    }
}

#[test]
fn plain_store_workload_of_2000_transactions() {
    workload(AtRest::Plain);
}

#[test]
fn encrypted_store_workload_of_2000_transactions() {
    workload(AtRest::Encrypted(&StoreKey::from_bytes([5; STORE_KEY_LEN])));
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort();
    values[values.len() / 2]
}

#[test]
#[ignore = "a measurement for a device, run by hand: --ignored --nocapture"]
fn compare_plain_and_encrypted_store() {
    const RUNS: usize = 7;
    let key = StoreKey::from_bytes([5; STORE_KEY_LEN]);
    let (mut plain, mut encrypted) = (Vec::new(), Vec::new());
    for _ in 0..RUNS {
        plain.push(workload(AtRest::Plain));
        encrypted.push(workload(AtRest::Encrypted(&key)));
    }
    let phase =
        |runs: &[Phases], pick: fn(&Phases) -> Duration| median(runs.iter().map(pick).collect());
    let total = |p: &Phases| p.create + p.write + p.refresh + p.reopen;
    println!("phase      plain_ms  encrypted_ms  ratio");
    for (name, pick) in [
        ("create", (|p: &Phases| p.create) as fn(&Phases) -> Duration),
        ("write", |p: &Phases| p.write),
        ("refresh", |p: &Phases| p.refresh),
        ("reopen", |p: &Phases| p.reopen),
        ("total", total),
    ] {
        let (a, b) = (phase(&plain, pick), phase(&encrypted, pick));
        println!(
            "{name:<10} {:>8.2}  {:>12.2}  {:.3}",
            a.as_secs_f64() * 1e3,
            b.as_secs_f64() * 1e3,
            b.as_secs_f64() / a.as_secs_f64()
        );
    }
}
