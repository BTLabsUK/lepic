// SPDX-License-Identifier: Apache-2.0
//! Times the payment calls of `lepic serve` on a wallet with a long history.
//!
//! The store is seeded with 22,000 transactions, 300 of them with an unspent output, before
//! serve starts. `LEPIC_LARGE_STORE_TRANSACTIONS` sets another size, up to 100,000. The test
//! prints one line per call with its time and asserts nothing on the times:
//!
//! ```text
//! cargo nextest run -p lepic-cli -E 'test(/^large_store::/)' --run-ignored only --no-capture
//! ```
//!
//! Requests wait up to ten minutes for an answer, where `support::http` waits
//! `support::PATIENCE`, so a slow call is timed instead of failing the test.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use crate::support;

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use lepic_keychain::{Identifier, Keychain, ProofBuilder, SwitchCommitment};
use lepic_node::mock::ChainOutput;
use lepic_primitives::amount::Height;
use lepic_primitives::output::OutputIdentifier;
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, OutputStatus};
use lepic_wallet::StoreOpener as _;
use serde_json::{Value, json};
use support::{
    FUNDING, Instance, Reply, SENDER_MNEMONIC, TestHost, parse_reply, serving, text, with_settings,
};

const SIZE_VARIABLE: &str = "LEPIC_LARGE_STORE_TRANSACTIONS";
const DEFAULT_TRANSACTIONS: u32 = 22_000;
const MAX_TRANSACTIONS: u32 = 100_000;
const UNSPENT: u32 = 300;
/// The caller's id the alias lookup goes by.
const ALIAS: &str = "a11a5e00-0000-4000-8000-000000000001";
/// How long a request may take before the test gives up on it.
const READ_PATIENCE: Duration = Duration::from_secs(600);

fn size() -> u32 {
    match std::env::var(SIZE_VARIABLE) {
        Ok(text) => {
            let size: u32 = text.trim().parse().unwrap();
            assert!(
                (1..=MAX_TRANSACTIONS).contains(&size),
                "{SIZE_VARIABLE} must lie between 1 and {MAX_TRANSACTIONS}"
            );
            size
        }
        Err(_) => DEFAULT_TRANSACTIONS,
    }
}

/// Writes the history into the stopped wallet's store, as the wallet opens it.
fn seed_store(wallet: &Instance, transactions: u32, unspent: u32) {
    let seed = lepic_keychain::Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
    let store = lepic_wallet::EncryptedSqliteStores
        .open(
            &wallet.data_dir(),
            lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
            &lepic_wallet::store_key(&seed).unwrap(),
        )
        .unwrap();
    lepic_store::seed::seed(&store, transactions, unspent).unwrap();
    // Leaves the log folded into the database, as a wallet that closed does.
    drop(store);
}

/// Swaps each seeded unspent output for the one its key and amount commit to and puts that on
/// the chain, so refresh keeps it unspent and a send can spend it.
fn make_unspent_real(host: &TestHost, wallet: &Instance) {
    let keychain = Keychain::from_mnemonic(SENDER_MNEMONIC, Network::Floonet).unwrap();
    let builder = ProofBuilder::new(&keychain).unwrap();
    let mut on_chain = Vec::new();
    with_settings(wallet, SENDER_MNEMONIC, |repos| {
        for record in repos.outputs(AccountIndex(0), Some(OutputStatus::Unspent))? {
            let key = Identifier::from_bytes(&record.key_id.0).unwrap();
            let output = lepic_keychain::proof::create_output(
                &keychain,
                &builder,
                record.amount.value(),
                &key,
                SwitchCommitment::Regular,
            )
            .unwrap();
            if output.commitment == record.id.commitment {
                continue;
            }
            repos.delete_output(record.commitment())?;
            on_chain.push(ChainOutput {
                commitment: output.commitment,
                features: output.features,
                proof: output.proof,
                height: record.height,
                mmr_index: record.mmr_index.unwrap(),
                spent: false,
            });
            repos.put_output(&lepic_store::OutputRecord {
                id: OutputIdentifier::new(output.features, output.commitment),
                ..record
            })?;
        }
        Ok(())
    });
    host.node
        .update_chain(|chain| chain.outputs.extend(on_chain));
}

/// The slate ids of the oldest and of a middle transaction.
fn old_payments(wallet: &Instance) -> (String, String) {
    with_settings(wallet, SENDER_MNEMONIC, |repos| {
        let mut slates: Vec<_> = repos
            .transactions(AccountIndex(0))?
            .into_iter()
            .filter_map(|transaction| transaction.entry.slate_id)
            .collect();
        let middle = slates.swap_remove(slates.len() / 2);
        repos.put_payment_delivery(&lepic_store::PaymentDelivery {
            payment_id: middle,
            alias: Some(ALIAS.to_owned()),
            state: None,
            state_reason: None,
            updated_at: jiff::Timestamp::now(),
        })?;
        Ok((slates[0].to_string(), middle.to_string()))
    })
}

fn database_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(lepic_wallet::ENCRYPTED_DATABASE_FILE)
        })
        .map(|entry| entry.metadata().unwrap().len())
        .sum()
}

/// One request to serve on `socket`, as `support::http` sends it, with a longer read timeout.
/// `None` when serve has not answered in time.
fn http(socket: &Path, method: &str, path: &str, body: Option<&str>) -> Option<Reply> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(READ_PATIENCE)).unwrap();
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: lepic\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut answer = String::new();
    match stream.read_to_string(&mut answer) {
        Ok(_) => Some(parse_reply(&answer)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(error) => panic!("{method} {path}: {error}"),
    }
}

/// Runs the call once, prints its name and time, and returns the answer, or `None` when it
/// took longer than [`READ_PATIENCE`].
fn timed(
    socket: &Path,
    name: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Option<Value> {
    let body = body.map(Value::to_string);
    let started = Instant::now();
    let reply = http(socket, method, path, body.as_deref());
    let elapsed = started.elapsed().as_millis();
    let Some(reply) = reply else {
        println!("large_store {name}: no answer within {elapsed} ms");
        return None;
    };
    println!("large_store {name}: {elapsed} ms");
    assert!(reply.status < 300, "{name}: {reply:?}");
    Some(reply.json())
}

#[test]
#[ignore = "benchmark: seeds a large store and runs for minutes"]
fn large_store_payment_calls() {
    let transactions = size();
    let unspent = UNSPENT.min(transactions);
    let host = TestHost::new();
    // Every seeded transaction is mined in its own block below the tip. The tip is raised
    // before the restore, so the wallet has scanned up to it and never rescans the history.
    host.node.update_chain(|chain| {
        chain.tip.height = Height::new(u64::from(transactions) + 10);
    });
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let started = Instant::now();
    seed_store(&wallet, transactions, unspent);
    let seeding = started.elapsed();
    println!(
        "large_store seed: {} ms for {transactions} transactions, {unspent} unspent",
        seeding.as_millis()
    );
    println!(
        "large_store database: {} bytes",
        database_size(&wallet.data_dir())
    );
    make_unspent_real(&host, &wallet);
    let (oldest, middle) = old_payments(&wallet);

    serving(host, &wallet, |socket, _| {
        let started = Instant::now();
        loop {
            let status = http(socket, "GET", "/api/v1/status", None).unwrap().ok();
            if status["refresh"]["last_success_at"].is_string() {
                break;
            }
            assert!(started.elapsed() < READ_PATIENCE, "no refresh: {status}");
            std::thread::sleep(Duration::from_millis(200));
        }
        println!(
            "large_store first_refresh: {} ms after serve answered",
            started.elapsed().as_millis()
        );
        let read = timed(
            socket,
            "get_payment_by_id",
            "GET",
            &format!("/api/v1/payments/{oldest}"),
            None,
        );
        if let Some(read) = read {
            assert_eq!(text(&read, "id"), oldest, "{read}");
        }
        let read = timed(
            socket,
            "get_payment_by_alias",
            "GET",
            &format!("/api/v1/payments/{ALIAS}"),
            None,
        );
        if let Some(read) = read {
            assert_eq!(text(&read, "id"), middle, "{read}");
        }
        timed(socket, "list_payments", "GET", "/api/v1/payments", None);
        timed(socket, "list_outputs", "GET", "/api/v1/outputs", None);
        let by_hand = json!({ "amount": "1", "deliver": false });
        timed(
            socket,
            "create_payment_deliver_false",
            "POST",
            "/api/v1/payments",
            Some(&by_hand),
        );
        let by_file = json!({ "amount": "1", "via": "file" });
        timed(
            socket,
            "create_payment_via_file",
            "POST",
            "/api/v1/payments",
            Some(&by_file),
        );
    });
}
