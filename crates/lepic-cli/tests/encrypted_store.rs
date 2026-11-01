// SPDX-License-Identifier: Apache-2.0
//! The CLI reads a wallet database encrypted at rest, also one another program made with the
//! same phrase and copied into a data directory the CLI restored without a scan.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::fs;
use std::path::Path;

use lepic_keychain::Seed;
use lepic_wallet::{ENCRYPTED_DATABASE_FILE, EncryptedSqliteStores, StoreOpener};

use support::{FUNDING, Instance, SENDER_MNEMONIC, TestHost};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// An empty encrypted database under the phrase's store key, so the wallet the CLI makes in
/// `data_dir` lives in it.
fn make_encrypted_database(data_dir: &Path, mnemonic: &str) {
    let mut folder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut folder, 0o700);
    folder.recursive(true).create(data_dir).unwrap();
    let seed = Seed::from_mnemonic(mnemonic).unwrap();
    drop(
        EncryptedSqliteStores
            .open(
                data_dir,
                lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
                &lepic_wallet::store_key(&seed).unwrap(),
            )
            .unwrap(),
    );
}

const DATABASE_FILES: [&str; 4] = ["", "-wal", "-shm", ".check"];

#[test]
fn a_copied_encrypted_store_opens_in_a_wallet_restored_without_a_scan() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);

    // The wallet that made the history, in an encrypted database.
    let maker = Instance::new("maker password");
    make_encrypted_database(&maker.data_dir(), SENDER_MNEMONIC);
    let restored = maker.restore(&host, SENDER_MNEMONIC);
    assert_eq!(restored["scan"]["restored"], 1);
    let made = maker.run(&host, &["tx", "list"]).ok().json();
    let made_transactions = made["transactions"].as_array().unwrap().clone();
    assert_eq!(made_transactions.len(), 1, "{made}");
    assert!(!maker.data_dir().join("wallet.sqlite3").exists());
    let encrypted = fs::read(maker.data_dir().join(ENCRYPTED_DATABASE_FILE)).unwrap();
    assert!(!contains(&encrypted, b"SQLite format 3"));

    // Another install of the phrase: restored without a scan, then given the database.
    let reader = Instance::new("reader password");
    reader
        .run_with(
            &host,
            &["wallet", "restore", "--no-scan"],
            reader.env(),
            &format!("{SENDER_MNEMONIC}\n"),
        )
        .ok();
    for suffix in DATABASE_FILES {
        let name = format!("{ENCRYPTED_DATABASE_FILE}{suffix}");
        let from = maker.data_dir().join(&name);
        if from.exists() {
            fs::copy(&from, reader.data_dir().join(&name)).unwrap();
        }
    }

    let info = reader.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000", "{info}");
    let listed = reader.run(&host, &["tx", "list"]).ok().json();
    assert_eq!(
        listed["transactions"].as_array().unwrap(),
        &made_transactions
    );

    // The copied database is still the one in use, unchanged in content.
    let again = reader.run(&host, &["tx", "list"]).ok().json();
    assert_eq!(
        again["transactions"].as_array().unwrap(),
        &made_transactions
    );
    let maker_again = maker.run(&host, &["tx", "list"]).ok().json();
    assert_eq!(
        maker_again["transactions"].as_array().unwrap(),
        &made_transactions
    );
}
