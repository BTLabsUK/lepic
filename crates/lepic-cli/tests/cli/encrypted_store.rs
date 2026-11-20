// SPDX-License-Identifier: Apache-2.0
//! The CLI reads a wallet database encrypted at rest, also one another program made with the
//! same phrase and copied into a data directory the CLI restored without a scan.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

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

/// A data directory an earlier build left: a plain database under the phrase's keys.
fn make_plain_database(data_dir: &Path, mnemonic: &str) {
    let mut folder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut folder, 0o700);
    folder.recursive(true).create(data_dir).unwrap();
    let seed = Seed::from_mnemonic(mnemonic).unwrap();
    drop(
        lepic_wallet::SqliteStores
            .open(
                data_dir,
                lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
                &lepic_wallet::store_key(&seed).unwrap(),
            )
            .unwrap(),
    );
    assert!(data_dir.join(lepic_wallet::DATABASE_FILE).exists());
}

#[test]
fn the_cli_moves_a_plain_store_to_encryption_and_opens_it_again() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);

    let instance = Instance::new("cli password");
    make_plain_database(&instance.data_dir(), SENDER_MNEMONIC);
    let restored = instance.restore(&host, SENDER_MNEMONIC);
    assert_eq!(restored["scan"]["restored"], 1);
    let dir = instance.data_dir();
    assert!(!dir.join(lepic_wallet::DATABASE_FILE).exists());
    assert!(dir.join("wallet.sqlite3.pre-encryption").exists());
    let encrypted = fs::read(dir.join(ENCRYPTED_DATABASE_FILE)).unwrap();
    assert!(!contains(&encrypted, b"SQLite format 3"));

    let listed = instance.run(&host, &["tx", "list"]).ok().json();
    assert_eq!(
        listed["transactions"].as_array().unwrap().len(),
        1,
        "{listed}"
    );
    let info = instance.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000", "{info}");
    assert!(!dir.join(lepic_wallet::DATABASE_FILE).exists());
}

/// The message of a JSON error and its causes, where the store names the set-aside file.
fn error_text(document: &serde_json::Value) -> String {
    let error = &document["error"];
    std::iter::once(&error["message"])
        .chain(error["causes"].as_array().into_iter().flatten())
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join(": ")
}

#[test]
fn a_damaged_store_is_kept_and_only_start_over_makes_a_new_one() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let instance = Instance::new("cli password");
    let restored = instance.restore(&host, SENDER_MNEMONIC);
    assert_eq!(restored["scan"]["restored"], 1);
    let dir = instance.data_dir();
    let database = dir.join(ENCRYPTED_DATABASE_FILE);
    let mut bytes = fs::read(&database).unwrap();
    let page_size = 4096;
    assert!(bytes.len() > 2 * page_size, "{}", bytes.len());
    for byte in &mut bytes[page_size..page_size + 64] {
        *byte ^= 0xff;
    }
    fs::write(&database, &bytes).unwrap();

    let damaged = instance.run(&host, &["wallet", "info"]);
    let document = damaged.json();
    assert_eq!(
        (damaged.code, document["error"]["kind"].as_str()),
        (1, Some("internal")),
        "{damaged:?}"
    );
    let message = error_text(&document);
    assert!(message.contains("moved aside"), "{document}");
    let kept: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("wallet.enc.sqlite3.damaged-") && !name.contains("-wal"))
        .filter(|name| !name.ends_with("-shm") && !name.ends_with(".check"))
        .collect();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(message.contains(&kept[0]), "{message}");

    let refused = instance.run(&host, &["wallet", "info"]);
    let document = refused.json();
    assert_eq!(
        (refused.code, document["error"]["kind"].as_str()),
        (5, Some("wallet_state")),
        "{refused:?}"
    );
    assert!(error_text(&document).contains(&kept[0]), "{document}");
    assert!(!database.exists());

    let started = instance
        .run(&host, &["wallet", "start-over", "--no-scan"])
        .ok();
    assert!(database.exists(), "{started:?}");
    assert!(dir.join(&kept[0]).exists());
    instance.run(&host, &["wallet", "scan"]).ok();
    let info = instance.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000", "{info}");
}
