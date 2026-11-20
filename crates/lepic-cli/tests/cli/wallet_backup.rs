// SPDX-License-Identifier: Apache-2.0
//! `wallet backup` writes a copy of the vault and the database that opens with the wallet
//! password, also while `serve` has the wallet open.

// Tests may unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::support;

use std::fs;

use support::{Instance, Outcome, SENDER_MNEMONIC, TestHost, funded, serving, text};

fn error_kind(outcome: &Outcome) -> String {
    text(&outcome.json()["error"], "kind").to_owned()
}

/// `wallet` with its data directory replaced by `dir`.
fn env_at(wallet: &Instance, dir: &std::path::Path) -> Vec<(String, String)> {
    let mut env = wallet.env();
    env.retain(|(name, _)| name != "LEPIC_DATA_DIR");
    env.push(("LEPIC_DATA_DIR".to_owned(), dir.display().to_string()));
    env
}

fn transactions(
    host: &TestHost,
    wallet: &Instance,
    dir: &std::path::Path,
) -> Vec<serde_json::Value> {
    let listed = wallet
        .run_with(host, &["tx", "list"], env_at(wallet, dir), "")
        .ok()
        .json();
    listed["transactions"].as_array().unwrap().clone()
}

#[test]
fn a_backup_opens_with_the_same_password_and_lists_the_same_transactions() {
    let (host, wallet) = funded();
    let made = transactions(&host, &wallet, &wallet.data_dir());
    assert_eq!(made.len(), 1, "{made:?}");

    let target = wallet.path("backup");
    let report = wallet
        .run(&host, &["wallet", "backup", target.to_str().unwrap()])
        .ok()
        .json();
    assert_eq!(report["dir"], target.display().to_string(), "{report}");
    let files: Vec<&str> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file.as_str().unwrap())
        .collect();
    assert_eq!(
        files,
        [
            "wallet.vault",
            "wallet.enc.sqlite3",
            "wallet.enc.sqlite3.check"
        ]
    );
    for file in files {
        assert!(target.join(file).is_file(), "{file}");
    }

    // The backup is a data directory: same password, same history, same balance.
    assert_eq!(transactions(&host, &wallet, &target), made);
    let info = wallet
        .run_with(&host, &["wallet", "info"], env_at(&wallet, &target), "")
        .ok()
        .json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000", "{info}");

    // A wrong password does not open it.
    let mut wrong = env_at(&wallet, &target);
    wrong.retain(|(name, _)| name != "LEPIC_PASSWORD");
    wrong.push(("LEPIC_PASSWORD".to_owned(), "another password".to_owned()));
    let refused = wallet.run_with(&host, &["tx", "list"], wrong, "");
    assert_eq!(
        (refused.code, error_kind(&refused).as_str()),
        (4, "wrong_password")
    );
}

#[test]
fn a_backup_made_while_serve_has_the_wallet_open_opens_too() {
    let (host, wallet) = funded();
    let made = transactions(&host, &wallet, &wallet.data_dir());
    let target = wallet.path("backup-while-serving");

    serving(host, &wallet, |_socket, client| {
        let report = wallet
            .run(client, &["wallet", "backup", target.to_str().unwrap()])
            .ok()
            .json();
        assert_eq!(report["dir"], target.display().to_string(), "{report}");
    });

    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, support::FUNDING, 1);
    assert_eq!(transactions(&host, &wallet, &target), made);
}

#[test]
fn a_backup_refuses_to_overwrite_a_path() {
    let (host, wallet) = funded();

    let folder = wallet.path("existing");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("keep"), "mine").unwrap();
    let outcome = wallet.run(&host, &["wallet", "backup", folder.to_str().unwrap()]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (2, "usage"),
        "{outcome:?}"
    );
    assert_eq!(fs::read_to_string(folder.join("keep")).unwrap(), "mine");
    assert_eq!(fs::read_dir(&folder).unwrap().count(), 1);

    let file = wallet.path("a-file");
    fs::write(&file, "mine").unwrap();
    let outcome = wallet.run(&host, &["wallet", "backup", file.to_str().unwrap()]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (2, "usage"),
        "{outcome:?}"
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), "mine");

    // A second backup to the first one's path is refused too, and leaves it intact.
    let target = wallet.path("backup");
    wallet
        .run(&host, &["wallet", "backup", target.to_str().unwrap()])
        .ok();
    let before = fs::read(target.join("wallet.enc.sqlite3")).unwrap();
    let again = wallet.run(&host, &["wallet", "backup", target.to_str().unwrap()]);
    assert_eq!((again.code, error_kind(&again).as_str()), (2, "usage"));
    assert_eq!(fs::read(target.join("wallet.enc.sqlite3")).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn a_backup_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let (host, wallet) = funded();
    let target = wallet.path("backup");
    wallet
        .run(&host, &["wallet", "backup", target.to_str().unwrap()])
        .ok();

    let mode = |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&target), 0o700);
    let mut names = Vec::new();
    for entry in fs::read_dir(&target).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(mode(&entry.path()), 0o600, "{:?}", entry.path());
        names.push(entry.file_name().into_string().unwrap());
    }
    names.sort();
    assert_eq!(
        names,
        [
            "wallet.enc.sqlite3",
            "wallet.enc.sqlite3.check",
            "wallet.vault"
        ]
    );
}

#[test]
fn a_backup_holds_no_password_and_no_seed() {
    let (host, wallet) = funded();
    let target = wallet.path("backup");
    let outcome = wallet
        .run(&host, &["wallet", "backup", target.to_str().unwrap()])
        .ok();
    assert!(!outcome.stdout.contains(&wallet.password));
    assert!(!outcome.stderr.contains(&wallet.password));

    let first_word = SENDER_MNEMONIC.split(' ').next().unwrap();
    let phrase = SENDER_MNEMONIC.as_bytes();
    for entry in fs::read_dir(&target).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        for needle in [wallet.password.as_bytes(), phrase, first_word.as_bytes()] {
            assert!(!bytes.windows(needle.len()).any(|window| window == needle));
        }
    }
}

#[test]
fn a_wrong_password_writes_no_backup() {
    let (host, wallet) = funded();
    let target = wallet.path("backup");
    let mut env = wallet.env();
    env.retain(|(name, _)| name != "LEPIC_PASSWORD");
    env.push(("LEPIC_PASSWORD".to_owned(), "another password".to_owned()));
    let outcome = wallet.run_with(
        &host,
        &["wallet", "backup", target.to_str().unwrap()],
        env,
        "",
    );
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (4, "wrong_password"),
        "{outcome:?}"
    );
    assert!(!target.exists());
}

#[test]
fn a_backup_needs_a_wallet_and_a_parent_folder() {
    let host = TestHost::new();
    let empty = Instance::new("some password");
    let target = empty.path("backup");
    let outcome = empty.run(&host, &["wallet", "backup", target.to_str().unwrap()]);
    assert_ne!(outcome.code, 0, "{outcome:?}");
    assert!(!target.exists());

    let (host, wallet) = funded();
    let nested = wallet.path("missing").join("backup");
    let outcome = wallet.run(&host, &["wallet", "backup", nested.to_str().unwrap()]);
    assert_ne!(outcome.code, 0, "{outcome:?}");
    assert!(!wallet.path("missing").exists());
}

#[test]
fn a_backup_leaves_the_log_files_alone_while_the_data_directory_is_locked() {
    let (host, wallet) = funded();
    let made = transactions(&host, &wallet, &wallet.data_dir());
    let source = wallet.data_dir().join("wallet.enc.sqlite3");
    let logs = [
        wallet.data_dir().join("wallet.enc.sqlite3-wal"),
        wallet.data_dir().join("wallet.enc.sqlite3-shm"),
    ];
    for log in &logs {
        drop(fs::remove_file(log));
    }
    assert!(source.is_file());

    // Another process holds the directory lock: the copy is made, the logs a reader leaves stay.
    let held = lepic_store::try_lock_data_dir(&wallet.data_dir()).unwrap();
    let busy = wallet.path("backup-busy");
    wallet
        .run(&host, &["wallet", "backup", busy.to_str().unwrap()])
        .ok();
    assert!(
        logs[0].exists(),
        "a log that a live process may own was removed"
    );
    drop(held);
    assert_eq!(transactions(&host, &wallet, &busy), made);

    // Free: the empty logs the backup's reader made are cleaned up as before.
    for log in &logs {
        drop(fs::remove_file(log));
    }
    let free = wallet.path("backup-free");
    wallet
        .run(&host, &["wallet", "backup", free.to_str().unwrap()])
        .ok();
    assert!(!logs[0].exists());
}
