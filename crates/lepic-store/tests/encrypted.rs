// SPDX-License-Identifier: Apache-2.0
//! The SQLite store encrypted at rest: no plaintext on disk, the key check, and a wrong key told
//! apart from a damaged file.

// Test code may unwrap, index and use plain arithmetic (docs/rules.md); clippy's test
// exemptions do not reach helpers outside `#[test]` functions.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use lepic_store::{AtRest, STORE_KEY_LEN, SqliteStore, StoreError, StoreKey, WalletStore};

use support::{account, context_key};

const MARKER: &str = "es1qcounterparty0marker0address";

fn store_key(byte: u8) -> StoreKey {
    StoreKey::from_bytes([byte; STORE_KEY_LEN])
}

fn encrypted_path(dir: &Path) -> PathBuf {
    dir.join("wallet.enc.sqlite3")
}

fn open(path: &Path, key: &StoreKey) -> Result<SqliteStore, StoreError> {
    SqliteStore::open(path, context_key(1), AtRest::Encrypted(key))
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Every file in `dir` with its bytes.
fn folder(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn encrypted_file_has_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    let key = store_key(1);
    let store = open(&path, &key).unwrap();
    store
        .write(|repos| {
            repos.put_account(&account(0, "default"))?;
            repos.put_setting("counterparty", MARKER)
        })
        .unwrap();
    // Read before closing, so the write-ahead log still holds the commit.
    let open_files = folder(dir.path());
    assert!(open_files.contains_key("wallet.enc.sqlite3-wal"));
    drop(store);
    for files in [open_files, folder(dir.path())] {
        for (name, bytes) in files {
            assert!(
                !contains(&bytes, MARKER.as_bytes()),
                "{name} holds the counterparty"
            );
            assert!(
                !contains(&bytes, b"SQLite format 3"),
                "{name} is plain SQLite"
            );
            assert!(
                !contains(&bytes, b"default"),
                "{name} holds the account label"
            );
        }
    }
    let reopened = open(&path, &key).unwrap();
    assert_eq!(
        reopened
            .read(|repos| repos.setting("counterparty"))
            .unwrap()
            .as_deref(),
        Some(MARKER)
    );
}

#[test]
fn a_new_encrypted_database_gets_a_key_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    drop(open(&path, &store_key(1)).unwrap());
    let check = fs::read(with_suffix(&path, ".check")).unwrap();
    assert_eq!(check.len(), 33);
    assert_eq!(check[0], 1);
}

#[test]
fn wrong_key_is_refused_and_nothing_moves() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    let store = open(&path, &store_key(1)).unwrap();
    store
        .write(|repos| repos.put_account(&account(0, "default")))
        .unwrap();
    drop(store);
    let before = folder(dir.path());

    let result = open(&path, &store_key(2));
    assert!(matches!(result, Err(StoreError::WrongKey)), "{result:?}");
    let existing =
        SqliteStore::open_existing(&path, context_key(1), AtRest::Encrypted(&store_key(2)));
    assert!(
        matches!(existing, Err(StoreError::WrongKey)),
        "{existing:?}"
    );
    assert_eq!(folder(dir.path()), before);

    let reopened = open(&path, &store_key(1)).unwrap();
    assert_eq!(reopened.read(|repos| repos.accounts()).unwrap().len(), 1);
}

/// Without its check nothing tells a wrong key from damage, so the file is never set aside.
#[test]
fn wrong_key_without_a_check_is_refused_and_nothing_moves() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    drop(open(&path, &store_key(1)).unwrap());
    fs::remove_file(with_suffix(&path, ".check")).unwrap();
    let before = folder(dir.path());

    let result = open(&path, &store_key(2));
    assert!(matches!(result, Err(StoreError::WrongKey)), "{result:?}");
    assert_eq!(folder(dir.path()), before);
}

#[test]
fn the_right_key_without_a_check_opens_and_writes_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    drop(open(&path, &store_key(1)).unwrap());
    let check = with_suffix(&path, ".check");
    fs::remove_file(&check).unwrap();

    drop(open(&path, &store_key(1)).unwrap());
    assert!(check.is_file());
    assert!(matches!(
        open(&path, &store_key(2)),
        Err(StoreError::WrongKey)
    ));
}

#[test]
fn damaged_encrypted_file_with_right_key_is_set_aside() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    let store = open(&path, &store_key(1)).unwrap();
    store
        .write(|repos| repos.put_account(&account(0, "default")))
        .unwrap();
    drop(store);
    let mut bytes = fs::read(&path).unwrap();
    let page_size = 4096;
    assert!(bytes.len() > 2 * page_size);
    for byte in &mut bytes[page_size..page_size + 64] {
        *byte ^= 0xff;
    }
    fs::write(&path, &bytes).unwrap();
    let check = fs::read(with_suffix(&path, ".check")).unwrap();

    let existing =
        SqliteStore::open_existing(&path, context_key(1), AtRest::Encrypted(&store_key(1)));
    assert!(matches!(existing, Err(StoreError::Damaged)), "{existing:?}");
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let result = open(&path, &store_key(1));
    assert!(
        matches!(result, Err(StoreError::DamagedSetAside)),
        "{result:?}"
    );
    let files = folder(dir.path());
    let aside = files
        .keys()
        .find(|name| {
            name.contains(".damaged-")
                && !name.ends_with("-wal")
                && !name.ends_with("-shm")
                && !name.ends_with(".check")
        })
        .unwrap()
        .clone();
    assert_eq!(files[&aside], bytes);
    assert_eq!(files[&format!("{aside}.check")], check);
    assert!(!path.exists());
    assert!(!with_suffix(&path, ".check").exists());

    let fresh = open(&path, &store_key(1)).unwrap();
    assert!(fresh.read(|repos| repos.accounts()).unwrap().is_empty());
}

#[test]
fn open_existing_finds_no_encrypted_database_and_creates_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    let found = SqliteStore::open_existing(&path, context_key(1), AtRest::Encrypted(&store_key(1)));
    assert!(found.unwrap().is_none());
    assert!(folder(dir.path()).is_empty());
}

/// A plain file is not one an encrypted open may take for its own, nor set aside.
#[test]
fn an_encrypted_open_of_a_plain_file_is_refused_and_leaves_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = encrypted_path(dir.path());
    let plain = SqliteStore::open(&path, context_key(1), AtRest::Plain).unwrap();
    plain
        .write(|repos| repos.put_account(&account(0, "default")))
        .unwrap();
    drop(plain);
    let before = folder(dir.path());

    let result = open(&path, &store_key(1));
    assert!(matches!(result, Err(StoreError::WrongKey)), "{result:?}");
    assert_eq!(folder(dir.path()), before);
}
