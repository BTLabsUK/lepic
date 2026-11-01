// SPDX-License-Identifier: Apache-2.0
//! The move of a plain wallet database into an encrypted one, stopped at every step.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use super::*;
use crate::context::ContextKey;
use crate::peer::PeerTagKey;
use crate::sqlite::schema::migrate_to;
use crate::transaction::TxId;

/// The schema of the last release before encryption.
const PLAIN_SCHEMA: u32 = 11;

fn keys() -> StoreKeys {
    StoreKeys::new(
        ContextKey::from_bytes([3; 32]),
        PeerTagKey::from_bytes([4; 32]),
    )
}

fn key() -> StoreKey {
    StoreKey::from_bytes([7; 32])
}

/// A plain v11 database as the last release leaves it, with `extra` more transactions and
/// outputs, and its last commit still only in the write-ahead log.
fn plain_database(dir: &Path, extra: u32) {
    let path = dir.join(DATABASE_FILE);
    let mut conn = Connection::open(&path).unwrap();
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )
    .unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    migrate_to(&mut conn, PLAIN_SCHEMA, &keys()).unwrap();
    conn.execute_batch(
        "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
         INSERT INTO settings (key, value) VALUES ('network', 'floonet');
         INSERT INTO transactions (id, account, direction, state, slate_id,
             amount_credited, amount_debited, created_at, updated_at)
         VALUES (1, 0, 'outgoing', 'cancelled', X'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a',
             0, 5, 1, 1);
         INSERT INTO peer_capabilities (key, support, learned_at) VALUES
             ('lepic-key', 'lepic', 1790000000000000000),
             ('stock-key', 'no-invoices', 1790000100000000000);",
    )
    .unwrap();
    if extra > 0 {
        conn.execute(
            "WITH RECURSIVE n(i) AS (SELECT 2 UNION ALL SELECT i + 1 FROM n WHERE i < ?1 + 1)
             INSERT INTO transactions (id, account, direction, state, slate_id,
                 amount_credited, amount_debited, fee, created_at, updated_at)
             SELECT i, 0, 'incoming', 'confirmed', randomblob(16), 1000 + i, 0, 7, i, i FROM n",
            [extra],
        )
        .unwrap();
        conn.execute(
            "WITH RECURSIVE n(i) AS (SELECT 2 UNION ALL SELECT i + 1 FROM n WHERE i < ?1 + 1)
             INSERT INTO outputs (commitment, features, key_id, account, amount, status, height,
                 lock_height, mmr_index, tx_id)
             SELECT randomblob(33), 0, randomblob(17), 0, 1000 + i, 'unspent', i, 0, i, i FROM n",
            [extra],
        )
        .unwrap();
    }
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('only-in-the-log', 'yes')",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(
        std::fs::metadata(with_suffix(&path, "-wal")).unwrap().len() > 0,
        "the fixture keeps commits in its log"
    );
}

/// Every file of `dir` by name, with its bytes, but the shared-memory index, which holds
/// nothing durable.
fn files(dir: &Path) -> BTreeMap<String, String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter(|entry| {
            !entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with("-shm")
        })
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = std::fs::read(entry.path()).unwrap();
            (
                entry.file_name().into_string().unwrap(),
                format!(
                    "{} bytes, sha256 {}",
                    bytes.len(),
                    Sha256::digest(&bytes)
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ),
            )
        })
        .collect()
}

fn plain_bytes(dir: &Path, base: &str) -> (Vec<u8>, Vec<u8>) {
    let path = dir.join(base);
    (
        std::fs::read(&path).unwrap(),
        std::fs::read(with_suffix(&path, "-wal")).unwrap_or_default(),
    )
}

fn version_of(path: &Path) -> u32 {
    let conn =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    stored_version(&conn).unwrap()
}

fn has_table(path: &Path, name: &str) -> bool {
    let conn =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )
    .unwrap()
}

/// What a store holds that the checks compare: transactions, outputs and settings.
fn contents(store: &SqliteStore) -> (i64, i64, Option<String>, Option<String>) {
    let conn = store.conn.lock().unwrap();
    let count = |table: &str| -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    };
    let setting = |name: &str| -> Option<String> {
        conn.query_row("SELECT value FROM settings WHERE key = ?1", [name], |row| {
            row.get(0)
        })
        .ok()
    };
    (
        count("transactions"),
        count("outputs"),
        setting("network"),
        setting("only-in-the-log"),
    )
}

struct CrashAt(Step);

impl Faults for CrashAt {
    fn at(&self, step: Step) -> Option<Fault> {
        (step == self.0).then_some(Fault::Crash)
    }
}

struct DiskFullAt(Step);

impl Faults for DiskFullAt {
    fn at(&self, step: Step) -> Option<Fault> {
        (step == self.0).then_some(Fault::DiskFull)
    }
}

struct HeldAt(Step);

impl Faults for HeldAt {
    fn at(&self, step: Step) -> Option<Fault> {
        (step == self.0).then_some(Fault::Held)
    }
}

/// The state every completed move ends in.
fn assert_migrated(dir: &Path, original: &(Vec<u8>, Vec<u8>), store: &SqliteStore) {
    assert!(
        !dir.join(DATABASE_FILE).exists(),
        "the plain file stays in place"
    );
    assert!(!dir.join(COPY_FILE).exists(), "the copy is left behind");
    assert!(!migration_in_progress(dir));
    let aside = format!("{DATABASE_FILE}{PRE_ENCRYPTION_SUFFIX}");
    assert_eq!(
        &plain_bytes(dir, &aside),
        original,
        "the plain file changed before it was set aside"
    );
    assert_eq!(
        version_of(&dir.join(&aside)),
        PLAIN_SCHEMA,
        "the plain file's schema was migrated"
    );
    assert!(has_table(&dir.join(&aside), "peer_capabilities"));
    let encrypted = std::fs::read(dir.join(ENCRYPTED_DATABASE_FILE)).unwrap();
    assert!(!encrypted.windows(15).any(|w| w == b"SQLite format 3"));
    assert!(
        dir.join(format!("{ENCRYPTED_DATABASE_FILE}.check"))
            .exists()
    );
    assert_eq!(
        contents(store),
        (1, 0, Some("floonet".to_owned()), Some("yes".to_owned()))
    );
    // The schema steps ran on the encrypted database.
    let conn = store.conn.lock().unwrap();
    assert_eq!(stored_version(&conn).unwrap(), SCHEMA_VERSION);
    let moved: i64 = conn
        .query_row("SELECT count(*) FROM peer_compat", [], |row| row.get(0))
        .unwrap();
    assert_eq!(moved, 2);
    let record: String = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [MIGRATED_FROM_SETTING],
            |row| row.get(0),
        )
        .unwrap();
    let record: MigrationRecord = serde_json::from_str(&record).unwrap();
    assert_eq!(record.schema, PLAIN_SCHEMA);
    assert_eq!(record.rows["transactions"], 1);
}

#[test]
fn migrates_and_keeps_every_row() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    let original = plain_bytes(dir.path(), DATABASE_FILE);
    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::MigratedNow);
    assert!(!report.rollback_set_aside);
    assert_migrated(dir.path(), &original, &store);
    let entry = store.read(|repos| repos.transaction(TxId(1))).unwrap();
    assert!(entry.is_some());
    drop(store);

    let (again, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
    assert!(!report.rollback_set_aside);
    assert_migrated(dir.path(), &original, &again);
}

#[test]
fn a_plain_database_without_a_log_is_copied_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    // Checkpointed and closed as the last release closes it: no log left.
    let conn = Connection::open(dir.path().join(DATABASE_FILE)).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(conn);
    assert!(!dir.path().join(format!("{DATABASE_FILE}-wal")).exists());
    let original = std::fs::read(dir.path().join(DATABASE_FILE)).unwrap();
    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::MigratedNow);
    let aside = dir
        .path()
        .join(format!("{DATABASE_FILE}{PRE_ENCRYPTION_SUFFIX}"));
    assert_eq!(std::fs::read(&aside).unwrap(), original);
    assert_eq!(contents(&store).3, Some("yes".to_owned()));
}

#[test]
fn a_crash_at_any_step_is_finished_by_the_next_open() {
    for at in [
        Step::Cleared,
        Step::Copying,
        Step::Copied,
        Step::Checked,
        Step::KeyChecked,
        Step::Switched,
        Step::SetAside,
    ] {
        let dir = tempfile::tempdir().unwrap();
        plain_database(dir.path(), 0);
        let original = plain_bytes(dir.path(), DATABASE_FILE);
        let crashed = open_wallet_dir_with(dir.path(), keys(), &key(), None, &CrashAt(at));
        assert!(crashed.is_err(), "{at:?}");
        if dir.path().join(DATABASE_FILE).exists() {
            assert_eq!(
                plain_bytes(dir.path(), DATABASE_FILE),
                original,
                "the plain file changed before {at:?}"
            );
            assert_eq!(version_of(&dir.path().join(DATABASE_FILE)), PLAIN_SCHEMA);
        }
        if at < Step::Switched {
            assert!(
                !dir.path().join(ENCRYPTED_DATABASE_FILE).exists(),
                "{at:?}: switched early"
            );
        }

        let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
        let expected = if at < Step::Switched {
            AtRestState::MigratedNow
        } else {
            AtRestState::Encrypted
        };
        assert_eq!(report.state, expected, "{at:?}");
        assert!(!report.rollback_set_aside, "{at:?}: taken for a rollback");
        assert_migrated(dir.path(), &original, &store);
    }
}

/// A plain database another program holds through every retry is not left under its name
/// beside a session on the encrypted one: the open fails, and the next one sets it aside.
#[test]
fn a_plain_database_held_at_the_set_aside_fails_the_open_and_the_next_finishes() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    let original = plain_bytes(dir.path(), DATABASE_FILE);
    let held = open_wallet_dir_with(dir.path(), keys(), &key(), None, &HeldAt(Step::SetAside));
    assert!(
        matches!(held, Err(StoreError::Io { ref source, .. })
            if source.kind() == std::io::ErrorKind::PermissionDenied),
        "{:?}",
        held.map(|_| ())
    );
    assert!(dir.path().join(ENCRYPTED_DATABASE_FILE).exists());
    assert_eq!(
        std::fs::read(dir.path().join(DATABASE_FILE)).unwrap(),
        original.0,
        "the plain file changed"
    );

    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
    assert!(!report.rollback_set_aside, "taken for a rollback");
    assert_migrated(dir.path(), &original, &store);
}

#[test]
fn a_set_aside_stopped_after_the_log_moved_is_finished() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    let original = plain_bytes(dir.path(), DATABASE_FILE);
    let crashed = open_wallet_dir_with(dir.path(), keys(), &key(), None, &CrashAt(Step::Switched));
    assert!(crashed.is_err());
    // The log went aside, the database not yet.
    let plain = dir.path().join(DATABASE_FILE);
    std::fs::rename(
        with_suffix(&plain, "-wal"),
        with_suffix(&with_suffix(&plain, PRE_ENCRYPTION_SUFFIX), "-wal"),
    )
    .unwrap();

    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
    assert!(!report.rollback_set_aside);
    assert_migrated(dir.path(), &original, &store);
}

/// A log left without its database under the `.pre-encryption` name, as a removal interrupted
/// by an older build could leave it, does not take in an older build's plain database: that is
/// set aside after a rollback, with a scan required.
#[test]
fn an_orphan_log_does_not_take_an_older_builds_database_for_the_source() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    drop(open_wallet_dir(dir.path(), keys(), &key(), None).unwrap());
    let aside = dir
        .path()
        .join(format!("{DATABASE_FILE}{PRE_ENCRYPTION_SUFFIX}"));
    std::fs::remove_file(&aside).unwrap();
    assert!(with_suffix(&aside, "-wal").exists());
    let older = {
        let path = dir.path().join(DATABASE_FILE);
        let mut conn = Connection::open(&path).unwrap();
        migrate_to(&mut conn, PLAIN_SCHEMA, &keys()).unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    };

    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert!(report.rollback_set_aside);
    assert!(!dir.path().join(DATABASE_FILE).exists());
    assert!(!aside.exists(), "taken for the source of the copy");
    let rolled: Vec<String> = files(dir.path())
        .into_keys()
        .filter(|name| name.contains(".after-rollback-") && !name.ends_with("-wal"))
        .collect();
    assert_eq!(rolled.len(), 1, "{rolled:?}");
    assert_eq!(std::fs::read(dir.path().join(&rolled[0])).unwrap(), older);
    let flag = store
        .read(|repos| repos.setting(ROLLBACK_SCAN_SETTING))
        .unwrap();
    assert_eq!(flag.as_deref(), Some("true"));
}

#[test]
fn a_full_disk_keeps_the_plain_database_and_the_next_open_migrates() {
    for at in [Step::Cleared, Step::Copying, Step::Copied] {
        let dir = tempfile::tempdir().unwrap();
        plain_database(dir.path(), 0);
        let (store, report) =
            open_wallet_dir_with(dir.path(), keys(), &key(), None, &DiskFullAt(at)).unwrap();
        let AtRestState::FellBackToPlain { reason } = &report.state else {
            panic!("{at:?}: {report:?}");
        };
        assert!(!reason.is_empty());
        assert!(!dir.path().join(COPY_FILE).exists(), "{at:?}");
        assert!(!dir.path().join(ENCRYPTED_DATABASE_FILE).exists(), "{at:?}");
        // The session runs on the plain file, which the schema steps migrated in place.
        assert_eq!(
            contents(&store),
            (1, 0, Some("floonet".to_owned()), Some("yes".to_owned()))
        );
        drop(store);
        assert_eq!(version_of(&dir.path().join(DATABASE_FILE)), SCHEMA_VERSION);

        let original = plain_bytes(dir.path(), DATABASE_FILE);
        let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
        assert_eq!(report.state, AtRestState::MigratedNow, "{at:?}");
        assert_eq!(
            contents(&store),
            (1, 0, Some("floonet".to_owned()), Some("yes".to_owned()))
        );
        let aside = format!("{DATABASE_FILE}{PRE_ENCRYPTION_SUFFIX}");
        assert_eq!(plain_bytes(dir.path(), &aside), original);
    }
}

/// An error after the rename to the encrypted database, as a folder flush that fails, fails the
/// open: the session never falls back to the plain file once the encrypted one is in place.
#[test]
fn an_error_after_the_switch_never_falls_back_to_the_plain_database() {
    for at in [Step::Switched, Step::SetAside] {
        let dir = tempfile::tempdir().unwrap();
        plain_database(dir.path(), 0);
        let original = plain_bytes(dir.path(), DATABASE_FILE);
        let failed = open_wallet_dir_with(dir.path(), keys(), &key(), None, &DiskFullAt(at));
        assert!(
            failed.is_err(),
            "{at:?}: {:?}",
            failed.map(|(_, report)| report)
        );
        assert!(dir.path().join(ENCRYPTED_DATABASE_FILE).exists(), "{at:?}");

        let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
        assert_eq!(report.state, AtRestState::Encrypted, "{at:?}");
        assert!(!report.rollback_set_aside, "{at:?}: taken for a rollback");
        assert_migrated(dir.path(), &original, &store);
    }
}

#[test]
fn a_wrong_key_is_refused_and_nothing_moves() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    drop(open_wallet_dir(dir.path(), keys(), &key(), None).unwrap());
    // An older build's plain file beside it, which a wrong key must not touch either.
    std::fs::write(dir.path().join(DATABASE_FILE), b"").unwrap();
    let before = files(dir.path());
    let other = StoreKey::from_bytes([8; 32]);
    let refused = open_wallet_dir(dir.path(), keys(), &other, None);
    assert!(matches!(refused, Err(StoreError::WrongKey)), "{refused:?}");
    assert_eq!(files(dir.path()), before);
    let refused = open_existing_wallet_dir(dir.path(), keys(), &other);
    assert!(matches!(refused, Err(StoreError::WrongKey)), "{refused:?}");
    assert_eq!(files(dir.path()), before);
}

#[test]
fn a_plain_database_an_older_build_made_after_a_rollback_is_set_aside_and_a_scan_required() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    drop(open_wallet_dir(dir.path(), keys(), &key(), None).unwrap());
    // The older build found no plain database and made an empty one.
    let older = {
        let path = dir.path().join(DATABASE_FILE);
        let mut conn = Connection::open(&path).unwrap();
        migrate_to(&mut conn, PLAIN_SCHEMA, &keys()).unwrap();
        drop(conn);
        std::fs::read(&path).unwrap()
    };

    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
    assert!(report.rollback_set_aside);
    assert!(!dir.path().join(DATABASE_FILE).exists());
    let aside: Vec<String> = files(dir.path())
        .into_keys()
        .filter(|name| name.contains(".after-rollback-") && !name.ends_with("-wal"))
        .collect();
    assert_eq!(aside.len(), 1, "{aside:?}");
    assert_eq!(std::fs::read(dir.path().join(&aside[0])).unwrap(), older);
    let flag = store
        .read(|repos| repos.setting(ROLLBACK_SCAN_SETTING))
        .unwrap();
    assert_eq!(flag.as_deref(), Some("true"));
    // The history is still the encrypted database's.
    assert_eq!(contents(&store).2, Some("floonet".to_owned()));
    drop(store);

    let (_, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert!(!report.rollback_set_aside);
}

#[test]
fn a_damaged_plain_database_is_set_aside_as_before() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(DATABASE_FILE), vec![0x5a; 8192]).unwrap();
    let opened = open_wallet_dir(dir.path(), keys(), &key(), None);
    assert!(
        matches!(opened, Err(StoreError::DamagedSetAside)),
        "{opened:?}"
    );
    assert!(!dir.path().join(COPY_FILE).exists());
    assert!(!dir.path().join(ENCRYPTED_DATABASE_FILE).exists());
    let (_, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
}

#[test]
fn a_new_directory_gets_an_encrypted_database() {
    let dir = tempfile::tempdir().unwrap();
    let (_, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
    assert!(dir.path().join(ENCRYPTED_DATABASE_FILE).exists());
    assert!(!dir.path().join(DATABASE_FILE).exists());
}

#[test]
fn a_phrase_check_reads_a_plain_database_through_a_throwaway_copy() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    let before = files(dir.path());
    let store = open_existing_wallet_dir(dir.path(), keys(), &key())
        .unwrap()
        .unwrap();
    assert_eq!(contents(&store).2, Some("floonet".to_owned()));
    store
        .write(|repos| repos.put_setting("wallet.seed_check", "00"))
        .unwrap();
    drop(store);
    assert_eq!(files(dir.path()), before, "the check left files behind");
    assert_eq!(version_of(&dir.path().join(DATABASE_FILE)), PLAIN_SCHEMA);

    let empty = tempfile::tempdir().unwrap();
    assert!(
        open_existing_wallet_dir(empty.path(), keys(), &key())
            .unwrap()
            .is_none()
    );
    assert_eq!(files(empty.path()).len(), 0);
}

/// The record of a plain database of `bytes`, as the copy stores it.
fn record_of(bytes: &[u8]) -> String {
    serde_json::to_string(&MigrationRecord {
        schema: PLAIN_SCHEMA,
        user_version: 0,
        bytes: u64::try_from(bytes.len()).unwrap(),
        sha256: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        wal_sha256: None,
        rows: BTreeMap::new(),
        at: 0,
    })
    .unwrap()
}

#[test]
fn retire_deletes_only_the_set_aside_plain_files() {
    let dir = tempfile::tempdir().unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let day = 24 * 60 * 60;
    let old = 1_800_000_000 - 31 * day;
    let recent = 1_800_000_000 - day;
    for name in [
        "wallet.sqlite3.pre-encryption".to_owned(),
        "wallet.sqlite3.pre-encryption-wal".to_owned(),
        format!("wallet.sqlite3.after-rollback-{old}"),
        format!("wallet.sqlite3.after-rollback-{old}-wal"),
        format!("wallet.sqlite3.after-rollback-{recent}"),
        // A log whose database is still being set aside.
        format!("wallet.sqlite3.after-rollback-{}-wal", old - 1),
        "wallet.sqlite3.damaged-1".to_owned(),
        "wallet.sqlite3".to_owned(),
        "wallet.enc.sqlite3.check".to_owned(),
        "wfe_meta.json".to_owned(),
    ] {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    // Another plain database set aside, which the encrypted one was not copied from.
    std::fs::write(dir.path().join("wallet.sqlite3.pre-encryption-1"), b"y").unwrap();
    let record = record_of(b"x");
    // Without the encrypted database nothing goes.
    let summary = retire_plain_store(
        dir.path(),
        Some(&record),
        Duration::from_secs(30 * day),
        now,
    )
    .unwrap();
    assert!(summary.deleted.is_empty());

    std::fs::write(dir.path().join(ENCRYPTED_DATABASE_FILE), b"x").unwrap();
    let mut summary = retire_plain_store(
        dir.path(),
        Some(&record),
        Duration::from_secs(30 * day),
        now,
    )
    .unwrap();
    summary.deleted.sort();
    assert_eq!(
        summary.deleted,
        vec![
            format!("wallet.sqlite3.after-rollback-{old}"),
            format!("wallet.sqlite3.after-rollback-{old}-wal"),
            "wallet.sqlite3.pre-encryption".to_owned(),
            "wallet.sqlite3.pre-encryption-wal".to_owned(),
        ]
    );
    assert_eq!(
        summary.kept,
        vec!["wallet.sqlite3.pre-encryption-1".to_owned()]
    );
    let left: Vec<String> = files(dir.path()).into_keys().collect();
    assert_eq!(
        left,
        vec![
            "wallet.enc.sqlite3".to_owned(),
            "wallet.enc.sqlite3.check".to_owned(),
            "wallet.sqlite3".to_owned(),
            format!("wallet.sqlite3.after-rollback-{}-wal", old - 1),
            format!("wallet.sqlite3.after-rollback-{recent}"),
            "wallet.sqlite3.damaged-1".to_owned(),
            "wallet.sqlite3.pre-encryption-1".to_owned(),
            "wfe_meta.json".to_owned(),
        ]
    );
}

/// An encrypted database rebuilt empty after damage does not hold the plain history: the
/// `.pre-encryption` file it was not copied from is the last readable copy and stays.
#[test]
fn retire_keeps_a_plain_copy_the_encrypted_database_does_not_record() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    let (store, _) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    let record = store
        .read(|repos| repos.setting(MIGRATED_FROM_SETTING))
        .unwrap();
    assert!(record.is_some());
    drop(store);
    let aside = format!("{DATABASE_FILE}{PRE_ENCRYPTION_SUFFIX}");

    for migrated_from in [None, Some(record_of(b"another database").as_str())] {
        let summary =
            retire_plain_store(dir.path(), migrated_from, Duration::ZERO, SystemTime::now())
                .unwrap();
        assert!(summary.deleted.is_empty(), "{summary:?}");
        assert_eq!(summary.kept, vec![aside.clone()]);
        assert!(dir.path().join(&aside).exists());
    }

    let summary = retire_plain_store(
        dir.path(),
        record.as_deref(),
        Duration::ZERO,
        SystemTime::now(),
    )
    .unwrap();
    assert!(summary.deleted.contains(&aside), "{summary:?}");
    assert!(summary.kept.is_empty());
    assert!(!dir.path().join(&aside).exists());
}

/// The deletion of a wallet takes every set-aside plain database, recorded or not.
#[test]
fn remove_set_aside_plain_takes_every_plain_copy() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "wallet.sqlite3.pre-encryption",
        "wallet.sqlite3.pre-encryption-wal",
        "wallet.sqlite3.pre-encryption-1",
        "wallet.sqlite3.after-rollback-5",
        "wallet.enc.sqlite3",
    ] {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    let mut deleted = remove_set_aside_plain(dir.path()).unwrap();
    deleted.sort();
    assert_eq!(deleted.len(), 4, "{deleted:?}");
    let left: Vec<String> = files(dir.path()).into_keys().collect();
    assert_eq!(left, vec!["wallet.enc.sqlite3".to_owned()]);
}

/// The keyed URI is written into a buffer of its exact size, and an error of the copy that
/// carries it holds only a result code, never the URI or the key.
#[test]
fn the_keyed_uri_never_grows_and_its_errors_never_carry_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("missing folder").join(COPY_FILE);
    let uri = keyed_uri(&copy, &key()).unwrap();
    let hex = "07".repeat(32);
    assert!(uri.ends_with(&format!("key=raw:{hex}")), "{}", uri.as_str());
    assert_eq!(uri.capacity(), uri.len());

    plain_database(dir.path(), 0);
    let reader = open_reader(&dir.path().join(DATABASE_FILE)).unwrap();
    let progress = Progress {
        observer: None,
        total: 1,
        page_size: 4096,
    };
    let error = copy_into(&reader, &copy, &key(), progress).unwrap_err();
    for shown in [format!("{error:?}"), format!("{error}"), {
        let mut chain = String::new();
        let mut source: Option<&dyn std::error::Error> = Some(&error);
        while let Some(error) = source {
            chain.push_str(&error.to_string());
            source = error.source();
        }
        chain
    }] {
        assert!(!shown.contains(&hex), "{shown}");
        assert!(!shown.contains("key="), "{shown}");
    }
}

#[test]
fn a_connection_given_a_key_wipes_freed_memory() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    let conn = store.conn.lock().unwrap();
    let level: String = conn
        .query_row("PRAGMA memory_security", [], |row| row.get(0))
        .unwrap();
    assert_eq!(level, "1");
}

#[test]
fn a_path_with_uri_characters_is_copied() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("a dir?#%&=");
    std::fs::create_dir(&dir).unwrap();
    plain_database(&dir, 0);
    let (_, report) = open_wallet_dir(&dir, keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::MigratedNow);
}

/// 10,000 transactions and outputs, the size the app shows a counter for. The time is
/// printed for the record; the bound only catches a copy gone badly wrong.
#[test]
fn ten_thousand_rows_migrate_within_budget_with_progress() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 10_000);
    let size = std::fs::metadata(dir.path().join(DATABASE_FILE))
        .unwrap()
        .len()
        + std::fs::metadata(dir.path().join(format!("{DATABASE_FILE}-wal")))
            .unwrap()
            .len();
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    let observer: Box<MigrationObserver> =
        Box::new(move |progress| seen.lock().unwrap().push(progress));
    let started = Instant::now();
    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), Some(&*observer)).unwrap();
    let elapsed = started.elapsed();
    eprintln!(
        "10,000-row store ({size} bytes) migrated in {} ms",
        elapsed.as_millis()
    );
    assert_eq!(report.state, AtRestState::MigratedNow);
    assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
    let (transactions, outputs, ..) = contents(&store);
    assert_eq!((transactions, outputs), (10_001, 10_000));

    let events = events.lock().unwrap();
    eprintln!("progress events: {}", events.len());
    let stages: Vec<MigrationStage> = events.iter().map(|event| event.stage).collect();
    assert!(stages.contains(&MigrationStage::Checking));
    assert_eq!(stages.last(), Some(&MigrationStage::Finished));
    let copying: Vec<&MigrationProgress> = events
        .iter()
        .filter(|event| event.stage == MigrationStage::Copying)
        .collect();
    assert!(
        copying
            .windows(2)
            .all(|pair| pair[0].done <= pair[1].done && pair[0].total == pair[1].total)
    );
    assert!(copying.iter().all(|event| event.done <= event.total));
}

/// A development build without encryption left a plain database at the current schema: it is
/// copied as it is.
#[test]
fn a_plain_database_at_the_current_schema_is_copied() {
    let dir = tempfile::tempdir().unwrap();
    let plain = SqliteStore::open(&dir.path().join(DATABASE_FILE), keys(), AtRest::Plain).unwrap();
    plain
        .write(|repos| repos.put_setting("network", "floonet"))
        .unwrap();
    drop(plain);
    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::MigratedNow);
    assert_eq!(contents(&store).2, Some("floonet".to_owned()));
    let aside = dir
        .path()
        .join(format!("{DATABASE_FILE}{PRE_ENCRYPTION_SUFFIX}"));
    assert_eq!(version_of(&aside), SCHEMA_VERSION);
}

/// A plain database of a newer schema than this build's is refused, unchanged, and nothing is
/// copied.
#[test]
fn a_plain_database_of_a_newer_schema_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DATABASE_FILE);
    drop(SqliteStore::open(&path, keys(), AtRest::Plain).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE schema_version SET version = ?1 WHERE id = 1",
        [SCHEMA_VERSION + 1],
    )
    .unwrap();
    drop(conn);
    let before = std::fs::read(&path).unwrap();
    let refused = open_wallet_dir(dir.path(), keys(), &key(), None);
    assert!(
        matches!(refused, Err(StoreError::SchemaTooNew { .. })),
        "{refused:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!dir.path().join(COPY_FILE).exists());
    assert!(!dir.path().join(ENCRYPTED_DATABASE_FILE).exists());
    assert_eq!(version_of(&path), SCHEMA_VERSION + 1);
}
