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

/// The same with a real Windows handle that does not share deletion, as an indexer, antivirus
/// or backup tool may hold: the rename is refused through every retry.
#[cfg(windows)]
#[test]
fn a_plain_database_another_program_holds_on_windows_is_set_aside_by_the_next_open() {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_SHARE_READ: u32 = 1;
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    let original = plain_bytes(dir.path(), DATABASE_FILE);
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(dir.path().join(DATABASE_FILE))
        .unwrap();
    let held = open_wallet_dir(dir.path(), keys(), &key(), None);
    assert!(held.is_err(), "{:?}", held.map(|(_, report)| report));
    assert!(dir.path().join(ENCRYPTED_DATABASE_FILE).exists());
    drop(holder);
    assert_eq!(
        std::fs::read(dir.path().join(DATABASE_FILE)).unwrap(),
        original.0
    );

    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
    assert!(!report.rollback_set_aside);
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
    let Err(StoreError::DamagedSetAside { set_aside }) = opened else {
        panic!("{opened:?}");
    };
    assert!(!dir.path().join(COPY_FILE).exists());
    assert!(!dir.path().join(ENCRYPTED_DATABASE_FILE).exists());
    let again = open_wallet_dir(dir.path(), keys(), &key(), None);
    assert!(
        matches!(&again, Err(StoreError::DamagedKept { set_aside: kept }) if *kept == set_aside),
        "{again:?}"
    );
    assert!(!dir.path().join(ENCRYPTED_DATABASE_FILE).exists());
    let (_, report) = start_over_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::Encrypted);
    assert_eq!(std::fs::read(&set_aside).unwrap(), vec![0x5a; 8192]);
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

/// The deletion of a wallet takes every set-aside plain database, recorded or not, damaged ones
/// too, and what an interrupted copy or key check left; never the databases themselves.
#[test]
fn remove_database_leftovers_takes_every_plain_copy_and_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "wallet.sqlite3.pre-encryption",
        "wallet.sqlite3.pre-encryption-wal",
        "wallet.sqlite3.pre-encryption-1",
        "wallet.sqlite3.after-rollback-5",
        "wallet.sqlite3.damaged-5",
        "wallet.sqlite3.damaged-5-wal",
        "wallet.enc.sqlite3.tmp",
        "wallet.enc.sqlite3.tmp-wal",
        "wallet.enc.sqlite3.check.tmp",
        "wallet.enc.sqlite3",
        "wallet.enc.sqlite3.check",
        "wallet.sqlite3",
    ] {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }
    let deleted = remove_database_leftovers(dir.path()).unwrap();
    assert_eq!(deleted.len(), 9, "{deleted:?}");
    let left: Vec<String> = files(dir.path()).into_keys().collect();
    assert_eq!(
        left,
        vec![
            "wallet.enc.sqlite3".to_owned(),
            "wallet.enc.sqlite3.check".to_owned(),
            "wallet.sqlite3".to_owned(),
        ]
    );
}

/// A key check whose write stopped before its rename leaves its temporary file, which the next
/// open removes with the copy's files.
#[test]
fn a_key_check_left_half_written_is_removed_by_the_next_open() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    std::fs::write(dir.path().join(CHECK_COPY_FILE), [1u8; 7]).unwrap();
    let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::MigratedNow);
    drop(store);
    std::fs::write(dir.path().join(CHECK_COPY_FILE), [1u8; 7]).unwrap();
    drop(open_wallet_dir(dir.path(), keys(), &key(), None).unwrap());
    assert!(!dir.path().join(CHECK_COPY_FILE).exists());
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
fn a_file_uri_names_the_path_whatever_its_form() {
    assert_eq!(
        file_uri(Path::new("/home/a b/wallet.enc.sqlite3.tmp")),
        "file:///home/a%20b/wallet.enc.sqlite3.tmp"
    );
    assert_eq!(
        file_uri(Path::new("data/wallet.enc.sqlite3.tmp")),
        "file:data/wallet.enc.sqlite3.tmp"
    );
    if cfg!(windows) {
        for (path, uri) in [
            (r"C:\Users\a b\w", "file:///C:/Users/a%20b/w"),
            (r"\\?\C:\Users\a b\w", "file:///C:/Users/a%20b/w"),
            (r"\\server\share\w", "file:////server/share/w"),
            (r"\\?\UNC\server\share\w", "file:////server/share/w"),
        ] {
            assert_eq!(file_uri(Path::new(path)), uri, "{path}");
        }
    }
}

/// A data directory the way the app's binding names it, canonicalised: on Windows that is the
/// verbatim `\\?\` form.
#[test]
fn a_canonical_data_directory_is_copied() {
    let parent = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(parent.path()).unwrap();
    plain_database(&dir, 0);
    let (_, report) = open_wallet_dir(&dir, keys(), &key(), None).unwrap();
    assert_eq!(report.state, AtRestState::MigratedNow);
}

#[test]
fn a_path_with_uri_characters_is_copied() {
    let parent = tempfile::tempdir().unwrap();
    // Windows allows no `?` in a file name.
    let name = if cfg!(windows) {
        "a dir#%&=+;"
    } else {
        "a dir?#%&=+;"
    };
    let dir = parent.path().join(name);
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

/// Spoils the copy once it is complete, before it is checked: runs `sql` in it, or, with no
/// SQL, overwrites a stretch of a page.
struct SpoilCopy {
    dir: std::path::PathBuf,
    sql: Option<&'static str>,
}

impl Faults for SpoilCopy {
    fn at(&self, step: Step) -> Option<Fault> {
        if step != Step::Copied {
            return None;
        }
        let copy = self.dir.join(COPY_FILE);
        match self.sql {
            Some(sql) => {
                let conn = Connection::open(&copy).unwrap();
                cipher::set_key(&conn, &key()).unwrap();
                conn.execute_batch(sql).unwrap();
            }
            None => {
                let mut bytes = std::fs::read(&copy).unwrap();
                assert!(bytes.len() > 3 * 4096, "the copy has pages to spoil");
                bytes[2 * 4096..2 * 4096 + 256].fill(0x5a);
                std::fs::write(&copy, bytes).unwrap();
            }
        }
        None
    }
}

/// A copy that does not match what the plain database held is refused whatever differs, so
/// the session stays on the plain file, which is not set aside, and the next open tries again.
#[test]
fn a_copy_that_does_not_match_the_plain_database_is_refused_and_the_plain_file_stays() {
    let cases: [(&str, Option<&str>, &str); 4] = [
        (
            "the schema",
            Some("UPDATE schema_version SET version = version + 1"),
            "match the schema of the encrypted copy",
        ),
        (
            "the user version",
            Some("PRAGMA user_version = 99"),
            "match the user version of the encrypted copy",
        ),
        (
            "the rows",
            Some("DELETE FROM settings WHERE key = 'only-in-the-log'"),
            "match the rows of the encrypted copy",
        ),
        ("a damaged page", None, "check the encrypted copy"),
    ];
    for (what, sql, operation) in cases {
        let dir = tempfile::tempdir().unwrap();
        plain_database(dir.path(), 200);
        let faults = SpoilCopy {
            dir: dir.path().to_owned(),
            sql,
        };

        let (store, report) =
            open_wallet_dir_with(dir.path(), keys(), &key(), None, &faults).unwrap();

        let AtRestState::FellBackToPlain { reason } = &report.state else {
            panic!("{what}: {report:?}");
        };
        assert!(reason.contains(operation), "{what}: {reason}");
        assert!(!dir.path().join(COPY_FILE).exists(), "{what}");
        assert!(!dir.path().join(ENCRYPTED_DATABASE_FILE).exists(), "{what}");
        let aside = format!("{DATABASE_FILE}{PRE_ENCRYPTION_SUFFIX}");
        assert!(!dir.path().join(&aside).exists(), "{what}: set aside");
        assert_eq!(
            contents(&store).0,
            201,
            "{what}: the session reads the plain file"
        );
        drop(store);

        let (store, report) = open_wallet_dir(dir.path(), keys(), &key(), None).unwrap();
        assert_eq!(report.state, AtRestState::MigratedNow, "{what}");
        assert_eq!(contents(&store).0, 201, "{what}");
        assert!(dir.path().join(&aside).exists(), "{what}");
    }
}

/// A rename that another program holds twice, then lets go of.
static HELD_TWICE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ALWAYS_HELD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static NEVER_THERE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn held_twice(_: &Path, _: &Path) -> std::io::Result<()> {
    if HELD_TWICE.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn always_held(_: &Path, _: &Path) -> std::io::Result<()> {
    ALWAYS_HELD.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Err(std::io::ErrorKind::PermissionDenied.into())
}

fn never_there(_: &Path, _: &Path) -> std::io::Result<()> {
    NEVER_THERE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Err(std::io::ErrorKind::NotFound.into())
}

fn denied_rename(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::PermissionDenied.into())
}

fn missing_rename(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::NotFound.into())
}

/// A rename another program holds is tried again until it lets go, up to the last wait; a
/// missing file is not tried again.
#[test]
fn a_held_rename_is_tried_again_and_a_missing_file_is_not() {
    use std::sync::atomic::Ordering::SeqCst;
    let from = Path::new("from");
    let to = Path::new("to");

    rename_retrying(from, to, held_twice).unwrap();
    assert_eq!(HELD_TWICE.load(SeqCst), 3);

    let error = rename_retrying(from, to, never_there).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(NEVER_THERE.load(SeqCst), 1);

    let error = rename_retrying(from, to, always_held).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(ALWAYS_HELD.load(SeqCst), 1 + RENAME_BACKOFF.len());
}

/// A file that is not there is nothing to set aside; one that cannot be renamed is an error.
#[test]
fn setting_a_file_aside_ignores_a_missing_file_and_reports_a_held_one() {
    let from = Path::new("from");
    let to = Path::new("to");
    rename_if_present(from, to, missing_rename).unwrap();
    rename_if_present(from, to, |_, _| Ok(())).unwrap();
    let error = rename_if_present(from, to, denied_rename).unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::Io { operation: "set the plain database aside", source }
                if source.kind() == std::io::ErrorKind::PermissionDenied
        ),
        "{error:?}"
    );
}

/// The test rename that holds the plain database moves every other file.
#[test]
fn the_held_database_rename_holds_the_database_and_moves_its_logs() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join(DATABASE_FILE);
    let wal = with_suffix(&plain, "-wal");
    std::fs::write(&plain, b"db").unwrap();
    std::fs::write(&wal, b"log").unwrap();

    let error = held_database_rename(&plain, &dir.path().join("db.moved")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(plain.exists());
    assert!(!dir.path().join("db.moved").exists());

    held_database_rename(&wal, &dir.path().join("wal.moved")).unwrap();
    assert!(!wal.exists());
    assert_eq!(std::fs::read(dir.path().join("wal.moved")).unwrap(), b"log");
}

#[test]
fn removing_a_file_says_whether_there_was_one() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a");
    assert!(!remove_if_present(&file).unwrap());
    std::fs::write(&file, b"x").unwrap();
    assert!(remove_if_present(&file).unwrap());
    assert!(!file.exists());

    // Something that is not a file to remove is an error, not "nothing there".
    let folder = dir.path().join("folder");
    std::fs::create_dir(&folder).unwrap();
    let error = remove_if_present(&folder).unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::Io {
                operation: "remove a database file",
                ..
            }
        ),
        "{error:?}"
    );
    assert!(folder.exists());
}

#[test]
fn a_set_aside_name_is_free_only_when_no_file_of_it_exists() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("wallet.sqlite3.pre-encryption");
    assert_eq!(free_name(&base).unwrap(), base);

    // Each file of a name takes it: the database, and every log alone.
    for taken in ["", "-wal", "-shm", "-journal"] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("wallet.sqlite3.pre-encryption");
        std::fs::write(with_suffix(&base, taken), b"x").unwrap();
        assert_eq!(
            free_name(&base).unwrap(),
            with_suffix(&base, "-1"),
            "taken by {taken:?}"
        );
    }

    std::fs::write(with_suffix(&base, "-wal"), b"x").unwrap();
    std::fs::write(with_suffix(&base, "-1-shm"), b"x").unwrap();
    assert_eq!(free_name(&base).unwrap(), with_suffix(&base, "-2"));
}

/// A set-aside log with no database is an orphan of an interrupted set-aside; a database
/// beside its log, or a lone -shm that is no moved log, is not.
#[test]
fn only_a_moved_log_without_its_database_is_an_orphan() {
    let name = "wallet.sqlite3.pre-encryption";
    let orphans = |present: &[&str]| {
        let dir = tempfile::tempdir().unwrap();
        for suffix in present {
            std::fs::write(dir.path().join(format!("{name}{suffix}")), b"x").unwrap();
        }
        orphan_logs(dir.path())
            .unwrap()
            .iter()
            .map(|path| file_name(path))
            .collect::<Vec<_>>()
    };
    assert_eq!(orphans(&["-wal"]), [name]);
    assert_eq!(orphans(&["-journal"]), [name]);
    assert!(orphans(&["", "-wal"]).is_empty());
    assert!(orphans(&[""]).is_empty());
    assert!(orphans(&["-shm"]).is_empty());
    assert!(orphans(&[]).is_empty());
}

#[test]
fn a_file_is_flushed_only_when_it_exists() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("copy");
    let error = sync_file(&file).unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::Io {
                operation: "flush the encrypted copy",
                ..
            }
        ),
        "{error:?}"
    );
    std::fs::write(&file, b"x").unwrap();
    sync_file(&file).unwrap();
}

/// The cut-off of a retired after-rollback file: one set aside exactly that long ago stays,
/// one a second older goes.
#[test]
fn retire_deletes_an_after_rollback_file_only_once_it_is_older_than_the_age() {
    let dir = tempfile::tempdir().unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let older_than = Duration::from_secs(100);
    let cutoff = 1_800_000_000 - 100;
    let at = |stamp: u64| format!("wallet.sqlite3.after-rollback-{stamp}");
    for stamp in [cutoff - 1, cutoff, cutoff + 1] {
        std::fs::write(dir.path().join(at(stamp)), b"x").unwrap();
    }
    std::fs::write(dir.path().join(ENCRYPTED_DATABASE_FILE), b"x").unwrap();

    let summary = retire_plain_store(dir.path(), None, older_than, now).unwrap();

    assert_eq!(summary.deleted, vec![at(cutoff - 1)]);
    assert!(summary.kept.is_empty());
    assert!(dir.path().join(at(cutoff)).exists());
    assert!(dir.path().join(at(cutoff + 1)).exists());
}

/// A record names a plain database by its size, its hash and its log's hash: a plain
/// database that differs in any one is not the one the copy was made from.
#[test]
fn a_plain_database_is_recorded_only_when_its_size_and_both_hashes_match() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join(DATABASE_FILE);
    std::fs::write(&plain, b"database").unwrap();
    std::fs::write(with_suffix(&plain, "-wal"), b"log").unwrap();
    let files = PlainFiles::of(&plain).unwrap();
    let record = MigrationRecord {
        schema: PLAIN_SCHEMA,
        user_version: 0,
        bytes: files.bytes,
        sha256: files.sha256.clone(),
        wal_sha256: files.wal_sha256.clone(),
        rows: BTreeMap::new(),
        at: 0,
    };
    assert_eq!(files.bytes, 8);
    assert!(files.wal_sha256.is_some());
    assert!(files.is_recorded(&record));

    let other_bytes = MigrationRecord {
        bytes: record.bytes + 1,
        ..record.clone()
    };
    let other_hash = MigrationRecord {
        sha256: "0".repeat(64),
        ..record.clone()
    };
    let other_log = MigrationRecord {
        wal_sha256: Some("0".repeat(64)),
        ..record.clone()
    };
    let no_log = MigrationRecord {
        wal_sha256: None,
        ..record.clone()
    };
    for (what, other) in [
        ("the size", other_bytes),
        ("the hash", other_hash),
        ("the log's hash", other_log),
        ("the log", no_log),
    ] {
        assert!(!files.is_recorded(&other), "{what} differs");
    }
}

#[test]
fn a_digest_is_the_length_and_sha256_of_the_file_and_none_for_a_missing_one() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(digest(&dir.path().join("missing")).unwrap(), None);

    let small = dir.path().join("small");
    std::fs::write(&small, b"abc").unwrap();
    assert_eq!(
        digest(&small).unwrap(),
        Some((
            3,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned()
        ))
    );

    // Longer than the read buffer: every chunk is counted and hashed.
    let large = dir.path().join("large");
    let bytes = vec![0x5a; 64 * 1024 * 2 + 17];
    std::fs::write(&large, &bytes).unwrap();
    let expected: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        digest(&large).unwrap(),
        Some((u64::try_from(bytes.len()).unwrap(), expected))
    );
}

/// A path that cannot be read is an error, not a missing file: a plain database that is
/// only unreadable must not be taken for one that is gone.
#[cfg(unix)]
#[test]
fn a_path_that_cannot_be_read_is_an_error_not_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    let error = digest(&file.join("child")).unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::Io {
                operation: "read the plain database",
                ..
            }
        ),
        "{error:?}"
    );
}

/// A reader of a plain database that had no log leaves an empty -wal and a -shm; they go,
/// unless they were there before, and a log with content never goes.
#[test]
fn the_logs_a_reader_made_go_and_the_logs_that_were_there_stay() {
    let plain = |dir: &Path| dir.join(DATABASE_FILE);
    let logs = |dir: &Path| {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| file_name(&entry.unwrap().path()))
            .filter(|name| name != DATABASE_FILE)
            .collect();
        names.sort();
        names
    };
    let set_up = |wal: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(plain(dir.path()), b"db").unwrap();
        std::fs::write(with_suffix(&plain(dir.path()), "-wal"), wal).unwrap();
        std::fs::write(with_suffix(&plain(dir.path()), "-shm"), b"shm").unwrap();
        dir
    };

    let dir = set_up(b"");
    forget_reader_logs(&plain(dir.path()), [false, false]).unwrap();
    assert!(logs(dir.path()).is_empty(), "both logs were the reader's");

    let dir = set_up(b"");
    forget_reader_logs(&plain(dir.path()), [true, false]).unwrap();
    assert_eq!(
        logs(dir.path()),
        ["wallet.sqlite3-shm", "wallet.sqlite3-wal"],
        "an empty log that was there stays"
    );

    let dir = set_up(b"");
    forget_reader_logs(&plain(dir.path()), [false, true]).unwrap();
    assert_eq!(
        logs(dir.path()),
        ["wallet.sqlite3-shm"],
        "an index that was there stays"
    );

    let dir = set_up(b"commits");
    forget_reader_logs(&plain(dir.path()), [false, false]).unwrap();
    assert_eq!(
        logs(dir.path()),
        ["wallet.sqlite3-shm", "wallet.sqlite3-wal"],
        "a log with content stays"
    );
}

/// An error of the copy keeps its result code and loses its message, which can quote the key.
#[test]
fn an_error_of_the_copy_keeps_its_code_and_loses_its_message() {
    let code_of = |error: &rusqlite::Error| {
        let StoreError::Database(error) = code_only(error) else {
            panic!("not a database error");
        };
        assert!(!format!("{error:?}").contains("key=SECRET"), "{error:?}");
        error.0.sqlite_error_code()
    };
    let failure = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
        Some("cannot open file:wallet?key=SECRET".to_owned()),
    );
    assert_eq!(code_of(&failure), Some(rusqlite::ErrorCode::CannotOpen));
    assert_eq!(
        code_of(&rusqlite::Error::QueryReturnedNoRows),
        Some(rusqlite::ErrorCode::Unknown)
    );
}

/// What the copy of a plain database that cannot be copied reports: a file that is no database
/// is damage, one that is not there is not.
#[test]
fn only_a_damaged_plain_database_is_reported_as_damaged() {
    let copy = |dir: &Path| copy_plain(dir, &key(), None, &NoFaults, Purpose::Probe);

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(DATABASE_FILE), vec![0x5a; 8192]).unwrap();
    assert!(matches!(copy(dir.path()), Err(Failure::PlainDamaged)));

    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(copy(dir.path()), Err(Failure::Failed(_))));
}

/// A plain database in rollback-journal mode, which another connection can lock out.
fn plain_rollback_database(dir: &Path) -> std::path::PathBuf {
    let path = dir.join(DATABASE_FILE);
    let mut conn = Connection::open(&path).unwrap();
    migrate_to(&mut conn, PLAIN_SCHEMA, &keys()).unwrap();
    conn.execute_batch("INSERT INTO settings (key, value) VALUES ('network', 'floonet')")
        .unwrap();
    path
}

fn pragma_i64(conn: &Connection, name: &str) -> i64 {
    conn.pragma_query_value(None, name, |row| row.get(0))
        .unwrap()
}

/// The connection the copy reads the plain database through can write nothing, keeps its
/// temporary tables in memory and gets the small page cache the copy budgets for.
#[test]
fn the_reader_of_a_plain_database_is_read_only_with_a_small_cache() {
    let dir = tempfile::tempdir().unwrap();
    plain_database(dir.path(), 0);
    let reader = open_reader(&dir.path().join(DATABASE_FILE)).unwrap();
    assert!(reader.is_readonly(rusqlite::MAIN_DB).unwrap());
    let error = reader
        .execute("INSERT INTO settings (key, value) VALUES ('k', 'v')", [])
        .unwrap_err();
    assert_eq!(
        error.sqlite_error_code(),
        Some(rusqlite::ErrorCode::ReadOnly),
        "{error:?}"
    );
    // A negative cache size counts kibibytes, a positive one pages.
    assert_eq!(pragma_i64(&reader, "cache_size"), -COPY_CACHE_KIB);
    assert_eq!(pragma_i64(&reader, "temp_store"), 2);
}

/// Damage is told from a busy or unreadable file by the code SQLite gave: only damage sets the
/// plain file aside, so a file another program holds must not be taken for damaged.
#[test]
fn inspecting_a_plain_database_tells_damage_from_a_failed_read() {
    let dir = tempfile::tempdir().unwrap();
    let garbage = dir.path().join("garbage.db");
    std::fs::write(&garbage, vec![0x5a; 8192]).unwrap();
    // Opened without the settings of `open_reader`, which would already fail on this file.
    let reader = Connection::open_with_flags(
        &garbage,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    assert!(matches!(
        inspect_plain(&reader).err(),
        Some(Failure::PlainDamaged)
    ));

    let busy_dir = tempfile::tempdir().unwrap();
    let path = plain_rollback_database(busy_dir.path());
    let reader = open_reader(&path).unwrap();
    reader.busy_timeout(Duration::ZERO).unwrap();
    let holder = Connection::open(&path).unwrap();
    holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
    match inspect_plain(&reader).err() {
        Some(Failure::Failed(StoreError::Database(error))) => {
            assert_eq!(
                error.0.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
        }
        _ => panic!("a locked plain database must fail the read, not count as damaged"),
    }
    holder.execute_batch("ROLLBACK").unwrap();
    assert!(inspect_plain(&reader).is_ok());
}

/// While the copy runs, progress is reported on a timer: never sooner than
/// [`PROGRESS_INTERVAL`] after the last report, and at all. Another connection holds the plain
/// database locked until two reports have come, so the copy lasts as long as the test needs
/// and no timing decides whether a report is due.
#[test]
fn the_copy_reports_progress_on_its_interval_while_it_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = plain_rollback_database(dir.path());
    let reader = open_reader(&path).unwrap();
    let holder = Connection::open(&path).unwrap();
    holder.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let reports = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let seen = Arc::clone(&reports);
    let observer: Box<MigrationObserver> = Box::new(move |progress| {
        assert_eq!(progress.stage, MigrationStage::Copying);
        seen.lock().unwrap().push(Instant::now());
    });
    let waited = Arc::clone(&reports);
    let release = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(4);
        while waited.lock().unwrap().len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        holder.execute_batch("ROLLBACK").unwrap();
    });

    let started = Instant::now();
    let progress = Progress {
        observer: Some(&*observer),
        total: 1000,
        page_size: 4096,
    };
    copy_into(&reader, &dir.path().join(COPY_FILE), &key(), progress).unwrap();
    release.join().unwrap();

    let reports = reports.lock().unwrap();
    assert!(
        reports.len() >= 2,
        "{} reports while the copy waited",
        reports.len()
    );
    assert!(
        reports[0].duration_since(started) >= PROGRESS_INTERVAL,
        "first report after {:?}",
        reports[0].duration_since(started)
    );
    for pair in reports.windows(2) {
        assert!(
            pair[1].duration_since(pair[0]) >= PROGRESS_INTERVAL,
            "reports {:?} apart",
            pair[1].duration_since(pair[0])
        );
    }
}
