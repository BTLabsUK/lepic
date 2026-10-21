//! Behaviour only the SQLite store has: the file, its schema version and its journal.

// Test code may unwrap, index and use plain arithmetic (docs/rules.md); clippy's test
// exemptions do not reach helpers outside `#[test]` functions.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::fs;

use lepic_store::{
    OutputStatus, ParticipantId, PrivateContext, Record, SCHEMA_VERSION, SqliteStore, StoreError,
    WalletStore,
};
use rusqlite::Connection;
use uuid::Uuid;

use support::{
    Backend, SqliteBackend, account, context_key, database_path, invoice, output, peer_key,
};

const SLATE: Uuid = Uuid::from_bytes([0x5a; 16]);

fn stored_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn new_database_is_created_at_the_current_schema_version() {
    let backend = SqliteBackend::create(context_key(1));
    let conn = Connection::open(backend.path()).unwrap();
    assert_eq!(stored_version(&conn), i64::from(SCHEMA_VERSION));
}

#[test]
fn database_uses_write_ahead_logging() {
    let backend = SqliteBackend::create(context_key(1));
    let conn = Connection::open(backend.path()).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn refuses_newer_schema_version_and_leaves_it_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = database_path(dir.path());
    drop(SqliteStore::open(&path, context_key(1)).unwrap());
    let newer = SCHEMA_VERSION + 1;
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE schema_version SET version = ?1", [newer])
        .unwrap();

    let result = SqliteStore::open(&path, context_key(1));
    assert!(matches!(
        result,
        Err(StoreError::SchemaTooNew { found, supported })
            if found == newer && supported == SCHEMA_VERSION
    ));
    assert_eq!(
        stored_version(&Connection::open(&path).unwrap()),
        i64::from(newer)
    );
}

#[test]
fn reopened_database_keeps_its_records() {
    let backend = SqliteBackend::create(context_key(1));
    backend
        .store()
        .write(|repos| repos.put_account(&account(0, "default")))
        .unwrap();
    let reopened = backend.reopen(context_key(1));
    let accounts = reopened.read(|repos| repos.accounts()).unwrap();
    assert_eq!(accounts, vec![account(0, "default")]);
}

#[test]
fn database_files_do_not_contain_private_context_plaintext() {
    let plaintext = b"blinding factor 0123456789abcdef".to_vec();
    let backend = SqliteBackend::create(context_key(1));
    backend
        .store()
        .write(|repos| {
            repos.put_context(
                SLATE,
                ParticipantId(0),
                &PrivateContext::new(plaintext.clone()),
            )
        })
        .unwrap();

    let mut scanned = 0;
    for entry in fs::read_dir(backend.dir()).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        scanned += bytes.len();
        assert!(
            !bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }
    assert!(scanned > 0);
}

#[test]
fn database_files_do_not_contain_pending_invoice_bytes() {
    let parked = invoice(SLATE, 1, 1);
    let backend = SqliteBackend::create(context_key(1));
    backend
        .store()
        .write(|repos| repos.park_invoice(&parked))
        .unwrap();

    let mut scanned = 0;
    for entry in fs::read_dir(backend.dir()).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        scanned += bytes.len();
        assert!(
            !bytes
                .windows(parked.bytes.len())
                .any(|window| window == parked.bytes)
        );
    }
    assert!(scanned > 0);
}

#[test]
fn pending_invoice_moved_to_another_sender_does_not_open() {
    let backend = SqliteBackend::create(context_key(1));
    backend
        .store()
        .write(|repos| repos.park_invoice(&invoice(SLATE, 1, 1)))
        .unwrap();
    Connection::open(backend.path())
        .unwrap()
        .execute("UPDATE pending_invoices SET sender_key = ?1", [peer_key(2)])
        .unwrap();
    assert!(matches!(
        backend.store().read(|repos| repos.pending_invoice(SLATE)),
        Err(StoreError::Undecryptable {
            record: Record::PendingInvoice
        })
    ));
}

#[test]
fn malformed_stored_value_is_a_typed_error() {
    let backend = SqliteBackend::create(context_key(1));
    backend
        .store()
        .write(|repos| {
            repos.put_account(&account(0, "default"))?;
            repos.put_output(&output(
                0,
                account(0, "default").index,
                OutputStatus::Unspent,
            ))
        })
        .unwrap();
    Connection::open(backend.path())
        .unwrap()
        .execute("UPDATE outputs SET status = 'misplaced'", [])
        .unwrap();
    let result = backend
        .store()
        .read(|repos| repos.outputs(account(0, "default").index, None));
    assert!(matches!(
        result,
        Err(StoreError::Corrupt {
            record: Record::Output,
            field: "status"
        })
    ));
}

#[test]
fn second_handle_sees_committed_writes() {
    let backend = SqliteBackend::create(context_key(1));
    let other = backend.reopen(context_key(1));
    backend
        .store()
        .write(|repos| repos.put_setting("tip", "100"))
        .unwrap();
    assert_eq!(
        other.read(|repos| repos.setting("tip")).unwrap().as_deref(),
        Some("100")
    );
}

/// The files in `dir` whose names start with the database's, sorted.
fn database_files(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("wallet.sqlite"))
        .collect();
    names.sort();
    names
}

fn set_aside(dir: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let names = database_files(dir);
    let name = names
        .iter()
        .find(|name| name.starts_with("wallet.sqlite.damaged-") && name.ends_with(suffix))
        .unwrap();
    dir.join(name)
}

#[test]
fn a_file_that_is_no_database_is_moved_aside_with_its_logs_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = database_path(dir.path());
    let with_suffix = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        std::path::PathBuf::from(name)
    };
    fs::write(&path, [0x5a; 8192]).unwrap();
    fs::write(with_suffix("-wal"), b"log").unwrap();
    fs::write(with_suffix("-shm"), b"index").unwrap();

    let result = SqliteStore::open(&path, context_key(1));
    assert!(
        matches!(result, Err(StoreError::DamagedSetAside)),
        "{result:?}"
    );

    let database = set_aside(dir.path(), "");
    assert!(!database.to_string_lossy().ends_with("-wal"));
    assert_eq!(fs::read(&database).unwrap(), [0x5a; 8192]);
    let mut wal = database.as_os_str().to_owned();
    wal.push("-wal");
    assert_eq!(fs::read(wal).unwrap(), b"log");
    let mut shm = database.as_os_str().to_owned();
    shm.push("-shm");
    // SQLite rebuilds this index of the log whenever it opens one, so only its place matters.
    assert!(std::path::Path::new(&shm).is_file());
    assert!(!path.exists());

    let reopened = SqliteStore::open(&path, context_key(1)).unwrap();
    assert!(reopened.read(|repos| repos.accounts()).unwrap().is_empty());
}

#[test]
fn a_database_that_fails_its_integrity_check_is_moved_aside() {
    let dir = tempfile::tempdir().unwrap();
    let path = database_path(dir.path());
    let store = SqliteStore::open(&path, context_key(1)).unwrap();
    store
        .write(|repos| repos.put_account(&account(0, "default")))
        .unwrap();
    drop(store);
    let mut bytes = fs::read(&path).unwrap();
    let page_size = 4096;
    assert!(bytes.len() > 2 * page_size);
    for byte in &mut bytes[page_size..page_size + 64] {
        *byte = 0xff;
    }
    fs::write(&path, &bytes).unwrap();

    let result = SqliteStore::open(&path, context_key(1));
    assert!(
        matches!(result, Err(StoreError::DamagedSetAside)),
        "{result:?}"
    );
    assert_eq!(fs::read(set_aside(dir.path(), "")).unwrap(), bytes);
    assert!(SqliteStore::open(&path, context_key(1)).is_ok());
}

/// Logs left without their database, as when setting a damaged one aside was cut short, would
/// be read into a new database; they are set aside before it is made.
#[test]
fn logs_without_their_database_are_moved_aside_before_a_new_one_is_made() {
    let dir = tempfile::tempdir().unwrap();
    let path = database_path(dir.path());
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    fs::write(&wal, b"log").unwrap();

    let store = SqliteStore::open(&path, context_key(1)).unwrap();
    assert!(store.read(|repos| repos.accounts()).unwrap().is_empty());
    assert_eq!(fs::read(set_aside(dir.path(), "-wal")).unwrap(), b"log");
}

#[test]
fn a_healthy_database_is_opened_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let path = database_path(dir.path());
    drop(SqliteStore::open(&path, context_key(1)).unwrap());
    drop(SqliteStore::open(&path, context_key(1)).unwrap());
    assert!(
        database_files(dir.path())
            .iter()
            .all(|name| !name.contains("damaged")),
        "{:?}",
        database_files(dir.path())
    );
}
