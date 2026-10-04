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
