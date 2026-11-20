// SPDX-License-Identifier: Apache-2.0
//! Reads databases built exactly as epic-wallet writes them.

// Test code may unwrap, index and use plain arithmetic (docs/rules.md); clippy's test
// exemptions do not reach helpers outside `#[test]` functions.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use lepic_primitives::amount::{Amount, Height};
use lepic_store::KeyId;
use lepic_store::legacy::{
    LegacyDbError, LegacyDbLocation, LegacyLimits, LegacyOutputStatus, LegacyRecord, LegacyTxKind,
    locate, read_copy, read_db_file,
};
use rusqlite::Connection;
use rusqlite::config::DbConfig;
use serde_json::{Value, json};
use sha2::Digest;

/// `Store::check_or_create` of epic-wallet 4.0.2 `impls/src/backends/db.rs`.
const UPSTREAM_SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS data (
        id INTEGER PRIMARY KEY,
        key BLOB NOT NULL UNIQUE,
        prefix TEXT,
        data TEXT NOT NULL,
        q_tx_id INTEGER,
        q_confirmed INTEGER,
        q_tx_status TEXT);
    CREATE INDEX IF NOT EXISTS prefix_index ON data (prefix);
    CREATE INDEX IF NOT EXISTS q_tx_id_index ON data (q_tx_id);
    CREATE INDEX IF NOT EXISTS q_confirmed_index ON data (q_confirmed);
    CREATE INDEX IF NOT EXISTS q_tx_status_index ON data (q_tx_status);
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    PRAGMA wal_checkpoint(TRUNCATE);
"#;

const DEFAULT_PATH: &str = "0200000000000000000000000000000000";
const SAVINGS_PATH: &str = "0200000001000000000000000000000000";
const COMMIT: &str = "08b7e0d1f02a9c4e7d1b33c0a1f2e3d4c5b6a79881726354f0e1d2c3b4a5968778";

fn key_id(hex: &str) -> [u8; 17] {
    let mut id = [0; 17];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    id
}

/// `epic_store::to_key` / `to_key_u64`.
fn to_key(prefix: u8, rest: &[u8], number: Option<u64>) -> Vec<u8> {
    let mut key = vec![prefix, b':'];
    key.extend_from_slice(rest);
    if let Some(number) = number {
        key.extend_from_slice(&number.to_be_bytes());
    }
    key
}

/// `Batch::put` of epic-wallet 4.1.0: bound parameters, key as `{:?}` text.
fn put(conn: &Connection, key: &[u8], data: &Value) {
    let prefix = (key[0] as char).to_string();
    let data = serde_json::to_string(data).unwrap();
    conn.execute(
        "INSERT INTO data (key, data, prefix) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET data = excluded.data",
        rusqlite::params![format!("{key:?}"), data, prefix],
    )
    .unwrap();
}

/// `Batch::put` of epic-wallet 4.0.2 for a `TxLogEntry`: the statement text built with `format!`.
fn put_tx_as_4_0_2(conn: &Connection, key: &[u8], tx: &Value) {
    let sql = format!(
        r#"INSERT INTO data
                (key, data, prefix, q_tx_id, q_confirmed, q_tx_status)
            VALUES
                ("{:?}", '{}', "{}", {}, {}, "{}");"#,
        key,
        serde_json::to_string(tx).unwrap(),
        key[0] as char,
        tx["id"],
        tx["confirmed"],
        "Sent",
    );
    conn.execute_batch(&sql).unwrap();
}

fn tx(id: u32, parent: &str, kind: &str) -> Value {
    json!({
        "confirmation_height": 1203,
        "parent_key_id": parent,
        "id": id,
        "tx_slate_id": "0436430c-2b02-624c-2032-570501212b00",
        "tx_type": kind,
        "creation_ts": "2024-03-01T10:20:30.123456789Z",
        "confirmation_ts": "2024-03-01T10:25:00Z",
        "confirmed": true,
        "num_inputs": 1,
        "num_outputs": 1,
        "amount_credited": "99000000",
        "amount_debited": "200000000",
        "fee": "1000000",
        "ttl_cutoff_height": null,
        "messages": null,
        "stored_tx": null,
        "kernel_excess": COMMIT,
        "kernel_lookup_min_height": 1200,
        "payment_proof": null,
        "public_addr": "esZ9vkLRuuGCqwsQZpw7MaDTGaQSXHU3y5pKJ8xTm3TZgnDtvBYX@epicbox.epiccash.com"
    })
}

/// As epic-wallet 3.3.2 wrote it: no `confirmation_height` or `public_addr`, integers unquoted.
fn tx_v3(id: u32) -> Value {
    json!({
        "parent_key_id": DEFAULT_PATH,
        "id": id,
        "tx_slate_id": null,
        "tx_type": "TxReceived",
        "creation_ts": "2021-06-01T08:00:00.5Z",
        "confirmation_ts": null,
        "confirmed": false,
        "num_inputs": 0,
        "num_outputs": 1,
        "amount_credited": 500000000,
        "amount_debited": 0,
        "fee": null,
        "ttl_cutoff_height": null,
        "messages": null,
        "stored_tx": null,
        "kernel_excess": null,
        "kernel_lookup_min_height": null,
        "payment_proof": null
    })
}

fn output(n_child: u32, mmr_index: Option<u64>, status: &str) -> Value {
    json!({
        "root_key_id": DEFAULT_PATH,
        "key_id": format!("03000000000000000000000000{n_child:08x}"),
        "n_child": n_child,
        "commit": COMMIT,
        "mmr_index": mmr_index.map(|i| i.to_string()),
        "value": "100000000",
        "status": status,
        "height": "1203",
        "lock_height": 0,
        "is_coinbase": false,
        "tx_log_entry": 0
    })
}

fn put_output(conn: &Connection, value: &Value) {
    let key_id = key_id(value["key_id"].as_str().unwrap());
    let mmr = value["mmr_index"].as_str().map(|i| i.parse().unwrap());
    put(conn, &to_key(b'o', &key_id, mmr), value);
}

fn put_tx(conn: &Connection, value: &Value) {
    let parent = key_id(value["parent_key_id"].as_str().unwrap());
    let id = value["id"].as_u64().unwrap();
    put(conn, &to_key(b't', &parent, Some(id)), value);
}

/// A wallet folder `<dir>/wallet_data/db/sqlite/epic.db` with a typical history.
fn wallet(dir: &Path) -> (PathBuf, Connection) {
    let sqlite = dir.join("wallet_data/db/sqlite");
    fs::create_dir_all(&sqlite).unwrap();
    fs::create_dir_all(dir.join("wallet_data/saved_txs")).unwrap();
    let db = sqlite.join("epic.db");
    let conn = Connection::open(&db).unwrap();
    conn.execute_batch(UPSTREAM_SCHEMA).unwrap();

    put(
        &conn,
        &to_key(b'a', b"default", None),
        &json!({"label": "default", "path": DEFAULT_PATH}),
    );
    put(
        &conn,
        &to_key(b'a', b"savings", None),
        &json!({"label": "savings", "path": SAVINGS_PATH}),
    );
    put(&conn, &to_key(b'd', &key_id(DEFAULT_PATH), None), &json!(3));
    put(&conn, &to_key(b'd', &key_id(SAVINGS_PATH), None), &json!(1));
    put(&conn, &to_key(b'i', &key_id(DEFAULT_PATH), None), &json!(3));
    put(
        &conn,
        &to_key(b'c', &key_id(DEFAULT_PATH), None),
        &json!(1250),
    );
    put(
        &conn,
        &to_key(b'l', b"LAST_SCANNED_KEY", None),
        &json!({"height": 1250, "hash": "00ff", "start_pmmr_index": 1, "last_pmmr_index": 9}),
    );
    // Private contexts must never be read; this one is not even valid JSON for any record.
    put(
        &conn,
        &to_key(b'p', &[7; 16], Some(0)),
        &json!({"sec_key": "not for import"}),
    );
    put(
        &conn,
        &to_key(b'h', &0_u32.to_le_bytes(), None),
        &output(9, None, "Spent"),
    );

    put_tx(&conn, &tx_v3(0));
    put_tx_as_4_0_2(
        &conn,
        &to_key(b't', &key_id(DEFAULT_PATH), Some(2)),
        &tx(2, DEFAULT_PATH, "TxSent"),
    );
    put_tx(&conn, &tx(1, DEFAULT_PATH, "ConfirmedCoinbase"));
    put_tx(&conn, &tx(0, SAVINGS_PATH, "TxSentCancelled"));

    put_output(&conn, &output(1, Some(4021), "Unspent"));
    put_output(&conn, &output(0, None, "Unconfirmed"));
    put_output(&conn, &output(2, Some(77), "Locked"));
    (db, conn)
}

/// Every file under `dir` with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.insert(path.clone(), Vec::new());
                pending.push(path);
            } else {
                files.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    files
}

fn copy_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn reads_history_written_like_epic_wallet() {
    let source = tempfile::tempdir().unwrap();
    let (_, conn) = wallet(source.path());
    drop(conn);
    let work = copy_dir();

    let history = read_copy(source.path(), work.path(), &LegacyLimits::default()).unwrap();

    assert_eq!(history.skipped.total(), 0);
    let labels: Vec<_> = history.accounts.iter().map(|a| a.label.as_str()).collect();
    assert_eq!(labels, ["default", "savings"]);
    assert_eq!(history.accounts[1].path, KeyId(key_id(SAVINGS_PATH)));

    let counters: Vec<_> = history
        .next_child
        .iter()
        .map(|c| (c.parent, c.next_child))
        .collect();
    assert_eq!(
        counters,
        [
            (KeyId(key_id(DEFAULT_PATH)), 3),
            (KeyId(key_id(SAVINGS_PATH)), 1)
        ]
    );

    let txs: Vec<_> = history
        .transactions
        .iter()
        .map(|t| (t.parent_key_id, t.id, t.kind))
        .collect();
    assert_eq!(
        txs,
        [
            (KeyId(key_id(DEFAULT_PATH)), 0, LegacyTxKind::TxReceived),
            (
                KeyId(key_id(DEFAULT_PATH)),
                1,
                LegacyTxKind::ConfirmedCoinbase
            ),
            (KeyId(key_id(DEFAULT_PATH)), 2, LegacyTxKind::TxSent),
            (
                KeyId(key_id(SAVINGS_PATH)),
                0,
                LegacyTxKind::TxSentCancelled
            ),
        ]
    );
    let old = &history.transactions[0];
    assert_eq!(old.confirmation_height, None);
    assert_eq!(old.public_addr, None);
    assert_eq!(old.amount_credited, Amount::new(500_000_000));
    assert_eq!(
        history.transactions[2].confirmation_height,
        Some(Height::new(1203))
    );

    let outputs: Vec<_> = history
        .outputs
        .iter()
        .map(|o| (o.n_child, o.mmr_index, o.status))
        .collect();
    assert_eq!(
        outputs,
        [
            (0, None, LegacyOutputStatus::Unconfirmed),
            (1, Some(4021), LegacyOutputStatus::Unspent),
            (2, Some(77), LegacyOutputStatus::Locked),
        ]
    );
    assert_eq!(history.outputs[1].lock_height, Height::ZERO);
}

#[test]
fn accepts_the_wallet_data_folder_itself() {
    let source = tempfile::tempdir().unwrap();
    let (db, conn) = wallet(source.path());
    drop(conn);
    let data_dir = source.path().join("wallet_data");
    assert_eq!(
        locate(&data_dir),
        LegacyDbLocation::Sqlite { db: db.clone() }
    );
    assert_eq!(locate(source.path()), LegacyDbLocation::Sqlite { db });
    let history = read_copy(&data_dir, copy_dir().path(), &LegacyLimits::default()).unwrap();
    assert_eq!(history.transactions.len(), 4);
}

#[test]
fn reads_rows_that_exist_only_in_the_write_ahead_log() {
    let source = tempfile::tempdir().unwrap();
    let (db, conn) = wallet(source.path());
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    put_tx(&conn, &tx(3, DEFAULT_PATH, "TxReceivedMempool"));
    put_output(&conn, &output(3, Some(90), "Unconfirmed"));
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .unwrap();
    drop(conn);
    let wal = sqlite_sibling(&db, "-wal");
    assert!(fs::metadata(&wal).unwrap().len() > 0);

    // The main file alone lacks the new rows.
    let main_only = copy_dir();
    fs::copy(&db, main_only.path().join("epic.db")).unwrap();
    let without_wal =
        read_db_file(&main_only.path().join("epic.db"), &LegacyLimits::default()).unwrap();
    assert_eq!(without_wal.transactions.len(), 4);

    let history = read_copy(source.path(), copy_dir().path(), &LegacyLimits::default()).unwrap();
    assert_eq!(history.transactions.len(), 5);
    assert_eq!(history.outputs.len(), 4);
    assert!(
        history
            .transactions
            .iter()
            .any(|t| t.kind == LegacyTxKind::TxReceivedMempool)
    );
    assert_ne!(history.source_fingerprint, without_wal.source_fingerprint);
}

fn sqlite_sibling(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[test]
fn leaves_the_source_folder_byte_identical() {
    for keep_wal in [false, true] {
        let source = tempfile::tempdir().unwrap();
        let (db, conn) = wallet(source.path());
        if keep_wal {
            conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
            put_tx(&conn, &tx(3, DEFAULT_PATH, "TxSent"));
            conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .unwrap();
        }
        drop(conn);
        let shm = sqlite_sibling(&db, "-shm");
        if shm.exists() {
            fs::remove_file(&shm).unwrap();
        }
        let before = snapshot(source.path());

        let work = copy_dir();
        read_copy(source.path(), work.path(), &LegacyLimits::default()).unwrap();

        assert_eq!(snapshot(source.path()), before);
        assert!(!shm.exists());
        assert!(!sqlite_sibling(&db, "-journal").exists());
        assert_eq!(sqlite_sibling(&db, "-wal").exists(), keep_wal);
        assert_eq!(
            fs::read_dir(work.path()).unwrap().count(),
            0,
            "the copy is removed once read"
        );
    }
}

#[test]
fn the_copy_is_removed_when_it_cannot_be_read() {
    let source = tempfile::tempdir().unwrap();
    let dir = source.path().join("wallet_data/db/sqlite");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("epic.db"), vec![7_u8; 4096]).unwrap();
    let work = copy_dir();
    assert!(read_copy(source.path(), work.path(), &LegacyLimits::default()).is_err());
    assert_eq!(fs::read_dir(work.path()).unwrap().count(), 0);
}

#[test]
fn fingerprint_is_sha256_of_database_then_log() {
    let source = tempfile::tempdir().unwrap();
    let (db, conn) = wallet(source.path());
    drop(conn);
    let bytes = fs::read(&db).unwrap();
    let work = copy_dir();
    let history = read_copy(source.path(), work.path(), &LegacyLimits::default()).unwrap();
    let expected: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    assert_eq!(history.source_fingerprint, expected);
}

#[test]
fn refuses_a_work_dir_that_is_not_empty() {
    let source = tempfile::tempdir().unwrap();
    drop(wallet(source.path()).1);
    let work = copy_dir();
    fs::write(work.path().join("epic.db"), b"left over").unwrap();
    assert!(matches!(
        read_copy(source.path(), work.path(), &LegacyLimits::default()),
        Err(LegacyDbError::WorkDirNotEmpty)
    ));
}

#[test]
fn reports_missing_and_lmdb_wallets() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(locate(empty.path()), LegacyDbLocation::Missing);
    assert!(matches!(
        read_copy(empty.path(), copy_dir().path(), &LegacyLimits::default()),
        Err(LegacyDbError::NotFound)
    ));

    let lmdb = tempfile::tempdir().unwrap();
    let env = lmdb.path().join("wallet_data/db/lmdb");
    fs::create_dir_all(&env).unwrap();
    fs::write(env.join("data.mdb"), [0_u8; 64]).unwrap();
    assert_eq!(locate(lmdb.path()), LegacyDbLocation::LmdbUnsupported);
    assert!(matches!(
        read_copy(lmdb.path(), copy_dir().path(), &LegacyLimits::default()),
        Err(LegacyDbError::LmdbUnsupported)
    ));
}

fn read_file_bytes(bytes: &[u8]) -> Result<lepic_store::legacy::LegacyHistory, LegacyDbError> {
    let dir = copy_dir();
    let db = dir.path().join("epic.db");
    fs::write(&db, bytes).unwrap();
    read_db_file(&db, &LegacyLimits::default())
}

#[test]
fn rejects_files_that_are_not_wallet_databases() {
    let garbage: Vec<u8> = (0..8192_u32).map(|i| (i * 31 % 251) as u8).collect();
    assert!(matches!(
        read_file_bytes(&garbage),
        Err(LegacyDbError::NotADatabase)
    ));

    let source = tempfile::tempdir().unwrap();
    let (db, conn) = wallet(source.path());
    for i in 0..200 {
        put_tx(&conn, &tx(10 + i, DEFAULT_PATH, "TxSent"));
    }
    drop(conn);
    let full = fs::read(&db).unwrap();
    assert!(full.len() > 8192);
    assert!(matches!(
        read_file_bytes(&full[..full.len() / 2]),
        Err(LegacyDbError::NotADatabase)
    ));

    let other = copy_dir();
    let other_db = other.path().join("epic.db");
    let conn = Connection::open(&other_db).unwrap();
    conn.execute_batch("CREATE TABLE data (id INTEGER PRIMARY KEY, value TEXT);")
        .unwrap();
    drop(conn);
    assert!(matches!(
        read_db_file(&other_db, &LegacyLimits::default()),
        Err(LegacyDbError::MissingTable)
    ));

    let empty_db = copy_dir();
    let conn = Connection::open(empty_db.path().join("epic.db")).unwrap();
    conn.execute_batch("CREATE TABLE other (x);").unwrap();
    drop(conn);
    assert!(matches!(
        read_db_file(&empty_db.path().join("epic.db"), &LegacyLimits::default()),
        Err(LegacyDbError::MissingTable)
    ));
}

#[test]
fn skips_and_counts_rows_that_do_not_parse() {
    let source = tempfile::tempdir().unwrap();
    let (_, conn) = wallet(source.path());
    let mut bad_tx = tx(5, DEFAULT_PATH, "TxSent");
    bad_tx["tx_type"] = json!("TxTeleported");
    put_tx(&conn, &bad_tx);
    let mut bad_output = output(5, None, "Unspent");
    bad_output["commit"] = json!("08ab");
    put_output(&conn, &bad_output);
    put(
        &conn,
        &to_key(b'a', b"broken", None),
        &json!({"label": "broken"}),
    );
    conn.execute(
        "INSERT INTO data (key, data, prefix) VALUES ('[100, 58, 1]', '5', 'd')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO data (key, data, prefix) VALUES ('[116, 58, 9]', x'00ff', 't')",
        [],
    )
    .unwrap();
    drop(conn);

    let history = read_copy(source.path(), copy_dir().path(), &LegacyLimits::default()).unwrap();
    assert_eq!(history.skipped.transactions, 2);
    assert_eq!(history.skipped.outputs, 1);
    assert_eq!(history.skipped.accounts, 1);
    assert_eq!(history.skipped.counters, 1);
    assert_eq!(history.transactions.len(), 4);
    assert_eq!(history.outputs.len(), 3);
}

#[test]
fn enforces_limits() {
    let source = tempfile::tempdir().unwrap();
    drop(wallet(source.path()).1);
    let defaults = LegacyLimits::default();

    let few_txs = LegacyLimits {
        max_transactions: 3,
        ..defaults
    };
    assert!(matches!(
        read_copy(source.path(), copy_dir().path(), &few_txs),
        Err(LegacyDbError::TooMany {
            record: LegacyRecord::Transaction,
            found: 4,
            limit: 3
        })
    ));
    let few_outputs = LegacyLimits {
        max_outputs: 2,
        ..defaults
    };
    assert!(matches!(
        read_copy(source.path(), copy_dir().path(), &few_outputs),
        Err(LegacyDbError::TooMany {
            record: LegacyRecord::Output,
            ..
        })
    ));
    let few_accounts = LegacyLimits {
        max_accounts: 1,
        ..defaults
    };
    assert!(matches!(
        read_copy(source.path(), copy_dir().path(), &few_accounts),
        Err(LegacyDbError::TooMany {
            record: LegacyRecord::Account,
            ..
        })
    ));
    let tiny_db = LegacyLimits {
        max_db_bytes: 1024,
        ..defaults
    };
    assert!(matches!(
        read_copy(source.path(), copy_dir().path(), &tiny_db),
        Err(LegacyDbError::TooLarge { .. })
    ));

    // Accounts and counters are about 80 bytes of JSON, transactions and outputs larger.
    let small_rows = LegacyLimits {
        max_row_bytes: 300,
        ..defaults
    };
    let history = read_copy(source.path(), copy_dir().path(), &small_rows).unwrap();
    assert_eq!(history.accounts.len(), 2);
    assert_eq!(history.next_child.len(), 2);
    assert_eq!(history.skipped.outputs, 3);
    assert!(history.transactions.is_empty());
    assert_eq!(history.skipped.transactions, 4);
}

/// Every `*.db` in `testdata/legacy-db/`, with the `*.txs.json` the wallet that wrote it exported.
fn fixture_dbs() -> Vec<PathBuf> {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/legacy-db");
    let mut dbs: Vec<PathBuf> = fs::read_dir(&fixtures)
        .unwrap_or_else(|error| panic!("{}: {error}", fixtures.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "db"))
        .collect();
    dbs.sort();
    dbs
}

fn read_fixture(path: &Path) -> lepic_store::legacy::LegacyHistory {
    let work = copy_dir();
    let db = work.path().join("epic.db");
    fs::copy(path, &db).unwrap();
    let wal = sqlite_sibling(path, "-wal");
    if wal.exists() {
        fs::copy(&wal, sqlite_sibling(&db, "-wal")).unwrap();
    }
    read_db_file(&db, &LegacyLimits::default())
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Real databases in `testdata/legacy-db/` must read without a skipped row. An empty folder fails
/// the test: a silent pass there would hide that the fixture is gone.
#[test]
fn reads_every_fixture_without_skipping() {
    let dbs = fixture_dbs();
    assert!(
        dbs.iter().any(|path| path
            .file_name()
            .is_some_and(|n| n == "epic-wallet-4.0.2.db")),
        "testdata/legacy-db holds no epic-wallet 4.0.2 database"
    );
    for path in dbs {
        let history = read_fixture(&path);
        assert_eq!(history.skipped.total(), 0, "{}", path.display());
        assert!(!history.accounts.is_empty(), "{}", path.display());
    }
}

fn tx_kind(name: &str) -> LegacyTxKind {
    match name {
        "ConfirmedCoinbase" => LegacyTxKind::ConfirmedCoinbase,
        "TxReceived" => LegacyTxKind::TxReceived,
        "TxSent" => LegacyTxKind::TxSent,
        "TxReceivedCancelled" => LegacyTxKind::TxReceivedCancelled,
        "TxSentCancelled" => LegacyTxKind::TxSentCancelled,
        "TxSentCreated" => LegacyTxKind::TxSentCreated,
        other => panic!("unexpected transaction type {other}"),
    }
}

fn amount_of(value: &Value) -> u64 {
    value.as_str().unwrap().parse().unwrap()
}

/// 4.0.2 writes a height as a string; a reader also accepts a number.
fn height_of(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().map(|text| text.parse().unwrap()))
}

/// The 4.0.2 database holds what the wallet itself exported with `export_tx --all`: every
/// transaction reads back with the same id, kind, time, amounts, fee, kernel and cancel height.
/// The database has the default account, a second account and five outputs (see its README entry).
#[test]
fn the_epic_wallet_402_fixture_reads_back_as_the_wallet_exported_it() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/legacy-db");
    let history = read_fixture(&dir.join("epic-wallet-4.0.2.db"));
    let exported: Vec<Value> =
        serde_json::from_str(&fs::read_to_string(dir.join("epic-wallet-4.0.2.txs.json")).unwrap())
            .unwrap();
    assert_eq!(exported.len(), 11);
    assert_eq!(history.transactions.len(), exported.len());
    assert_eq!(history.skipped.total(), 0);

    let labels: Vec<&str> = history.accounts.iter().map(|a| a.label.as_str()).collect();
    assert_eq!(labels, ["default", "savings"]);
    assert_eq!(history.accounts[0].path, KeyId(key_id(DEFAULT_PATH)));
    assert_eq!(history.accounts[1].path, KeyId(key_id(SAVINGS_PATH)));
    assert_outputs_as_the_wallet_wrote_them(&history);

    for (tx, want) in history.transactions.iter().zip(&exported) {
        assert_transaction_as_exported(tx, want);
    }
}

/// One imported transaction against its entry in the wallet's own export.
fn assert_transaction_as_exported(tx: &lepic_store::legacy::LegacyTxLogEntry, want: &Value) {
    let id = want["id"].as_u64().unwrap();
    assert_eq!(u64::from(tx.id), id, "id");
    assert_eq!(
        tx.parent_key_id,
        KeyId(key_id(want["parent_key_id"].as_str().unwrap())),
        "tx {id}"
    );
    assert_eq!(
        tx.slate_id.map(|slate| slate.to_string()).as_deref(),
        want["tx_slate_id"].as_str(),
        "tx {id}"
    );
    assert_eq!(
        tx.kind,
        tx_kind(want["tx_type"].as_str().unwrap()),
        "tx {id}"
    );
    assert_eq!(
        tx.created_at.to_string(),
        trim_fraction(want["creation_ts"].as_str().unwrap()),
        "tx {id}"
    );
    assert_eq!(
        tx.confirmed_at.map(|t| t.to_string()).as_deref(),
        want["confirmation_ts"]
            .as_str()
            .map(trim_fraction)
            .as_deref(),
        "tx {id}"
    );
    assert_eq!(
        tx.confirmed,
        want["confirmed"].as_bool().unwrap(),
        "tx {id}"
    );
    assert_eq!(
        u64::from(tx.num_inputs),
        want["num_inputs"].as_u64().unwrap(),
        "tx {id}"
    );
    assert_eq!(
        u64::from(tx.num_outputs),
        want["num_outputs"].as_u64().unwrap(),
        "tx {id}"
    );
    assert_eq!(
        tx.amount_credited.value(),
        amount_of(&want["amount_credited"]),
        "tx {id}"
    );
    assert_eq!(
        tx.amount_debited.value(),
        amount_of(&want["amount_debited"]),
        "tx {id}"
    );
    assert_eq!(
        tx.fee.map(|fee| fee.to_amount().value()),
        want["fee"].as_str().map(|fee| fee.parse().unwrap()),
        "tx {id}"
    );
    assert_eq!(
        tx.ttl_cutoff_height.map(Height::value),
        height_of(&want["ttl_cutoff_height"]),
        "tx {id}"
    );
    assert_eq!(
        tx.kernel_lookup_min_height.map(Height::value),
        height_of(&want["kernel_lookup_min_height"]),
        "tx {id}"
    );
    assert_eq!(
        tx.kernel_excess
            .map(|k| k.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        want["kernel_excess"].as_str().map(str::to_owned),
        "tx {id}"
    );
    assert_eq!(
        tx.confirmation_height.map(Height::value),
        height_of(&want["confirmation_height"]),
        "tx {id}"
    );
    assert_eq!(
        tx.public_addr.as_deref(),
        want["public_addr"].as_str(),
        "tx {id}"
    );
    assert_eq!(
        tx.stored_tx.as_deref(),
        want["stored_tx"].as_str(),
        "tx {id}"
    );
    assert_messages_as_exported(tx, want);
}

/// The messages of one transaction, with their keys and signatures, against the export.
fn assert_messages_as_exported(tx: &lepic_store::legacy::LegacyTxLogEntry, want: &Value) {
    let id = want["id"].as_u64().unwrap();
    let want_messages = want["messages"]["messages"]
        .as_array()
        .map_or(&[][..], |m| m);
    assert_eq!(tx.messages.len(), want_messages.len(), "tx {id}");
    for (message, want) in tx.messages.iter().zip(want_messages) {
        assert_eq!(
            message.participant,
            want["id"].as_str().unwrap().parse::<u64>().unwrap(),
            "tx {id}"
        );
        assert_eq!(
            hex_of(&message.public_key),
            want["public_key"].as_str().unwrap(),
            "tx {id}"
        );
        assert_eq!(message.text.as_deref(), want["message"].as_str(), "tx {id}");
        assert_eq!(
            message.signature.as_ref().map(|s| hex_of(s)).as_deref(),
            want["message_sig"].as_str(),
            "tx {id}"
        );
    }
}

/// The wallet prints a time with nine fractional digits; the reader prints it without trailing zeros.
fn trim_fraction(time: &str) -> String {
    match time.strip_suffix('Z') {
        Some(clock) if clock.contains('.') => format!("{}Z", clock.trim_end_matches('0')),
        _ => time.to_owned(),
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The five outputs of the real 4.0.2 wallet, as it stored them (see the README entry): three
/// coinbases (one spent by the confirmed send, one locked by the unfinished send, one unspent),
/// the confirmed send's change and the unfinished send's unconfirmed change.
fn assert_outputs_as_the_wallet_wrote_them(history: &lepic_store::legacy::LegacyHistory) {
    let rows: Vec<_> = history
        .outputs
        .iter()
        .map(|o| {
            (
                o.n_child,
                o.commitment.map(|c| hex_of(&c)),
                o.value.value(),
                o.status,
                o.height.value(),
                o.lock_height.value(),
                o.is_coinbase,
                o.tx_log_entry,
                o.mmr_index,
            )
        })
        .collect();
    let want = [
        (
            0,
            "08c63b2bdd980e2b66397769fe5a1e2e2c46fa473369cd0290b2ec5d3817395c8b",
            1_457_920_000,
            LegacyOutputStatus::Spent,
            980,
            983,
            true,
            Some(9),
        ),
        (
            1,
            "09f37f37cbcdd337ba13813724d1505fd651fb9aa7f5cde2af203fefcd459ae03d",
            1_457_920_000,
            LegacyOutputStatus::Locked,
            984,
            987,
            true,
            Some(10),
        ),
        (
            2,
            "09cc134f04f204fe277f5af19b98e2cdfef6c55623647baf2af701e4ac97d1d263",
            1_457_920_000,
            LegacyOutputStatus::Unspent,
            988,
            991,
            true,
            Some(8),
        ),
        (
            3,
            "08492b118d4fa7c95a4f2e4c1ca7be5e9a431b177b20c9e96eac752dad0a2bd8ab",
            457_120_000,
            LegacyOutputStatus::Unspent,
            999,
            0,
            false,
            Some(9),
        ),
        (
            4,
            "081750045ce66d2b7c5a1ed249e08264e7719b088af5c6e6e119518fd119231739",
            957_120_000,
            LegacyOutputStatus::Unconfirmed,
            1000,
            0,
            false,
            Some(10),
        ),
    ];
    let want: Vec<_> = want
        .into_iter()
        .map(
            |(n, commit, value, status, height, lock, coinbase, entry)| {
                (
                    n,
                    Some(commit.to_owned()),
                    value,
                    status,
                    height,
                    lock,
                    coinbase,
                    entry,
                    None,
                )
            },
        )
        .collect();
    assert_eq!(rows, want);
    for output in &history.outputs {
        assert_eq!(output.root_key_id, KeyId(key_id(DEFAULT_PATH)));
    }
}
