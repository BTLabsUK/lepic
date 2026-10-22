//! Migration harness: every older schema version must open and migrate with its data intact.
//!
//! A schema change adds a migration and an [`UpgradeCase`] for the version it replaces. The seed
//! is written in that older version's schema, and the check reads it back through the current
//! repositories.

use jiff::Timestamp;
use lepic_primitives::amount::Height;
use rusqlite::Connection;

use super::SqliteStore;
use super::schema::{SCHEMA_VERSION, migrate_to, stored_version};
use crate::account::{AccountIndex, AccountRecord};
use crate::context::ContextKey;
use crate::error::StoreError;
use crate::invoice::{InvoiceAddressIndex, PendingInvoice, PendingInvoiceStatus};
use crate::peer::{AllowedPeer, PeerSupport};
use crate::store::WalletStore;
use crate::transaction::{TxId, TxState};

struct UpgradeCase {
    from: u32,
    seed: &'static str,
    check: fn(&SqliteStore),
}

fn check_empty(store: &SqliteStore) {
    let accounts = store.read(|repos| repos.accounts()).unwrap();
    assert!(accounts.is_empty());
}

fn check_v1_seed(store: &SqliteStore) {
    let accounts = store.read(|repos| repos.accounts()).unwrap();
    assert_eq!(
        accounts,
        vec![AccountRecord {
            index: AccountIndex(0),
            label: "default".to_owned(),
            next_child: 4,
        }]
    );
    let setting = store.read(|repos| repos.setting("network")).unwrap();
    assert_eq!(setting.as_deref(), Some("floonet"));
    let (entry, height) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                repos.transaction(TxId(1))?,
                repos.confirmed_height(TxId(1))?,
            ))
        })
        .unwrap();
    assert_eq!(entry.map(|entry| entry.state), Some(TxState::Confirmed));
    assert_eq!(height, None);
    store
        .write(|repos| repos.set_confirmed_height(TxId(1), Height::new(321)))
        .unwrap();
    let height = store.read(|repos| repos.confirmed_height(TxId(1))).unwrap();
    assert_eq!(height, Some(Height::new(321)));
}

fn check_v2_seed(store: &SqliteStore) {
    let height = store.read(|repos| repos.confirmed_height(TxId(1))).unwrap();
    assert_eq!(height, Some(Height::new(654)));
    let counterparty = store.read(|repos| repos.counterparty(TxId(1))).unwrap();
    assert_eq!(counterparty, None);
    store
        .write(|repos| repos.set_counterparty(TxId(1), "peer@relay"))
        .unwrap();
    let counterparty = store.read(|repos| repos.counterparty(TxId(1))).unwrap();
    assert_eq!(counterparty.as_deref(), Some("peer@relay"));
}

fn check_v3_seed(store: &SqliteStore) {
    let counterparty = store.read(|repos| repos.counterparty(TxId(1))).unwrap();
    assert_eq!(counterparty.as_deref(), Some("peer@relay"));
    let (invoices, peers, index) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                repos.pending_invoices()?,
                repos.allowed_peers()?,
                repos.invoice_address_index()?,
            ))
        })
        .unwrap();
    assert!(invoices.is_empty() && peers.is_empty());
    assert_eq!(index, None);
    let parked = PendingInvoice {
        slate_id: uuid::Uuid::from_bytes([4; 16]),
        sender_key: "key".to_owned(),
        sender_address: "key@relay".to_owned(),
        received_at: Timestamp::from_second(1).unwrap(),
        status: PendingInvoiceStatus::Parked,
        codec: "legacy-v3".to_owned(),
        bytes: b"i1".to_vec(),
    };
    store.write(|repos| repos.park_invoice(&parked)).unwrap();
    let stored = store.read(|repos| repos.pending_invoices()).unwrap();
    assert_eq!(stored, vec![parked]);
}

fn check_v4_seed(store: &SqliteStore) {
    let (peers, capability, index) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                repos.allowed_peers()?,
                repos.peer_capability("key")?,
                repos.invoice_address_index()?,
            ))
        })
        .unwrap();
    assert_eq!(
        peers,
        vec![AllowedPeer {
            key: "key".to_owned(),
            address: "key@relay".to_owned(),
            label: "shop".to_owned(),
            added_at: Timestamp::from_nanosecond(7).unwrap(),
        }]
    );
    assert_eq!(
        capability.map(|capability| capability.support),
        Some(PeerSupport::NoInvoices)
    );
    assert_eq!(index, InvoiceAddressIndex::new(3));
}

fn check_v5_seed(store: &SqliteStore) {
    let imported = store
        .read(|repos| repos.imported_transaction(TxId(1)))
        .unwrap();
    assert_eq!(imported, None);
    let entry = store.read(|repos| repos.transaction(TxId(1))).unwrap();
    assert_eq!(entry.map(|entry| entry.state), Some(TxState::Received));
}

const V1_SEED: &str = "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 4);
    INSERT INTO settings (key, value) VALUES ('network', 'floonet');
    INSERT INTO transactions (id, account, direction, state, amount_credited, amount_debited,
        created_at, updated_at)
    VALUES (1, 0, 'incoming', 'confirmed', 5, 0, 1, 1);";

const UPGRADES: &[UpgradeCase] = &[
    UpgradeCase {
        from: 0,
        seed: "",
        check: check_empty,
    },
    UpgradeCase {
        from: 1,
        seed: V1_SEED,
        check: check_v1_seed,
    },
    UpgradeCase {
        from: 2,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, amount_credited,
                   amount_debited, created_at, updated_at, confirmed_height)
               VALUES (1, 0, 'incoming', 'confirmed', 5, 0, 1, 1, 654);",
        check: check_v2_seed,
    },
    UpgradeCase {
        from: 3,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, amount_credited,
                   amount_debited, created_at, updated_at, counterparty)
               VALUES (1, 0, 'incoming', 'received', 5, 0, 1, 1, 'peer@relay');",
        check: check_v3_seed,
    },
    UpgradeCase {
        from: 4,
        seed: "INSERT INTO allowed_peers (key, address, label, added_at)
               VALUES ('key', 'key@relay', 'shop', 7);
               INSERT INTO peer_capabilities (key, support, learned_at)
               VALUES ('key', 'no-invoices', 8);
               INSERT INTO invoice_address (id, idx) VALUES (1, 3);",
        check: check_v4_seed,
    },
    UpgradeCase {
        from: 5,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, amount_credited,
                   amount_debited, created_at, updated_at)
               VALUES (1, 0, 'incoming', 'received', 5, 0, 1, 1);",
        check: check_v5_seed,
    },
];

fn key() -> ContextKey {
    ContextKey::from_bytes([3; 32])
}

#[test]
fn every_schema_version_has_an_upgrade_case() {
    let covered: Vec<u32> = UPGRADES.iter().map(|case| case.from).collect();
    let expected: Vec<u32> = (0..=SCHEMA_VERSION).collect();
    assert_eq!(covered, expected);
}

#[test]
fn every_older_schema_version_migrates_to_the_current_one() {
    for case in UPGRADES {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        {
            let mut conn = Connection::open(&path).unwrap();
            migrate_to(&mut conn, case.from).unwrap();
            conn.execute_batch(case.seed).unwrap();
            assert_eq!(stored_version(&conn).unwrap(), case.from);
        }

        let store = SqliteStore::open(&path, key()).unwrap();
        (case.check)(&store);
        drop(store);

        let conn = Connection::open(&path).unwrap();
        assert_eq!(
            stored_version(&conn).unwrap(),
            SCHEMA_VERSION,
            "from {}",
            case.from
        );
    }
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
#[test]
fn a_new_database_and_its_log_are_readable_by_their_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    // Migrating the new file writes the schema, so the write-ahead log exists while it is open.
    let _store = SqliteStore::open(&path, key()).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir.path().join("wallet.sqlite-wal")), 0o600);
}

#[cfg(unix)]
#[test]
fn opening_an_existing_database_restricts_it_to_its_owner() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    drop(SqliteStore::open(&path, key()).unwrap());
    let wal = dir.path().join("wallet.sqlite-wal");
    let shm = dir.path().join("wallet.sqlite-shm");
    // Non-empty leftovers, as a run that was killed leaves them; SQLite itself re-modes empty ones.
    for file in [&path, &wal, &shm] {
        if !file.exists() {
            std::fs::write(file, [0u8; 32]).unwrap();
        }
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _store = SqliteStore::open(&path, key()).unwrap();
    for file in [&path, &wal, &shm] {
        assert_eq!(mode(file), 0o600, "{}", file.display());
    }
}

#[cfg(unix)]
#[test]
fn a_database_path_that_cannot_be_created_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing").join("wallet.sqlite");
    let error = SqliteStore::open(&path, key()).err().unwrap();
    assert!(
        matches!(
            &error,
            crate::StoreError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound
        ),
        "{error:?}"
    );
}
