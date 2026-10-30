// SPDX-License-Identifier: Apache-2.0
//! Migration harness: every older schema version must open and migrate with its data intact.
//!
//! A schema change adds a migration and an [`UpgradeCase`] for the version it replaces. The seed
//! is written in that older version's schema, and the check reads it back through the current
//! repositories.

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Height};
use rusqlite::Connection;

use super::SqliteStore;
use super::schema::{SCHEMA_VERSION, migrate_to, stored_version};
use crate::account::{AccountIndex, AccountRecord};
use crate::context::ContextKey;
use crate::error::StoreError;
use crate::invoice::{InvoiceAddressIndex, PendingInvoice, PendingInvoiceStatus};
use crate::output::KeyId;
use crate::peer::PeerSupport;
use crate::store::WalletStore;
use crate::transaction::{TxId, TxState};
use crate::tx_record::{
    FoundDuring, OtherWalletSpend, ScanFoundRecord, TxMarks, TxWatch, WatchPhase, WatchedOutput,
};

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
    let (invoices, index) = store
        .read(|repos| {
            Ok::<_, StoreError>((repos.pending_invoices()?, repos.invoice_address_index()?))
        })
        .unwrap();
    assert!(invoices.is_empty());
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
    let (capability, index) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                repos.peer_capability("key")?,
                repos.invoice_address_index()?,
            ))
        })
        .unwrap();
    // The invoice allowlist is gone; the contact tables take its place.
    let conn = store.conn.lock().unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN ('allowed_peers', 'contacts', 'pairings', 'contact_outbox', 'contact_mailboxes', 'contact_slot_counters')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!tables.iter().any(|name| name == "allowed_peers"));
    assert_eq!(tables.len(), 5);
    drop(conn);
    assert_eq!(
        capability.map(|capability| capability.support),
        Some(PeerSupport::NoInvoices)
    );
    assert_eq!(index, InvoiceAddressIndex::new(3));
}

fn check_v6_seed(store: &SqliteStore) {
    assert!(store.read(|repos| repos.contacts()).unwrap().is_empty());
    // The seen set moved to its own table.
    assert_eq!(
        store.read(|repos| repos.setting("contact.seen")).unwrap(),
        None
    );
    assert!(
        store
            .read(|repos| repos.contact_slot_counters())
            .unwrap()
            .is_empty()
    );
}

#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn check_v7_seed(store: &SqliteStore) {
    assert!(!store.read(|repos| repos.envelope_seen(&[1; 32])).unwrap());
    let commitment = |byte: u8, fill: u8| {
        let mut bytes = [fill; 33];
        bytes[0] = byte;
        bytes
    };
    let mut key_id = [0; 17];
    key_id[0] = 3;
    key_id[4] = 7;
    let (marks, watches, spends, found, left) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                [repos.tx_marks(TxId(1))?, repos.tx_marks(TxId(2))?],
                repos.tx_watches()?,
                repos.other_wallet_spends()?,
                [repos.scan_found(TxId(2))?, repos.scan_found(TxId(3))?],
                [
                    repos.setting("network")?,
                    repos.setting("send.local_cutoff.1")?,
                    repos.setting("send.local_cutoff.9")?,
                    repos.setting("tx.other_wallet.open")?,
                    repos.setting("scan.found.2")?,
                    repos.setting("release.kernel_absent.1")?,
                ],
            ))
        })
        .unwrap();
    assert_eq!(
        marks,
        [
            TxMarks {
                local_cutoff: Some(Height::new(120)),
                finalized_at: Some(Height::new(100)),
                inputs_spent_elsewhere: true,
                ..TxMarks::default()
            },
            TxMarks {
                receive_seen_at: Some(Height::new(55)),
                receive_inputs_unspent: true,
                ..TxMarks::default()
            },
        ],
        "a height that does not parse is dropped"
    );
    assert_eq!(
        watches,
        vec![
            (
                TxId(1),
                TxWatch {
                    phase: WatchPhase::Kernel,
                    excess: commitment(0x08, 0x11),
                    min_height: Height::new(90),
                    ended_at: Height::new(1_530),
                    outputs: vec![WatchedOutput {
                        commitment: commitment(0x09, 0x22),
                        key_id: KeyId(key_id),
                        amount: Amount::new(899_200_000),
                    }],
                },
            ),
            (
                TxId(2),
                TxWatch {
                    phase: WatchPhase::Outputs,
                    excess: commitment(0x08, 0x11),
                    min_height: Height::new(40),
                    ended_at: Height::new(50),
                    outputs: Vec::new(),
                },
            ),
        ]
    );
    assert_eq!(
        spends,
        vec![(
            TxId(3),
            OtherWalletSpend {
                after: Height::new(10),
                to: Height::new(20),
                open: true,
                spent: vec![commitment(0x09, 0x22)],
                change: Vec::new(),
            },
        )],
        "a commitment that does not parse is skipped"
    );
    assert_eq!(
        found,
        [
            None,
            Some(ScanFoundRecord {
                output: Some(commitment(0x09, 0x22)),
                during: Some(FoundDuring::Restore),
                dated_by_block: true,
            }),
        ]
    );
    assert_eq!(
        left,
        [Some("floonet".to_owned()), None, None, None, None, None],
        "only the moved settings are deleted"
    );
}

fn check_v8_seed(store: &SqliteStore) {
    let contact = crate::contact::ContactId([0x0f; 16]);
    let (slate, tx, left) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                repos.slate_contact(uuid::Uuid::from_bytes([0x0a; 16]))?,
                [repos.tx_contact(TxId(1))?, repos.tx_contact(TxId(2))?],
                [
                    repos.setting("network")?,
                    repos.setting("contact.tx.1")?,
                    repos.setting("contact.slate.not-a-uuid")?,
                ],
            ))
        })
        .unwrap();
    assert_eq!(slate, Some(contact));
    assert_eq!(
        tx,
        [Some(contact), None],
        "the link of a gone transaction is dropped"
    );
    assert_eq!(left, [Some("floonet".to_owned()), None, None]);
}

fn check_v9_seed(store: &SqliteStore) {
    let (marks, left) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                [repos.tx_marks(TxId(1))?, repos.tx_marks(TxId(2))?],
                [
                    repos.setting("network")?,
                    repos.setting(
                        "notice.withdrawn_answered.0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a",
                    )?,
                    repos.setting("notice.posted_reported.0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b")?,
                    repos.setting("invoice.origin.0c0c0c0c-0c0c-0c0c-0c0c-0c0c0c0c0c0c")?,
                ],
            ))
        })
        .unwrap();
    assert_eq!(
        marks,
        [
            TxMarks {
                receive_seen_at: Some(Height::new(77)),
                withdrawn_answered: true,
                ..TxMarks::default()
            },
            TxMarks::default(),
        ],
        "the answered withdrawal moves to its transaction; the posted report is dropped"
    );
    assert_eq!(left, [Some("floonet".to_owned()), None, None, None]);
}

fn check_v10_seed(store: &SqliteStore) {
    let marks = store.read(|repos| repos.tx_marks(TxId(1))).unwrap();
    assert_eq!(
        marks,
        TxMarks {
            sender_posted_at: Some(Timestamp::from_second(1_790_000_000).unwrap()),
            withdrawn_answered: true,
            ..TxMarks::default()
        },
        "the new marks start unset"
    );
}

fn check_v11_seed(store: &SqliteStore) {
    check_empty(store);
    assert!(store.read(|repos| repos.tx_watches()).unwrap().is_empty());
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
    UpgradeCase {
        from: 6,
        seed: "INSERT INTO settings (key, value) VALUES ('contact.seen', '{}');",
        check: check_v6_seed,
    },
    UpgradeCase {
        from: 7,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, amount_credited,
                   amount_debited, created_at, updated_at)
               VALUES (1, 0, 'outgoing', 'cancelled', 0, 5, 1, 1),
                      (2, 0, 'incoming', 'cancelled', 5, 0, 1, 1),
                      (3, 0, 'outgoing', 'confirmed', 0, 5, 1, 1);
               INSERT INTO settings (key, value) VALUES
                   ('network', 'floonet'),
                   ('send.local_cutoff.1', '120'),
                   ('send.local_cutoff.9', '5'),
                   ('release.finalized_height.1', '100'),
                   ('release.kernel_absent.1', '1x'),
                   ('tx.inputs_spent_elsewhere.1', '1'),
                   ('refresh.receive_seen.2', '55'),
                   ('refresh.receive_inputs_unspent.2', '1'),
                   ('release.released.1', '081111111111111111111111111111111111111111111111111111111111111111 90 1530 092222222222222222222222222222222222222222222222222222222222222222:0300000007000000000000000000000000:899200000'),
                   ('release.late.2', '081111111111111111111111111111111111111111111111111111111111111111 40 50'),
                   ('tx.other_wallet.3',
                    '{\"spent\":[\"092222222222222222222222222222222222222222222222222222222222222222\",\"zz\"],\"change\":[],\"after\":10,\"to\":20}'),
                   ('tx.other_wallet.open', '[3,7]'),
                   ('scan.found.2', 'rescan noon'),
                   ('scan.found.3', 'restore block'),
                   ('scan.found_output.3', '092222222222222222222222222222222222222222222222222222222222222222');",
        check: check_v7_seed,
    },
    UpgradeCase {
        from: 8,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, amount_credited,
                   amount_debited, created_at, updated_at)
               VALUES (1, 0, 'outgoing', 'sent', 0, 5, 1, 1);
               INSERT INTO settings (key, value) VALUES
                   ('network', 'floonet'),
                   ('contact.slate.0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a', '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f'),
                   ('contact.slate.not-a-uuid', '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f'),
                   ('contact.tx.1', '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f'),
                   ('contact.tx.2', '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f'),
                   ('contact.tx.1x', '0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f');",
        check: check_v8_seed,
    },
    UpgradeCase {
        from: 9,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, slate_id,
                   amount_credited, amount_debited, created_at, updated_at)
               VALUES (1, 0, 'incoming', 'cancelled', X'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a',
                   5, 0, 1, 1),
                      (2, 0, 'incoming', 'received', X'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
                   5, 0, 1, 1);
               INSERT INTO tx_marks (tx_id, receive_seen_at, receive_inputs_unspent,
                   inputs_spent_elsewhere)
               VALUES (1, 77, 0, 0);
               INSERT INTO settings (key, value) VALUES
                   ('network', 'floonet'),
                   ('notice.withdrawn_answered.0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a',
                    '2026-10-28T00:00:00Z'),
                   ('notice.posted_reported.0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b',
                    '2026-10-28T00:00:00Z'),
                   ('invoice.origin.0c0c0c0c-0c0c-0c0c-0c0c-0c0c0c0c0c0c', 'key@relay');",
        check: check_v9_seed,
    },
    UpgradeCase {
        from: 10,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, slate_id,
                   amount_credited, amount_debited, created_at, updated_at)
               VALUES (1, 0, 'incoming', 'received', X'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a',
                   5, 0, 1, 1);
               INSERT INTO tx_marks (tx_id, receive_inputs_unspent, inputs_spent_elsewhere,
                   sender_posted_at, withdrawn_answered)
               VALUES (1, 0, 0, 1790000000000000000, 1);",
        check: check_v10_seed,
    },
    UpgradeCase {
        from: 11,
        seed: "",
        check: check_v11_seed,
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

/// The `icacls` listing of `path`.
#[cfg(windows)]
fn access_list(path: &std::path::Path) -> String {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success(), "icacls {}", path.display());
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A database made before the access list was set (inherited entries only, as earlier builds
/// left it) is restricted at its next open, with its logs, and still opens and keeps its data.
#[cfg(windows)]
#[test]
fn opening_an_existing_database_restricts_it_to_its_owner_on_windows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    drop(SqliteStore::open(&path, key()).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE probe (x); INSERT INTO probe VALUES (7);")
        .unwrap();
    let wal = dir.path().join("wallet.sqlite-wal");
    let shm = dir.path().join("wallet.sqlite-shm");
    // Back to the folder's inherited entries, as an earlier build left every file.
    for file in [&path, &wal, &shm] {
        if !file.exists() {
            std::fs::write(file, []).unwrap();
        }
        let reset = std::process::Command::new("icacls")
            .arg(file)
            .arg("/reset")
            .output()
            .unwrap();
        assert!(reset.status.success());
        assert!(access_list(file).contains("(I)"), "inherited entries only");
    }

    let store = SqliteStore::open(&path, key()).unwrap();
    for file in [&path, &wal, &shm] {
        let list = access_list(file);
        assert!(!list.contains("(I)"), "{list}");
        // Account names are in the system's language; SYSTEM keeps its name in each.
        assert!(list.contains("\\SYSTEM:(F)"), "{list}");
        assert_eq!(
            list.matches(":(F)").count(),
            2,
            "the user and SYSTEM only: {list}"
        );
    }
    drop(store);

    let store = SqliteStore::open(&path, key()).unwrap();
    drop(store);
    let conn = Connection::open(&path).unwrap();
    let kept: i64 = conn
        .query_row("SELECT x FROM probe", [], |row| row.get(0))
        .unwrap();
    assert_eq!(kept, 7);
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
