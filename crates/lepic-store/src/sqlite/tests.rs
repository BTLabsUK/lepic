//! Migration harness: every older schema version must open and migrate with its data intact.
//!
//! A schema change adds a migration and an [`UpgradeCase`] for the version it replaces. The seed
//! is written in that older version's schema, and the check reads it back through the current
//! repositories.

use rusqlite::Connection;

use super::SqliteStore;
use super::schema::{SCHEMA_VERSION, migrate_to, stored_version};
use crate::account::{AccountIndex, AccountRecord};
use crate::context::ContextKey;
use crate::store::WalletStore;

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
}

const UPGRADES: &[UpgradeCase] = &[
    UpgradeCase {
        from: 0,
        seed: "",
        check: check_empty,
    },
    UpgradeCase {
        from: 1,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 4);
               INSERT INTO settings (key, value) VALUES ('network', 'floonet');",
        check: check_v1_seed,
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
