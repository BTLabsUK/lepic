//! Schema versions and forward-only migrations.
//!
//! `MIGRATIONS[n]` takes a database from version `n` to version `n + 1`. A released migration is
//! never edited; a schema change appends one and a test that opens the previous version.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::error::{Record, StoreError};

const V1: &str = "
CREATE TABLE schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);

CREATE TABLE accounts (
    idx INTEGER PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    next_child INTEGER NOT NULL
);

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    account INTEGER NOT NULL REFERENCES accounts (idx),
    direction TEXT NOT NULL,
    state TEXT NOT NULL,
    slate_id BLOB,
    transport TEXT,
    amount_credited INTEGER NOT NULL,
    amount_debited INTEGER NOT NULL,
    fee INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (slate_id, direction)
);
CREATE INDEX transactions_account ON transactions (account);

CREATE TABLE outputs (
    commitment BLOB PRIMARY KEY,
    features INTEGER NOT NULL,
    key_id BLOB NOT NULL,
    account INTEGER NOT NULL REFERENCES accounts (idx),
    amount INTEGER NOT NULL,
    status TEXT NOT NULL,
    height INTEGER NOT NULL,
    lock_height INTEGER NOT NULL,
    mmr_index INTEGER,
    tx_id INTEGER REFERENCES transactions (id)
);
CREATE INDEX outputs_account_status ON outputs (account, status);
CREATE INDEX outputs_tx ON outputs (tx_id);

CREATE TABLE slates (
    slate_id BLOB NOT NULL,
    stage TEXT NOT NULL,
    codec TEXT NOT NULL,
    bytes BLOB NOT NULL,
    PRIMARY KEY (slate_id, stage)
);

CREATE TABLE private_contexts (
    slate_id BLOB NOT NULL,
    participant INTEGER NOT NULL,
    sealed BLOB NOT NULL,
    PRIMARY KEY (slate_id, participant)
);

CREATE TABLE relay_inbox (
    msg_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE relay_outbox (
    id INTEGER PRIMARY KEY,
    transport TEXT NOT NULL,
    destination TEXT NOT NULL,
    slate_id BLOB NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX relay_outbox_status ON relay_outbox (status);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO schema_version (id, version) VALUES (1, 0);
";

/// The block height at which refresh or a scan confirmed a transaction; NULL when unknown.
const V2: &str = "
ALTER TABLE transactions ADD COLUMN confirmed_height INTEGER;
";

pub(crate) const MIGRATIONS: &[&str] = &[V1, V2];

/// The version this build writes.
pub const SCHEMA_VERSION: u32 = 2;

/// The schema version stored in the database; 0 for a database without a schema.
pub(crate) fn stored_version(conn: &Connection) -> Result<u32, StoreError> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        return Ok(0);
    }
    let version: Option<i64> = conn
        .query_row(
            "SELECT version FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    version
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(StoreError::Corrupt {
            record: Record::SchemaVersion,
            field: "version",
        })
}

/// Brings the database to `target` in one transaction. Fails with
/// [`StoreError::SchemaTooNew`], changing nothing, when the database is already past `target`.
pub(crate) fn migrate_to(conn: &mut Connection, target: u32) -> Result<(), StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = stored_version(&tx)?;
    if current > target {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported: target,
        });
    }
    for version in current..target {
        let migration = usize::try_from(version)
            .ok()
            .and_then(|index| MIGRATIONS.get(index))
            .ok_or(StoreError::SchemaTooNew {
                found: target,
                supported: SCHEMA_VERSION,
            })?;
        tx.execute_batch(migration)?;
        let reached = version.checked_add(1).ok_or(StoreError::OutOfRange {
            field: "schema version",
        })?;
        tx.execute(
            "UPDATE schema_version SET version = ?1 WHERE id = 1",
            [reached],
        )?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_counts_the_migrations() {
        assert_eq!(usize::try_from(SCHEMA_VERSION).unwrap(), MIGRATIONS.len());
    }

    #[test]
    fn empty_database_is_version_zero() {
        let conn = Connection::open_in_memory().unwrap();
        assert_eq!(stored_version(&conn).unwrap(), 0);
    }

    #[test]
    fn each_migration_advances_the_version_by_one() {
        let mut conn = Connection::open_in_memory().unwrap();
        for target in 1..=SCHEMA_VERSION {
            migrate_to(&mut conn, target).unwrap();
            assert_eq!(stored_version(&conn).unwrap(), target);
        }
    }

    #[test]
    fn rejects_downgrade() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_to(&mut conn, SCHEMA_VERSION).unwrap();
        assert!(matches!(
            migrate_to(&mut conn, SCHEMA_VERSION - 1),
            Err(StoreError::SchemaTooNew { .. })
        ));
    }
}
