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

/// The address of the other party, when the transport has one; NULL otherwise.
const V3: &str = "
ALTER TABLE transactions ADD COLUMN counterparty TEXT;
";

/// Invoices received on the invoice address, the senders it accepts, what each peer is proven to
/// support, and the index of the invoice address.
const V4: &str = "
CREATE TABLE pending_invoices (
    slate_id BLOB PRIMARY KEY,
    sender_key TEXT NOT NULL,
    sender_address TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    codec TEXT NOT NULL,
    sealed BLOB NOT NULL
);
CREATE INDEX pending_invoices_status_sender ON pending_invoices (status, sender_key);
CREATE INDEX pending_invoices_received ON pending_invoices (received_at);

CREATE TABLE allowed_peers (
    key TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    label TEXT NOT NULL,
    added_at INTEGER NOT NULL
);

CREATE TABLE peer_capabilities (
    key TEXT PRIMARY KEY,
    support TEXT NOT NULL,
    learned_at INTEGER NOT NULL
);

CREATE TABLE invoice_address (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    idx INTEGER NOT NULL CHECK (idx >= 1)
);
";

/// Transactions imported from another wallet's history: what only the old wallet knew of each,
/// its messages, and the outputs it recorded, which a scan links to the transaction that made
/// them.
const V5: &str = "
CREATE TABLE imported_transactions (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id),
    source_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    slate_id BLOB,
    confirmed_at INTEGER,
    input_count INTEGER NOT NULL,
    output_count INTEGER NOT NULL,
    kernel_excess BLOB,
    kernel_lookup_min_height INTEGER,
    ttl_cutoff_height INTEGER,
    chain_check TEXT NOT NULL
);

CREATE TABLE imported_messages (
    tx_id INTEGER NOT NULL REFERENCES imported_transactions (tx_id),
    position INTEGER NOT NULL,
    participant INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (tx_id, position)
);

CREATE TABLE imported_outputs (
    commitment BLOB PRIMARY KEY,
    tx_id INTEGER NOT NULL REFERENCES transactions (id),
    status TEXT NOT NULL,
    height INTEGER NOT NULL,
    amount INTEGER NOT NULL
);
CREATE INDEX imported_outputs_status ON imported_outputs (status);
CREATE INDEX imported_outputs_tx ON imported_outputs (tx_id);
";

/// Paired contacts with their mailboxes, pairings in progress, the contact outbox and the slot
/// counter of each account. The invoice allowlist goes: invoice trust now lives on the contact
/// (`allow_invoices`).
const V6: &str = "
CREATE TABLE contacts (
    contact_id BLOB PRIMARY KEY,
    card BLOB,
    peer_sig_key BLOB UNIQUE,
    peer_enc_key BLOB,
    peer_hint_key BLOB,
    card_seq INTEGER,
    kind TEXT,
    claimed_name TEXT,
    alt_card BLOB,
    alt_sig_key BLOB,
    alt_enc_key BLOB,
    alt_hint_key BLOB,
    alt_seq INTEGER,
    alt_kind TEXT,
    alt_name TEXT,
    label TEXT NOT NULL,
    state TEXT NOT NULL,
    verified_at INTEGER,
    allow_invoices INTEGER NOT NULL,
    seal TEXT NOT NULL,
    last_sealed_in INTEGER,
    app_contact TEXT,
    imported_from_backup INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    account INTEGER NOT NULL,
    slot INTEGER NOT NULL,
    box_salt BLOB NOT NULL,
    sas BLOB,
    own_card BLOB NOT NULL
);
CREATE INDEX contacts_hint_key ON contacts (peer_hint_key);
CREATE INDEX contacts_slot ON contacts (account, slot);

CREATE TABLE contact_slot_counters (
    account INTEGER PRIMARY KEY,
    next_slot INTEGER NOT NULL
);
CREATE INDEX contacts_allow_invoices ON contacts (created_at) WHERE allow_invoices = 1;

CREATE TABLE contact_mailboxes (
    contact_id BLOB PRIMARY KEY REFERENCES contacts (contact_id) ON DELETE CASCADE,
    peer_mailbox TEXT NOT NULL,
    our_mailbox TEXT NOT NULL,
    home_relay TEXT NOT NULL,
    onion TEXT,
    prev_relay TEXT,
    prev_peer_mailbox TEXT,
    prev_our_mailbox TEXT,
    prev_until INTEGER
);
CREATE INDEX contact_mailboxes_our ON contact_mailboxes (our_mailbox);
CREATE INDEX contact_mailboxes_prev_our ON contact_mailboxes (prev_our_mailbox);

CREATE TABLE contact_relay_backoff (
    contact_id BLOB NOT NULL REFERENCES contacts (contact_id) ON DELETE CASCADE,
    relay TEXT NOT NULL,
    next_try_at INTEGER NOT NULL,
    failures INTEGER NOT NULL,
    PRIMARY KEY (contact_id, relay)
);

CREATE TABLE pairings (
    pairing_id BLOB PRIMARY KEY,
    role TEXT NOT NULL,
    contact_id BLOB NOT NULL,
    sealed BLOB NOT NULL,
    invite_id BLOB NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    our_mailbox TEXT NOT NULL,
    peer_mailbox TEXT,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    invite BLOB NOT NULL
);
CREATE INDEX pairings_expires ON pairings (expires_at);

CREATE TABLE contact_outbox (
    id INTEGER PRIMARY KEY,
    contact_id BLOB NOT NULL REFERENCES contacts (contact_id) ON DELETE CASCADE,
    slate_id BLOB NOT NULL,
    stage TEXT NOT NULL,
    payload TEXT NOT NULL,
    destination TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    next_try_at INTEGER NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    delivered_at INTEGER
);
CREATE INDEX contact_outbox_due ON contact_outbox (state, next_try_at);
CREATE INDEX contact_outbox_contact ON contact_outbox (contact_id);

DROP TABLE allowed_peers;
";

/// The hashes of envelopes taken from contact and pairing mailboxes, for deduplication; they
/// were one JSON setting before.
const V7: &str = "
CREATE TABLE contact_seen (
    hash BLOB PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
CREATE INDEX contact_seen_at ON contact_seen (seen_at);

DELETE FROM settings WHERE key = 'contact.seen';
";

/// The records the wallet keeps per transaction, which were settings keyed by transaction id
/// before; [`super::v8::move_settings`] moves the stored ones after this runs.
const V8: &str = "
CREATE TABLE tx_marks (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    local_cutoff INTEGER,
    finalized_at INTEGER,
    kernel_absent_at INTEGER,
    receive_seen_at INTEGER,
    receive_inputs_unspent INTEGER NOT NULL CHECK (receive_inputs_unspent IN (0, 1)),
    inputs_spent_elsewhere INTEGER NOT NULL CHECK (inputs_spent_elsewhere IN (0, 1))
);

CREATE TABLE tx_watch (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    phase TEXT NOT NULL CHECK (phase IN ('kernel', 'outputs')),
    excess BLOB NOT NULL,
    min_height INTEGER NOT NULL,
    ended_at INTEGER NOT NULL
);

CREATE TABLE tx_watch_outputs (
    tx_id INTEGER NOT NULL REFERENCES tx_watch (tx_id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    commitment BLOB NOT NULL,
    key_id BLOB NOT NULL,
    amount INTEGER NOT NULL,
    PRIMARY KEY (tx_id, position)
);

CREATE TABLE other_wallet_spends (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    after_height INTEGER NOT NULL,
    to_height INTEGER NOT NULL,
    open INTEGER NOT NULL CHECK (open IN (0, 1))
);

CREATE TABLE other_wallet_outputs (
    tx_id INTEGER NOT NULL REFERENCES other_wallet_spends (tx_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('spent', 'change')),
    position INTEGER NOT NULL,
    commitment BLOB NOT NULL,
    PRIMARY KEY (tx_id, role, position)
);

CREATE TABLE scan_found (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    output BLOB,
    during TEXT CHECK (during IN ('restore', 'rescan')),
    dated_by_block INTEGER NOT NULL CHECK (dated_by_block IN (0, 1))
);
";

/// Which contact a slate or a transaction was exchanged with, which were settings keyed by slate
/// and transaction id before. A link to a transaction goes with it; a slate's link stays, so a
/// contact can never take over a slate id this wallet used with someone else.
const V9: &str = "
CREATE TABLE contact_slates (
    slate_id BLOB PRIMARY KEY,
    contact_id BLOB NOT NULL
);

CREATE TABLE contact_transactions (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    contact_id BLOB NOT NULL
);

INSERT INTO contact_slates (slate_id, contact_id)
    SELECT unhex(replace(substr(key, 15), '-', '')), unhex(value) FROM settings
    WHERE substr(key, 1, 14) = 'contact.slate.'
        AND length(replace(substr(key, 15), '-', '')) = 32
        AND unhex(replace(substr(key, 15), '-', '')) IS NOT NULL
        AND length(value) = 32 AND unhex(value) IS NOT NULL;

INSERT INTO contact_transactions (tx_id, contact_id)
    SELECT CAST(substr(key, 12) AS INTEGER), unhex(value) FROM settings
    WHERE substr(key, 1, 11) = 'contact.tx.'
        AND substr(key, 12) <> '' AND substr(key, 12) NOT GLOB '*[^0-9]*'
        AND length(substr(key, 12)) <= 10
        AND CAST(substr(key, 12) AS INTEGER) IN (SELECT id FROM transactions)
        AND length(value) = 32 AND unhex(value) IS NOT NULL;

DELETE FROM settings WHERE substr(key, 1, 14) = 'contact.slate.' OR substr(key, 1, 11) = 'contact.tx.';
";

pub(crate) const MIGRATIONS: &[&str] = &[V1, V2, V3, V4, V5, V6, V7, V8, V9];

/// The version this build writes.
pub const SCHEMA_VERSION: u32 = 9;

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
        if reached == 8 {
            super::v8::move_settings(&tx)?;
        }
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
