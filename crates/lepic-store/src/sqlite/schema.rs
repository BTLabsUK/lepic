// SPDX-License-Identifier: Apache-2.0
//! Schema versions and forward-only migrations.
//!
//! `MIGRATIONS[n]` takes a database from version `n` to version `n + 1`. A released migration is
//! never edited; a schema change appends one and a test that opens the previous version.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::context::StoreKeys;
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

/// Invoices received, the senders the retired invoice address accepted, what each peer is proven
/// to support, and the index of that address.
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

/// Two more marks of a transaction, which were settings keyed by its slate id: when the sender
/// of a received payment reported it posted, and that the payer of a withdrawn invoice was told.
/// A posted report is advisory for an hour, so stored ones are dropped. The parked invoices' origin
/// addresses, no longer written since the invoice address was retired, go too.
const V10: &str = "
ALTER TABLE tx_marks ADD COLUMN sender_posted_at INTEGER;
ALTER TABLE tx_marks ADD COLUMN withdrawn_answered INTEGER NOT NULL DEFAULT 0
    CHECK (withdrawn_answered IN (0, 1));

INSERT INTO tx_marks (tx_id, receive_inputs_unspent, inputs_spent_elsewhere, withdrawn_answered)
    SELECT transactions.id, 0, 0, 1 FROM settings JOIN transactions
        ON transactions.slate_id = unhex(replace(substr(settings.key, 27), '-', ''))
    WHERE substr(settings.key, 1, 26) = 'notice.withdrawn_answered.'
        AND length(replace(substr(settings.key, 27), '-', '')) = 32
    ON CONFLICT (tx_id) DO UPDATE SET withdrawn_answered = 1;

DELETE FROM settings WHERE substr(key, 1, 26) = 'notice.withdrawn_answered.'
    OR substr(key, 1, 23) = 'notice.posted_reported.'
    OR substr(key, 1, 15) = 'invoice.origin.';
";

/// Two more marks of a transaction for the `cancelled` notice: when the sender of a received
/// payment reported it cancelled it, and that the receiver of a cancelled send was told.
const V11: &str = "
ALTER TABLE tx_marks ADD COLUMN sender_cancelled_at INTEGER;
ALTER TABLE tx_marks ADD COLUMN cancelled_answered INTEGER NOT NULL DEFAULT 0
    CHECK (cancelled_answered IN (0, 1));
";

/// What each peer key showed, sealed and found by a keyed hash of the key, replacing the clear
/// `peer_capabilities` rows, which [`super::v12::move_peer_capabilities`] moves and drops after
/// this runs; and whether the latest answer to a send carried the LEPIC marker, unknown and so
/// unset for the sends before.
const V12: &str = "
CREATE TABLE peer_compat (
    key_tag BLOB PRIMARY KEY CHECK (length(key_tag) = 32),
    sealed BLOB NOT NULL
);

ALTER TABLE tx_marks ADD COLUMN answer_marked INTEGER NOT NULL DEFAULT 0
    CHECK (answer_marked IN (0, 1));
";

/// What a pairing learns after it is stored, as facts beside its state: the proven payments
/// address, the claimed features, when the contact was heard and confirmed the check, and how the
/// pairing ended, which moves here from the settings rows that marked a contact's own removal.
/// Pairings in progress keep the address they must prove, the invitee's reply to post again,
/// and a cancel. Pairing requests from other wallets and the pairing status notices get tables
/// of their own; and a received transaction names the listing it came in on.
const V13: &str = "
ALTER TABLE contacts ADD COLUMN payments_address TEXT;
ALTER TABLE contacts ADD COLUMN payments_key BLOB
    CHECK (payments_key IS NULL OR length(payments_key) = 33);
ALTER TABLE contacts ADD COLUMN peer_features INTEGER NOT NULL DEFAULT 0;
ALTER TABLE contacts ADD COLUMN peer_heard_at INTEGER;
ALTER TABLE contacts ADD COLUMN peer_verified_at INTEGER;
ALTER TABLE contacts ADD COLUMN peer_verdict BLOB;
ALTER TABLE contacts ADD COLUMN ended_reason TEXT
    CHECK (ended_reason IN ('mismatch', 'peer-mismatch', 'unpaired', 'never-finished'));
ALTER TABLE contacts ADD COLUMN ended_at INTEGER;
ALTER TABLE contacts ADD COLUMN heard_wait INTEGER NOT NULL DEFAULT 0;
ALTER TABLE contacts ADD COLUMN heard_wait_mark INTEGER;
CREATE INDEX contacts_payments_key ON contacts (payments_key);

UPDATE contacts SET peer_heard_at = created_at
    WHERE state IN ('paired', 'verified', 'keys-changed');

UPDATE contacts SET ended_reason = 'unpaired',
    ended_at = (SELECT CAST(value AS INTEGER) * 1000000000 FROM settings
                WHERE key = 'contact.unpaired.' || lower(hex(contacts.contact_id))
                    AND value <> '' AND value NOT GLOB '*[^0-9]*' AND length(value) <= 10)
    WHERE EXISTS (SELECT 1 FROM settings
                  WHERE key = 'contact.unpaired.' || lower(hex(contacts.contact_id)));
DELETE FROM settings WHERE substr(key, 1, 17) = 'contact.unpaired.';

ALTER TABLE pairings ADD COLUMN expect_address TEXT;
ALTER TABLE pairings ADD COLUMN expect_key BLOB
    CHECK (expect_key IS NULL OR length(expect_key) = 33);
ALTER TABLE pairings ADD COLUMN reply BLOB;
ALTER TABLE pairings ADD COLUMN cancelled_at INTEGER;
CREATE INDEX pairings_expect_key ON pairings (expect_key);

CREATE TABLE pair_requests (
    sender_key BLOB PRIMARY KEY CHECK (length(sender_key) = 33),
    sender_address TEXT NOT NULL,
    invite_id BLOB NOT NULL,
    invite BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    dismissed_at INTEGER,
    answered_at INTEGER
);
CREATE INDEX pair_requests_received ON pair_requests (received_at);
CREATE INDEX pair_requests_invite ON pair_requests (invite_id);

CREATE TABLE contact_status_out (
    id INTEGER PRIMARY KEY,
    contact_id BLOB NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('finished', 'match', 'mismatch', 'unpaired')),
    payload TEXT NOT NULL,
    destination TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    next_try_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    delivered_at INTEGER
);
CREATE INDEX contact_status_out_due ON contact_status_out (next_try_at)
    WHERE delivered_at IS NULL;
CREATE INDEX contact_status_out_contact ON contact_status_out (contact_id);

ALTER TABLE transactions ADD COLUMN receive_listing_dkey BLOB
    CHECK (receive_listing_dkey IS NULL OR length(receive_listing_dkey) = 33);
ALTER TABLE transactions ADD COLUMN receive_listing_gen INTEGER
    CHECK (receive_listing_gen IS NULL OR receive_listing_gen BETWEEN 0 AND 4294967295)
    CHECK ((receive_listing_gen IS NULL) = (receive_listing_dkey IS NULL));
";

/// The domain a contact claimed in its pairing and the raw proof it sent, kept unverified
/// (RFC 0002 6.3, ADR 0043). Both are set or both are NULL.
const V14: &str = "
ALTER TABLE contacts ADD COLUMN peer_domain TEXT;
ALTER TABLE contacts ADD COLUMN peer_domain_attestation BLOB;
";

/// When a block reward no block confirmed yet was last built, which decides the one to drop at
/// the cap (ADR 0048). 0 for an output nothing touched.
const V15: &str = "
ALTER TABLE outputs ADD COLUMN touched INTEGER NOT NULL DEFAULT 0;
CREATE INDEX outputs_touched ON outputs (touched);
";

/// The seal key each native endpoint showed the first time this wallet sent to it, kept under
/// the account that sent and the endpoint's origin. Nothing in the wallet writes or reads the
/// table.
const V16: &str = "
CREATE TABLE peer_pins (
    account INTEGER NOT NULL CHECK (account BETWEEN 0 AND 4294967295),
    origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 300),
    seal_key BLOB NOT NULL CHECK (length(seal_key) = 32),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (account, origin)
) WITHOUT ROWID;
";

/// The serve API's event log and its idempotency records. AUTOINCREMENT keeps an event id from
/// being given twice after a prune. Content is stored as given: the store relies on the
/// whole-file encryption, as peer pins and transaction records do.
const V17: &str = "
CREATE TABLE api_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    created_at INTEGER NOT NULL,
    data BLOB NOT NULL CHECK (length(data) <= 1048576)
);
CREATE INDEX api_events_created_at ON api_events (created_at);
CREATE TABLE api_requests (
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 32),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scope, id)
) WITHOUT ROWID;
CREATE INDEX api_requests_created_at ON api_requests (created_at);
";

/// Delivery state (ADR 0062): the watched mailboxes, the native posts owed, the delivery state
/// of each payment and the posts of each transaction to the node. The hook in `v18.rs` fills
/// the first three from the records that hold them before this version; no row is deleted.
const V18: &str = "
CREATE TABLE watch_set (
    key_ref TEXT NOT NULL CHECK (length(key_ref) BETWEEN 1 AND 128),
    relay TEXT NOT NULL CHECK (length(relay) BETWEEN 1 AND 300),
    class TEXT NOT NULL CHECK (class IN ('contact', 'pairing', 'link', 'reply', 'in-person',
        'previous-home')),
    expires_at INTEGER,
    PRIMARY KEY (key_ref, relay)
) WITHOUT ROWID;
CREATE TABLE native_outbox (
    id INTEGER PRIMARY KEY,
    payment_id BLOB NOT NULL CHECK (length(payment_id) = 16),
    from_ref TEXT NOT NULL CHECK (length(from_ref) BETWEEN 1 AND 128),
    route_method TEXT NOT NULL CHECK (length(route_method) BETWEEN 1 AND 32),
    route_value TEXT NOT NULL CHECK (length(route_value) BETWEEN 1 AND 1024),
    envelope TEXT NOT NULL CHECK (length(envelope) BETWEEN 1 AND 1048576),
    state TEXT NOT NULL CHECK (state IN ('queued', 'posted', 'uncertain', 'failed')),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 4294967295),
    next_at INTEGER NOT NULL,
    cutoff_height INTEGER,
    stage TEXT CHECK (stage IN ('S1', 'S2', 'S3', 'I1', 'I2', 'I3')),
    created_at INTEGER NOT NULL,
    posted_at INTEGER
);
CREATE INDEX native_outbox_from ON native_outbox (from_ref);
CREATE INDEX native_outbox_due ON native_outbox (state, next_at);
CREATE INDEX native_outbox_payment ON native_outbox (payment_id);
CREATE TABLE payment_delivery (
    payment_id BLOB PRIMARY KEY CHECK (length(payment_id) = 16),
    alias TEXT CHECK (length(alias) BETWEEN 1 AND 128),
    state TEXT CHECK (state IN ('queued', 'posted', 'uncertain', 'failed')),
    state_reason TEXT CHECK (length(state_reason) BETWEEN 1 AND 512),
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE UNIQUE INDEX payment_delivery_alias ON payment_delivery (alias);
CREATE TABLE node_post (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 4294967295),
    last_at INTEGER NOT NULL,
    last_height INTEGER NOT NULL,
    last_outcome TEXT NOT NULL CHECK (last_outcome IN ('accepted', 'refused', 'unreachable')),
    last_error TEXT CHECK (length(last_error) <= 1024),
    accepted_once INTEGER NOT NULL CHECK (accepted_once IN (0, 1)),
    unreachable_once INTEGER NOT NULL CHECK (unreachable_once IN (0, 1))
);
CREATE INDEX transactions_state ON transactions (state);
";

/// The recovery of a payment (ADR 0062 section 8): its self-send pair and where it stands.
const V19: &str = "
CREATE TABLE recovery (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    sent_tx INTEGER NOT NULL REFERENCES transactions (id) ON DELETE CASCADE,
    received_tx INTEGER NOT NULL REFERENCES transactions (id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('uncertain', 'posted', 'confirming', 'done',
        'failed')),
    kernel_height INTEGER,
    last_error TEXT CHECK (length(last_error) <= 1024),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
";

/// The open transactions of a state, oldest first, without reading the table. The index of
/// version 18 on state alone serves nothing this one does not, so it goes.
const V20: &str = "
CREATE INDEX transactions_state_created ON transactions (state, created_at);
DROP INDEX transactions_state;
";

/// Where each mailbox stands with an outbox entry posted to a key's mailbox on several relays:
/// which took it, which are owed it, and which hold a copy to cancel.
const V21: &str = "
CREATE TABLE native_outbox_mailbox (
    outbox_id INTEGER NOT NULL REFERENCES native_outbox (id) ON DELETE CASCADE,
    mailbox TEXT NOT NULL CHECK (length(mailbox) BETWEEN 1 AND 300),
    state TEXT NOT NULL CHECK (state IN ('taken', 'owed', 'cancel')),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 4294967295),
    next_at INTEGER NOT NULL,
    PRIMARY KEY (outbox_id, mailbox)
) WITHOUT ROWID;
CREATE INDEX native_outbox_mailbox_due ON native_outbox_mailbox (state, next_at);
";

/// Marks the outbox rows that carry a notice (ADR 0067). A notice has no slate stage. Rows
/// stored before this version carried a notice under a slate stage it borrowed or under none;
/// they are marked here so they still go out as notices:
///
/// - a payer's `posted` (`epic1-init:`), a refusal (`epic1-resp:`) and a contact's status or
///   `unpaired` notice (`contact:`), all without a stage;
/// - every contact row under S3, which no contact slate takes;
/// - a contact row under S2 of a payment this wallet never received: a refusal's `declined`;
/// - a contact row under I1 of a payment this wallet did not issue (a payer's `declined`), of
///   an invoice it withdrew (`withdrawn`), or after the first I1 row of the payment (`posted`).
const V22: &str = "
ALTER TABLE native_outbox ADD COLUMN notice INTEGER NOT NULL DEFAULT 0
    CHECK (notice IN (0, 1) AND (notice = 0 OR stage IS NULL));
UPDATE native_outbox SET notice = 1, stage = NULL
WHERE (stage IS NULL AND (from_ref LIKE 'epic1-init:%' OR from_ref LIKE 'epic1-resp:%'
        OR from_ref LIKE 'contact:%'))
    OR (from_ref LIKE 'contact:%' AND (
        stage = 'S3'
        OR (stage = 'S2' AND NOT EXISTS (SELECT 1 FROM transactions t
            WHERE t.slate_id = native_outbox.payment_id AND t.direction = 'incoming'))
        OR (stage = 'I1' AND (
            NOT EXISTS (SELECT 1 FROM transactions t
                WHERE t.slate_id = native_outbox.payment_id AND t.direction = 'incoming'
                    AND t.state <> 'cancelled')
            OR EXISTS (SELECT 1 FROM native_outbox earlier
                WHERE earlier.payment_id = native_outbox.payment_id
                    AND earlier.from_ref = native_outbox.from_ref
                    AND earlier.stage = 'I1' AND earlier.id < native_outbox.id)))));
";

pub(crate) const MIGRATIONS: &[&str] = &[
    V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17, V18, V19, V20, V21,
    V22,
];

/// The version this build writes.
pub const SCHEMA_VERSION: u32 = 22;

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

/// Brings the database to `target` in one transaction, sealing what a migration moves under
/// `keys`. Fails with [`StoreError::SchemaTooNew`], changing nothing, when the database is
/// already past `target`.
pub(crate) fn migrate_to(
    conn: &mut Connection,
    target: u32,
    keys: &StoreKeys,
) -> Result<(), StoreError> {
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
        if reached == 12 {
            super::v12::move_peer_capabilities(&tx, keys)?;
        }
        if reached == 18 {
            super::v18::fill(&tx, super::v18::clock_nanos())?;
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
    use crate::context::ContextKey;
    use crate::peer::PeerTagKey;

    fn keys() -> StoreKeys {
        StoreKeys::new(
            ContextKey::from_bytes([1; 32]),
            PeerTagKey::from_bytes([2; 32]),
        )
    }

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
            migrate_to(&mut conn, target, &keys()).unwrap();
            assert_eq!(stored_version(&conn).unwrap(), target);
        }
    }

    #[test]
    fn rejects_downgrade() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_to(&mut conn, SCHEMA_VERSION, &keys()).unwrap();
        assert!(matches!(
            migrate_to(&mut conn, SCHEMA_VERSION - 1, &keys()),
            Err(StoreError::SchemaTooNew { .. })
        ));
    }
}
