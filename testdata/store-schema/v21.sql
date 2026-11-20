-- Schema 21 of the LEPIC store with the rows a wallet of that release holds. See README.md.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);
INSERT INTO schema_version VALUES(1,21);
CREATE TABLE accounts (
    idx INTEGER PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    next_child INTEGER NOT NULL
);
INSERT INTO accounts VALUES(0,'default',12);
INSERT INTO accounts VALUES(1,'savings',3);
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
    updated_at INTEGER NOT NULL, confirmed_height INTEGER, counterparty TEXT, receive_listing_dkey BLOB
    CHECK (receive_listing_dkey IS NULL OR length(receive_listing_dkey) = 33), receive_listing_gen INTEGER
    CHECK (receive_listing_gen IS NULL OR receive_listing_gen BETWEEN 0 AND 4294967295)
    CHECK ((receive_listing_gen IS NULL) = (receive_listing_dkey IS NULL)),
    UNIQUE (slate_id, direction)
);
INSERT INTO transactions VALUES(1,0,'incoming','confirmed',X'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1','epicbox',5000000000,0,NULL,1790000000000000000,1790000100000000000,1234,'peer@relay',NULL,NULL);
INSERT INTO transactions VALUES(2,0,'outgoing','posted',X'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2','file',0,2010000000,10000000,1790000200000000000,1790000300000000000,NULL,NULL,NULL,NULL);
INSERT INTO transactions VALUES(3,1,'outgoing','cancelled',X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3',NULL,0,510000000,NULL,1790000600000000000,1790000700000000000,NULL,NULL,NULL,NULL);
INSERT INTO transactions VALUES(4,0,'outgoing','posted',NULL,NULL,0,3,NULL,2,2,NULL,NULL,NULL,NULL);
INSERT INTO transactions VALUES(5,0,'incoming','posted',NULL,NULL,3,0,NULL,2,2,NULL,NULL,NULL,NULL);
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
, touched INTEGER NOT NULL DEFAULT 0);
INSERT INTO outputs VALUES(X'080101010101010101010101010101010101010101010101010101010101010101',0,X'03000000010000000000000000000000ff',0,5000000000,'unspent',1234,1234,77,1,0);
INSERT INTO outputs VALUES(X'090808080808080808080808080808080808080808080808080808080808080808',1,X'03000000040000000000000000000000ff',1,60000000000,'unconfirmed',0,1500,NULL,NULL,1790000000000000001);
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
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO settings VALUES('network','mainnet');
INSERT INTO settings VALUES('invoice.expiry_minutes','60');
CREATE TABLE pending_invoices (
    slate_id BLOB PRIMARY KEY,
    sender_key TEXT NOT NULL,
    sender_address TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    codec TEXT NOT NULL,
    sealed BLOB NOT NULL
);
CREATE TABLE invoice_address (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    idx INTEGER NOT NULL CHECK (idx >= 1)
);
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
, payments_address TEXT, payments_key BLOB
    CHECK (payments_key IS NULL OR length(payments_key) = 33), peer_features INTEGER NOT NULL DEFAULT 0, peer_heard_at INTEGER, peer_verified_at INTEGER, peer_verdict BLOB, ended_reason TEXT
    CHECK (ended_reason IN ('mismatch', 'peer-mismatch', 'unpaired', 'never-finished')), ended_at INTEGER, heard_wait INTEGER NOT NULL DEFAULT 0, heard_wait_mark INTEGER, peer_domain TEXT, peer_domain_attestation BLOB);
INSERT INTO contacts VALUES(X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'Alice','paired',NULL,1,'on',NULL,NULL,0,1790000000000000000,1790000000000000000,0,1,X'11111111111111111111111111111111',NULL,X'aa',NULL,NULL,0,NULL,NULL,NULL,NULL,NULL,0,NULL,NULL,NULL);
CREATE TABLE contact_slot_counters (
    account INTEGER PRIMARY KEY,
    next_slot INTEGER NOT NULL
);
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
, expect_address TEXT, expect_key BLOB
    CHECK (expect_key IS NULL OR length(expect_key) = 33), reply BLOB, cancelled_at INTEGER);
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
CREATE TABLE contact_seen (
    hash BLOB PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
CREATE TABLE tx_marks (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    local_cutoff INTEGER,
    finalized_at INTEGER,
    kernel_absent_at INTEGER,
    receive_seen_at INTEGER,
    receive_inputs_unspent INTEGER NOT NULL CHECK (receive_inputs_unspent IN (0, 1)),
    inputs_spent_elsewhere INTEGER NOT NULL CHECK (inputs_spent_elsewhere IN (0, 1))
, sender_posted_at INTEGER, withdrawn_answered INTEGER NOT NULL DEFAULT 0
    CHECK (withdrawn_answered IN (0, 1)), sender_cancelled_at INTEGER, cancelled_answered INTEGER NOT NULL DEFAULT 0
    CHECK (cancelled_answered IN (0, 1)), answer_marked INTEGER NOT NULL DEFAULT 0
    CHECK (answer_marked IN (0, 1)));
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
CREATE TABLE contact_slates (
    slate_id BLOB PRIMARY KEY,
    contact_id BLOB NOT NULL
);
CREATE TABLE contact_transactions (
    tx_id INTEGER PRIMARY KEY REFERENCES transactions (id) ON DELETE CASCADE,
    contact_id BLOB NOT NULL
);
CREATE TABLE peer_compat (
    key_tag BLOB PRIMARY KEY CHECK (length(key_tag) = 32),
    sealed BLOB NOT NULL
);
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
CREATE TABLE peer_pins (
    account INTEGER NOT NULL CHECK (account BETWEEN 0 AND 4294967295),
    origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 300),
    seal_key BLOB NOT NULL CHECK (length(seal_key) = 32),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (account, origin)
) WITHOUT ROWID;
CREATE TABLE api_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    created_at INTEGER NOT NULL,
    data BLOB NOT NULL CHECK (length(data) <= 1048576)
);
CREATE TABLE api_requests (
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 32),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scope, id)
) WITHOUT ROWID;
CREATE TABLE watch_set (
    key_ref TEXT NOT NULL CHECK (length(key_ref) BETWEEN 1 AND 128),
    relay TEXT NOT NULL CHECK (length(relay) BETWEEN 1 AND 300),
    class TEXT NOT NULL CHECK (class IN ('contact', 'pairing', 'link', 'reply', 'in-person',
        'previous-home')),
    expires_at INTEGER,
    PRIMARY KEY (key_ref, relay)
) WITHOUT ROWID;
INSERT INTO watch_set VALUES('contact:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1','relay-a','contact',NULL);
INSERT INTO watch_set VALUES('link:0.screen.3','relay-b','link',1790090000000000000);
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
INSERT INTO native_outbox VALUES(1,X'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2','tx:2','epicbox','key-a','{}','queued',0,1,NULL,'S1',1,NULL);
INSERT INTO native_outbox VALUES(2,X'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1','epic1-init:ab','epicbox','key-b','{}','queued',0,2,NULL,NULL,2,NULL);
INSERT INTO native_outbox VALUES(3,X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3','contact:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1','epicbox','key-c','{}','posted',1,3,NULL,'S3',3,4);
CREATE TABLE payment_delivery (
    payment_id BLOB PRIMARY KEY CHECK (length(payment_id) = 16),
    alias TEXT CHECK (length(alias) BETWEEN 1 AND 128),
    state TEXT CHECK (state IN ('queued', 'posted', 'uncertain', 'failed')),
    state_reason TEXT CHECK (length(state_reason) BETWEEN 1 AND 512),
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
INSERT INTO payment_delivery VALUES(X'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2','alias-2','queued',NULL,1);
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
INSERT INTO node_post VALUES(2,2,1,100,'refused','double spend',1,0);
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
INSERT INTO recovery VALUES(2,4,5,'confirming',120,'not mined yet',2,3);
CREATE TABLE native_outbox_mailbox (
    outbox_id INTEGER NOT NULL REFERENCES native_outbox (id) ON DELETE CASCADE,
    mailbox TEXT NOT NULL CHECK (length(mailbox) BETWEEN 1 AND 300),
    state TEXT NOT NULL CHECK (state IN ('taken', 'owed', 'cancel')),
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 4294967295),
    next_at INTEGER NOT NULL,
    PRIMARY KEY (outbox_id, mailbox)
) WITHOUT ROWID;
INSERT INTO native_outbox_mailbox VALUES(1,'box-a@relay-a','taken',0,1);
INSERT INTO native_outbox_mailbox VALUES(1,'box-b@relay-b','owed',1,5);
CREATE INDEX transactions_account ON transactions (account);
CREATE INDEX outputs_account_status ON outputs (account, status);
CREATE INDEX outputs_tx ON outputs (tx_id);
CREATE INDEX relay_outbox_status ON relay_outbox (status);
CREATE INDEX pending_invoices_status_sender ON pending_invoices (status, sender_key);
CREATE INDEX pending_invoices_received ON pending_invoices (received_at);
CREATE INDEX imported_outputs_status ON imported_outputs (status);
CREATE INDEX imported_outputs_tx ON imported_outputs (tx_id);
CREATE INDEX contacts_hint_key ON contacts (peer_hint_key);
CREATE INDEX contacts_slot ON contacts (account, slot);
CREATE INDEX contacts_allow_invoices ON contacts (created_at) WHERE allow_invoices = 1;
CREATE INDEX contact_mailboxes_our ON contact_mailboxes (our_mailbox);
CREATE INDEX contact_mailboxes_prev_our ON contact_mailboxes (prev_our_mailbox);
CREATE INDEX pairings_expires ON pairings (expires_at);
CREATE INDEX contact_outbox_due ON contact_outbox (state, next_try_at);
CREATE INDEX contact_outbox_contact ON contact_outbox (contact_id);
CREATE INDEX contact_seen_at ON contact_seen (seen_at);
CREATE INDEX contacts_payments_key ON contacts (payments_key);
CREATE INDEX pairings_expect_key ON pairings (expect_key);
CREATE INDEX pair_requests_received ON pair_requests (received_at);
CREATE INDEX pair_requests_invite ON pair_requests (invite_id);
CREATE INDEX contact_status_out_due ON contact_status_out (next_try_at)
    WHERE delivered_at IS NULL;
CREATE INDEX contact_status_out_contact ON contact_status_out (contact_id);
CREATE INDEX outputs_touched ON outputs (touched);
CREATE INDEX api_events_created_at ON api_events (created_at);
CREATE INDEX api_requests_created_at ON api_requests (created_at);
CREATE INDEX native_outbox_from ON native_outbox (from_ref);
CREATE INDEX native_outbox_due ON native_outbox (state, next_at);
CREATE INDEX native_outbox_payment ON native_outbox (payment_id);
CREATE UNIQUE INDEX payment_delivery_alias ON payment_delivery (alias);
CREATE INDEX transactions_state_created ON transactions (state, created_at);
CREATE INDEX native_outbox_mailbox_due ON native_outbox_mailbox (state, next_at);
COMMIT;