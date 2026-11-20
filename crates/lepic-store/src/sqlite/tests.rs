// SPDX-License-Identifier: Apache-2.0
//! Migration harness: every older schema version must open and migrate with its data intact.
//!
//! A schema change adds a migration and an [`UpgradeCase`] for the version it replaces. The seed
//! is written in that older version's schema, and the check reads it back through the current
//! repositories.

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Height};
use rusqlite::{Connection, OptionalExtension};

use super::SqliteStore;
use super::schema::{SCHEMA_VERSION, migrate_to, stored_version};
use crate::account::{AccountIndex, AccountRecord};
use crate::context::{ContextKey, StoreKeys};
use crate::error::StoreError;
use crate::invoice::{PendingInvoice, PendingInvoiceStatus};
use crate::output::KeyId;
use crate::peer::{self, PeerCompat, PeerTagKey};
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

/// The row the upgrade wrote for the Epicbox key `key`, opened.
fn peer_compat(store: &SqliteStore, key: &str) -> Option<PeerCompat> {
    let tag = store.keys.peer_tag.tag(key).unwrap();
    let conn = store.conn.lock().unwrap();
    let sealed: Option<Vec<u8>> = conn
        .query_row(
            "SELECT sealed FROM peer_compat WHERE key_tag = ?1",
            [tag.0.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    sealed.map(|sealed| peer::open(&store.keys.context, &tag, &sealed).unwrap())
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
    let invoices = store.read(|repos| repos.pending_invoices()).unwrap();
    assert!(invoices.is_empty());
    assert_eq!(invoice_address_index(store), None);
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
    let compat = peer_compat(store, "key");
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
        compat,
        Some(PeerCompat {
            last_unmarked_at: Some(Timestamp::from_nanosecond(8).unwrap()),
            ..PeerCompat::default()
        }),
        "a returned invoice is an unmarked answer"
    );
    assert_eq!(invoice_address_index(store), Some(3));
}

/// The invoice address row an old store kept; nothing reads it any more.
fn invoice_address_index(store: &SqliteStore) -> Option<u32> {
    let conn = store.conn.lock().unwrap();
    conn.query_row("SELECT idx FROM invoice_address WHERE id = 1", [], |row| {
        row.get(0)
    })
    .optional()
    .unwrap()
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
    let at = |second| Some(Timestamp::from_second(second).unwrap());
    let peers = ["lepic-key", "stock-key", "odd-key"].map(|key| peer_compat(store, key));
    let marks = store.read(|repos| repos.tx_marks(TxId(1))).unwrap();
    assert_eq!(
        peers,
        [
            Some(PeerCompat {
                last_marked_at: at(1_790_000_000),
                claimed: 1,
                works: 1,
                ..PeerCompat::default()
            }),
            Some(PeerCompat {
                last_unmarked_at: at(1_790_000_100),
                ..PeerCompat::default()
            }),
            None,
        ],
        "a proven key keeps its date as the last marked message; an unknown value is dropped"
    );
    assert_eq!(
        marks,
        TxMarks {
            cancelled_answered: true,
            ..TxMarks::default()
        },
        "an earlier send's answer counts as unmarked"
    );
    let conn = store.conn.lock().unwrap();
    let (old_tables, rows): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM sqlite_schema WHERE name = 'peer_capabilities'),
                    (SELECT count(*) FROM peer_compat)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((old_tables, rows), (0, 2));
}

fn check_v12_seed(store: &SqliteStore) {
    use crate::contact::{ContactId, PairingEndReason};
    let records = store.read(|repos| repos.contacts()).unwrap();
    let facts: Vec<_> = records
        .iter()
        .map(|record| (record.contact_id, record.facts.clone()))
        .collect();
    let at = |nanos: i128| Some(Timestamp::from_nanosecond(nanos).unwrap());
    assert_eq!(facts.len(), 3);
    assert_eq!(facts[0].0, ContactId([1; 16]));
    assert_eq!(
        facts[0].1.peer_heard_at,
        at(5),
        "a paired record counts as heard"
    );
    assert_eq!(facts[0].1.ended_reason, Some(PairingEndReason::Unpaired));
    assert_eq!(facts[0].1.ended_at, at(1_790_000_000_000_000_000));
    assert_eq!(
        facts[1].1.peer_heard_at, None,
        "an invite waiting is not heard"
    );
    assert_eq!(facts[1].1.ended_reason, None);
    assert_eq!(facts[2].1.peer_heard_at, at(7));
    assert_eq!(
        (facts[2].1.ended_reason, facts[2].1.ended_at),
        (Some(PairingEndReason::Unpaired), None),
        "a marker whose time does not read still ends the pairing"
    );
    for (_, fact) in &facts {
        assert_eq!(fact.peer_features, 0);
        assert_eq!(fact.payments_address, None);
    }
    let left = store
        .read(|repos| {
            Ok::<_, StoreError>([
                repos.setting("contact.unpaired.01010101010101010101010101010101")?,
                repos.setting("contact.unpaired.03030303030303030303030303030303")?,
                repos.setting("network")?,
            ])
        })
        .unwrap();
    assert_eq!(left, [None, None, Some("floonet".to_owned())]);
    let conn = store.conn.lock().unwrap();
    let pairing: (i64, Option<String>, Option<Vec<u8>>, Option<i64>) = conn
        .query_row(
            "SELECT count(*), max(expect_address), max(reply), max(cancelled_at) FROM pairings",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        pairing,
        (1, None, None, None),
        "a pairing in progress is kept"
    );
    let new_tables: i64 = conn
        .query_row(
            "SELECT (SELECT count(*) FROM pair_requests) + (SELECT count(*) FROM contact_status_out)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(new_tables, 0);
    let listing: (Option<Vec<u8>>, Option<i64>) = conn
        .query_row(
            "SELECT receive_listing_dkey, receive_listing_gen FROM transactions WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        listing,
        (None, None),
        "an earlier receive came in on the payments address"
    );
    let set = |service_key: &str, generation: &str| {
        conn.execute(
            &format!(
                "UPDATE transactions SET receive_listing_dkey = {service_key}, \
                 receive_listing_gen = {generation} WHERE id = 1"
            ),
            [],
        )
    };
    for (service_key, generation) in [
        ("zeroblob(33)", "NULL"),
        ("NULL", "0"),
        ("zeroblob(32)", "0"),
        ("zeroblob(34)", "0"),
    ] {
        assert!(
            set(service_key, generation).is_err(),
            "a listing of {service_key} and {generation} is refused"
        );
    }
    assert_eq!(set("zeroblob(33)", "7").unwrap(), 1);
    assert_eq!(set("NULL", "NULL").unwrap(), 1);
}

fn check_v13_seed(store: &SqliteStore) {
    check_empty(store);
}

fn v13_store_migrates_to_v14_with_null_domain(store: &SqliteStore) {
    let contacts = store.read(|repos| repos.contacts()).unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].facts.peer_domain, None);
    let conn = store.conn.lock().unwrap();
    let columns: (Option<String>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT peer_domain, peer_domain_attestation FROM contacts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(columns, (None, None));
}

fn check_v5_seed(store: &SqliteStore) {
    let imported = store
        .read(|repos| repos.imported_transaction(TxId(1)))
        .unwrap();
    assert_eq!(imported, None);
    let entry = store.read(|repos| repos.transaction(TxId(1))).unwrap();
    assert_eq!(entry.map(|entry| entry.state), Some(TxState::Received));
}

fn check_v15_seed(store: &SqliteStore) {
    use crate::contact::{ContactId, ContactState, SealMode};
    use crate::transaction::TxDirection;
    let accounts = store.read(|repos| repos.accounts()).unwrap();
    assert_eq!(
        accounts,
        vec![
            AccountRecord {
                index: AccountIndex(0),
                label: "default".to_owned(),
                next_child: 12,
            },
            AccountRecord {
                index: AccountIndex(1),
                label: "savings".to_owned(),
                next_child: 3,
            },
        ]
    );
    let entry = store
        .read(|repos| repos.transaction(TxId(3)))
        .unwrap()
        .unwrap();
    assert_eq!(entry.direction, TxDirection::Outgoing);
    assert_eq!(entry.state, TxState::Posted);
    assert_eq!(entry.account, AccountIndex(0));
    assert_eq!(entry.transport.as_deref(), Some("epicbox"));
    assert_eq!(entry.amount_credited, Amount::new(0));
    assert_eq!(entry.amount_debited, Amount::new(1_010_000_000));
    assert_eq!(
        entry.slate_id,
        Some(uuid::Uuid::from_bytes([0xa3; 16])),
        "the slate id is kept"
    );
    let marks = store.read(|repos| repos.tx_marks(TxId(3))).unwrap();
    assert_eq!(marks.local_cutoff, Some(Height::new(1290)));
    let contacts = store.read(|repos| repos.contacts()).unwrap();
    assert_eq!(contacts.len(), 3);
    let alice = store
        .read(|repos| repos.contact(ContactId([0xc1; 16])))
        .unwrap()
        .unwrap();
    assert_eq!(alice.label, "Alice");
    assert_eq!(alice.state, ContactState::Verified);
    assert_eq!(alice.seal, SealMode::On);
    assert!(alice.allow_invoices);
    assert_eq!(alice.slot, 1);
    assert_eq!(alice.facts.peer_features, 7);
    assert_eq!(
        alice.facts.peer_domain.map(|claim| claim.domain),
        Some("alice.example".to_owned())
    );
    let carol = store
        .read(|repos| repos.contact(ContactId([0xc3; 16])))
        .unwrap()
        .unwrap();
    assert_eq!(carol.state, ContactState::Paired);
    assert_eq!(carol.seal, SealMode::Degraded);
    assert_eq!(carol.facts.peer_features, 1);
    let unspent = store
        .read(|repos| repos.outputs(AccountIndex(0), Some(crate::output::OutputStatus::Unspent)))
        .unwrap();
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].amount, Amount::new(5_000_000_000));
    assert_eq!(unspent[0].height, Height::new(1234));
    assert_eq!(unspent[0].mmr_index, Some(77));
    assert_eq!(unspent[0].tx, Some(TxId(1)));
    assert_eq!(
        store.read(|repos| repos.setting("network")).unwrap(),
        Some("mainnet".to_owned())
    );
}

const V1_SEED: &str = "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 4);
    INSERT INTO settings (key, value) VALUES ('network', 'floonet');
    INSERT INTO transactions (id, account, direction, state, amount_credited, amount_debited,
        created_at, updated_at)
    VALUES (1, 0, 'incoming', 'confirmed', 5, 0, 1, 1);";

/// A wallet at schema 15 with rows in the tables a wallet in use fills, so an upgrade has
/// something to keep. Commitments are valid points; the other keys are placeholders of the right length.
const V15_SEED: &str = "
INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 12), (1, 'savings', 3);

INSERT INTO transactions (id, account, direction, state, slate_id, transport, amount_credited,
    amount_debited, fee, created_at, updated_at, confirmed_height, counterparty)
VALUES
    (1, 0, 'incoming', 'confirmed', X'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', 'epicbox', 5000000000, 0,
     NULL, 1790000000000000000, 1790000100000000000, 1234, 'peer@relay'),
    (2, 0, 'outgoing', 'confirmed', X'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2', 'file', 0, 2010000000,
     10000000, 1790000200000000000, 1790000300000000000, 1240, NULL),
    (3, 0, 'outgoing', 'posted', X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3', 'epicbox', 0, 1010000000,
     10000000, 1790000400000000000, 1790000500000000000, NULL, 'peer@relay'),
    (4, 1, 'outgoing', 'cancelled', X'a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4', NULL, 0, 510000000,
     NULL, 1790000600000000000, 1790000700000000000, NULL, NULL),
    (5, 0, 'incoming', 'received', X'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5', 'epicbox', 700000000, 0,
     NULL, 1790000800000000000, 1790000900000000000, NULL, 'shop@relay');

INSERT INTO outputs (commitment, features, key_id, account, amount, status, height, lock_height,
    mmr_index, tx_id, touched)
VALUES
    (X'080101010101010101010101010101010101010101010101010101010101010101', 0,
     X'03000000010000000000000000000000ff', 0, 5000000000, 'unspent', 1234, 1234, 77, 1, 0),
    (X'080202020202020202020202020202020202020202020202020202020202020202', 0,
     X'03000000020000000000000000000000ff', 0, 2010000000, 'spent', 1100, 1100, 70, 2, 0),
    (X'090707070707070707070707070707070707070707070707070707070707070707', 0,
     X'03000000030000000000000000000000ff', 0, 990000000, 'locked', 1250, 1250, 80, 3, 0),
    (X'090808080808080808080808080808080808080808080808080808080808080808', 1,
     X'03000000040000000000000000000000ff', 1, 60000000000, 'unconfirmed', 0, 1500, NULL, NULL,
     1790000000000000001);

INSERT INTO slates (slate_id, stage, codec, bytes) VALUES
    (X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3', 'standard1', 'slatepack', X'0102030405'),
    (X'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5', 'standard2', 'slatepack', X'0a0b0c');

INSERT INTO private_contexts (slate_id, participant, sealed) VALUES
    (X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3', 0, X'deadbeef'),
    (X'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5', 1, X'cafebabe');

INSERT INTO tx_marks (tx_id, local_cutoff, finalized_at, kernel_absent_at, receive_seen_at,
    receive_inputs_unspent, inputs_spent_elsewhere, sender_posted_at, withdrawn_answered,
    sender_cancelled_at, cancelled_answered, answer_marked)
VALUES
    (3, 1290, 1790000450000000000, NULL, NULL, 0, 0, NULL, 0, NULL, 0, 1),
    (4, NULL, NULL, NULL, NULL, 0, 1, NULL, 0, 1790000650000000000, 1, 0),
    (5, NULL, NULL, NULL, 1790000850000000000, 1, 0, 1790000860000000000, 0, NULL, 0, 0);

INSERT INTO settings (key, value) VALUES
    ('network', 'mainnet'),
    ('contact.next_slot_hint', '4'),
    ('invoice.expiry_minutes', '60');

INSERT INTO contacts (contact_id, card, peer_sig_key, peer_enc_key, peer_hint_key, card_seq, kind,
    claimed_name, label, state, verified_at, allow_invoices, seal, last_sealed_in, app_contact,
    imported_from_backup, created_at, updated_at, account, slot, box_salt, sas, own_card,
    payments_address, payments_key, peer_features, peer_heard_at, peer_verified_at, peer_verdict,
    ended_reason, ended_at, heard_wait, heard_wait_mark, peer_domain, peer_domain_attestation)
VALUES
    (X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'b1b1b1', X'5151515151515151515151515151515151515151515151515151515151515151',
     X'5252525252525252525252525252525252525252525252525252525252525252', X'5353535353535353535353535353535353535353535353535353535353535353', 3, 'person',
     'Alice', 'Alice', 'verified', 1790001000000000000, 1, 'on', 1790001100000000000, 'addr-1',
     0, 1790000000000000000, 1790001200000000000, 0, 1, X'11111111111111111111111111111111',
     X'0a0b0c0d', X'a0a0a0', 'alice@relay',
     X'026161616161616161616161616161616161616161616161616161616161616161', 7,
     1790001050000000000, 1790001060000000000,
     X'7171717171717171717171717171717171717171717171717171717171717171', NULL, NULL, 0, NULL,
     'alice.example', X'ee01'),
    (X'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'Bob',
     'pending-invite', NULL, 0, 'on', NULL, NULL, 0, 1790002000000000000, 1790002000000000000, 0,
     2, X'22222222222222222222222222222222', NULL, X'b0b0b0', NULL, NULL, 0, NULL, NULL, NULL,
     NULL, NULL, 0, NULL, NULL, NULL),
    (X'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3', X'b3b3b3', X'5454545454545454545454545454545454545454545454545454545454545454',
     X'5555555555555555555555555555555555555555555555555555555555555555', X'5656565656565656565656565656565656565656565656565656565656565656', 1, 'shop', 'Carol',
     'Carol', 'paired', NULL, 0, 'degraded', NULL, NULL, 1, 1790003000000000000,
     1790003500000000000, 1, 3, X'33333333333333333333333333333333', NULL, X'c0c0c0', NULL, NULL,
     1, 1790003100000000000, NULL, NULL, 'unpaired', 1790003400000000000, 0, NULL, NULL, NULL);

INSERT INTO contact_slot_counters (account, next_slot) VALUES (0, 3), (1, 4);

INSERT INTO contact_mailboxes (contact_id, peer_mailbox, our_mailbox, home_relay, onion,
    prev_relay, prev_peer_mailbox, prev_our_mailbox, prev_until)
VALUES
    (X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', 'peer-box@relay-a', 'our-box@relay-a', 'relay-a',
     'abcdefghij.onion', 'relay-old', 'peer-old@relay-old', 'our-old@relay-old',
     1790009000000000000),
    (X'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3', 'peer-c@relay-b', 'our-c@relay-b', 'relay-b', NULL,
     NULL, NULL, NULL, NULL);

INSERT INTO contact_relay_backoff (contact_id, relay, next_try_at, failures)
VALUES (X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', 'relay-a', 1790005000000000000, 2);

INSERT INTO pairings (pairing_id, role, contact_id, sealed, invite_id, expires_at, our_mailbox,
    peer_mailbox, state, created_at, invite, expect_address, expect_key, reply, cancelled_at)
VALUES
    (X'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2', 'inviter', X'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2',
     X'0badf00d', X'0202020202020202', 1790090000000000000, 'invite-box@relay-a', NULL,
     'pending-invite', 1790002000000000000, X'd2d2d2', NULL, NULL, NULL, NULL),
    (X'c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4', 'invitee', X'c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4',
     X'0badf00e', X'0404040404040404', 1790090000000000000, 'reply-box@relay-b',
     'peer-box@relay-b', 'cancelled', 1790004000000000000, X'd4d4d4', 'dave@relay',
     X'034141414141414141414141414141414141414141414141414141414141414141',
     X'e4e4', 1790004500000000000);

INSERT INTO contact_outbox (id, contact_id, slate_id, stage, payload, destination, attempts,
    next_try_at, state, created_at, delivered_at)
VALUES
    (1, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3', 'standard1',
     'envelope-text', 'peer-box@relay-a', 1, 1790006000000000000, 'queued', 1790000450000000000,
     NULL);

INSERT INTO contact_seen (hash, seen_at) VALUES
    (X'9191919191919191919191919191919191919191919191919191919191919191', 1790007000000000000);

INSERT INTO peer_compat (key_tag, sealed) VALUES
    (X'8181818181818181818181818181818181818181818181818181818181818181', X'5ea1ed00');

INSERT INTO pending_invoices (slate_id, sender_key, sender_address, received_at, status, codec,
    sealed)
VALUES (X'a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6', 'sender-key', 'sender@relay', 1790008000, 'parked',
    'slatepack', X'0ddba110');

INSERT INTO relay_outbox (id, transport, destination, slate_id, stage, status, attempts,
    created_at, updated_at)
VALUES (1, 'epicbox', 'peer@relay', X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3', 'standard1', 'queued', 0,
    1790000450, 1790000450);

INSERT INTO imported_transactions (tx_id, source_id, kind, slate_id, confirmed_at, input_count,
    output_count, kernel_excess, kernel_lookup_min_height, ttl_cutoff_height, chain_check)
VALUES (2, 41, 'sent', X'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2', 1790000300, 1, 2,
    X'087777777777777777777777777777777777777777777777777777777777777777', 1200,
    NULL, 'confirmed');

INSERT INTO imported_messages (tx_id, position, participant, text) VALUES (2, 0, 0, 'rent');

INSERT INTO imported_outputs (commitment, tx_id, status, height, amount)
VALUES (X'088888888888888888888888888888888888888888888888888888888888888888', 2,
    'spent', 1100, 2010000000);

INSERT INTO contact_slates (slate_id, contact_id)
VALUES (X'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3', X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1');

INSERT INTO contact_transactions (tx_id, contact_id)
VALUES (3, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1');

INSERT INTO pair_requests (sender_key, sender_address, invite_id, invite, expires_at, received_at,
    dismissed_at, answered_at)
VALUES (X'024242424242424242424242424242424242424242424242424242424242424242',
    'erin@relay', X'0505050505050505', X'd5d5d5', 1790090000000000000, 1790005000000000000,
    NULL, NULL);

INSERT INTO contact_status_out (id, contact_id, kind, payload, destination, attempts, next_try_at,
    created_at, expires_at, delivered_at)
VALUES (1, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', 'finished', 'status-text', 'peer-box@relay-a', 0,
    1790006500000000000, 1790006400000000000, 1790090000000000000, NULL);

INSERT INTO invoice_address (id, idx) VALUES (1, 3);

INSERT INTO tx_watch (tx_id, phase, excess, min_height, ended_at)
VALUES (4, 'kernel', X'089999999999999999999999999999999999999999999999999999999999999999',
    1000, 1790000700000000000);

INSERT INTO tx_watch_outputs (tx_id, position, commitment, key_id, amount)
VALUES (4, 0, X'091212121212121212121212121212121212121212121212121212121212121212',
    X'03000000050000000000000000000000ff', 510000000);

INSERT INTO other_wallet_spends (tx_id, after_height, to_height, open) VALUES (3, 1250, 1300, 1);

INSERT INTO other_wallet_outputs (tx_id, role, position, commitment)
VALUES (3, 'spent', 0, X'081313131313131313131313131313131313131313131313131313131313131313');

INSERT INTO scan_found (tx_id, output, during, dated_by_block) VALUES (1, NULL, 'restore', 1);
";

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
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, slate_id,
                   amount_credited, amount_debited, created_at, updated_at)
               VALUES (1, 0, 'outgoing', 'cancelled', X'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a',
                   0, 5, 1, 1);
               INSERT INTO tx_marks (tx_id, receive_inputs_unspent, inputs_spent_elsewhere,
                   cancelled_answered)
               VALUES (1, 0, 0, 1);
               INSERT INTO peer_capabilities (key, support, learned_at) VALUES
                   ('lepic-key', 'lepic', 1790000000000000000),
                   ('stock-key', 'no-invoices', 1790000100000000000),
                   ('odd-key', 'maybe', 1);",
        check: check_v11_seed,
    },
    UpgradeCase {
        from: 12,
        seed: "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
               INSERT INTO transactions (id, account, direction, state, amount_credited,
                   amount_debited, created_at, updated_at)
               VALUES (1, 0, 'incoming', 'received', 5, 0, 1, 1);
               INSERT INTO contacts (contact_id, label, state, allow_invoices, seal,
                   imported_from_backup, created_at, updated_at, account, slot, box_salt,
                   own_card)
               VALUES (X'01010101010101010101010101010101', 'a', 'paired', 0, 'on', 0, 5, 5, 0,
                   1, X'11111111111111111111111111111111', X'aa'),
                      (X'02020202020202020202020202020202', '', 'pending-invite', 0, 'on', 0, 6,
                   6, 0, 2, X'22222222222222222222222222222222', X'bb'),
                      (X'03030303030303030303030303030303', 'c', 'verified', 0, 'on', 0, 7, 7, 0,
                   3, X'33333333333333333333333333333333', X'cc');
               INSERT INTO pairings (pairing_id, role, contact_id, sealed, invite_id, expires_at,
                   our_mailbox, state, created_at, invite)
               VALUES (X'02020202020202020202020202020202', 'inviter',
                   X'02020202020202020202020202020202', X'00', X'0202020202020202', 100,
                   'box@relay', 'pending-invite', 6, X'dd');
               INSERT INTO settings (key, value) VALUES
                   ('network', 'floonet'),
                   ('contact.unpaired.01010101010101010101010101010101', '1790000000'),
                   ('contact.unpaired.03030303030303030303030303030303', 'x1');",
        check: check_v12_seed,
    },
    UpgradeCase {
        from: 13,
        seed: "INSERT INTO contacts (contact_id, label, state, allow_invoices, seal,
                   imported_from_backup, created_at, updated_at, account, slot, box_salt,
                   own_card)
               VALUES (X'01010101010101010101010101010101', 'a', 'paired', 0, 'on', 0, 5, 5, 0,
                   1, X'11111111111111111111111111111111', X'aa');",
        check: v13_store_migrates_to_v14_with_null_domain,
    },
    UpgradeCase {
        from: 14,
        seed: "",
        check: check_v13_seed,
    },
    UpgradeCase {
        from: 15,
        seed: V15_SEED,
        check: check_v15_seed,
    },
    UpgradeCase {
        from: 16,
        seed: V16_SEED,
        check: check_v16_seed,
    },
    UpgradeCase {
        from: 17,
        seed: V17_SEED,
        check: check_v17_seed,
    },
    UpgradeCase {
        from: 18,
        seed: V18_SEED,
        check: check_v18_seed,
    },
    UpgradeCase {
        from: 19,
        seed: V19_SEED,
        check: check_v19_seed,
    },
    UpgradeCase {
        from: 20,
        seed: V20_SEED,
        check: check_v20_seed,
    },
    UpgradeCase {
        from: 21,
        seed: "",
        check: check_empty,
    },
    UpgradeCase {
        from: 22,
        seed: "",
        check: check_empty,
    },
];

/// A queued post to a slot, which version 21 keeps with no mailbox copies yet.
const V20_SEED: &str = "
INSERT INTO native_outbox (id, payment_id, from_ref, route_method, route_value, envelope, state,
    attempts, next_at, cutoff_height, stage, created_at, posted_at)
VALUES (1, x'2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a', 'tx:1', 'epicbox', 'key', '{}', 'queued', 0, 1,
    NULL, 'S1', 1, NULL);
";

fn check_v20_seed(store: &SqliteStore) {
    use crate::delivery::{NativeOutboxId, OutboxState};

    let (stored, copies) = store
        .read(|repos| {
            let stored = repos.native_outbox_of(uuid::Uuid::from_bytes([42; 16]))?;
            let copies = repos.outbox_copies(NativeOutboxId(1))?;
            Ok::<_, StoreError>((stored, copies))
        })
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].entry.state, OutboxState::Queued);
    assert!(copies.is_empty());
}

/// A payment under recovery, its self-send pair and the recovery, mined and confirming.
const V19_SEED: &str = "
INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 4);
INSERT INTO transactions (id, account, direction, state, amount_credited, amount_debited,
    created_at, updated_at)
VALUES
    (1, 0, 'outgoing', 'sent', 0, 5, 1, 1),
    (2, 0, 'outgoing', 'posted', 0, 3, 2, 2),
    (3, 0, 'incoming', 'posted', 3, 0, 2, 2);
INSERT INTO recovery (tx_id, sent_tx, received_tx, state, kernel_height, last_error,
    created_at, updated_at)
VALUES (1, 2, 3, 'confirming', 120, 'not mined yet', 2, 3);
";

fn check_v19_seed(store: &SqliteStore) {
    use crate::recovery::RecoveryState;

    let recovery = store
        .read(|repos| repos.recovery(TxId(1)))
        .unwrap()
        .unwrap();
    assert_eq!((recovery.sent_tx, recovery.received_tx), (TxId(2), TxId(3)));
    assert_eq!(recovery.state, RecoveryState::Confirming);
    assert_eq!(recovery.kernel_height, Some(Height::new(120)));
    assert_eq!(recovery.last_error.as_deref(), Some("not mined yet"));
}

/// A posted send with a refused post to the node, which version 19 keeps and gives no recovery.
const V18_SEED: &str = "
INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 4);
INSERT INTO transactions (id, account, direction, state, amount_credited, amount_debited,
    created_at, updated_at)
VALUES (1, 0, 'outgoing', 'posted', 0, 5, 1, 1);
INSERT INTO node_post (tx_id, attempts, last_at, last_height, last_outcome, last_error,
    accepted_once, unreachable_once)
VALUES (1, 2, 1, 100, 'refused', 'double spend', 1, 0);
";

fn check_v18_seed(store: &SqliteStore) {
    use crate::node_post::NodeOutcome;

    let (entry, post, recoveries) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                repos.transaction(TxId(1))?,
                repos.node_post(TxId(1))?,
                repos.recoveries()?,
            ))
        })
        .unwrap();
    assert_eq!(entry.map(|entry| entry.state), Some(TxState::Posted));
    let post = post.unwrap();
    assert_eq!(post.last_outcome, NodeOutcome::Refused);
    assert_eq!(post.last_error.as_deref(), Some("double spend"));
    assert!(recoveries.is_empty());
}

/// 2100-01-01, in nanoseconds: an end the fill keeps whenever the test runs.
const Y2100: i64 = 4_102_444_800_000_000_000;

/// Every record the version 18 fill reads, with records it skips: a payment that does not read,
/// a second alias of one payment, an alias of no slate id, a contact ended on a key mismatch,
/// and a contact post of a slate id that is not 16 bytes.
const V17_SEED: &str = r#"
INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);

INSERT INTO transactions (id, account, direction, state, slate_id, amount_credited,
    amount_debited, created_at, updated_at)
VALUES
    (1, 0, 'outgoing', 'sent', X'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', 0, 100, 1, 1),
    (2, 0, 'incoming', 'received', X'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2', 100, 0, 1, 1);

INSERT INTO contacts (contact_id, card, label, state, allow_invoices, seal,
    imported_from_backup, created_at, updated_at, account, slot, box_salt, own_card,
    ended_reason)
VALUES
    (X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'b1', 'Alice', 'paired', 0, 'on', 0, 1, 1, 0, 1,
     X'11111111111111111111111111111111', X'a0', NULL),
    (X'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3', X'b3', 'Carol', 'paired', 0, 'on', 0, 1, 1, 0, 2,
     X'33333333333333333333333333333333', X'c0', 'mismatch');

INSERT INTO contact_mailboxes (contact_id, peer_mailbox, our_mailbox, home_relay, prev_relay,
    prev_until)
VALUES
    (X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', 'peer@relay-a', 'our@relay-a', 'relay-a', 'relay-old',
     4102444800000000000),
    (X'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3', 'peer@relay-m', 'our@relay-m', 'relay-m', NULL, NULL);

INSERT INTO pairings (pairing_id, role, contact_id, sealed, invite_id, expires_at, our_mailbox,
    state, created_at, invite)
VALUES
    (X'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2', 'inviter', X'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2',
     X'0badf00d', X'0202020202020202', 4102444800000000000, 'invite@relay-p:9000',
     'pending-invite', 1, X'd2');

INSERT INTO contact_outbox (id, contact_id, slate_id, stage, payload, destination, attempts,
    next_try_at, state, created_at, delivered_at)
VALUES
    (1, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1', 'S1',
     'envelope-1', 'peer@relay-a', 1, 1790006000000000000, 'queued', 5, NULL),
    (2, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2', 'S2',
     'envelope-2', 'peer@relay-a', 40, 1790007000000000000, 'stuck', 6, 7),
    (3, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'01', 'S1', 'envelope-3', 'peer@relay-a',
     0, 1790008000000000000, 'queued', 1, NULL);

INSERT INTO settings (key, value) VALUES
    ('contact.oldsalt.c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', '{"salt":"0101"}'),
    ('epic1.link.0.printed.1', '{"issued_at":1,"used_at":null,"relays":["relay-l"]}'),
    ('epic1.pay.a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1', '{"tx_id":1,"account":0,
        "envelope":"00","address":"epic1x","entries":[{"mailbox":"aa","host":"relay-a"}],
        "next":1,"posted":0,"finalized":false,"reply_relay":"relay-r"}'),
    ('epic1.pay.d4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4', 'not json'),
    ('inperson.code.b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2', '{"tx_id":2,"account":0,
        "kind":"invoice","ttl_cutoff":900,"mailbox":"relay-i","closed":false,"finalized":null,
        "answers":[]}'),
    ('api.alias.order-1', 'a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1'),
    ('api.alias.order-2', 'a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1'),
    ('api.alias.order-3', 'c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3'),
    ('api.alias.order-4', 'not a slate id');
"#;

/// The version 18 fill finds every mailbox, contact post and payment alias of [`V17_SEED`], and
/// nothing of the records it skips or of its epic1 links and payments.
fn check_v17_seed(store: &SqliteStore) {
    use crate::delivery::{MailClass, WatchRow};

    let at = |nanos: i64| Some(Timestamp::from_nanosecond(i128::from(nanos)).unwrap());
    let watch = |key_ref: &str, relay: &str, class, expires_at| WatchRow {
        key_ref: key_ref.to_owned(),
        relay: relay.to_owned(),
        class,
        expires_at,
    };
    let c1 = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    assert_eq!(
        store.read(|repos| repos.watch_set()).unwrap(),
        [
            watch(
                &format!("contact-old-salt:{c1}"),
                "relay-a",
                MailClass::Contact,
                None
            ),
            watch(
                &format!("contact:{c1}"),
                "relay-a",
                MailClass::Contact,
                None
            ),
            watch(
                "inperson:b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2",
                "relay-i",
                MailClass::InPerson,
                None
            ),
            watch(
                &format!("contact:{c1}"),
                "relay-old",
                MailClass::PreviousHome,
                at(Y2100)
            ),
            watch(
                "pairing:c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2",
                "relay-p:9000",
                MailClass::Pairing,
                at(Y2100)
            ),
        ]
    );

    check_v17_outbox(store);
    check_v17_deliveries(store);
}

/// The contact posts of [`V17_SEED`] as native outbox entries, without the short slate id.
fn check_v17_outbox(store: &SqliteStore) {
    use crate::delivery::{NativeOutboxEntry, OutboxState};
    use crate::slate::SlateStage;

    let c1 = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    let at = |nanos: i64| Timestamp::from_nanosecond(i128::from(nanos)).unwrap();
    let entry = |envelope: &str,
                 stage,
                 state,
                 attempts,
                 next_at: i64,
                 created_at,
                 posted_at: Option<i64>| NativeOutboxEntry {
        payment_id: uuid::Uuid::nil(),
        from_ref: format!("contact:{c1}"),
        route_method: "epicbox".to_owned(),
        route_value: "peer@relay-a".to_owned(),
        envelope: envelope.to_owned(),
        state,
        attempts,
        next_at: at(next_at),
        cutoff_height: None,
        stage: Some(stage),
        notice: false,
        created_at: at(created_at),
        posted_at: posted_at.map(at),
    };
    for (slate, expected) in [
        (
            0xe1,
            entry(
                "envelope-1",
                SlateStage::Standard1,
                OutboxState::Queued,
                1,
                1_790_006_000_000_000_000,
                5,
                None,
            ),
        ),
        // An S2 of a payment this wallet never received is a refusal's `declined`: version 22
        // marks it a notice.
        (
            0xe2,
            NativeOutboxEntry {
                stage: None,
                notice: true,
                ..entry(
                    "envelope-2",
                    SlateStage::Standard2,
                    OutboxState::Failed,
                    40,
                    1_790_007_000_000_000_000,
                    6,
                    Some(7),
                )
            },
        ),
    ] {
        let payment_id = uuid::Uuid::from_bytes([slate; 16]);
        let stored = store
            .read(|repos| repos.native_outbox_of(payment_id))
            .unwrap();
        let entries: Vec<_> = stored.into_iter().map(|stored| stored.entry).collect();
        assert_eq!(
            entries,
            [NativeOutboxEntry {
                payment_id,
                ..expected
            }]
        );
    }
    let due = store
        .read(|repos| repos.due_native_outbox(at(Y2100)))
        .unwrap();
    assert_eq!(
        due.len(),
        1,
        "one queued post, and none of the short slate id"
    );
}

/// The aliases of [`V17_SEED`] as delivery rows without a state, without the second alias of a
/// payment or the alias of no slate id. The epic1 payment gets no state of its own.
fn check_v17_deliveries(store: &SqliteStore) {
    use crate::delivery::PaymentDelivery;

    // The fill dates each delivery with the time it ran.
    let migrated_after = Timestamp::from_second(1_700_000_000).unwrap();
    let delivery = |slate: &str| {
        let payment_id = uuid::Uuid::parse_str(slate).unwrap();
        let found = store
            .read(|repos| repos.payment_delivery(payment_id))
            .unwrap()
            .unwrap();
        assert!(found.updated_at > migrated_after, "{found:?}");
        PaymentDelivery {
            updated_at: Timestamp::UNIX_EPOCH,
            ..found
        }
    };
    let a1 = "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1";
    let c3 = "c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3";
    let expected = |slate: &str, alias: &str, state| PaymentDelivery {
        payment_id: uuid::Uuid::parse_str(slate).unwrap(),
        alias: Some(alias.to_owned()),
        state,
        state_reason: None,
        updated_at: Timestamp::UNIX_EPOCH,
    };
    assert_eq!(delivery(a1), expected(a1, "order-1", None));
    assert_eq!(delivery(c3), expected(c3, "order-3", None));
    for (alias, found) in [
        ("order-1", Some(a1)),
        ("order-2", None),
        ("order-3", Some(c3)),
        ("order-4", None),
    ] {
        let by_alias = store
            .read(|repos| repos.payment_delivery_by_alias(alias))
            .unwrap()
            .map(|delivery| delivery.payment_id);
        assert_eq!(
            by_alias,
            found.map(|slate| uuid::Uuid::parse_str(slate).unwrap()),
            "{alias}"
        );
    }
    let d4 = uuid::Uuid::from_bytes([0xd4; 16]);
    assert_eq!(
        store.read(|repos| repos.payment_delivery(d4)).unwrap(),
        None
    );
}

const V16_SEED: &str = "INSERT INTO peer_pins (account, origin, seal_key, first_seen, last_seen)
    VALUES (0, 'https://wallet.example:443', X'0707070707070707070707070707070707070707070707070707070707070707', 5, 6);";

/// A v16 database keeps its pin and gains empty, usable event and request tables.
fn check_v16_seed(store: &SqliteStore) {
    let pins: i64 = store
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM peer_pins
             WHERE account = 0 AND origin = 'https://wallet.example:443'
               AND seal_key = X'0707070707070707070707070707070707070707070707070707070707070707'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pins, 1);
    store
        .read(|repos| {
            assert_eq!(repos.api_event_bounds()?, None);
            assert_eq!(repos.api_event_last_id()?, 0);
            Ok::<_, StoreError>(())
        })
        .unwrap();
    let id = store
        .write(|repos| repos.append_api_event("payment.created", Timestamp::UNIX_EPOCH, b"{}"))
        .unwrap();
    assert_eq!(id, 1);
}

fn key() -> StoreKeys {
    StoreKeys::new(
        ContextKey::from_bytes([3; 32]),
        PeerTagKey::from_bytes([4; 32]),
    )
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
            migrate_to(&mut conn, case.from, &key()).unwrap();
            conn.execute_batch(case.seed).unwrap();
            assert_eq!(stored_version(&conn).unwrap(), case.from);
        }

        let store = SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap();
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

/// A watch row of a link's mailbox kept by the earlier release reads as an address row under
/// its old key reference, so listing the watch set does not fail on it.
#[test]
fn a_link_watch_row_of_the_earlier_release_reads_as_an_address_row() {
    use crate::delivery::{MailClass, WatchRow};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "INSERT INTO watch_set (key_ref, relay, class, expires_at)
             VALUES ('link:0.screen.3', 'relay-a', 'link', NULL);",
        )
        .unwrap();

    let store = SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap();
    assert_eq!(
        store.read(|repos| repos.watch_set()).unwrap(),
        [WatchRow {
            key_ref: "link:0.screen.3".to_owned(),
            relay: "relay-a".to_owned(),
            class: MailClass::Address,
            expires_at: None,
        }]
    );
}

#[test]
fn the_state_tally_searches_the_state_index_without_a_sort() {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate_to(&mut conn, SCHEMA_VERSION, &key()).unwrap();
    // One index serves both: the count by its state, the oldest by its order of time.
    for sql in [super::repos::STATE_COUNT, super::repos::STATE_OLDEST] {
        let index = "transactions_state_created";
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let values: [&dyn rusqlite::ToSql; 4] = [&"sent", &"incoming", &"self", &2];
        let wanted = statement.parameter_count();
        let plan: Vec<String> = statement
            .query_map(&values[..wanted], |row| row.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            plan,
            vec![format!("SEARCH transactions USING INDEX {index} (state=?)")],
            "{sql}"
        );
    }
}

#[test]
fn a_settings_prefix_reads_a_range_of_the_key_index() {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate_to(&mut conn, SCHEMA_VERSION, &key()).unwrap();
    let plan: Vec<String> = conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            super::repos::SETTINGS_RANGE
        ))
        .unwrap()
        .query_map(["notice.declined.", "notice.declined/"], |row| row.get(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        plan,
        vec!["SEARCH settings USING INDEX sqlite_autoindex_settings_1 (key>? AND key<?)"]
    );
}

/// Every schema object, then every table's rows in rowid order, rendered as text.
#[derive(Debug, PartialEq)]
struct Dump {
    schema: Vec<(String, String, String, Option<String>)>,
    tables: std::collections::BTreeMap<String, Vec<Vec<String>>>,
}

fn render(value: rusqlite::types::ValueRef<'_>) -> String {
    format!("{value:?}")
}

fn dump(conn: &Connection) -> Dump {
    let schema: Vec<(String, String, String, Option<String>)> = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let names: Vec<String> = schema
        .iter()
        .filter(|(kind, name, ..)| kind == "table" && !name.starts_with("sqlite_"))
        .map(|(_, name, ..)| name.clone())
        .collect();
    let mut tables = std::collections::BTreeMap::new();
    for name in names {
        let mut statement = conn.prepare(&format!("SELECT * FROM \"{name}\"")).unwrap();
        let columns = statement.column_count();
        // Sorted here: a WITHOUT ROWID table has no rowid to order by.
        let mut rows: Vec<Vec<String>> = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get_ref(column).map(render))
                    .collect()
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        tables.insert(name, rows);
    }
    Dump { schema, tables }
}

/// A database at schema 15 holding [`V15_SEED`], and its path.
fn seeded_v15() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let mut conn = Connection::open(&path).unwrap();
    migrate_to(&mut conn, 15, &key()).unwrap();
    conn.execute_batch(V15_SEED).unwrap();
    assert_eq!(stored_version(&conn).unwrap(), 15);
    (dir, path)
}

#[test]
fn a_v15_database_keeps_every_row_and_table_when_upgraded() {
    let (_dir, path) = seeded_v15();
    let before = dump(&Connection::open(&path).unwrap());
    assert!(
        before
            .tables
            .values()
            .filter(|rows| !rows.is_empty())
            .count()
            >= 25,
        "the seed fills the tables a wallet in use fills"
    );

    drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
    let conn = Connection::open(&path).unwrap();
    let after = dump(&conn);

    for object in &before.schema {
        assert!(
            after.schema.contains(object),
            "the schema object {} {} is unchanged",
            object.0,
            object.1
        );
    }
    for object in after.schema.iter().filter(|o| !before.schema.contains(o)) {
        assert!(
            matches!(object.0.as_str(), "table" | "index"),
            "the only new objects are tables and indexes, not {} {}",
            object.0,
            object.1
        );
        // Version 20 indexes transactions by state and time.
        if object.0 == "index" && object.1 != "transactions_state_created" {
            assert!(
                !before.tables.contains_key(&object.2),
                "the new index {} is on a new table",
                object.1
            );
        }
    }
    for (table, rows) in &before.tables {
        if table == "schema_version" {
            continue;
        }
        assert_eq!(after.tables.get(table), Some(rows), "rows of {table}");
    }
    // Version 18 fills these from the records above; `check_v17_seed` checks what.
    let filled = ["watch_set", "native_outbox", "payment_delivery"];
    for (table, rows) in &after.tables {
        if !before.tables.contains_key(table) && !filled.contains(&table.as_str()) {
            assert!(rows.is_empty(), "the new table {table} starts empty");
        }
    }
    assert_eq!(stored_version(&conn).unwrap(), SCHEMA_VERSION);
}

#[test]
fn the_v18_fill_deletes_only_the_alias_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    {
        let mut conn = Connection::open(&path).unwrap();
        migrate_to(&mut conn, 17, &key()).unwrap();
        conn.execute_batch(V17_SEED).unwrap();
    }
    let aliases = |conn: &Connection| -> usize {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM settings WHERE key LIKE 'api.alias.%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        usize::try_from(count).unwrap()
    };
    let conn = Connection::open(&path).unwrap();
    let before = dump(&conn);
    let alias_rows = aliases(&conn);
    assert_eq!(alias_rows, 4, "the seed holds alias settings");
    drop(conn);

    drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
    let conn = Connection::open(&path).unwrap();
    let after = dump(&conn);

    // Every settings row left was there before; the ones gone are the alias settings.
    assert_eq!(aliases(&conn), 0);
    let settings = &after.tables["settings"];
    assert!(
        settings
            .iter()
            .all(|row| before.tables["settings"].contains(row))
    );
    assert_eq!(settings.len(), before.tables["settings"].len() - alias_rows);
    for (table, rows) in &before.tables {
        if table != "schema_version" && table != "settings" {
            assert_eq!(after.tables.get(table), Some(rows), "rows of {table}");
        }
    }
    let filled = |table: &str| after.tables.get(table).map(Vec::len);
    assert_eq!(filled("watch_set"), Some(5));
    assert_eq!(filled("native_outbox"), Some(2));
    assert_eq!(filled("payment_delivery"), Some(2));
}

/// A contact, its payments and the contact outbox rows of a released version (schema 17).
const V17_NOTICE_ROWS: &str = r#"
INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
INSERT INTO contacts (contact_id, label, state, allow_invoices, seal, imported_from_backup,
    created_at, updated_at, account, slot, box_salt, own_card)
VALUES (X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', 'a', 'paired', 0, 'on', 0, 1, 1, 0, 1,
    X'11111111111111111111111111111111', X'aa');
INSERT INTO transactions (id, account, direction, state, slate_id, amount_credited,
    amount_debited, created_at, updated_at)
VALUES
    (1, 0, 'incoming', 'received', X'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1', 100, 0, 1, 1),
    (2, 0, 'incoming', 'cancelled', X'e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2', 100, 0, 1, 1),
    (3, 0, 'incoming', 'received', X'e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3', 100, 0, 1, 1),
    (4, 0, 'outgoing', 'cancelled', X'e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6', 0, 100, 1, 1),
    (5, 0, 'outgoing', 'sent', X'e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7', 0, 100, 1, 1);
INSERT INTO contact_outbox (id, contact_id, slate_id, stage, payload, destination, attempts,
    next_try_at, state, created_at, delivered_at)
VALUES
    (1, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1', 'I1',
     'invoice', 'peer@relay-a', 1, 10, 'delivered', 1, 2),
    (2, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1', 'I1',
     'posted', 'peer@relay-a', 0, 10, 'queued', 3, NULL),
    (3, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2', 'I1',
     'withdrawn', 'peer@relay-a', 0, 10, 'queued', 3, NULL),
    (4, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4', 'I1',
     'declined', 'peer@relay-a', 0, 10, 'queued', 3, NULL),
    (5, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3', 'S2',
     'answer', 'peer@relay-a', 0, 10, 'queued', 3, NULL),
    (6, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5', 'S2',
     'refused', 'peer@relay-a', 0, 10, 'queued', 3, NULL),
    (7, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6', 'S3',
     'cancelled', 'peer@relay-a', 0, 10, 'queued', 3, NULL),
    (8, X'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1', X'e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7', 'S1',
     'send', 'peer@relay-a', 0, 10, 'queued', 3, NULL);
"#;

/// Native outbox rows of version 18 to 21: a payer's notice, a refusal, a status notice and
/// pairing mail, none with a stage.
const V21_NOTICE_ROWS: &str = r#"
INSERT INTO native_outbox (payment_id, from_ref, route_method, route_value, envelope, state,
    attempts, next_at, cutoff_height, stage, created_at, posted_at)
VALUES
    (X'f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1', 'epic1-init:0', 'epicbox', 'payee@relay-a',
     'payer-posted', 'queued', 0, 10, NULL, NULL, 4, NULL),
    (X'f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2', 'epic1-resp:0', 'epicbox', 'reply@relay-a',
     'refusal', 'queued', 0, 10, NULL, NULL, 4, NULL),
    (X'f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3', 'contact:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',
     'epicbox', 'peer@relay-a', 'status', 'queued', 0, 10, NULL, NULL, 4, NULL),
    (X'f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4', 'pairing:c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2',
     'epicbox', 'invite@relay-p', 'pairing-reply', 'queued', 0, 10, NULL, NULL, 4, NULL);
"#;

/// Notice rows stored by a released version under a borrowed slate stage, and by version 18 to
/// 21 without one, are marked as notices by version 22 and still load; slate rows and pairing
/// mail are left as they were.
#[test]
fn old_notice_rows_are_marked_as_notices_and_still_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let mut conn = Connection::open(&path).unwrap();
    migrate_to(&mut conn, 17, &key()).unwrap();
    conn.execute_batch(V17_NOTICE_ROWS).unwrap();
    migrate_to(&mut conn, 21, &key()).unwrap();
    conn.execute_batch(V21_NOTICE_ROWS).unwrap();
    drop(conn);

    let store = SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap();
    let mut rows: Vec<(String, Option<String>, bool)> = store
        .read(|repos| {
            repos.due_native_outbox(Timestamp::from_nanosecond(i128::from(Y2100)).unwrap())
        })
        .unwrap()
        .into_iter()
        .map(|stored| {
            let entry = stored.entry;
            (
                entry.envelope,
                entry.stage.map(|stage| stage.code().to_owned()),
                entry.notice,
            )
        })
        .collect();
    rows.sort();
    let row = |envelope: &str, stage: Option<&str>, notice| {
        (envelope.to_owned(), stage.map(str::to_owned), notice)
    };
    assert_eq!(
        rows,
        [
            row("answer", Some("S2"), false),
            row("cancelled", None, true),
            row("declined", None, true),
            row("pairing-reply", None, false),
            row("payer-posted", None, true),
            row("posted", None, true),
            row("refusal", None, true),
            row("refused", None, true),
            row("send", Some("S1"), false),
            row("status", None, true),
            row("withdrawn", None, true),
        ]
    );
    // The delivered invoice is not due; it keeps its stage.
    let invoice = store
        .read(|repos| repos.native_outbox_of(uuid::Uuid::from_bytes([0xe1; 16])))
        .unwrap();
    assert_eq!(
        invoice
            .iter()
            .map(|stored| (
                stored.entry.stage.map(crate::slate::SlateStage::code),
                stored.entry.notice
            ))
            .collect::<Vec<_>>(),
        [(Some("I1"), false), (None, true)]
    );
}

#[test]
fn an_upgraded_database_refuses_an_older_build() {
    let (_dir, path) = seeded_v15();
    drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
    let mut conn = Connection::open(&path).unwrap();
    let before = dump(&conn);

    // An older build opens with its own, lower, schema version as the target.
    let result = migrate_to(&mut conn, SCHEMA_VERSION - 1, &key());
    assert!(matches!(
        result,
        Err(StoreError::SchemaTooNew { found, supported })
            if found == SCHEMA_VERSION && supported == SCHEMA_VERSION - 1
    ));
    assert_eq!(dump(&conn), before);
    assert_eq!(stored_version(&conn).unwrap(), SCHEMA_VERSION);
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
    let _store = SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir.path().join("wallet.sqlite-wal")), 0o600);
}

#[cfg(unix)]
#[test]
fn opening_an_existing_database_restricts_it_to_its_owner() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
    let wal = dir.path().join("wallet.sqlite-wal");
    let shm = dir.path().join("wallet.sqlite-shm");
    // Non-empty leftovers, as a run that was killed leaves them; SQLite itself re-modes empty ones.
    for file in [&path, &wal, &shm] {
        if !file.exists() {
            std::fs::write(file, [0u8; 32]).unwrap();
        }
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let _store = SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap();
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
    drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
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

    let store = SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap();
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

    let store = SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap();
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
    let error = SqliteStore::open(&path, key(), crate::AtRest::Plain)
        .err()
        .unwrap();
    assert!(
        matches!(
            &error,
            crate::StoreError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound
        ),
        "{error:?}"
    );
}

/// The schemas that released stores held, written out as `.sql` dumps with the rows such a store
/// holds (`testdata/store-schema/README.md`). They are the one record of those schemas that a
/// later edit of `MIGRATIONS` cannot follow: the cases of `UPGRADES` build their old database with
/// the current migrations.
const FROZEN_SCHEMAS: [u32; 6] = [14, 18, 19, 20, 21, 22];

/// The schema objects in one dump and not the other, so a failure names them and not the whole schema.
fn schema_diff(left: &Dump, right: &Dump) -> Vec<String> {
    let mut diff = Vec::new();
    for object in &left.schema {
        if !right.schema.contains(object) {
            diff.push(format!(
                "only in the first: {} {}: {:?}",
                object.0, object.1, object.3
            ));
        }
    }
    for object in &right.schema {
        if !left.schema.contains(object) {
            diff.push(format!(
                "only in the second: {} {}: {:?}",
                object.0, object.1, object.3
            ));
        }
    }
    diff
}

fn frozen_sql(version: u32) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../testdata/store-schema/v{version}.sql"));
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The frozen schema `version` loaded into a database file, and its path.
fn frozen_database(version: u32) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(&frozen_sql(version)).unwrap();
    assert_eq!(stored_version(&conn).unwrap(), version);
    (dir, path)
}

/// A database the current migrations make from nothing, up to `version`.
fn migrated_to(version: u32) -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate_to(&mut conn, version, &key()).unwrap();
    conn
}

#[test]
fn a_frozen_schema_is_the_schema_the_migrations_make() {
    for version in FROZEN_SCHEMAS {
        let (_dir, path) = frozen_database(version);
        let frozen = dump(&Connection::open(&path).unwrap());
        assert!(
            frozen
                .tables
                .values()
                .filter(|rows| !rows.is_empty())
                .count()
                >= 4,
            "schema {version} holds rows"
        );
        assert_eq!(
            schema_diff(&frozen, &dump(&migrated_to(version))),
            Vec::<String>::new(),
            "the migrations to {version} no longer make the schema frozen for it"
        );
    }
}

/// What each frozen schema's outbox rows read after the upgrade: id, stage, notice. Version 22
/// marks the notices that earlier versions stored under a stage or none.
fn outbox_after_upgrade(version: u32) -> Vec<(i64, Option<String>, i64)> {
    let first = (1, Some("S1".to_owned()), 0);
    match version {
        14 => vec![],
        18..=20 => vec![first],
        _ => vec![first, (2, None, 1), (3, None, 1)],
    }
}

#[test]
fn every_frozen_schema_upgrades_to_the_current_one_and_keeps_its_rows() {
    let current = dump(&migrated_to(SCHEMA_VERSION));
    for version in FROZEN_SCHEMAS {
        let (_dir, path) = frozen_database(version);
        let before = dump(&Connection::open(&path).unwrap());

        drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
        let conn = Connection::open(&path).unwrap();
        let after = dump(&conn);

        assert_eq!(
            stored_version(&conn).unwrap(),
            SCHEMA_VERSION,
            "from {version}"
        );
        assert_eq!(
            schema_diff(&after, &current),
            Vec::<String>::new(),
            "the schema reached from {version} is not the current one"
        );
        // A later version only adds columns at the end of a row, so each row kept is a prefix.
        // The outbox is checked below: version 22 rewrites the rows it marks.
        for (table, rows) in &before.tables {
            if table == "schema_version" || table == "native_outbox" {
                continue;
            }
            for row in rows {
                assert!(
                    after.tables[table].iter().any(|kept| kept.starts_with(row)),
                    "from {version}: the row {row:?} of {table} is kept"
                );
            }
            assert!(
                after.tables[table].len() >= rows.len(),
                "from {version}: {table} lost no row"
            );
        }
        let outbox: Vec<(i64, Option<String>, i64)> = conn
            .prepare("SELECT id, stage, notice FROM native_outbox ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            outbox,
            outbox_after_upgrade(version),
            "outbox from {version}"
        );
    }
}

/// Version 15 added `touched` to rows that existed: it reads 0, the value of an output nothing
/// touched, not the default of a new column (ADR 0048 drops the oldest touched reward at the cap).
#[test]
fn an_output_of_a_version_14_store_reads_untouched_after_the_upgrade() {
    let (_dir, path) = frozen_database(14);
    let conn = Connection::open(&path).unwrap();
    assert!(
        conn.prepare("SELECT touched FROM outputs").is_err(),
        "the frozen schema 14 has no touched column"
    );
    let outputs: i64 = conn
        .query_row("SELECT COUNT(*) FROM outputs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(outputs, 3);
    drop(conn);

    drop(SqliteStore::open(&path, key(), crate::AtRest::Plain).unwrap());
    let conn = Connection::open(&path).unwrap();
    let touched: Vec<i64> = conn
        .prepare("SELECT touched FROM outputs ORDER BY commitment")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(touched, [0, 0, 0]);
}

/// Version 7 kept these settings as text. The step to version 8 alone moves each one that
/// decodes into its table and drops the rest, so a setting only the step itself could move is
/// checked here: running every later step too would hide a step that moved nothing.
#[test]
fn the_step_to_version_8_moves_what_decodes_and_drops_the_rest() {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate_to(&mut conn, 7, &key()).unwrap();
    let c1 = "081111111111111111111111111111111111111111111111111111111111111111";
    let c2 = "092222222222222222222222222222222222222222222222222222222222222222";
    let c3 = "0a3333333333333333333333333333333333333333333333333333333333333333";
    let c1_short = &c1[..64];
    conn.execute_batch(&format!(
        "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);
         INSERT INTO transactions (id, account, direction, state, amount_credited,
             amount_debited, created_at, updated_at)
         VALUES (1, 0, 'outgoing', 'sent', 0, 5, 1, 1),
                (2, 0, 'outgoing', 'sent', 0, 5, 1, 1),
                (3, 0, 'incoming', 'confirmed', 5, 0, 1, 1),
                (4, 0, 'incoming', 'confirmed', 5, 0, 1, 1),
                (5, 0, 'incoming', 'confirmed', 5, 0, 1, 1);
         INSERT INTO settings (key, value) VALUES
             ('network', 'floonet'),
             ('release.kernel_absent.1', '77'),
             ('send.local_cutoff.+2', '9'),
             ('send.local_cutoff.', '9'),
             ('release.released.2', '{c1} 90 1530 {c2}:0300000007000000000000000000000000:5 {c3}:0300000007000000000000000000000000:6 {c1}:0300000007000000000000000000000000:7'),
             ('release.released.3', '{c1} 90 1530'),
             ('release.late.4', '{c1}ff 40 50'),
             ('release.late.5', '{c1_short} 40 50'),
             ('tx.other_wallet.3',
              '{{\"spent\":[\"{c1}\",\"{c2}\",\"{c3}\"],\"change\":[\"{c3}\",\"{c2}\",\"{c1}\"],\"after\":10,\"to\":20}}'),
             ('scan.found.4', 'rescan block'),
             ('scan.found.5', 'restore scan');"
    ))
    .unwrap();

    migrate_to(&mut conn, 8, &key()).unwrap();

    let rows = |sql: &str| -> Vec<String> {
        let mut statement = conn.prepare(sql).unwrap();
        statement
            .query_map([], |row| {
                let columns = row.as_ref().column_count();
                Ok((0..columns)
                    .map(|index| {
                        format!("{:?}", row.get::<_, rusqlite::types::Value>(index).unwrap())
                    })
                    .collect::<Vec<_>>()
                    .join(","))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(
        rows("SELECT tx_id, kernel_absent_at, local_cutoff FROM tx_marks ORDER BY tx_id"),
        ["Integer(1),Integer(77),Null"],
        "a valid mark moves; a transaction id that is not plain digits does not match"
    );
    assert_eq!(
        rows("SELECT tx_id, phase FROM tx_watch ORDER BY tx_id"),
        ["Integer(2),Text(\"kernel\")", "Integer(3),Text(\"kernel\")"],
        "an excess that is not 33 hex bytes is dropped"
    );
    assert_eq!(
        rows("SELECT tx_id, position, amount FROM tx_watch_outputs ORDER BY tx_id, position"),
        [
            "Integer(2),Integer(0),Integer(5)",
            "Integer(2),Integer(1),Integer(6)",
            "Integer(2),Integer(2),Integer(7)"
        ],
    );
    assert_eq!(
        rows(
            "SELECT role, position, hex(commitment) FROM other_wallet_outputs ORDER BY role, position"
        ),
        [
            format!(
                "Text(\"change\"),Integer(0),Text(\"{}\")",
                c3.to_uppercase()
            ),
            format!(
                "Text(\"change\"),Integer(1),Text(\"{}\")",
                c2.to_uppercase()
            ),
            format!(
                "Text(\"change\"),Integer(2),Text(\"{}\")",
                c1.to_uppercase()
            ),
            format!("Text(\"spent\"),Integer(0),Text(\"{}\")", c1.to_uppercase()),
            format!("Text(\"spent\"),Integer(1),Text(\"{}\")", c2.to_uppercase()),
            format!("Text(\"spent\"),Integer(2),Text(\"{}\")", c3.to_uppercase()),
        ],
    );
    assert_eq!(
        rows("SELECT tx_id, during, dated_by_block FROM scan_found ORDER BY tx_id"),
        [
            "Integer(4),Text(\"rescan\"),Integer(1)",
            "Integer(5),Text(\"restore\"),Integer(0)"
        ],
    );
    assert_eq!(
        rows("SELECT key FROM settings"),
        ["Text(\"network\")"],
        "the step itself deletes every moved setting"
    );
}

/// A step that fails part-way through an upgrade must undo the steps before it: the version and
/// every row read as they did before the upgrade began.
#[test]
fn a_failing_step_leaves_the_version_and_the_rows_unchanged() {
    let (_dir, path) = frozen_database(14);
    let mut conn = Connection::open(&path).unwrap();
    // Version 18 creates this table, so the step to 18 fails after 14 to 17 ran.
    conn.execute_batch("CREATE TABLE watch_set (blocker INTEGER)")
        .unwrap();
    let before = dump(&conn);

    let result = migrate_to(&mut conn, SCHEMA_VERSION, &key());

    assert!(matches!(result, Err(StoreError::Database(_))), "{result:?}");
    assert_eq!(stored_version(&conn).unwrap(), 14);
    assert_eq!(dump(&conn), before, "an earlier step was kept");
}

#[test]
fn a_target_past_the_last_migration_is_refused_and_changes_nothing() {
    let (_dir, path) = frozen_database(14);
    let mut conn = Connection::open(&path).unwrap();
    let before = dump(&conn);

    let result = migrate_to(&mut conn, SCHEMA_VERSION + 1, &key());

    assert!(
        matches!(
            result,
            Err(StoreError::SchemaTooNew { found, supported })
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ),
        "{result:?}"
    );
    assert_eq!(stored_version(&conn).unwrap(), 14);
    assert_eq!(
        dump(&conn),
        before,
        "the steps before the missing one were kept"
    );
}

#[test]
fn opening_a_database_of_a_newer_schema_is_refused_and_keeps_its_rows() {
    let (_dir, path) = frozen_database(SCHEMA_VERSION);
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE schema_version SET version = ?1 WHERE id = 1",
        [SCHEMA_VERSION + 1],
    )
    .unwrap();
    let before = dump(&conn);
    drop(conn);

    let result = SqliteStore::open(&path, key(), crate::AtRest::Plain);

    assert!(
        matches!(
            result,
            Err(StoreError::SchemaTooNew { found, supported })
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ),
        "{:?}",
        result.err()
    );
    let conn = Connection::open(&path).unwrap();
    assert_eq!(stored_version(&conn).unwrap(), SCHEMA_VERSION + 1);
    assert_eq!(dump(&conn), before);
}
