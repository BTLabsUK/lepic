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
use crate::context::{ContextKey, StoreKeys};
use crate::error::StoreError;
use crate::invoice::{InvoiceAddressIndex, PendingInvoice, PendingInvoiceStatus};
use crate::output::KeyId;
use crate::peer::{PeerCompat, PeerTagKey};
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
    let (compat, index) = store
        .read(|repos| {
            Ok::<_, StoreError>((repos.peer_compat("key")?, repos.invoice_address_index()?))
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
        compat,
        Some(PeerCompat {
            last_unmarked_at: Some(Timestamp::from_nanosecond(8).unwrap()),
            ..PeerCompat::default()
        }),
        "a returned invoice is an unmarked answer"
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
    let at = |second| Some(Timestamp::from_second(second).unwrap());
    let (peers, marks) = store
        .read(|repos| {
            Ok::<_, StoreError>((
                [
                    repos.peer_compat("lepic-key")?,
                    repos.peer_compat("stock-key")?,
                    repos.peer_compat("odd-key")?,
                ],
                repos.tx_marks(TxId(1))?,
            ))
        })
        .unwrap();
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
        seed: "",
        check: check_v13_seed,
    },
];

const V16_SEED: &str = "INSERT INTO peer_pins (account, origin, seal_key, first_seen, last_seen)
    VALUES (0, 'https://wallet.example:443', X'0707070707070707070707070707070707070707070707070707070707070707', 5, 6);";

/// A v16 database keeps its pin and gains empty, usable event and request tables.
fn check_v16_seed(store: &SqliteStore) {
    let pin = store
        .read(|repos| repos.peer_pin(AccountIndex(0), "https://wallet.example:443"))
        .unwrap()
        .unwrap();
    assert_eq!(pin.seal_key, [7; 32]);
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
        if object.0 == "index" {
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
    for (table, rows) in &after.tables {
        if !before.tables.contains_key(table) {
            assert!(rows.is_empty(), "the new table {table} starts empty");
        }
    }
    assert_eq!(stored_version(&conn).unwrap(), SCHEMA_VERSION);
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
