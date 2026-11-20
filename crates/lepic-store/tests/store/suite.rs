// SPDX-License-Identifier: Apache-2.0
//! One behavioural suite, run against the SQLite and the in-memory store.

// Test code may unwrap, index and use plain arithmetic (docs/rules.md); clippy's test
// exemptions do not reach helpers outside `#[test]` functions.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_store::{
    AccountIndex, AccountRecord, ApiRequest, CONTACT_SLOT_COUNT, ChainCheck, ContactCap,
    ContactState, DomainClaimBytes, FoundDuring, ImportSummary, ImportedKind, ImportedMessage,
    ImportedOutput, ImportedOutputStatus, ImportedTransaction, InboxEntry, InboxStatus, InvoiceCap,
    KeyId, MAX_CANCELLED_PAIRINGS, MAX_CONTACTS, MAX_IMPORTED_MESSAGE_BYTES, MAX_PARKED_INVOICES,
    MAX_PARKED_INVOICES_PER_SENDER, MAX_PENDING_PAIRINGS, OpenReceipt, OtherWalletSpend,
    OutboxEntry, OutboxId, OutboxStatus, OutputStatus, PRIVATE_SLOT_END, PairingEndReason,
    PairingFacts, PairingId, PairingState, ParticipantId, PeerCard, PendingInvoiceStatus,
    PrivateContext, Record, Repositories, ScanFoundRecord, SealMode, SlateStage, StoreError,
    TransactionEntry, TxDirection, TxId, TxMarks, TxState, TxWatch, WalletStore, WatchPhase,
    WatchedOutput, export_contacts, import_contacts,
};
use lepic_store::{
    CopyState, MAX_ALIAS_LEN, MAX_KEY_REF_LEN, MAX_NODE_ERROR_LEN, MAX_RECOVERY_ERROR_LEN,
    MAX_RELAY_LEN, MailClass, NativeOutboxEntry, NativeOutboxId, NodeOutcome, NodePost, OutboxCopy,
    OutboxState, PaymentDelivery, Recovery, RecoveryState, StoredNativeOutbox, StoredOutboxCopy,
    WatchRow,
};
use uuid::Uuid;

use support::{
    Backend, account, contact, contact_id, contact_mailbox, context_key, invoice, invoice_id,
    output, pairing, peer_card, slate, transaction,
};

const DEFAULT: AccountIndex = AccountIndex(0);
const SLATE_A: Uuid = Uuid::from_bytes([0xa1; 16]);
const SLATE_B: Uuid = Uuid::from_bytes([0xb2; 16]);

fn write<S: WalletStore, R>(
    store: &S,
    operation: impl FnOnce(&mut dyn Repositories) -> Result<R, StoreError>,
) -> Result<R, StoreError> {
    store.write(operation)
}

fn read<S: WalletStore, R>(
    store: &S,
    operation: impl FnOnce(&dyn Repositories) -> Result<R, StoreError>,
) -> Result<R, StoreError> {
    store.read(operation)
}

fn with_default_account<B: Backend>() -> B {
    let backend = B::create(context_key(1));
    write(backend.store(), |repos| {
        repos.put_account(&account(0, "default"))
    })
    .unwrap();
    backend
}

fn accounts_round_trip_in_index_order<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        repos.put_account(&account(5, "savings"))?;
        repos.put_account(&account(0, "default"))
    })
    .unwrap();
    let (all, by_label, by_index, missing) = read(store, |repos| {
        Ok((
            repos.accounts()?,
            repos.account_by_label("savings")?,
            repos.account(AccountIndex(0))?,
            repos.account(AccountIndex(9))?,
        ))
    })
    .unwrap();
    assert_eq!(all, vec![account(0, "default"), account(5, "savings")]);
    assert_eq!(by_label, Some(account(5, "savings")));
    assert_eq!(by_index, Some(account(0, "default")));
    assert_eq!(missing, None);
}

fn put_account_replaces_label_and_child_counter<B: Backend>() {
    let backend = with_default_account::<B>();
    let updated = AccountRecord {
        index: DEFAULT,
        label: "main".to_owned(),
        next_child: 7,
    };
    write(backend.store(), |repos| repos.put_account(&updated)).unwrap();
    let all = read(backend.store(), |repos| repos.accounts()).unwrap();
    assert_eq!(all, vec![updated]);
}

fn rejects_label_used_by_another_account<B: Backend>() {
    let backend = with_default_account::<B>();
    let result = write(backend.store(), |repos| {
        repos.put_account(&account(1, "default"))
    });
    assert!(matches!(result, Err(StoreError::LabelTaken)));
}

fn outputs_round_trip_and_filter_by_account_and_status<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let unspent = output(0, DEFAULT, OutputStatus::Unspent);
    let mut locked = output(1, DEFAULT, OutputStatus::Locked);
    locked.id.features = OutputFeatures::Coinbase;
    locked.amount = Amount::new(u64::MAX);
    locked.mmr_index = Some(u64::MAX);
    locked.lock_height = Height::new(1_440);
    let other_account = output(2, AccountIndex(1), OutputStatus::Unspent);
    write(store, |repos| {
        repos.put_account(&account(1, "other"))?;
        repos.put_output(&locked)?;
        repos.put_output(&unspent)?;
        repos.put_output(&other_account)
    })
    .unwrap();

    let (all, only_locked, fetched, missing) = read(store, |repos| {
        Ok((
            repos.outputs(DEFAULT, None)?,
            repos.outputs(DEFAULT, Some(OutputStatus::Locked))?,
            repos.output(locked.commitment())?,
            repos.output(&[0; 33])?,
        ))
    })
    .unwrap();
    let mut expected = vec![unspent, locked.clone()];
    expected.sort_by_key(|output| *output.commitment());
    assert_eq!(all, expected);
    assert_eq!(only_locked, vec![locked.clone()]);
    assert_eq!(fetched, Some(locked));
    assert_eq!(missing, None);
}

fn insert_output_refuses_a_stored_commitment_and_keeps_it<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let stored = output(0, DEFAULT, OutputStatus::Unspent);
    write(store, |repos| repos.insert_output(&stored)).unwrap();
    let mut again = stored.clone();
    again.status = OutputStatus::Unconfirmed;
    again.amount = Amount::new(1);

    let result = write(store, |repos| repos.insert_output(&again));

    assert!(matches!(
        result,
        Err(StoreError::Duplicate {
            record: Record::Output
        })
    ));
    let kept = read(store, |repos| repos.output(stored.commitment())).unwrap();
    assert_eq!(kept, Some(stored));
}

fn put_output_replaces_and_delete_removes<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let mut record = output(0, DEFAULT, OutputStatus::Unconfirmed);
    write(store, |repos| repos.put_output(&record)).unwrap();
    record.status = OutputStatus::Spent;
    record.height = Height::new(99);
    write(store, |repos| repos.put_output(&record)).unwrap();
    assert_eq!(
        read(store, |repos| repos.output(record.commitment())).unwrap(),
        Some(record.clone())
    );
    write(store, |repos| {
        repos.delete_output(record.commitment())?;
        repos.delete_output(record.commitment())
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.output(record.commitment())).unwrap(),
        None
    );
}

fn rejects_output_for_unknown_account_or_transaction<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let unknown_account = output(0, AccountIndex(3), OutputStatus::Unspent);
    assert!(matches!(
        write(store, |repos| repos.put_output(&unknown_account)),
        Err(StoreError::UnknownAccount(AccountIndex(3)))
    ));
    let mut unknown_tx = output(0, DEFAULT, OutputStatus::Unspent);
    unknown_tx.tx = Some(TxId(4));
    assert!(matches!(
        write(store, |repos| repos.put_output(&unknown_tx)),
        Err(StoreError::UnknownTransaction(TxId(4)))
    ));
}

fn outputs_by_touch_lists_the_least_recently_touched_first<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let first = output(0, DEFAULT, OutputStatus::Unconfirmed);
    let second = output(1, DEFAULT, OutputStatus::Unconfirmed);
    let never = output(2, DEFAULT, OutputStatus::Unconfirmed);
    write(store, |repos| {
        for record in [&first, &second, &never] {
            repos.put_output(record)?;
        }
        repos.touch_output(first.commitment())?;
        repos.touch_output(second.commitment())?;
        repos.touch_output(first.commitment())?;
        // Storing the output again leaves its place.
        repos.put_output(&second)?;
        repos.touch_output(&[9; 33])
    })
    .unwrap();
    let listed = read(store, |repos| {
        repos.outputs_by_touch(OutputStatus::Unconfirmed)
    })
    .unwrap();
    assert_eq!(listed, [never.clone(), second.clone(), first.clone()]);
    let other = read(store, |repos| repos.outputs_by_touch(OutputStatus::Unspent)).unwrap();
    assert!(other.is_empty());

    write(store, |repos| repos.delete_output(first.commitment())).unwrap();
    let left = read(store, |repos| {
        repos.outputs_by_touch(OutputStatus::Unconfirmed)
    })
    .unwrap();
    assert_eq!(left, [never, second]);
}

fn outputs_of_transaction_lists_linked_outputs<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let (tx, linked) = write(store, |repos| {
        let tx = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?;
        let mut linked = output(0, DEFAULT, OutputStatus::Locked);
        linked.tx = Some(tx);
        repos.put_output(&linked)?;
        repos.put_output(&output(1, DEFAULT, OutputStatus::Unspent))?;
        Ok((tx, linked))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.outputs_of_transaction(tx)).unwrap(),
        vec![linked]
    );
}

fn transactions_get_sequential_ids_and_round_trip<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let first = transaction(DEFAULT, Some(SLATE_A));
    let mut second = transaction(DEFAULT, None);
    second.direction = TxDirection::Incoming;
    second.fee = None;
    second.transport = None;
    second.amount_credited = Amount::new(u64::MAX);
    let ids = write(store, |repos| {
        Ok((
            repos.insert_transaction(&first)?,
            repos.insert_transaction(&second)?,
        ))
    })
    .unwrap();
    assert_eq!(ids, (TxId(1), TxId(2)));
    let (listed, fetched, by_slate) = read(store, |repos| {
        Ok((
            repos.transactions(DEFAULT)?,
            repos.transaction(TxId(2))?,
            repos.transaction_by_slate(SLATE_A, TxDirection::Outgoing)?,
        ))
    })
    .unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|stored| (stored.id, &stored.entry))
            .collect::<Vec<_>>(),
        vec![(TxId(1), &first), (TxId(2), &second)]
    );
    assert_eq!(fetched, Some(second));
    assert_eq!(
        by_slate.map(|stored| (stored.id, stored.entry)),
        Some((TxId(1), first))
    );
}

fn a_deleted_transactions_id_is_never_handed_out_again<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let entry = transaction(DEFAULT, None);
    let newest = write(store, |repos| {
        repos.insert_transaction(&entry)?;
        repos.insert_transaction(&entry)
    })
    .unwrap();
    assert_eq!(newest, TxId(2));

    let next = write(store, |repos| {
        repos.delete_transaction(newest)?;
        repos.insert_transaction(&entry)
    })
    .unwrap();

    assert_eq!(next, TxId(3));
}

fn update_transaction_replaces_entry<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let mut entry = transaction(DEFAULT, Some(SLATE_A));
    let id = write(store, |repos| repos.insert_transaction(&entry)).unwrap();
    entry.state = TxState::Finalized;
    entry.updated_at = Timestamp::from_nanosecond(1_800_000_000_000_000_001).unwrap();
    write(store, |repos| repos.update_transaction(id, &entry)).unwrap();
    assert_eq!(
        read(store, |repos| repos.transaction(id)).unwrap(),
        Some(entry.clone())
    );
    assert!(matches!(
        write(store, |repos| repos.update_transaction(TxId(77), &entry)),
        Err(StoreError::NotFound {
            record: Record::Transaction
        })
    ));
}

fn slate_id_is_unique_per_direction<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let outgoing = transaction(DEFAULT, Some(SLATE_A));
    let mut incoming = outgoing.clone();
    incoming.direction = TxDirection::Incoming;
    write(store, |repos| {
        repos.insert_transaction(&outgoing)?;
        repos.insert_transaction(&incoming)
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos.insert_transaction(&outgoing)),
        Err(StoreError::Duplicate {
            record: Record::Transaction
        })
    ));
    let other = write(store, |repos| {
        repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_B)))
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos.update_transaction(other, &outgoing)),
        Err(StoreError::Duplicate {
            record: Record::Transaction
        })
    ));
}

fn rejects_transaction_for_unknown_account<B: Backend>() {
    let backend = with_default_account::<B>();
    assert!(matches!(
        write(backend.store(), |repos| {
            repos.insert_transaction(&transaction(AccountIndex(8), None))
        }),
        Err(StoreError::UnknownAccount(AccountIndex(8)))
    ));
}

fn rejects_timestamp_outside_storable_range<B: Backend>() {
    let backend = with_default_account::<B>();
    let mut entry = transaction(DEFAULT, None);
    entry.created_at = Timestamp::MAX;
    assert!(matches!(
        write(backend.store(), |repos| repos.insert_transaction(&entry)),
        Err(StoreError::OutOfRange { .. })
    ));
}

fn slates_are_stored_once_per_stage<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let s2 = slate(SLATE_A, SlateStage::Standard2, b"s2");
    let s1 = slate(SLATE_A, SlateStage::Standard1, b"s1");
    write(store, |repos| {
        repos.insert_slate(&s2)?;
        repos.insert_slate(&s1)?;
        repos.insert_slate(&slate(SLATE_B, SlateStage::Invoice1, b"i1"))
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos.insert_slate(&slate(
            SLATE_A,
            SlateStage::Standard1,
            b"other"
        ))),
        Err(StoreError::Duplicate {
            record: Record::Slate
        })
    ));
    let (stages, lengths, one, missing) = read(store, |repos| {
        Ok((
            repos.slates(SLATE_A)?,
            repos.slate_stages(SLATE_A)?,
            repos.slate(SLATE_A, SlateStage::Standard2)?,
            repos.slate(SLATE_A, SlateStage::Standard3)?,
        ))
    })
    .unwrap();
    assert_eq!(stages, vec![s1, s2.clone()]);
    assert_eq!(
        lengths,
        vec![(SlateStage::Standard1, 2), (SlateStage::Standard2, 2)]
    );
    assert_eq!(one, Some(s2));
    assert_eq!(missing, None);
}

fn contexts_round_trip_replace_and_delete<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        repos.put_context(
            SLATE_A,
            ParticipantId(0),
            &PrivateContext::new(b"first".to_vec()),
        )?;
        repos.put_context(
            SLATE_A,
            ParticipantId(0),
            &PrivateContext::new(b"second".to_vec()),
        )?;
        repos.put_context(
            SLATE_A,
            ParticipantId(1),
            &PrivateContext::new(b"other".to_vec()),
        )
    })
    .unwrap();
    let opened = read(store, |repos| repos.context(SLATE_A, ParticipantId(0))).unwrap();
    assert_eq!(opened.unwrap().expose(), b"second");
    write(store, |repos| {
        repos.delete_context(SLATE_A, ParticipantId(0))
    })
    .unwrap();
    let (deleted, kept) = read(store, |repos| {
        Ok((
            repos.context(SLATE_A, ParticipantId(0))?,
            repos.context(SLATE_A, ParticipantId(1))?,
        ))
    })
    .unwrap();
    assert!(deleted.is_none());
    assert_eq!(kept.unwrap().expose(), b"other");
}

fn private_contexts_cannot_be_read_without_the_key<B: Backend>() {
    let backend = B::create(context_key(1));
    write(backend.store(), |repos| {
        repos.put_context(
            SLATE_A,
            ParticipantId(0),
            &PrivateContext::new(b"blinding".to_vec()),
        )
    })
    .unwrap();

    let wrong_key = backend.reopen(context_key(2));
    assert!(matches!(
        read(&wrong_key, |repos| repos.context(SLATE_A, ParticipantId(0))),
        Err(StoreError::ContextUndecryptable)
    ));

    let right_key = backend.reopen(context_key(1));
    let opened = read(&right_key, |repos| repos.context(SLATE_A, ParticipantId(0))).unwrap();
    assert_eq!(opened.unwrap().expose(), b"blinding");
}

fn inbox_entries_are_replaced_by_message_id<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let received = InboxEntry {
        msg_id: "relay-message-1".to_owned(),
        status: InboxStatus::Received,
        received_at: support::time(10),
        updated_at: support::time(10),
    };
    let acknowledged = InboxEntry {
        status: InboxStatus::Acknowledged,
        updated_at: support::time(20),
        ..received.clone()
    };
    write(store, |repos| {
        repos.put_inbox(&received)?;
        repos.put_inbox(&acknowledged)
    })
    .unwrap();
    let (found, missing) = read(store, |repos| {
        Ok((repos.inbox("relay-message-1")?, repos.inbox("unknown")?))
    })
    .unwrap();
    assert_eq!(found, Some(acknowledged));
    assert_eq!(missing, None);
}

fn outbox_entries_are_queued_updated_and_deleted<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let pending = OutboxEntry {
        transport: "epicbox".to_owned(),
        destination: "peer-address".to_owned(),
        slate_id: SLATE_A,
        stage: SlateStage::Standard2,
        status: OutboxStatus::Pending,
        attempts: 0,
        created_at: support::time(1),
        updated_at: support::time(1),
    };
    let ids = write(store, |repos| {
        Ok((
            repos.enqueue_outbox(&pending)?,
            repos.enqueue_outbox(&pending)?,
        ))
    })
    .unwrap();
    assert_eq!(ids, (OutboxId(1), OutboxId(2)));

    let delivered = OutboxEntry {
        status: OutboxStatus::Delivered,
        attempts: 1,
        updated_at: support::time(2),
        ..pending.clone()
    };
    write(store, |repos| repos.update_outbox(OutboxId(1), &delivered)).unwrap();
    let (still_pending, done) = read(store, |repos| {
        Ok((
            repos.outbox(OutboxStatus::Pending)?,
            repos.outbox(OutboxStatus::Delivered)?,
        ))
    })
    .unwrap();
    assert_eq!(
        still_pending
            .into_iter()
            .map(|stored| (stored.id, stored.entry))
            .collect::<Vec<_>>(),
        vec![(OutboxId(2), pending.clone())]
    );
    assert_eq!(
        done.into_iter()
            .map(|stored| (stored.id, stored.entry))
            .collect::<Vec<_>>(),
        vec![(OutboxId(1), delivered.clone())]
    );
    let other = OutboxEntry {
        slate_id: SLATE_B,
        ..pending.clone()
    };
    let other_id = write(store, |repos| repos.enqueue_outbox(&other)).unwrap();
    let (of_a, of_b) = read(store, |repos| {
        Ok((
            repos.outbox_of_slate(SLATE_A)?,
            repos.outbox_of_slate(SLATE_B)?,
        ))
    })
    .unwrap();
    assert_eq!(
        of_a.into_iter()
            .map(|stored| (stored.id, stored.entry))
            .collect::<Vec<_>>(),
        vec![
            (OutboxId(1), delivered.clone()),
            (OutboxId(2), pending.clone())
        ]
    );
    assert_eq!(
        of_b.into_iter().map(|stored| stored.id).collect::<Vec<_>>(),
        vec![other_id]
    );

    write(store, |repos| repos.delete_outbox(OutboxId(1))).unwrap();
    assert!(
        read(store, |repos| repos.outbox(OutboxStatus::Delivered))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        write(store, |repos| repos.update_outbox(OutboxId(1), &delivered)),
        Err(StoreError::NotFound {
            record: Record::OutboxMessage
        })
    ));
}

fn settings_are_replaced_and_deleted<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        repos.put_setting("node_url", "http://127.0.0.1:3413")?;
        repos.put_setting("node_url", "http://127.0.0.1:13413")
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.setting("node_url"))
            .unwrap()
            .as_deref(),
        Some("http://127.0.0.1:13413")
    );
    write(store, |repos| repos.delete_setting("node_url")).unwrap();
    assert_eq!(
        read(store, |repos| repos.setting("node_url")).unwrap(),
        None
    );
    write(store, |repos| {
        repos.put_setting("held.b", "2")?;
        repos.put_setting("held.a", "1")?;
        repos.put_setting("held", "0")?;
        repos.put_setting("helm.a", "3")?;
        // The first key past the prefix, a key that goes on past ASCII, and a prefix that ends
        // past ASCII.
        repos.put_setting("held/", "4")?;
        repos.put_setting("held.\u{e9}", "5")?;
        repos.put_setting("h\u{e9}.a", "6")
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.settings_with_prefix("held.")).unwrap(),
        vec![
            ("held.a".to_owned(), "1".to_owned()),
            ("held.b".to_owned(), "2".to_owned()),
            ("held.\u{e9}".to_owned(), "5".to_owned()),
        ]
    );
    assert_eq!(
        read(store, |repos| repos.settings_with_prefix("h\u{e9}")).unwrap(),
        vec![("h\u{e9}.a".to_owned(), "6".to_owned())]
    );
}

#[derive(Debug)]
enum EngineError {
    Store(StoreError),
    Rejected,
}

impl From<StoreError> for EngineError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

fn failed_write_leaves_every_repository_unchanged<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let result: Result<(), EngineError> = store.write(|repos| {
        repos.put_account(&account(1, "second"))?;
        let tx = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?;
        let mut locked = output(0, DEFAULT, OutputStatus::Locked);
        locked.tx = Some(tx);
        repos.put_output(&locked)?;
        repos.insert_slate(&slate(SLATE_A, SlateStage::Standard1, b"s1"))?;
        repos.put_context(
            SLATE_A,
            ParticipantId(0),
            &PrivateContext::new(b"ctx".to_vec()),
        )?;
        repos.put_setting("key", "value")?;
        repos.put_inbox(&InboxEntry {
            msg_id: "m".to_owned(),
            status: InboxStatus::Processed,
            received_at: support::time(1),
            updated_at: support::time(1),
        })?;
        repos.park_invoice(&invoice(SLATE_B, 1, 1))?;
        repos.put_contact(&contact(1, 1))?;
        Err(EngineError::Rejected)
    });
    assert!(matches!(result, Err(EngineError::Rejected)));

    let empty = read(store, |repos| {
        Ok(repos.accounts()? == vec![account(0, "default")]
            && repos.transactions(DEFAULT)?.is_empty()
            && repos.outputs(DEFAULT, None)?.is_empty()
            && repos.slates(SLATE_A)?.is_empty()
            && repos.context(SLATE_A, ParticipantId(0))?.is_none()
            && repos.setting("key")?.is_none()
            && repos.inbox("m")?.is_none()
            && repos.pending_invoices()?.is_empty()
            && repos.contacts()?.is_empty())
    })
    .unwrap();
    assert!(empty);
}

fn store_error_inside_write_rolls_back_earlier_changes<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let result: Result<(), EngineError> = store.write(|repos| {
        repos.put_setting("key", "value")?;
        repos.put_account(&account(1, "default"))?;
        Ok(())
    });
    assert!(matches!(
        result,
        Err(EngineError::Store(StoreError::LabelTaken))
    ));
    assert_eq!(read(store, |repos| repos.setting("key")).unwrap(), None);
}

fn write_sees_its_own_changes_and_commits_them_together<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let seen = write(store, |repos| {
        let tx = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?;
        repos.insert_slate(&slate(SLATE_A, SlateStage::Standard1, b"s1"))?;
        repos.put_context(
            SLATE_A,
            ParticipantId(0),
            &PrivateContext::new(b"ctx".to_vec()),
        )?;
        Ok(repos.transaction(tx)?.is_some()
            && repos.slate(SLATE_A, SlateStage::Standard1)?.is_some())
    })
    .unwrap();
    assert!(seen);
    let stored = read(store, |repos| {
        Ok(repos
            .transaction_by_slate(SLATE_A, TxDirection::Outgoing)?
            .is_some()
            && repos.slates(SLATE_A)?.len() == 1
            && repos.context(SLATE_A, ParticipantId(0))?.is_some())
    })
    .unwrap();
    assert!(stored);
}

fn fee_and_amount_extremes_round_trip<B: Backend>() {
    let backend = with_default_account::<B>();
    let mut entry = transaction(DEFAULT, None);
    entry.amount_debited = Amount::new(u64::MAX);
    entry.fee = Some(Fee::new(u64::MAX));
    let id = write(backend.store(), |repos| repos.insert_transaction(&entry)).unwrap();
    assert_eq!(
        read(backend.store(), |repos| repos.transaction(id)).unwrap(),
        Some(entry)
    );
}

fn confirmed_height_is_recorded_and_survives_updates<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let mut entry = transaction(DEFAULT, Some(SLATE_A));
    let id = write(store, |repos| repos.insert_transaction(&entry)).unwrap();
    assert_eq!(
        read(store, |repos| repos.confirmed_height(id)).unwrap(),
        None
    );
    write(store, |repos| {
        repos.set_confirmed_height(id, Height::new(10))?;
        repos.set_confirmed_height(id, Height::new(u64::MAX))
    })
    .unwrap();
    entry.state = TxState::Confirmed;
    write(store, |repos| repos.update_transaction(id, &entry)).unwrap();
    assert_eq!(
        read(store, |repos| repos.confirmed_height(id)).unwrap(),
        Some(Height::new(u64::MAX))
    );
    assert!(matches!(
        write(store, |repos| repos
            .set_confirmed_height(TxId(9), Height::new(1))),
        Err(StoreError::UnknownTransaction(TxId(9)))
    ));
    assert_eq!(
        read(store, |repos| repos.confirmed_height(TxId(9))).unwrap(),
        None
    );
}

fn confirmed_from_lists_recent_confirmations_and_a_cleared_height_drops_out<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let mut confirmed = transaction(DEFAULT, Some(SLATE_A));
    confirmed.state = TxState::Confirmed;
    let open = transaction(DEFAULT, Some(SLATE_B));
    let (old, recent, high) = write(store, |repos| {
        let old = repos.insert_transaction(&confirmed)?;
        let recent = repos.insert_transaction(&TransactionEntry {
            slate_id: None,
            ..confirmed.clone()
        })?;
        let high = repos.insert_transaction(&TransactionEntry {
            slate_id: None,
            ..confirmed.clone()
        })?;
        let waiting = repos.insert_transaction(&open)?;
        repos.set_confirmed_height(old, Height::new(99))?;
        repos.set_confirmed_height(recent, Height::new(100))?;
        repos.set_confirmed_height(high, Height::new(u64::MAX))?;
        repos.set_confirmed_height(waiting, Height::new(150))?;
        Ok((old, recent, high))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.confirmed_from(Height::new(100))).unwrap(),
        vec![(recent, Height::new(100)), (high, Height::new(u64::MAX))],
        "only confirmed entries at or above the height"
    );

    write(store, |repos| repos.clear_confirmed_height(recent)).unwrap();
    assert_eq!(
        read(store, |repos| repos.confirmed_height(recent)).unwrap(),
        None
    );
    assert_eq!(
        read(store, |repos| repos.confirmed_from(Height::ZERO)).unwrap(),
        vec![(old, Height::new(99)), (high, Height::new(u64::MAX))]
    );
    assert!(matches!(
        write(store, |repos| repos.clear_confirmed_height(TxId(99))),
        Err(StoreError::UnknownTransaction(TxId(99)))
    ));
}

fn counterparty_is_recorded_and_survives_updates<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let mut entry = transaction(DEFAULT, Some(SLATE_A));
    let id = write(store, |repos| repos.insert_transaction(&entry)).unwrap();
    assert_eq!(read(store, |repos| repos.counterparty(id)).unwrap(), None);
    write(store, |repos| {
        repos.set_counterparty(id, "first@relay")?;
        repos.set_counterparty(id, "second@relay")
    })
    .unwrap();
    entry.state = TxState::Confirmed;
    write(store, |repos| repos.update_transaction(id, &entry)).unwrap();
    assert_eq!(
        read(store, |repos| repos.counterparty(id))
            .unwrap()
            .as_deref(),
        Some("second@relay")
    );
    assert!(matches!(
        write(store, |repos| repos.set_counterparty(TxId(9), "x@relay")),
        Err(StoreError::UnknownTransaction(TxId(9)))
    ));
    assert_eq!(
        read(store, |repos| repos.counterparty(TxId(9))).unwrap(),
        None
    );
}

fn receive_listing_is_recorded_and_survives_updates<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let mut entry = transaction(DEFAULT, Some(SLATE_A));
    let id = write(store, |repos| repos.insert_transaction(&entry)).unwrap();
    assert_eq!(
        read(store, |repos| repos.receive_listing(id)).unwrap(),
        None
    );
    let listing = lepic_store::ReceiveListing {
        service_key: [2; 33],
        generation: u32::MAX,
    };
    write(store, |repos| repos.set_receive_listing(id, &listing)).unwrap();
    entry.state = TxState::Confirmed;
    write(store, |repos| repos.update_transaction(id, &entry)).unwrap();
    assert_eq!(
        read(store, |repos| repos.receive_listing(id)).unwrap(),
        Some(listing)
    );
    assert!(matches!(
        write(store, |repos| repos.set_receive_listing(TxId(9), &listing)),
        Err(StoreError::UnknownTransaction(TxId(9)))
    ));
}

fn open_receipts_lists_answered_incoming_payments_oldest_first<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let incoming = |slate_id: Uuid, transport: &str| TransactionEntry {
        direction: TxDirection::Incoming,
        state: TxState::Received,
        transport: Some(transport.to_owned()),
        ..transaction(DEFAULT, Some(slate_id))
    };
    let invoice = Uuid::from_bytes([0xc3; 16]);
    let by_file = Uuid::from_bytes([0xd4; 16]);
    let (first, second) = write(store, |repos| {
        let first = repos.insert_transaction(&incoming(SLATE_A, "epicbox"))?;
        repos.set_counterparty(first, "key-a@relay")?;
        repos.insert_slate(&slate(SLATE_A, SlateStage::Standard2, b"s2"))?;
        let second = repos.insert_transaction(&incoming(SLATE_B, "epicbox"))?;
        repos.insert_slate(&slate(SLATE_B, SlateStage::Standard2, b"s2"))?;
        repos.insert_transaction(&incoming(invoice, "epicbox"))?;
        repos.insert_slate(&slate(invoice, SlateStage::Invoice1, b"i1"))?;
        repos.insert_transaction(&incoming(by_file, "file"))?;
        repos.insert_slate(&slate(by_file, SlateStage::Standard2, b"s2"))?;
        Ok((first, second))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.open_receipts("epicbox")).unwrap(),
        vec![
            OpenReceipt {
                id: first,
                counterparty: Some("key-a@relay".to_owned())
            },
            OpenReceipt {
                id: second,
                counterparty: None
            },
        ]
    );
    let mut finalized = incoming(SLATE_A, "epicbox");
    finalized.state = TxState::Posted;
    write(store, |repos| repos.update_transaction(first, &finalized)).unwrap();
    assert_eq!(
        read(store, |repos| repos.open_receipts("epicbox")).unwrap(),
        vec![OpenReceipt {
            id: second,
            counterparty: None
        }]
    );
}

fn transactions_in_state_counts_every_account_and_lists_the_oldest_first<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let second = AccountIndex(1);
    let entry = |account, direction, state, transport: &str, created: i64| TransactionEntry {
        direction,
        state,
        transport: Some(transport.to_owned()),
        created_at: Timestamp::from_second(created).unwrap(),
        ..transaction(account, None)
    };
    let (newest, other_account, same_time, self_send, received) = write(store, |repos| {
        repos.put_account(&account(1, "second"))?;
        let out = TxDirection::Outgoing;
        let newest =
            repos.insert_transaction(&entry(DEFAULT, out, TxState::Sent, "epicbox", 300))?;
        let other_account =
            repos.insert_transaction(&entry(second, out, TxState::Sent, "file", 100))?;
        let same_time =
            repos.insert_transaction(&entry(DEFAULT, out, TxState::Sent, "epicbox", 100))?;
        repos.insert_transaction(&entry(DEFAULT, out, TxState::Confirmed, "epicbox", 50))?;
        let self_send =
            repos.insert_transaction(&entry(DEFAULT, out, TxState::Finalized, "self", 200))?;
        let incoming = TxDirection::Incoming;
        repos.insert_transaction(&entry(second, incoming, TxState::Finalized, "self", 200))?;
        let received =
            repos.insert_transaction(&entry(DEFAULT, incoming, TxState::Finalized, "file", 250))?;
        Ok((newest, other_account, same_time, self_send, received))
    })
    .unwrap();
    let tally = |state, oldest| {
        let tally = read(store, |repos| {
            repos.transactions_in_state(state, "self", oldest)
        })
        .unwrap();
        let ids: Vec<TxId> = tally.oldest.iter().map(|(id, _)| *id).collect();
        (tally.count, ids)
    };
    assert_eq!(tally(TxState::Sent, 2), (3, vec![other_account, same_time]));
    assert_eq!(
        tally(TxState::Sent, 9),
        (3, vec![other_account, same_time, newest])
    );
    assert_eq!(tally(TxState::Sent, 0), (3, vec![]));
    assert_eq!(tally(TxState::Finalized, 9), (2, vec![self_send, received]));
    assert_eq!(tally(TxState::Received, 9), (0, vec![]));
    let first = read(store, |repos| {
        repos.transactions_in_state(TxState::Sent, "self", 1)
    })
    .unwrap();
    assert_eq!(
        first.oldest,
        vec![(other_account, Timestamp::from_second(100).unwrap())]
    );
}

fn transactions_before_walks_newest_first_and_ends_on_a_whole_millisecond<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let at = |milli: i64, nano: i64| {
        Timestamp::from_nanosecond(i128::from(milli * 1_000_000 + nano)).unwrap()
    };
    // Five entries: two share millisecond 30 (at different nanoseconds), then 20, 10, 5.
    let times = [at(5, 0), at(30, 7), at(10, 0), at(30, 900_000), at(20, 0)];
    let ids = write(store, |repos| {
        let mut ids = Vec::new();
        for created in times {
            ids.push(repos.insert_transaction(&TransactionEntry {
                created_at: created,
                ..transaction(DEFAULT, None)
            })?);
        }
        Ok(ids)
    })
    .unwrap();
    let walk = |before: Option<Timestamp>, at_least| {
        read(store, |repos| repos.transactions_before(before, at_least))
            .unwrap()
            .into_iter()
            .map(|stored| stored.id)
            .collect::<Vec<_>>()
    };
    // Newest first; the step asked to hold one entry holds the whole of millisecond 30.
    assert_eq!(walk(None, 1), vec![ids[3], ids[1]]);
    // The next step starts before that millisecond.
    assert_eq!(walk(Some(at(30, 0)), 1), vec![ids[4]]);
    assert_eq!(walk(Some(at(20, 0)), 1), vec![ids[2]]);
    assert_eq!(walk(Some(at(10, 0)), 1), vec![ids[0]]);
    assert_eq!(walk(Some(at(5, 0)), 1), Vec::<TxId>::new());
    // A bigger step ends on a whole millisecond too, and everything fits in a large one.
    assert_eq!(walk(None, 3), vec![ids[3], ids[1], ids[4]]);
    assert_eq!(walk(None, 99), vec![ids[3], ids[1], ids[4], ids[2], ids[0]]);
}

fn delete_transaction_removes_an_unlinked_entry_only<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let (kept, dropped) = write(store, |repos| {
        let kept = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?;
        let dropped = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_B)))?;
        repos.set_confirmed_height(dropped, Height::new(7))?;
        repos.set_counterparty(dropped, "peer@relay")?;
        let mut linked = output(0, DEFAULT, OutputStatus::Unspent);
        linked.tx = Some(kept);
        repos.put_output(&linked)?;
        Ok((kept, dropped))
    })
    .unwrap();

    assert!(matches!(
        write(store, |repos| repos.delete_transaction(kept)),
        Err(StoreError::InUse {
            record: Record::Transaction
        })
    ));
    write(store, |repos| repos.delete_transaction(dropped)).unwrap();
    assert!(matches!(
        write(store, |repos| repos.delete_transaction(dropped)),
        Err(StoreError::UnknownTransaction(id)) if id == dropped
    ));

    let (kept_entry, gone, height, counterparty) = read(store, |repos| {
        Ok((
            repos.transaction(kept)?,
            repos.transaction(dropped)?,
            repos.confirmed_height(dropped)?,
            repos.counterparty(dropped)?,
        ))
    })
    .unwrap();
    assert!(kept_entry.is_some());
    assert_eq!((gone, height, counterparty), (None, None, None));
}

fn pending_invoices_round_trip_oldest_first<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let newest = invoice(invoice_id(1), 1, 30);
    let oldest = invoice(invoice_id(2), 2, 10);
    let mut paid = invoice(invoice_id(3), 1, 20);
    paid.codec = "legacy-v2".to_owned();
    write(store, |repos| {
        repos.park_invoice(&newest)?;
        repos.park_invoice(&oldest)?;
        repos.park_invoice(&paid)?;
        repos.set_pending_invoice_status(paid.slate_id, PendingInvoiceStatus::Paid)
    })
    .unwrap();
    paid.status = PendingInvoiceStatus::Paid;
    let (all, one, missing) = read(store, |repos| {
        Ok((
            repos.pending_invoices()?,
            repos.pending_invoice(invoice_id(3))?,
            repos.pending_invoice(invoice_id(9))?,
        ))
    })
    .unwrap();
    assert_eq!(all, vec![oldest, paid.clone(), newest]);
    assert_eq!(one, Some(paid));
    assert_eq!(missing, None);
}

fn rejects_a_second_invoice_with_the_same_slate_id<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| repos.park_invoice(&invoice(SLATE_A, 1, 1))).unwrap();
    assert!(matches!(
        write(store, |repos| repos.park_invoice(&invoice(SLATE_A, 2, 2))),
        Err(StoreError::Duplicate {
            record: Record::PendingInvoice
        })
    ));
    let kept = read(store, |repos| repos.pending_invoice(SLATE_A)).unwrap();
    assert_eq!(kept, Some(invoice(SLATE_A, 1, 1)));
}

fn pending_invoice_status_changes_and_delete_removes<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        repos.park_invoice(&invoice(SLATE_A, 1, 1))?;
        repos.park_invoice(&invoice(SLATE_B, 1, 2))?;
        repos.set_pending_invoice_status(SLATE_A, PendingInvoiceStatus::Declined)
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.parked_invoice_count()).unwrap(),
        1
    );
    let declined = read(store, |repos| repos.pending_invoice(SLATE_A)).unwrap();
    assert_eq!(
        declined.map(|found| found.status),
        Some(PendingInvoiceStatus::Declined)
    );
    assert!(matches!(
        write(store, |repos| repos.set_pending_invoice_status(
            invoice_id(9),
            PendingInvoiceStatus::Paid
        )),
        Err(StoreError::NotFound {
            record: Record::PendingInvoice
        })
    ));
    write(store, |repos| {
        repos.delete_pending_invoice(SLATE_A)?;
        repos.delete_pending_invoice(SLATE_A)
    })
    .unwrap();
    let left = read(store, |repos| repos.pending_invoices()).unwrap();
    assert_eq!(left, vec![invoice(SLATE_B, 1, 2)]);
}

fn park_invoice_accepts_only_a_parked_invoice<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    for status in [PendingInvoiceStatus::Paid, PendingInvoiceStatus::Declined] {
        let mut settled = invoice(SLATE_A, 1, 1);
        settled.status = status;
        assert!(matches!(
            write(store, |repos| repos.park_invoice(&settled)),
            Err(StoreError::InvalidStatus {
                record: Record::PendingInvoice
            })
        ));
    }
    assert!(
        read(store, |repos| repos.pending_invoices())
            .unwrap()
            .is_empty()
    );
}

fn pending_invoice_status_moves_only_from_parked_to_paid_or_declined<B: Backend>() {
    use PendingInvoiceStatus::{Declined, Paid, Parked};
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        repos.park_invoice(&invoice(SLATE_A, 1, 1))?;
        repos.park_invoice(&invoice(SLATE_B, 1, 2))?;
        repos.set_pending_invoice_status(SLATE_A, Paid)?;
        repos.set_pending_invoice_status(SLATE_B, Declined)
    })
    .unwrap();
    for (slate_id, status) in [
        (SLATE_A, Parked),
        (SLATE_A, Paid),
        (SLATE_A, Declined),
        (SLATE_B, Parked),
        (SLATE_B, Paid),
        (SLATE_B, Declined),
    ] {
        assert!(
            matches!(
                write(store, |repos| repos
                    .set_pending_invoice_status(slate_id, status)),
                Err(StoreError::InvalidStatus {
                    record: Record::PendingInvoice
                })
            ),
            "{slate_id} to {status:?}"
        );
    }
    let statuses: Vec<_> = read(store, |repos| repos.pending_invoices())
        .unwrap()
        .into_iter()
        .map(|kept| kept.status)
        .collect();
    assert_eq!(statuses, vec![Paid, Declined]);
}

fn a_settled_invoice_cannot_return_past_the_per_sender_cap<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let cap = u32::try_from(MAX_PARKED_INVOICES_PER_SENDER).unwrap();
    write(store, |repos| {
        for n in 0..cap {
            repos.park_invoice(&invoice(invoice_id(n), 1, i64::from(n)))?;
        }
        repos.set_pending_invoice_status(invoice_id(0), PendingInvoiceStatus::Paid)?;
        repos.park_invoice(&invoice(invoice_id(cap), 1, 99))
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos.set_pending_invoice_status(
            invoice_id(0),
            PendingInvoiceStatus::Parked
        )),
        Err(StoreError::InvalidStatus {
            record: Record::PendingInvoice
        })
    ));
    let parked = read(store, |repos| repos.pending_invoices())
        .unwrap()
        .into_iter()
        .filter(|kept| kept.status == PendingInvoiceStatus::Parked)
        .count();
    assert_eq!(parked, MAX_PARKED_INVOICES_PER_SENDER);
}

fn parking_stops_at_the_per_sender_cap<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let cap = u32::try_from(MAX_PARKED_INVOICES_PER_SENDER).unwrap();
    write(store, |repos| {
        for n in 0..cap {
            repos.park_invoice(&invoice(invoice_id(n), 1, i64::from(n)))?;
        }
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos.park_invoice(&invoice(
            invoice_id(cap),
            1,
            99
        ))),
        Err(StoreError::InvoiceCapReached {
            cap: InvoiceCap::PerSender
        })
    ));
    assert_eq!(
        read(store, |repos| repos.pending_invoice(invoice_id(cap))).unwrap(),
        None
    );
    // Another sender still has room, and an invoice the user paid no longer counts.
    write(store, |repos| {
        repos.park_invoice(&invoice(invoice_id(cap + 1), 2, 99))?;
        repos.set_pending_invoice_status(invoice_id(0), PendingInvoiceStatus::Paid)?;
        repos.park_invoice(&invoice(invoice_id(cap), 1, 99))
    })
    .unwrap();
    let stored = read(store, |repos| repos.pending_invoices()).unwrap();
    assert_eq!(stored.len(), MAX_PARKED_INVOICES_PER_SENDER + 2);
}

fn parking_stops_at_the_total_cap<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let total = u32::try_from(MAX_PARKED_INVOICES).unwrap();
    let per_sender = u32::try_from(MAX_PARKED_INVOICES_PER_SENDER).unwrap();
    write(store, |repos| {
        for n in 0..total {
            repos.park_invoice(&invoice(invoice_id(n), n / per_sender, i64::from(n)))?;
        }
        Ok(())
    })
    .unwrap();
    let fresh_sender = total;
    assert!(matches!(
        write(store, |repos| repos.park_invoice(&invoice(
            invoice_id(total),
            fresh_sender,
            0
        ))),
        Err(StoreError::InvoiceCapReached {
            cap: InvoiceCap::Total
        })
    ));
    // An invoice the user paid no longer counts.
    write(store, |repos| {
        repos.set_pending_invoice_status(invoice_id(0), PendingInvoiceStatus::Paid)?;
        repos.park_invoice(&invoice(invoice_id(total), fresh_sender, 0))
    })
    .unwrap();
    let stored = read(store, |repos| repos.pending_invoices()).unwrap();
    assert_eq!(stored.len(), MAX_PARKED_INVOICES + 1);
}

fn pending_invoice_bytes_cannot_be_read_without_the_key<B: Backend>() {
    let backend = B::create(context_key(1));
    write(backend.store(), |repos| {
        repos.park_invoice(&invoice(SLATE_A, 1, 1))
    })
    .unwrap();
    let wrong_key = backend.reopen(context_key(2));
    for result in [
        read(&wrong_key, |repos| repos.pending_invoice(SLATE_A).map(drop)),
        read(&wrong_key, |repos| repos.pending_invoices().map(drop)),
    ] {
        assert!(matches!(
            result,
            Err(StoreError::Undecryptable {
                record: Record::PendingInvoice
            })
        ));
    }
    let right_key = backend.reopen(context_key(1));
    assert_eq!(
        read(&right_key, |repos| repos.pending_invoice(SLATE_A)).unwrap(),
        Some(invoice(SLATE_A, 1, 1))
    );
}

fn contacts_round_trip_and_are_found_by_every_lookup<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut first = contact(1, 5);
    first.allow_invoices = true;
    first.state = ContactState::KeysChanged;
    first.alternate = Some(peer_card(9));
    first.verified_at = Some(support::time(3));
    first.last_sealed_in = Some(support::time(4));
    first.app_contact = Some("address-book-17".to_owned());
    first.seal = SealMode::Degraded;
    let mut waiting = contact(2, 1);
    waiting.peer = None;
    waiting.state = ContactState::PendingInvite;
    write(store, |repos| {
        repos.put_contact(&first)?;
        repos.put_contact(&contact(3, 9))?;
        repos.put_contact(&waiting)?;
        repos.put_contact_mailbox(&contact_mailbox(1))?;
        repos.put_contact_mailbox(&contact_mailbox(3))
    })
    .unwrap();
    let card = peer_card(1);
    read(store, |repos| {
        assert_eq!(repos.contact(contact_id(1))?, Some(first.clone()));
        assert_eq!(repos.contact(contact_id(2))?, Some(waiting.clone()));
        assert_eq!(repos.contact(contact_id(8))?, None);
        assert_eq!(
            repos.contact_by_peer_sig_key(&card.sig_key)?,
            Some(first.clone())
        );
        assert_eq!(repos.contact_by_peer_sig_key(&[77; 32])?, None);
        assert_eq!(
            repos.contacts()?,
            vec![waiting.clone(), first.clone(), contact(3, 9)]
        );
        Ok(())
    })
    .unwrap();
}

fn put_contact_replaces_by_id_and_keeps_the_peer_key_unique<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut renamed = contact(1, 5);
    renamed.label = "renamed".to_owned();
    renamed.allow_invoices = true;
    write(store, |repos| {
        repos.put_contact(&contact(1, 5))?;
        repos.put_contact(&renamed)
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.contacts()).unwrap(),
        vec![renamed]
    );

    let mut clash = contact(2, 6);
    clash.peer = Some(peer_card(1));
    let error = write(store, |repos| repos.put_contact(&clash)).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Duplicate {
            record: Record::Contact
        }
    ));
    assert_eq!(read(store, |repos| repos.contacts()).unwrap().len(), 1);
}

fn contacts_stop_at_the_cap<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        for n in 0..MAX_CONTACTS {
            let mut record = contact(0, 1);
            let bytes = u32::try_from(n).unwrap().to_be_bytes();
            record.contact_id = lepic_store::ContactId([
                bytes[0], bytes[1], bytes[2], bytes[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]);
            record.peer.as_mut().unwrap().sig_key = [
                bytes[0], bytes[1], bytes[2], bytes[3], 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
            ];
            repos.put_contact(&record)?;
        }
        Ok(())
    })
    .unwrap();
    let error = write(store, |repos| repos.put_contact(&contact(1, 1))).unwrap_err();
    assert!(matches!(
        error,
        StoreError::ContactCapReached {
            cap: ContactCap::Contacts
        }
    ));
    // An existing contact can still be replaced at the cap.
    let first = read(store, |repos| repos.contacts()).unwrap().remove(0);
    write(store, |repos| repos.put_contact(&first)).unwrap();
}

fn slots_count_up_per_account_from_the_callers_start<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let (first, second) = (AccountIndex(0), AccountIndex(1));
    let taken = write(store, |repos| {
        assert_eq!(repos.contact_slot_counter(first)?, None);
        Ok(vec![
            repos.take_contact_slot(first, 31_000)?,
            // The start only applies while the account has no counter.
            repos.take_contact_slot(first, 5)?,
            repos.take_contact_slot(second, 0)?,
        ])
    })
    .unwrap();
    assert_eq!(taken, vec![31_000, 31_001, 0]);
    read(store, |repos| {
        assert_eq!(repos.contact_slot_counter(first)?, Some(31_002));
        assert_eq!(
            repos.contact_slot_counters()?,
            vec![(first, 31_002), (second, 1)]
        );
        Ok(())
    })
    .unwrap();
    // A slot taken back lifts the counter above it; a lower value changes nothing.
    write(store, |repos| {
        repos.raise_contact_slot_counter(second, 9)?;
        repos.raise_contact_slot_counter(second, 3)?;
        repos.raise_contact_slot_counter(AccountIndex(2), 4)
    })
    .unwrap();
    read(store, |repos| {
        assert_eq!(repos.contact_slot_counter(second)?, Some(9));
        assert_eq!(repos.contact_slot_counter(AccountIndex(2))?, Some(4));
        Ok(())
    })
    .unwrap();
}

fn slots_run_out_at_65536<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let account = AccountIndex(0);
    let last = write(store, |repos| {
        repos.take_contact_slot(account, CONTACT_SLOT_COUNT - 1)
    })
    .unwrap();
    assert_eq!(last, CONTACT_SLOT_COUNT - 1);
    let error = write(store, |repos| repos.take_contact_slot(account, 0)).unwrap_err();
    assert!(matches!(
        error,
        StoreError::ContactCapReached {
            cap: ContactCap::Slots
        }
    ));
    for start in [CONTACT_SLOT_COUNT, u32::MAX] {
        let error = write(store, |repos| {
            repos.take_contact_slot(AccountIndex(1), start)
        })
        .unwrap_err();
        assert!(matches!(error, StoreError::OutOfRange { .. }), "{start}");
    }
    let error = write(store, |repos| {
        repos.raise_contact_slot_counter(account, CONTACT_SLOT_COUNT + 1)
    })
    .unwrap_err();
    assert!(matches!(error, StoreError::OutOfRange { .. }));
    // Slots from CONTACT_SLOT_COUNT up are private pairings', below PRIVATE_SLOT_END.
    let mut record = contact(1, 1);
    record.slot = PRIVATE_SLOT_END;
    let error = write(store, |repos| repos.put_contact(&record)).unwrap_err();
    assert!(matches!(error, StoreError::OutOfRange { .. }));
    record.slot = CONTACT_SLOT_COUNT;
    write(store, |repos| repos.put_contact(&record)).unwrap();
}

fn twin_records_share_a_slot_but_not_a_peer_key<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let one = contact(1, 1);
    let mut twin = contact(2, 2);
    twin.slot = one.slot;
    twin.box_salt = one.box_salt;
    write(store, |repos| {
        repos.put_contact(&one)?;
        repos.put_contact(&twin)
    })
    .unwrap();
    let stored = read(store, |repos| repos.contacts()).unwrap();
    assert_eq!(stored, vec![one, twin]);
}

fn mailboxes_need_their_contact_and_go_with_it<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let error = write(store, |repos| {
        repos.put_contact_mailbox(&contact_mailbox(1))
    })
    .unwrap_err();
    assert!(matches!(
        error,
        StoreError::NotFound {
            record: Record::Contact
        }
    ));

    let mut moved = contact_mailbox(1);
    moved.previous = None;
    moved.onion = None;
    moved.backoff = Vec::new();
    write(store, |repos| {
        repos.put_contact(&contact(1, 1))?;
        repos.put_contact_mailbox(&contact_mailbox(1))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.contact_mailbox(contact_id(1))).unwrap(),
        Some(contact_mailbox(1))
    );
    write(store, |repos| repos.put_contact_mailbox(&moved)).unwrap();
    assert_eq!(
        read(store, |repos| repos.contact_mailbox(contact_id(1))).unwrap(),
        Some(moved)
    );
    let removed = write(store, |repos| {
        Ok((
            repos.delete_contact(contact_id(1))?,
            repos.delete_contact(contact_id(1))?,
        ))
    })
    .unwrap();
    assert_eq!(removed, (true, false));
    read(store, |repos| {
        assert_eq!(repos.contact_mailbox(contact_id(1))?, None);
        Ok(())
    })
    .unwrap();
}

/// Updating a contact, its mailbox or its pairing changes that row in place: the contact's
/// mailbox and relay backoff survive, as they would not if the row were deleted and inserted
/// again with its cascades.
fn updates_keep_a_contacts_mailbox_and_backoff<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        repos.put_contact(&contact(1, 1))?;
        repos.put_contact_mailbox(&contact_mailbox(1))?;
        repos.put_pending_pairing(&pairing(1, 1))
    })
    .unwrap();

    let mut verified = contact(1, 1);
    verified.state = ContactState::Verified;
    verified.verified_at = Some(Timestamp::from_second(2).unwrap());
    verified.allow_invoices = true;
    verified.label = "Anna".to_owned();
    let mut moved = contact_mailbox(1);
    moved.peer_mailbox = "peer1@relay.example:8443".to_owned();
    let mut answered = pairing(1, 1);
    answered.state = PairingState::PendingReply;
    write(store, |repos| {
        repos.put_contact(&verified)?;
        repos.put_pending_pairing(&answered)?;
        repos.put_contact(&verified)
    })
    .unwrap();
    read(store, |repos| {
        assert_eq!(repos.contact(contact_id(1))?, Some(verified.clone()));
        assert_eq!(
            repos.contact_mailbox(contact_id(1))?,
            Some(contact_mailbox(1))
        );
        assert_eq!(
            repos.pending_pairing(PairingId([1; 16]))?.unwrap().state,
            PairingState::PendingReply
        );
        Ok(())
    })
    .unwrap();

    write(store, |repos| repos.put_contact_mailbox(&moved)).unwrap();
    read(store, |repos| {
        assert_eq!(repos.contact_mailbox(contact_id(1))?, Some(moved.clone()));
        assert_eq!(repos.contact(contact_id(1))?, Some(verified.clone()));
        Ok(())
    })
    .unwrap();
}

fn seen_envelopes_are_remembered_and_forgotten_by_age<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let at = |second: i64| Timestamp::from_second(second).unwrap();
    write(store, |repos| {
        repos.remember_envelope(&[1; 32], at(10))?;
        repos.remember_envelope(&[2; 32], at(20))?;
        // Seen again: the time moves on.
        repos.remember_envelope(&[1; 32], at(30))
    })
    .unwrap();
    read(store, |repos| {
        assert!(repos.envelope_seen(&[1; 32])?);
        assert!(repos.envelope_seen(&[2; 32])?);
        assert!(!repos.envelope_seen(&[3; 32])?);
        Ok(())
    })
    .unwrap();
    let forgotten = write(store, |repos| repos.forget_envelopes_before(at(25))).unwrap();
    assert_eq!(forgotten, 1);
    read(store, |repos| {
        assert!(repos.envelope_seen(&[1; 32])?);
        assert!(!repos.envelope_seen(&[2; 32])?);
        Ok(())
    })
    .unwrap();
}

fn pairings_round_trip_with_their_secrets_and_are_found_by_invite<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut reply = pairing(2, 20);
    reply.role = lepic_store::PairingRole::Invitee;
    reply.state = PairingState::PendingReply;
    reply.peer_mailbox = Some("peer@relay.example".to_owned());
    write(store, |repos| {
        repos.put_pending_pairing(&pairing(1, 10))?;
        repos.put_pending_pairing(&reply)
    })
    .unwrap();
    read(store, |repos| {
        assert_eq!(
            repos.pending_pairing(PairingId([1; 16]))?,
            Some(pairing(1, 10))
        );
        assert_eq!(
            repos.pending_pairing_by_invite(&[2; 8])?,
            Some(reply.clone())
        );
        assert_eq!(repos.pending_pairing_by_invite(&[3; 8])?, None);
        assert_eq!(
            repos.pending_pairings()?,
            vec![pairing(1, 10), reply.clone()]
        );
        Ok(())
    })
    .unwrap();

    let mut clash = pairing(3, 30);
    clash.invite_id = [1; 8];
    let error = write(store, |repos| repos.put_pending_pairing(&clash)).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Duplicate {
            record: Record::PendingPairing
        }
    ));

    let removed = write(store, |repos| {
        Ok((
            repos.delete_pending_pairing(PairingId([2; 16]))?,
            repos.delete_pending_pairing(PairingId([2; 16]))?,
        ))
    })
    .unwrap();
    assert_eq!(removed, (true, false));
}

fn settings_beside_a_contact_go_once_nothing_holds_its_id<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let kept = |n: u8| lepic_store::contact_extra_key(contact_id(n), "label");
    let extras = |store: &B::Store| {
        read(store, |repos| {
            repos.settings_with_prefix(lepic_store::CONTACT_EXTRA_PREFIX)
        })
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>()
    };
    // Contact 1 is paired and pairing again; 2 is only paired; 3 and 4 are only pairing. A key
    // outside every contact's prefix stays.
    let mut late = pairing(3, 1_000);
    late.invite_id = [30; 8];
    write(store, |repos| {
        repos.put_contact(&contact(1, 1))?;
        repos.put_contact(&contact(2, 2))?;
        repos.put_pending_pairing(&pairing(1, 10))?;
        repos.put_pending_pairing(&late)?;
        repos.put_pending_pairing(&pairing(4, 10))?;
        for n in [1, 2, 3, 4] {
            repos.put_setting(&kept(n), "x")?;
        }
        repos.put_setting("contact_extra.other", "x")
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.setting(&kept(2)))
            .unwrap()
            .as_deref(),
        Some("x")
    );

    // A pairing in progress still holds contact 1's id; the contact alone holds 2's.
    write(store, |repos| repos.delete_contact(contact_id(1)).map(drop)).unwrap();
    write(store, |repos| repos.delete_contact(contact_id(2)).map(drop)).unwrap();
    let mut left = vec![kept(1), kept(3), kept(4)];
    left.sort();
    let mut wanted = left.clone();
    wanted.push("contact_extra.other".to_owned());
    wanted.sort();
    assert_eq!(extras(store), wanted);

    // A deleted pairing lets its id go.
    write(store, |repos| {
        repos.delete_pending_pairing(PairingId([1; 16]))?;
        repos.delete_pending_pairing(PairingId([4; 16])).map(drop)
    })
    .unwrap();
    assert!(!extras(store).contains(&kept(1)));
    assert!(!extras(store).contains(&kept(4)));
    write(store, |repos| {
        repos.delete_pending_pairing(late.pairing_id).map(drop)
    })
    .unwrap();
    assert_eq!(extras(store), vec!["contact_extra.other".to_owned()]);
}

fn pairing_secrets_cannot_be_read_without_the_key<B: Backend>() {
    let backend = B::create(context_key(1));
    write(backend.store(), |repos| {
        repos.put_pending_pairing(&pairing(1, 10))
    })
    .unwrap();
    let other = backend.reopen(context_key(2));
    let error = read(&other, |repos| repos.pending_pairing(PairingId([1; 16]))).unwrap_err();
    assert!(matches!(
        error,
        StoreError::Undecryptable {
            record: Record::PendingPairing
        }
    ));
}

fn pending_pairings_stop_at_the_cap<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        for n in 0..MAX_PENDING_PAIRINGS {
            let mut next = pairing(0, 10);
            let id = u8::try_from(n).unwrap();
            next.pairing_id = PairingId([id; 16]);
            next.invite_id = [id; 8];
            repos.put_pending_pairing(&next)?;
        }
        Ok(())
    })
    .unwrap();
    let error = write(store, |repos| repos.put_pending_pairing(&pairing(200, 10))).unwrap_err();
    assert!(matches!(
        error,
        StoreError::ContactCapReached {
            cap: ContactCap::PendingPairings
        }
    ));
    // Replacing one at the cap works; so does a new one after one is removed.
    write(store, |repos| {
        repos.put_pending_pairing(&pairing(1, 10))?;
        repos.delete_pending_pairing(PairingId([1; 16]))?;
        repos.put_pending_pairing(&pairing(200, 10))
    })
    .unwrap();
}

/// Pairing `n` on the role `role`, answered when it holds no nA.
fn numbered_pairing(
    n: usize,
    role: lepic_store::PairingRole,
    answered: bool,
) -> lepic_store::PendingPairing {
    let id = u8::try_from(n).unwrap();
    let mut next = pairing(0, 10);
    next.pairing_id = PairingId([id; 16]);
    next.invite_id = [id; 8];
    next.role = role;
    if answered {
        next.secrets.na = None;
    }
    next
}

fn answered_invites_leave_the_pending_cap<B: Backend>() {
    use lepic_store::PairingRole::{Invitee, Inviter};
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        for n in 0..MAX_PENDING_PAIRINGS {
            repos.put_pending_pairing(&numbered_pairing(n, Inviter, true))?;
        }
        Ok(())
    })
    .unwrap();
    // Answered invites hold no room: a full cap of waiting ones fits beside them.
    write(store, |repos| {
        for n in 100..(100 + MAX_PENDING_PAIRINGS) {
            repos.put_pending_pairing(&numbered_pairing(n, Inviter, false))?;
        }
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos
            .put_pending_pairing(&numbered_pairing(200, Inviter, false))),
        Err(StoreError::ContactCapReached {
            cap: ContactCap::PendingPairings
        })
    ));
    // An invitee waits for the confirm whatever its secrets hold.
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        for n in 0..MAX_PENDING_PAIRINGS {
            repos.put_pending_pairing(&numbered_pairing(n, Invitee, true))?;
        }
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos
            .put_pending_pairing(&numbered_pairing(200, Inviter, false))),
        Err(StoreError::ContactCapReached {
            cap: ContactCap::PendingPairings
        })
    ));
}

fn a_pairing_that_cannot_be_opened_counts_as_waiting<B: Backend>() {
    let backend = B::create(context_key(1));
    write(backend.store(), |repos| {
        for n in 0..MAX_PENDING_PAIRINGS {
            repos.put_pending_pairing(&numbered_pairing(
                n,
                lepic_store::PairingRole::Inviter,
                true,
            ))?;
        }
        Ok(())
    })
    .unwrap();
    // Under another key no answered row can be told apart: each holds its room, and reading
    // one still fails as it did.
    let other = backend.reopen(context_key(2));
    assert!(matches!(
        write(&other, |repos| repos.put_pending_pairing(&pairing(200, 10))),
        Err(StoreError::ContactCapReached {
            cap: ContactCap::PendingPairings
        })
    ));
    assert!(matches!(
        read(&other, |repos| repos.pending_pairing(PairingId([1; 16]))),
        Err(StoreError::Undecryptable {
            record: Record::PendingPairing
        })
    ));
}

fn pairing_facts_round_trip_and_are_found_by_payments_key<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut proven = contact(1, 1);
    proven.facts = PairingFacts {
        payments_address: Some("key@relay.example".to_owned()),
        payments_key: Some([2; 33]),
        peer_features: 0x8000_000a,
        peer_heard_at: Some(support::time(3)),
        peer_verified_at: Some(support::time(4)),
        peer_verdict: Some([5; 32]),
        ended_reason: Some(PairingEndReason::PeerMismatch),
        ended_at: Some(support::time(6)),
        heard_wait: std::time::Duration::from_secs(7),
        heard_wait_mark: Some(support::time(8)),
        peer_domain: None,
    };
    write(store, |repos| {
        repos.put_contact(&proven)?;
        repos.put_contact(&contact(2, 2))
    })
    .unwrap();
    read(store, |repos| {
        assert_eq!(repos.contact(contact_id(1))?, Some(proven.clone()));
        assert_eq!(
            repos.contacts_by_payments_key(&[2; 33])?,
            vec![proven.clone()]
        );
        assert!(repos.contacts_by_payments_key(&[3; 33])?.is_empty());
        Ok(())
    })
    .unwrap();
    // An address is never stored without its key.
    let mut half = contact(3, 3);
    half.facts.payments_address = Some("key@relay.example".to_owned());
    assert!(matches!(
        write(store, |repos| repos.put_contact(&half)),
        Err(StoreError::OutOfRange { .. })
    ));
}

fn cancelled_pairings_have_a_cap_of_their_own<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let numbered = |n: usize, cancelled: bool| {
        let id = u8::try_from(n).unwrap();
        let mut next = pairing(0, 10);
        next.pairing_id = PairingId([id; 16]);
        next.invite_id = [id; 8];
        next.cancelled_at = cancelled.then(|| support::time(11));
        next.expect_address = Some("key@relay.example".to_owned());
        next.expect_key = Some([id; 33]);
        next.reply = Some(vec![id; 3]);
        next
    };
    write(store, |repos| {
        for n in 0..MAX_PENDING_PAIRINGS {
            repos.put_pending_pairing(&numbered(n, false))?;
        }
        Ok(())
    })
    .unwrap();
    // A full set of pairings in progress leaves room for cancelled ones, and cancelling one
    // makes room for a new one in progress.
    write(store, |repos| {
        repos.put_pending_pairing(&numbered(0, true))?;
        repos.put_pending_pairing(&numbered(100, false))
    })
    .unwrap();
    write(store, |repos| {
        for n in 101..(100 + MAX_CANCELLED_PAIRINGS) {
            repos.put_pending_pairing(&numbered(n, true))?;
        }
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        write(store, |repos| repos
            .put_pending_pairing(&numbered(250, true))),
        Err(StoreError::ContactCapReached {
            cap: ContactCap::PendingPairings
        })
    ));
    let stored = read(store, |repos| repos.pending_pairing(PairingId([0; 16])))
        .unwrap()
        .unwrap();
    assert_eq!(stored, numbered(0, true));
}

fn facts_round_trip_domain<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut claimed = contact(1, 1);
    claimed.facts.peer_domain = Some(DomainClaimBytes {
        domain: "shop.example".to_owned(),
        attestation: vec![9; 300],
    });
    write(store, |repos| {
        repos.put_contact(&claimed)?;
        repos.put_contact(&contact(2, 2))
    })
    .unwrap();
    read(store, |repos| {
        assert_eq!(repos.contact(contact_id(1))?, Some(claimed.clone()));
        assert_eq!(
            repos.contact(contact_id(2))?.unwrap().facts.peer_domain,
            None
        );
        Ok(())
    })
    .unwrap();
    // A proof over the limit is refused on write.
    let mut huge = contact(3, 3);
    huge.facts.peer_domain = Some(DomainClaimBytes {
        domain: "shop.example".to_owned(),
        attestation: vec![0; 4097],
    });
    assert!(write(store, |repos| repos.put_contact(&huge)).is_err());
    // The limit itself is stored.
    huge.facts
        .peer_domain
        .as_mut()
        .unwrap()
        .attestation
        .truncate(4096);
    write(store, |repos| repos.put_contact(&huge)).unwrap();
}

fn backup_round_trips_domain<B: Backend>() {
    let source = B::create(context_key(1));
    let mut claimed = contact(1, 1);
    claimed.facts.peer_domain = Some(DomainClaimBytes {
        domain: "shop.example".to_owned(),
        attestation: vec![0xab, 0xcd, 0xef],
    });
    write(source.store(), |repos| repos.put_contact(&claimed)).unwrap();
    let json = read(source.store(), |repos| {
        export_contacts(repos, Network::Floonet)
    })
    .unwrap();
    assert!(json.contains(r#""peer_domain":"shop.example""#), "{json}");
    assert!(
        json.contains(r#""peer_domain_attestation":"abcdef""#),
        "{json}"
    );
    let clean = B::create(context_key(2));
    write(clean.store(), |repos| import(repos, &json)).unwrap();
    let restored = read(clean.store(), |repos| repos.contacts()).unwrap();
    assert_eq!(restored[0].facts.peer_domain, claimed.facts.peer_domain);
}

fn backup_v1_without_domain_imports<B: Backend>() {
    let source = B::create(context_key(1));
    write(source.store(), |repos| repos.put_contact(&contact(1, 1))).unwrap();
    let json = read(source.store(), |repos| {
        export_contacts(repos, Network::Floonet)
    })
    .unwrap();
    // No domain: the fields are left out of the document, and an older document imports.
    assert!(!json.contains("peer_domain"), "{json}");
    let clean = B::create(context_key(2));
    let summary = write(clean.store(), |repos| import(repos, &json)).unwrap();
    assert_eq!(summary.imported, 1);
    let restored = read(clean.store(), |repos| repos.contacts()).unwrap();
    assert_eq!(restored[0].facts.peer_domain, None);
}

fn contact_backup_leaves_out_ended_and_unheard_records<B: Backend>() {
    let source = B::create(context_key(1));
    let mut proven = contact(1, 1);
    proven.facts.payments_address = Some("key@relay.example".to_owned());
    proven.facts.payments_key = Some([7; 33]);
    proven.facts.peer_features = 8;
    proven.facts.peer_verified_at = Some(support::time(5));
    proven.facts.peer_verdict = Some([6; 32]);
    let mut ended = contact(2, 2);
    ended.facts.ended_reason = Some(PairingEndReason::Mismatch);
    ended.facts.ended_at = Some(support::time(3));
    let mut unheard = contact(3, 3);
    unheard.facts.peer_heard_at = None;
    write(source.store(), |repos| {
        repos.put_contact(&proven)?;
        repos.put_contact(&ended)?;
        repos.put_contact(&unheard)
    })
    .unwrap();
    let json = read(source.store(), |repos| {
        export_contacts(repos, Network::Floonet)
    })
    .unwrap();
    let clean = B::create(context_key(2));
    let summary = write(clean.store(), |repos| import(repos, &json)).unwrap();
    assert_eq!(summary.imported, 1);
    // Nothing learned about the contact's wallet is in the backup: no features, no times it
    // was heard or said it verified. Its proven address is.
    for field in ["peer_features", "peer_heard_at", "peer_verified_at"] {
        assert!(!json.contains(field), "{json}");
    }
    let mut expected = proven.clone();
    expected.imported_from_backup = true;
    expected.facts.peer_features = 0;
    expected.facts.peer_verified_at = None;
    expected.facts.peer_heard_at = Some(proven.created_at);
    assert_eq!(
        read(clean.store(), |repos| repos.contacts()).unwrap(),
        vec![expected]
    );
    // A document without the address and verdict restores none.
    let older = json
        .replace(r#","payments_address":"key@relay.example""#, "")
        .replace(&format!(r#","payments_key":"{}""#, "07".repeat(33)), "")
        .replace(&format!(r#","peer_verdict":"{}""#, "06".repeat(32)), "");
    assert!(!older.contains("peer_"), "{older}");
    let restored = B::create(context_key(3));
    write(restored.store(), |repos| import(repos, &older)).unwrap();
    let facts = read(restored.store(), |repos| repos.contacts()).unwrap()[0]
        .facts
        .clone();
    assert_eq!(
        facts,
        PairingFacts {
            peer_heard_at: Some(proven.created_at),
            ..PairingFacts::default()
        }
    );
}

/// Reads the support module's stand-in cards the way the wallet reads real ones: peer cards
/// `c0 n de ad` and own cards of 60 equal bytes. Anything else does not decode.
fn read_test_card(bytes: &[u8]) -> Option<PeerCard> {
    match bytes {
        [0xc0, n, 0xde, 0xad] => Some(peer_card(*n)),
        [n, rest @ ..] if rest.len() == 59 && rest.iter().all(|byte| byte == n) => Some(PeerCard {
            bytes: bytes.to_vec(),
            ..peer_card(*n)
        }),
        _ => None,
    }
}

fn import<R: lepic_store::ContactRepository + ?Sized>(
    repos: &mut R,
    json: &str,
) -> Result<ImportSummary, StoreError> {
    import_contacts(repos, json, Network::Floonet, &read_test_card)
}

fn contact_backup_round_trips_without_secrets_and_flags_imports<B: Backend>() {
    let source = B::create(context_key(1));
    let mut verified = contact(1, 1);
    verified.state = ContactState::Verified;
    verified.verified_at = Some(support::time(2));
    verified.allow_invoices = true;
    verified.app_contact = Some("book-1".to_owned());
    let mut changed = contact(2, 2);
    changed.state = ContactState::KeysChanged;
    changed.alternate = Some(peer_card(8));
    let mut waiting = contact(3, 3);
    waiting.peer = None;
    waiting.state = ContactState::PendingInvite;
    let mut twin = contact(4, 4);
    twin.slot = verified.slot;
    twin.box_salt = [0xee; 16];
    twin.sas = None;
    write(source.store(), |repos| {
        repos.put_contact(&verified)?;
        repos.put_contact(&changed)?;
        repos.put_contact(&waiting)?;
        repos.put_contact(&twin)?;
        repos.raise_contact_slot_counter(AccountIndex(0), 40)?;
        repos.raise_contact_slot_counter(AccountIndex(3), 7)?;
        repos.put_contact_mailbox(&contact_mailbox(1))?;
        repos.put_pending_pairing(&pairing(3, 3))
    })
    .unwrap();
    let json = read(source.store(), |repos| {
        export_contacts(repos, Network::Floonet)
    })
    .unwrap();
    assert!(json.starts_with("{\"version\":1,\"network\":\"floonet\",\"contacts\":["));
    assert!(!json.contains("pairing") && !json.contains("secret"));

    let target = B::create(context_key(2));
    // A contact the target already holds is kept as it is.
    let mut local = contact(2, 2);
    local.label = "mine".to_owned();
    write(target.store(), |repos| repos.put_contact(&local)).unwrap();
    let mut conflicting = contact(5, 5);
    conflicting.peer = Some(peer_card(1));
    write(target.store(), |repos| repos.put_contact(&conflicting)).unwrap();
    let summary = write(target.store(), |repos| import(repos, &json)).unwrap();
    assert_eq!(
        summary,
        ImportSummary {
            imported: 1,
            skipped_existing: 1,
            skipped_conflict: 1
        }
    );

    let clean = B::create(context_key(3));
    let summary = write(clean.store(), |repos| import(repos, &json)).unwrap();
    assert_eq!(
        summary,
        ImportSummary {
            imported: 3,
            ..ImportSummary::default()
        }
    );
    read(clean.store(), |repos| {
        let mut expected = verified.clone();
        expected.imported_from_backup = true;
        let mut expected_changed = changed.clone();
        expected_changed.imported_from_backup = true;
        let mut expected_twin = twin.clone();
        expected_twin.imported_from_backup = true;
        assert_eq!(
            repos.contacts()?,
            vec![expected, expected_changed, expected_twin]
        );
        assert_eq!(
            repos.contact_slot_counters()?,
            vec![(AccountIndex(0), 40), (AccountIndex(3), 7)]
        );
        let mut mailbox = contact_mailbox(1);
        mailbox.backoff = Vec::new();
        assert_eq!(repos.contact_mailbox(contact_id(1))?, Some(mailbox));
        assert!(repos.pending_pairings()?.is_empty());
        // The restored store exports the same document.
        assert_eq!(export_contacts(repos, Network::Floonet)?, json);
        Ok(())
    })
    .unwrap();
}

fn contact_backup_rejects_unknown_versions_and_malformed_records<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let newer = write(store, |repos| {
        import(
            repos,
            "{\"version\":2,\"network\":\"floonet\",\"contacts\":[],\"slot_counters\":[]}",
        )
    })
    .unwrap_err();
    assert!(matches!(newer, StoreError::UnsupportedBackup { found: 2 }));
    for bad in [
        "not json",
        "{\"version\":1}",
        "{\"version\":1,\"contacts\":[],\"slot_counters\":[]}",
        "{\"version\":1,\"network\":\"floonet\",\"contacts\":[],\"slot_counters\":[{}]}",
        "{\"version\":1,\"network\":\"floonet\",\"contacts\":[{}],\"slot_counters\":[]}",
    ] {
        let error = write(store, |repos| import(repos, bad)).unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::Corrupt {
                    record: Record::Contact,
                    ..
                }
            ),
            "{bad}"
        );
    }
    let empty = write(store, |repos| {
        import(
            repos,
            "{\"version\":1,\"network\":\"floonet\",\"contacts\":[],\"slot_counters\":[]}",
        )
    })
    .unwrap();
    assert_eq!(empty, ImportSummary::default());
}

fn contact_backup_refuses_the_other_network<B: Backend>() {
    let source = B::create(context_key(1));
    write(source.store(), |repos| repos.put_contact(&contact(1, 1))).unwrap();
    let json = read(source.store(), |repos| {
        export_contacts(repos, Network::Mainnet)
    })
    .unwrap();
    let target = B::create(context_key(2));
    let error = write(target.store(), |repos| import(repos, &json)).unwrap_err();
    assert!(
        matches!(error, StoreError::BackupOfOtherNetwork),
        "{error:?}"
    );
    assert!(
        read(target.store(), |repos| repos.contacts())
            .unwrap()
            .is_empty()
    );
}

fn contact_backup_takes_card_fields_from_the_card_bytes<B: Backend>() {
    let source = B::create(context_key(1));
    let mut stale = contact(1, 1);
    // An index that no longer matches its bytes is not exported as such.
    stale.peer = Some(PeerCard {
        seq: 9,
        claimed_name: "renamed".to_owned(),
        ..peer_card(1)
    });
    write(source.store(), |repos| repos.put_contact(&stale)).unwrap();
    let json = read(source.store(), |repos| {
        export_contacts(repos, Network::Floonet)
    })
    .unwrap();
    assert!(
        !json.contains("renamed") && !json.contains("sig_key"),
        "{json}"
    );

    let target = B::create(context_key(2));
    write(target.store(), |repos| import(repos, &json)).unwrap();
    let restored = read(target.store(), |repos| repos.contact(contact_id(1)))
        .unwrap()
        .unwrap();
    assert_eq!(restored.peer, Some(peer_card(1)));

    // A card the wallet cannot read fails the whole import.
    for unreadable in [
        json.replace("c001dead", "c001beef"),
        json.replace(&"01".repeat(60), &"01".repeat(59)),
    ] {
        let fresh = B::create(context_key(3));
        let error = write(fresh.store(), |repos| import(repos, &unreadable)).unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::Corrupt {
                    record: Record::Contact,
                    ..
                }
            ),
            "{error:?}"
        );
    }
}

fn imported(source_id: u32) -> ImportedTransaction {
    ImportedTransaction {
        source_id,
        kind: ImportedKind::Sent,
        slate_id: Some(SLATE_B),
        confirmed_at: Some(Timestamp::from_second(1_700_000_000).unwrap()),
        input_count: 2,
        output_count: 1,
        kernel_excess: Some([8; 33]),
        kernel_lookup_min_height: Some(Height::new(880)),
        ttl_cutoff_height: Some(Height::new(900)),
        messages: vec![
            ImportedMessage {
                participant: 0,
                text: "for coffee".to_owned(),
            },
            ImportedMessage {
                participant: 1,
                text: "thanks ☕".to_owned(),
            },
        ],
        check: ChainCheck::Unchecked,
    }
}

fn imported_output(n: u8, tx: TxId, status: ImportedOutputStatus) -> ImportedOutput {
    ImportedOutput {
        commitment: [n; 33],
        tx,
        status,
        height: Height::new(u64::from(n) + 100),
        amount: Amount::new(u64::from(n) * 1_000),
    }
}

fn imported_transactions_round_trip_and_are_replaced<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let tx = write(store, |repos| {
        repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.imported_transaction(tx)).unwrap(),
        None
    );
    let mut record = imported(7);
    write(store, |repos| repos.put_imported_transaction(tx, &record)).unwrap();
    assert_eq!(
        read(store, |repos| repos.imported_transaction(tx)).unwrap(),
        Some(record.clone())
    );

    record.messages.truncate(1);
    record.kernel_excess = None;
    record.kernel_lookup_min_height = None;
    record.confirmed_at = None;
    record.slate_id = None;
    write(store, |repos| repos.put_imported_transaction(tx, &record)).unwrap();
    write(store, |repos| {
        repos.set_chain_check(tx, ChainCheck::OnChain)
    })
    .unwrap();
    record.check = ChainCheck::OnChain;
    assert_eq!(
        read(store, |repos| repos.imported_transaction(tx)).unwrap(),
        Some(record)
    );
}

fn imported_records_need_their_transaction_and_bounded_messages<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let missing = TxId(41);
    assert!(matches!(
        write(store, |repos| repos.put_imported_transaction(missing, &imported(1))),
        Err(StoreError::UnknownTransaction(id)) if id == missing
    ));
    assert!(matches!(
        write(store, |repos| repos.put_imported_output(&imported_output(
            1,
            missing,
            ImportedOutputStatus::Unspent
        ))),
        Err(StoreError::UnknownTransaction(id)) if id == missing
    ));
    assert!(matches!(
        write(store, |repos| repos
            .set_chain_check(missing, ChainCheck::OnChain)),
        Err(StoreError::NotFound {
            record: Record::ImportedTransaction
        })
    ));
    let tx = write(store, |repos| {
        repos.insert_transaction(&transaction(DEFAULT, None))
    })
    .unwrap();
    let mut long = imported(1);
    long.messages[0].text = "x".repeat(MAX_IMPORTED_MESSAGE_BYTES + 1);
    assert!(matches!(
        write(store, |repos| repos.put_imported_transaction(tx, &long)),
        Err(StoreError::OutOfRange { .. })
    ));
    let mut many = imported(1);
    many.messages.push(many.messages[0].clone());
    assert!(matches!(
        write(store, |repos| repos.put_imported_transaction(tx, &many)),
        Err(StoreError::OutOfRange { .. })
    ));
}

fn imported_outputs_are_found_by_commitment_and_status<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let tx = write(store, |repos| {
        repos.insert_transaction(&transaction(DEFAULT, None))
    })
    .unwrap();
    write(store, |repos| {
        repos.put_imported_output(&imported_output(3, tx, ImportedOutputStatus::Unspent))?;
        repos.put_imported_output(&imported_output(1, tx, ImportedOutputStatus::Unspent))?;
        repos.put_imported_output(&imported_output(2, tx, ImportedOutputStatus::Spent))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.imported_output(&[2; 33])).unwrap(),
        Some(imported_output(2, tx, ImportedOutputStatus::Spent))
    );
    assert_eq!(
        read(store, |repos| repos.imported_output(&[9; 33])).unwrap(),
        None
    );
    let unspent = read(store, |repos| {
        repos.imported_outputs(ImportedOutputStatus::Unspent)
    })
    .unwrap();
    assert_eq!(
        unspent,
        vec![
            imported_output(1, tx, ImportedOutputStatus::Unspent),
            imported_output(3, tx, ImportedOutputStatus::Unspent),
        ]
    );
    write(store, |repos| {
        repos.put_imported_output(&imported_output(3, tx, ImportedOutputStatus::Locked))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos
            .imported_outputs(ImportedOutputStatus::Unspent))
        .unwrap()
        .len(),
        1
    );
}

fn deleting_a_transaction_removes_what_was_imported_with_it<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let tx = write(store, |repos| {
        let tx = repos.insert_transaction(&transaction(DEFAULT, None))?;
        repos.put_imported_transaction(tx, &imported(5))?;
        repos.put_imported_output(&imported_output(4, tx, ImportedOutputStatus::Spent))?;
        Ok(tx)
    })
    .unwrap();
    write(store, |repos| repos.delete_transaction(tx)).unwrap();
    let reused = write(store, |repos| {
        repos.insert_transaction(&transaction(DEFAULT, None))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.imported_transaction(reused)).unwrap(),
        None
    );
    assert_eq!(
        read(store, |repos| repos.imported_output(&[4; 33])).unwrap(),
        None
    );
}

fn api_event_ids_rise_and_are_not_reused_after_a_prune<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    assert_eq!(read(store, |repos| repos.api_event_last_id()).unwrap(), 0);
    assert_eq!(read(store, |repos| repos.api_event_bounds()).unwrap(), None);
    let ids = write(store, |repos| {
        Ok((
            repos.append_api_event("payment.created", support::time(10), b"{\"n\":1}")?,
            repos.append_api_event("payment.completed", support::time(20), b"{}")?,
            repos.append_api_event("link.created", support::time(30), b"")?,
        ))
    })
    .unwrap();
    assert_eq!(ids, (1, 2, 3));
    assert_eq!(
        read(store, |repos| repos.api_event_bounds()).unwrap(),
        Some((1, 3))
    );
    let first = read(store, |repos| repos.api_events_after(0, 10, &[])).unwrap();
    assert_eq!(first.len(), 3);
    assert_eq!(first[0].id, 1);
    assert_eq!(first[0].kind, "payment.created");
    assert_eq!(first[0].created_at, support::time(10));
    assert_eq!(first[0].data, b"{\"n\":1}");
    assert_eq!(first[2].data, b"");

    // Two events are older than time 25.
    let pruned = write(store, |repos| repos.prune_api_events(support::time(25))).unwrap();
    assert_eq!(pruned, 2);
    assert_eq!(
        read(store, |repos| repos.api_event_bounds()).unwrap(),
        Some((3, 3))
    );
    let next = write(store, |repos| {
        repos.append_api_event("link.paid", support::time(40), b"{}")
    })
    .unwrap();
    assert_eq!(next, 4);

    // Every event pruned: the last id stays.
    write(store, |repos| repos.prune_api_events(support::time(1000))).unwrap();
    assert_eq!(read(store, |repos| repos.api_event_bounds()).unwrap(), None);
    assert_eq!(read(store, |repos| repos.api_event_last_id()).unwrap(), 4);
    let after_all = write(store, |repos| {
        repos.append_api_event("link.paid", support::time(1001), b"{}")
    })
    .unwrap();
    assert_eq!(after_all, 5);
}

fn api_events_are_read_after_an_id_with_a_limit_and_a_kind_filter<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let kinds = [
        "payment.created",
        "payment.completed",
        "payments",
        "link.created",
        "payment.created",
    ];
    write(store, |repos| {
        for (index, kind) in kinds.iter().enumerate() {
            repos.append_api_event(kind, support::time(1), &[u8::try_from(index).unwrap()])?;
        }
        Ok(())
    })
    .unwrap();
    let ids = |after: u64, limit: usize, filter: &[&str]| -> Vec<u64> {
        let filter: Vec<String> = filter.iter().map(|kind| (*kind).to_owned()).collect();
        read(store, |repos| repos.api_events_after(after, limit, &filter))
            .unwrap()
            .iter()
            .map(|event| event.id)
            .collect()
    };
    assert_eq!(ids(0, 100, &[]), vec![1, 2, 3, 4, 5]);
    assert_eq!(ids(2, 100, &[]), vec![3, 4, 5]);
    assert_eq!(ids(0, 2, &[]), vec![1, 2]);
    assert_eq!(ids(0, 0, &[]), Vec::<u64>::new());
    assert_eq!(ids(5, 100, &[]), Vec::<u64>::new());
    assert_eq!(ids(u64::MAX, 100, &[]), Vec::<u64>::new());
    // Exact: only the equal kind.
    assert_eq!(ids(0, 100, &["payment.created"]), vec![1, 5]);
    assert_eq!(ids(0, 100, &["payment"]), Vec::<u64>::new());
    // Wildcard: the dotted prefix, not `payments`.
    assert_eq!(ids(0, 100, &["payment.*"]), vec![1, 2, 5]);
    // Several entries are alternatives; the limit applies after filtering.
    assert_eq!(ids(0, 100, &["payments", "link.*"]), vec![3, 4]);
    assert_eq!(ids(0, 2, &["payment.*"]), vec![1, 2]);
    assert_eq!(ids(1, 100, &["payment.*"]), vec![2, 5]);

    for bad in [
        "*",
        ".*",
        "payment*",
        "payment.**",
        "pay*ment.*",
        "pay ment",
        "payment.%",
        "",
        "x'; DROP TABLE api_events; --",
    ] {
        let filter = vec![bad.to_owned()];
        let error = read(store, |repos| repos.api_events_after(0, 10, &filter)).unwrap_err();
        assert!(
            matches!(error, StoreError::OutOfRange { .. }),
            "{bad}: {error:?}"
        );
    }
    let many = vec!["a.b".to_owned(); 33];
    assert!(matches!(
        read(store, |repos| repos.api_events_after(0, 10, &many)).unwrap_err(),
        StoreError::OutOfRange { .. }
    ));
    assert!(matches!(
        read(store, |repos| repos.api_events_after(0, 1001, &[])).unwrap_err(),
        StoreError::OutOfRange { .. }
    ));
}

fn api_event_inputs_are_bounded<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    for kind in [
        String::new(),
        "k".repeat(65),
        "bad kind".to_owned(),
        "a*".to_owned(),
    ] {
        let error = write(store, |repos| {
            repos.append_api_event(&kind, support::time(1), b"{}")
        })
        .unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::OutOfRange {
                    field: "api event kind"
                }
            ),
            "{error:?}"
        );
    }
    let big = vec![b'x'; 1 << 20];
    write(store, |repos| {
        repos.append_api_event("big", support::time(1), &big)
    })
    .unwrap();
    let too_big = vec![b'x'; (1 << 20) + 1];
    let error = write(store, |repos| {
        repos.append_api_event("big", support::time(1), &too_big)
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::OutOfRange {
                field: "api event data"
            }
        ),
        "{error:?}"
    );
    // The refused events took no id.
    assert_eq!(read(store, |repos| repos.api_event_last_id()).unwrap(), 1);
}

fn a_deleted_api_request_can_be_recorded_again<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let request = ApiRequest {
        scope: "payment".to_owned(),
        id: "a".to_owned(),
        digest: [1; 32],
        created_at: support::time(10),
    };
    write(store, |repos| repos.put_api_request(&request)).unwrap();
    assert!(write(store, |repos| repos.delete_api_request("payment", "a")).unwrap());
    assert!(!write(store, |repos| repos.delete_api_request("payment", "a")).unwrap());
    assert_eq!(
        read(store, |repos| repos.api_request("payment", "a")).unwrap(),
        None
    );
    write(store, |repos| repos.put_api_request(&request)).unwrap();
}

fn api_requests_are_stored_once_and_pruned_by_time<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let request = |scope: &str, id: &str, digest: u8, at: i64| ApiRequest {
        scope: scope.to_owned(),
        id: id.to_owned(),
        digest: [digest; 32],
        created_at: support::time(at),
    };
    write(store, |repos| {
        repos.put_api_request(&request("payment", "a", 1, 10))?;
        repos.put_api_request(&request("link", "a", 2, 20))?;
        repos.put_api_request(&request("payment", "b", 3, 30))
    })
    .unwrap();
    let error = write(store, |repos| {
        repos.put_api_request(&request("payment", "a", 9, 99))
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::Duplicate {
                record: Record::ApiRequest
            }
        ),
        "{error:?}"
    );
    // The first record stands.
    assert_eq!(
        read(store, |repos| repos.api_request("payment", "a")).unwrap(),
        Some(request("payment", "a", 1, 10))
    );
    assert_eq!(
        read(store, |repos| repos.api_request("link", "a")).unwrap(),
        Some(request("link", "a", 2, 20))
    );
    assert_eq!(
        read(store, |repos| repos.api_request("contact", "a")).unwrap(),
        None
    );
    for (scope, id) in [
        ("", "a"),
        ("payment", ""),
        (&"s".repeat(33), "a"),
        ("payment", &"i".repeat(129)),
    ] {
        let error = write(store, |repos| {
            repos.put_api_request(&request(scope, id, 1, 1))
        })
        .unwrap_err();
        assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");
    }
    let pruned = write(store, |repos| repos.prune_api_requests(support::time(25))).unwrap();
    assert_eq!(pruned, 2);
    assert_eq!(
        read(store, |repos| repos.api_request("payment", "a")).unwrap(),
        None
    );
    assert_eq!(
        read(store, |repos| repos.api_request("payment", "b")).unwrap(),
        Some(request("payment", "b", 3, 30))
    );
    // A pruned id can be recorded again.
    write(store, |repos| {
        repos.put_api_request(&request("payment", "a", 7, 40))
    })
    .unwrap();
}

fn watch(key_ref: &str, relay: &str, class: MailClass, expires: Option<i64>) -> WatchRow {
    WatchRow {
        key_ref: key_ref.to_owned(),
        relay: relay.to_owned(),
        class,
        expires_at: expires.map(support::time),
    }
}

fn watch_rows_are_replaced_listed_by_relay_and_expire<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let rows = [
        watch("contact:01", "relay-b", MailClass::Contact, None),
        watch("pairing:02", "relay-a:9000", MailClass::Pairing, Some(20)),
        watch("contact:01", "relay-a", MailClass::PreviousHome, Some(10)),
        watch("address:0.1", "relay-b", MailClass::Address, None),
    ];
    write(store, |repos| {
        rows.iter().try_for_each(|row| repos.put_watch(row))
    })
    .unwrap();
    let replaced = watch("contact:01", "relay-b", MailClass::Reply, Some(40));
    write(store, |repos| repos.put_watch(&replaced)).unwrap();
    assert_eq!(
        read(store, |repos| repos.watch_set()).unwrap(),
        [
            rows[2].clone(),
            rows[1].clone(),
            rows[3].clone(),
            replaced.clone(),
        ]
    );

    for bad in [
        watch("", "relay-a", MailClass::Contact, None),
        watch(
            &"k".repeat(MAX_KEY_REF_LEN + 1),
            "relay-a",
            MailClass::Contact,
            None,
        ),
        watch("contact:01", "", MailClass::Contact, None),
        watch(
            "contact:01",
            &"r".repeat(MAX_RELAY_LEN + 1),
            MailClass::Contact,
            None,
        ),
    ] {
        let error = write(store, |repos| repos.put_watch(&bad)).unwrap_err();
        assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");
    }

    // A row expires once now reaches its end; one without an end stays.
    let removed = write(store, |repos| {
        repos.remove_expired_watches(support::time(20))
    })
    .unwrap();
    assert_eq!(removed, 2);
    assert_eq!(
        read(store, |repos| repos.watch_set()).unwrap(),
        [rows[3].clone(), replaced.clone()]
    );
    assert!(write(store, |repos| repos.delete_watch("contact:01", "relay-b")).unwrap());
    assert!(!write(store, |repos| repos.delete_watch("contact:01", "relay-b")).unwrap());
    assert_eq!(
        read(store, |repos| repos.watch_set()).unwrap(),
        [rows[3].clone()]
    );
}

fn native_entry(payment: Uuid, state: OutboxState, next_at: i64) -> NativeOutboxEntry {
    NativeOutboxEntry {
        payment_id: payment,
        from_ref: "contact:01".to_owned(),
        route_method: "epicbox".to_owned(),
        route_value: "box@relay-a".to_owned(),
        envelope: "sealed".to_owned(),
        state,
        attempts: 0,
        next_at: support::time(next_at),
        cutoff_height: Some(Height::new(u64::MAX)),
        stage: Some(SlateStage::Standard1),
        notice: false,
        created_at: support::time(1),
        posted_at: None,
    }
}

fn stored(id: NativeOutboxId, entry: &NativeOutboxEntry) -> StoredNativeOutbox {
    StoredNativeOutbox {
        id,
        entry: entry.clone(),
    }
}

fn native_outbox_lists_by_payment_and_due_time<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let later = native_entry(SLATE_A, OutboxState::Queued, 30);
    let posted = native_entry(SLATE_A, OutboxState::Posted, 5);
    let sooner = NativeOutboxEntry {
        cutoff_height: None,
        ..native_entry(SLATE_B, OutboxState::Queued, 10)
    };
    let ids = write(store, |repos| {
        [&later, &posted, &sooner]
            .into_iter()
            .map(|entry| repos.enqueue_native_outbox(entry))
            .collect::<Result<Vec<_>, _>>()
    })
    .unwrap();
    assert!(ids[0] < ids[1] && ids[1] < ids[2], "{ids:?}");
    assert_eq!(
        read(store, |repos| repos.native_outbox_of(SLATE_A)).unwrap(),
        [stored(ids[0], &later), stored(ids[1], &posted)]
    );
    assert_eq!(
        read(store, |repos| repos.native_outbox_entry(ids[2])).unwrap(),
        Some(stored(ids[2], &sooner))
    );
    assert_eq!(
        read(store, |repos| repos.due_native_outbox(support::time(30))).unwrap(),
        [stored(ids[2], &sooner), stored(ids[0], &later)]
    );
    assert_eq!(
        read(store, |repos| repos.due_native_outbox(support::time(29))).unwrap(),
        [stored(ids[2], &sooner)]
    );

    let retried = NativeOutboxEntry {
        attempts: u32::MAX,
        state: OutboxState::Uncertain,
        stage: None,
        notice: true,
        posted_at: Some(support::time(31)),
        ..later.clone()
    };
    write(store, |repos| repos.update_native_outbox(ids[0], &retried)).unwrap();
    assert_eq!(
        read(store, |repos| repos.native_outbox_entry(ids[0])).unwrap(),
        Some(stored(ids[0], &retried))
    );
    // An uncertain entry is posted again when due; a failed one never.
    assert_eq!(
        read(store, |repos| repos.due_native_outbox(support::time(30))).unwrap(),
        [stored(ids[2], &sooner), stored(ids[0], &retried)]
    );
    let failed = NativeOutboxEntry {
        state: OutboxState::Failed,
        ..retried.clone()
    };
    write(store, |repos| repos.update_native_outbox(ids[0], &failed)).unwrap();
    assert_eq!(
        read(store, |repos| repos.due_native_outbox(support::time(30))).unwrap(),
        [stored(ids[2], &sooner)]
    );
    write(store, |repos| repos.update_native_outbox(ids[0], &retried)).unwrap();
    let missing = NativeOutboxId(ids[2].0 + 100);
    let error = write(store, |repos| repos.update_native_outbox(missing, &retried)).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::NotFound {
                record: Record::NativeOutbox
            }
        ),
        "{error:?}"
    );
    let empty = NativeOutboxEntry {
        envelope: String::new(),
        ..later.clone()
    };
    let error = write(store, |repos| repos.enqueue_native_outbox(&empty)).unwrap_err();
    assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");
    // A notice has no slate stage.
    let staged = NativeOutboxEntry {
        notice: true,
        ..later.clone()
    };
    let error = write(store, |repos| repos.enqueue_native_outbox(&staged)).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::InvalidStatus {
                record: Record::NativeOutbox
            }
        ),
        "{error:?}"
    );

    assert!(write(store, |repos| repos.delete_native_outbox(ids[0])).unwrap());
    assert!(!write(store, |repos| repos.delete_native_outbox(ids[0])).unwrap());
    assert_eq!(
        read(store, |repos| repos.native_outbox_of(SLATE_A)).unwrap(),
        [stored(ids[1], &posted)]
    );
}

fn native_outbox_is_listed_redirected_and_dropped_by_sender<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let queued = native_entry(SLATE_A, OutboxState::Queued, 10);
    let posted = native_entry(SLATE_A, OutboxState::Posted, 10);
    let elsewhere = NativeOutboxEntry {
        route_value: "box@relay-c".to_owned(),
        ..native_entry(SLATE_B, OutboxState::Queued, 10)
    };
    let other = NativeOutboxEntry {
        from_ref: "contact:02".to_owned(),
        ..native_entry(SLATE_B, OutboxState::Queued, 10)
    };
    let ids = write(store, |repos| {
        [&queued, &posted, &elsewhere, &other]
            .into_iter()
            .map(|entry| repos.enqueue_native_outbox(entry))
            .collect::<Result<Vec<_>, _>>()
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.native_outbox_from("contact:01")).unwrap(),
        [
            stored(ids[0], &queued),
            stored(ids[1], &posted),
            stored(ids[2], &elsewhere)
        ]
    );

    // Only the queued entry on the old mailbox moves; the posted one and the other sender's
    // keep their route.
    let moved = write(store, |repos| {
        repos.redirect_native_outbox("contact:01", "box@relay-a", "box@relay-b")
    })
    .unwrap();
    assert_eq!(moved, 1);
    let redirected = NativeOutboxEntry {
        route_value: "box@relay-b".to_owned(),
        ..queued.clone()
    };
    assert_eq!(
        read(store, |repos| repos.native_outbox_from("contact:01")).unwrap(),
        [
            stored(ids[0], &redirected),
            stored(ids[1], &posted),
            stored(ids[2], &elsewhere)
        ]
    );
    assert_eq!(
        read(store, |repos| repos.native_outbox_entry(ids[3])).unwrap(),
        Some(stored(ids[3], &other))
    );
    let error = write(store, |repos| {
        repos.redirect_native_outbox("contact:01", "box@relay-b", "")
    })
    .unwrap_err();
    assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");

    assert_eq!(
        write(store, |repos| repos.delete_native_outbox_from("contact:01")).unwrap(),
        3
    );
    assert!(
        read(store, |repos| repos.native_outbox_from("contact:01"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        read(store, |repos| repos.native_outbox_from("contact:02")).unwrap(),
        [stored(ids[3], &other)]
    );
}

fn copy(mailbox: &str, state: CopyState, next_at: i64) -> OutboxCopy {
    OutboxCopy {
        mailbox: mailbox.to_owned(),
        state,
        attempts: 1,
        next_at: support::time(next_at),
    }
}

fn outbox_copies_are_replaced_listed_when_due_and_go_with_their_entry<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let ids = write(store, |repos| {
        [
            native_entry(SLATE_A, OutboxState::Posted, 5),
            native_entry(SLATE_B, OutboxState::Posted, 5),
        ]
        .iter()
        .map(|entry| repos.enqueue_native_outbox(entry))
        .collect::<Result<Vec<_>, _>>()
    })
    .unwrap();
    let taken = copy("b.test:443", CopyState::Taken, 5);
    let owed = copy("a.test:443", CopyState::Owed, 20);
    let cancel = copy("c.test:443", CopyState::Cancel, 10);
    let other = copy("a.test:443", CopyState::Owed, 20);
    write(store, |repos| {
        repos.put_outbox_copy(ids[0], &taken)?;
        repos.put_outbox_copy(ids[0], &owed)?;
        repos.put_outbox_copy(ids[0], &cancel)?;
        repos.put_outbox_copy(ids[1], &other)
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.outbox_copies(ids[0])).unwrap(),
        [owed.clone(), taken.clone(), cancel.clone()]
    );
    // A taken copy is never due; the others are by time, then entry.
    let due = |at| read(store, |repos| repos.due_outbox_copies(support::time(at))).unwrap();
    let stored = |id, copy: &OutboxCopy| StoredOutboxCopy {
        id,
        copy: copy.clone(),
    };
    assert_eq!(
        due(20),
        [
            stored(ids[0], &cancel),
            stored(ids[0], &owed),
            stored(ids[1], &other)
        ]
    );
    assert_eq!(due(19), [stored(ids[0], &cancel)]);

    // The copy of the same mailbox is replaced.
    let took = OutboxCopy {
        state: CopyState::Taken,
        attempts: u32::MAX,
        ..owed.clone()
    };
    write(store, |repos| repos.put_outbox_copy(ids[0], &took)).unwrap();
    assert_eq!(
        read(store, |repos| repos.outbox_copies(ids[0])).unwrap(),
        [took, taken.clone(), cancel.clone()]
    );
    assert!(
        write(store, |repos| repos
            .delete_outbox_copy(ids[0], "c.test:443"))
        .unwrap()
    );
    assert!(
        !write(store, |repos| repos
            .delete_outbox_copy(ids[0], "c.test:443"))
        .unwrap()
    );

    let missing = NativeOutboxId(ids[1].0 + 100);
    let error = write(store, |repos| repos.put_outbox_copy(missing, &taken)).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::NotFound {
                record: Record::NativeOutbox
            }
        ),
        "{error:?}"
    );
    for mailbox in [String::new(), "a".repeat(301)] {
        let bad = OutboxCopy {
            mailbox,
            ..taken.clone()
        };
        let error = write(store, |repos| repos.put_outbox_copy(ids[0], &bad)).unwrap_err();
        assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");
    }

    // Deleting an entry, alone or with its sender's, deletes its copies.
    assert!(write(store, |repos| repos.delete_native_outbox(ids[0])).unwrap());
    assert!(
        read(store, |repos| repos.outbox_copies(ids[0]))
            .unwrap()
            .is_empty()
    );
    assert_eq!(due(20), [stored(ids[1], &other)]);
    write(store, |repos| repos.delete_native_outbox_from("contact:01")).unwrap();
    assert!(due(20).is_empty());
}

fn delivery(payment: Uuid, alias: Option<&str>, state: Option<OutboxState>) -> PaymentDelivery {
    PaymentDelivery {
        payment_id: payment,
        alias: alias.map(str::to_owned),
        state,
        state_reason: state.map(|_| "relay answered".to_owned()),
        updated_at: support::time(7),
    }
}

fn payment_delivery_is_found_by_id_and_alias_and_aliases_stay_unique<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let first = delivery(SLATE_A, Some("order-1"), None);
    write(store, |repos| repos.put_payment_delivery(&first)).unwrap();
    assert_eq!(
        read(store, |repos| repos.payment_delivery(SLATE_A)).unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        read(store, |repos| repos.payment_delivery_by_alias("order-1")).unwrap(),
        Some(first.clone())
    );

    let taken = delivery(SLATE_B, Some("order-1"), Some(OutboxState::Queued));
    let error = write(store, |repos| repos.put_payment_delivery(&taken)).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::Duplicate {
                record: Record::PaymentDelivery
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        read(store, |repos| repos.payment_delivery(SLATE_B)).unwrap(),
        None
    );

    // The same payment may keep its alias, or drop it and free it.
    let posted = delivery(SLATE_A, Some("order-1"), Some(OutboxState::Posted));
    write(store, |repos| repos.put_payment_delivery(&posted)).unwrap();
    let dropped = delivery(SLATE_A, None, Some(OutboxState::Failed));
    write(store, |repos| repos.put_payment_delivery(&dropped)).unwrap();
    write(store, |repos| repos.put_payment_delivery(&taken)).unwrap();
    assert_eq!(
        read(store, |repos| repos.payment_delivery(SLATE_A)).unwrap(),
        Some(dropped)
    );
    assert_eq!(
        read(store, |repos| repos.payment_delivery_by_alias("order-1")).unwrap(),
        Some(taken)
    );
    assert_eq!(
        read(store, |repos| repos.payment_delivery_by_alias("order-2")).unwrap(),
        None
    );

    for alias in [String::new(), "a".repeat(MAX_ALIAS_LEN + 1)] {
        let bad = delivery(SLATE_B, Some(&alias), None);
        let error = write(store, |repos| repos.put_payment_delivery(&bad)).unwrap_err();
        assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");
    }
}

fn node_post_for(tx_id: TxId, outcome: NodeOutcome, error: Option<String>) -> NodePost {
    NodePost {
        tx_id,
        attempts: 2,
        last_at: support::time(50),
        last_height: Height::new(1_000),
        last_outcome: outcome,
        last_error: error,
        accepted_once: outcome == NodeOutcome::Accepted,
        unreachable_once: outcome == NodeOutcome::Unreachable,
    }
}

fn node_posts_need_their_transaction_and_go_with_it<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let tx = write(store, |repos| {
        repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))
    })
    .unwrap();
    assert_eq!(read(store, |repos| repos.node_post(tx)).unwrap(), None);

    let refused = node_post_for(tx, NodeOutcome::Refused, Some("double spend".to_owned()));
    write(store, |repos| repos.put_node_post(&refused)).unwrap();
    let accepted = node_post_for(tx, NodeOutcome::Accepted, None);
    write(store, |repos| repos.put_node_post(&accepted)).unwrap();
    assert_eq!(
        read(store, |repos| repos.node_post(tx)).unwrap(),
        Some(accepted)
    );
    let refused_after_both = NodePost {
        accepted_once: true,
        unreachable_once: true,
        ..node_post_for(tx, NodeOutcome::Refused, None)
    };
    write(store, |repos| repos.put_node_post(&refused_after_both)).unwrap();
    assert_eq!(
        read(store, |repos| repos.node_post(tx)).unwrap(),
        Some(refused_after_both)
    );

    let long = node_post_for(
        tx,
        NodeOutcome::Unreachable,
        Some("e".repeat(MAX_NODE_ERROR_LEN + 1)),
    );
    let error = write(store, |repos| repos.put_node_post(&long)).unwrap_err();
    assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");
    let unknown = TxId(tx.0 + 1);
    let error = write(store, |repos| {
        repos.put_node_post(&node_post_for(unknown, NodeOutcome::Refused, None))
    })
    .unwrap_err();
    assert!(
        matches!(error, StoreError::UnknownTransaction(id) if id == unknown),
        "{error:?}"
    );

    write(store, |repos| repos.delete_transaction(tx)).unwrap();
    assert_eq!(read(store, |repos| repos.node_post(tx)).unwrap(), None);
}

fn recovery_of(payment: TxId, sent_tx: TxId, received_tx: TxId) -> Recovery {
    Recovery {
        tx_id: payment,
        sent_tx,
        received_tx,
        state: RecoveryState::Uncertain,
        kernel_height: None,
        last_error: None,
        created_at: support::time(50),
        updated_at: support::time(50),
    }
}

fn recoveries_need_their_transactions_and_go_with_the_payment<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let (payment, sent, received, other) = write(store, |repos| {
        Ok::<_, StoreError>((
            repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?,
            repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_B)))?,
            repos.insert_transaction(&transaction(DEFAULT, None))?,
            repos.insert_transaction(&transaction(DEFAULT, None))?,
        ))
    })
    .unwrap();
    assert_eq!(read(store, |repos| repos.recovery(payment)).unwrap(), None);
    assert!(read(store, |repos| repos.recoveries()).unwrap().is_empty());

    let opened = recovery_of(payment, sent, received);
    write(store, |repos| repos.put_recovery(&opened)).unwrap();
    let confirming = Recovery {
        state: RecoveryState::Confirming,
        kernel_height: Some(Height::new(1_000)),
        last_error: Some("refused".to_owned()),
        updated_at: support::time(60),
        ..opened.clone()
    };
    write(store, |repos| repos.put_recovery(&confirming)).unwrap();
    assert_eq!(
        read(store, |repos| repos.recovery(payment)).unwrap(),
        Some(confirming.clone())
    );
    for state in [
        RecoveryState::Posted,
        RecoveryState::Done,
        RecoveryState::Failed,
    ] {
        let moved = Recovery {
            state,
            ..confirming.clone()
        };
        write(store, |repos| repos.put_recovery(&moved)).unwrap();
        assert_eq!(
            read(store, |repos| repos.recovery(payment)).unwrap(),
            Some(moved)
        );
    }
    let second = recovery_of(other, sent, received);
    write(store, |repos| repos.put_recovery(&second)).unwrap();
    assert_eq!(
        read(store, |repos| repos.recoveries())
            .unwrap()
            .iter()
            .map(|recovery| recovery.tx_id)
            .collect::<Vec<_>>(),
        vec![payment, other]
    );

    let long = Recovery {
        last_error: Some("e".repeat(MAX_RECOVERY_ERROR_LEN + 1)),
        ..opened.clone()
    };
    let error = write(store, |repos| repos.put_recovery(&long)).unwrap_err();
    assert!(matches!(error, StoreError::OutOfRange { .. }), "{error:?}");
    let unknown = TxId(other.0 + 1);
    for bad in [
        recovery_of(unknown, sent, received),
        recovery_of(payment, unknown, received),
        recovery_of(payment, sent, unknown),
    ] {
        let error = write(store, |repos| repos.put_recovery(&bad)).unwrap_err();
        assert!(
            matches!(error, StoreError::UnknownTransaction(id) if id == unknown),
            "{error:?}"
        );
    }

    write(store, |repos| repos.delete_transaction(payment)).unwrap();
    assert_eq!(read(store, |repos| repos.recovery(payment)).unwrap(), None);
    write(store, |repos| repos.delete_transaction(received)).unwrap();
    assert!(read(store, |repos| repos.recoveries()).unwrap().is_empty());
}

macro_rules! shared_suite {
    ($backend:ty: $($test:ident),+ $(,)?) => {
        $(
            #[test]
            fn $test() {
                super::$test::<$backend>();
            }
        )+
    };
}

macro_rules! for_each_backend {
    ($($test:ident),+ $(,)?) => {
        mod sqlite {
            shared_suite!(crate::support::SqliteBackend: $($test),+);
        }
        mod memory {
            shared_suite!(crate::support::MemoryBackend: $($test),+);
        }
    };
}

fn tx_record_fixture() -> (TxMarks, TxWatch, OtherWalletSpend, ScanFoundRecord) {
    let marks = TxMarks {
        local_cutoff: Some(Height::new(120)),
        finalized_at: Some(Height::new(100)),
        kernel_absent_at: Some(Height::new(u64::MAX)),
        receive_seen_at: None,
        receive_inputs_unspent: true,
        inputs_spent_elsewhere: false,
        sender_posted_at: Some(Timestamp::from_nanosecond(1_727_000_000_123_456_789).unwrap()),
        withdrawn_answered: true,
        sender_cancelled_at: Some(Timestamp::from_nanosecond(1_727_000_100_987_654_321).unwrap()),
        cancelled_answered: true,
    };
    let watch = TxWatch {
        phase: WatchPhase::Kernel,
        excess: [0x08; 33],
        min_height: Height::new(90),
        ended_at: Height::new(1_530),
        outputs: vec![
            WatchedOutput {
                commitment: [0x09; 33],
                key_id: KeyId([3; 17]),
                amount: Amount::new(u64::MAX),
            },
            WatchedOutput {
                commitment: [0x08; 33],
                key_id: KeyId([4; 17]),
                amount: Amount::new(1),
            },
        ],
    };
    let spend = OtherWalletSpend {
        after: Height::new(10),
        to: Height::new(20),
        open: true,
        spent: vec![[0x09; 33], [0x08; 33]],
        change: vec![[0x08; 33]],
    };
    let found = ScanFoundRecord {
        output: Some([0x09; 33]),
        during: Some(FoundDuring::Restore),
        dated_by_block: true,
    };
    (marks, watch, spend, found)
}

fn transaction_records_round_trip_and_are_replaced<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let (marks, watch, spend, found) = tx_record_fixture();
    let (first, second) = write(store, |repos| {
        let first = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?;
        let second = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_B)))?;
        repos.put_tx_marks(first, &marks)?;
        repos.put_tx_watch(second, &watch)?;
        repos.put_tx_watch(first, &watch)?;
        repos.put_other_wallet_spend(first, &spend)?;
        repos.put_scan_found(first, &found)?;
        Ok((first, second))
    })
    .unwrap();
    let stored = read(store, |repos| {
        Ok((
            repos.tx_marks(first)?,
            repos.tx_marks(second)?,
            repos.tx_watch(first)?,
            repos.tx_watches()?,
            repos.other_wallet_spend(first)?,
            repos.other_wallet_spends()?,
            repos.scan_found(first)?,
            repos.scan_found(second)?,
        ))
    })
    .unwrap();
    assert_eq!(stored.0, marks);
    assert_eq!(stored.1, TxMarks::default());
    assert_eq!(stored.2.as_ref(), Some(&watch));
    assert_eq!(
        stored.3,
        vec![(first, watch.clone()), (second, watch.clone())]
    );
    assert_eq!(stored.4.as_ref(), Some(&spend));
    assert_eq!(stored.5, vec![(first, spend.clone())]);
    assert_eq!(stored.6, Some(found));
    assert_eq!(stored.7, None);

    let moved = TxWatch {
        phase: WatchPhase::Outputs,
        outputs: vec![watch.outputs[1]],
        ..watch.clone()
    };
    let closed = OtherWalletSpend {
        open: false,
        change: Vec::new(),
        ..spend.clone()
    };
    let received = ScanFoundRecord {
        during: None,
        dated_by_block: false,
        ..found
    };
    write(store, |repos| {
        repos.put_tx_watch(first, &moved)?;
        repos.delete_tx_watch(second)?;
        repos.put_other_wallet_spend(first, &closed)?;
        repos.put_scan_found(first, &received)?;
        repos.put_tx_marks(first, &TxMarks::default())
    })
    .unwrap();
    let stored = read(store, |repos| {
        Ok((
            repos.tx_watches()?,
            repos.other_wallet_spend(first)?,
            repos.scan_found(first)?,
            repos.tx_marks(first)?,
        ))
    })
    .unwrap();
    assert_eq!(stored.0, vec![(first, moved)]);
    assert_eq!(stored.1, Some(closed));
    assert_eq!(stored.2, Some(received));
    assert_eq!(stored.3, TxMarks::default());
}

fn transaction_records_need_their_transaction_and_go_with_it<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let (marks, watch, spend, found) = tx_record_fixture();
    let missing = TxId(9);
    let refused = [
        write(store, |repos| repos.put_tx_marks(missing, &marks)),
        write(store, |repos| repos.put_tx_watch(missing, &watch)),
        write(store, |repos| repos.put_other_wallet_spend(missing, &spend)),
        write(store, |repos| repos.put_scan_found(missing, &found)),
    ];
    for result in refused {
        assert!(matches!(
            result,
            Err(StoreError::UnknownTransaction(TxId(9)))
        ));
    }

    let (id, kept) = write(store, |repos| {
        let id = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?;
        let kept = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_B)))?;
        for tx in [id, kept] {
            repos.put_tx_marks(tx, &marks)?;
            repos.put_tx_watch(tx, &watch)?;
            repos.put_other_wallet_spend(tx, &spend)?;
            repos.put_scan_found(tx, &found)?;
        }
        Ok((id, kept))
    })
    .unwrap();
    write(store, |repos| repos.delete_transaction(id)).unwrap();
    let after = read(store, |repos| {
        Ok((
            repos.tx_marks(id)?,
            repos.tx_watch(id)?,
            repos.other_wallet_spend(id)?,
            repos.scan_found(id)?,
            repos.tx_watches()?.len(),
            repos.other_wallet_spends()?.len(),
            repos.tx_marks(kept)?,
        ))
    })
    .unwrap();
    assert_eq!(after.0, TxMarks::default());
    assert_eq!(after.1, None);
    assert_eq!(after.2, None);
    assert_eq!(after.3, None);
    assert_eq!(
        (after.4, after.5),
        (1, 1),
        "the other entry keeps its records"
    );
    assert_eq!(after.6, marks);

    // A new entry never inherits the records of a deleted one.
    let next = write(store, |repos| {
        repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))
    })
    .unwrap();
    assert_ne!(next, id);
    assert_eq!(read(store, |repos| repos.tx_watch(next)).unwrap(), None);
}

fn contact_links_are_replaced_and_a_transactions_goes_with_it<B: Backend>() {
    let backend = with_default_account::<B>();
    let store = backend.store();
    let (first, second) = (contact_id(1), contact_id(2));
    let tx = write(store, |repos| {
        let tx = repos.insert_transaction(&transaction(DEFAULT, Some(SLATE_A)))?;
        repos.set_slate_contact(SLATE_A, first)?;
        repos.set_slate_contact(SLATE_A, second)?;
        repos.set_tx_contact(tx, first)?;
        Ok(tx)
    })
    .unwrap();
    let links = |store: &B::Store| {
        read(store, |repos| {
            Ok((
                repos.slate_contact(SLATE_A)?,
                repos.slate_contact(SLATE_B)?,
                repos.tx_contact(tx)?,
            ))
        })
        .unwrap()
    };
    assert_eq!(links(store), (Some(second), None, Some(first)));
    assert!(matches!(
        write(store, |repos| repos.set_tx_contact(TxId(9), first)),
        Err(StoreError::UnknownTransaction(TxId(9)))
    ));

    write(store, |repos| repos.delete_transaction(tx)).unwrap();
    assert_eq!(
        links(store),
        (Some(second), None, None),
        "the slate stays taken"
    );
}

for_each_backend!(
    accounts_round_trip_in_index_order,
    put_account_replaces_label_and_child_counter,
    rejects_label_used_by_another_account,
    outputs_round_trip_and_filter_by_account_and_status,
    put_output_replaces_and_delete_removes,
    insert_output_refuses_a_stored_commitment_and_keeps_it,
    rejects_output_for_unknown_account_or_transaction,
    outputs_by_touch_lists_the_least_recently_touched_first,
    outputs_of_transaction_lists_linked_outputs,
    transactions_get_sequential_ids_and_round_trip,
    a_deleted_transactions_id_is_never_handed_out_again,
    update_transaction_replaces_entry,
    slate_id_is_unique_per_direction,
    rejects_transaction_for_unknown_account,
    rejects_timestamp_outside_storable_range,
    slates_are_stored_once_per_stage,
    contexts_round_trip_replace_and_delete,
    private_contexts_cannot_be_read_without_the_key,
    inbox_entries_are_replaced_by_message_id,
    outbox_entries_are_queued_updated_and_deleted,
    settings_are_replaced_and_deleted,
    failed_write_leaves_every_repository_unchanged,
    store_error_inside_write_rolls_back_earlier_changes,
    write_sees_its_own_changes_and_commits_them_together,
    fee_and_amount_extremes_round_trip,
    confirmed_height_is_recorded_and_survives_updates,
    confirmed_from_lists_recent_confirmations_and_a_cleared_height_drops_out,
    counterparty_is_recorded_and_survives_updates,
    receive_listing_is_recorded_and_survives_updates,
    open_receipts_lists_answered_incoming_payments_oldest_first,
    transactions_in_state_counts_every_account_and_lists_the_oldest_first,
    transactions_before_walks_newest_first_and_ends_on_a_whole_millisecond,
    delete_transaction_removes_an_unlinked_entry_only,
    pending_invoices_round_trip_oldest_first,
    rejects_a_second_invoice_with_the_same_slate_id,
    pending_invoice_status_changes_and_delete_removes,
    park_invoice_accepts_only_a_parked_invoice,
    pending_invoice_status_moves_only_from_parked_to_paid_or_declined,
    a_settled_invoice_cannot_return_past_the_per_sender_cap,
    parking_stops_at_the_per_sender_cap,
    parking_stops_at_the_total_cap,
    pending_invoice_bytes_cannot_be_read_without_the_key,
    contacts_round_trip_and_are_found_by_every_lookup,
    put_contact_replaces_by_id_and_keeps_the_peer_key_unique,
    contacts_stop_at_the_cap,
    mailboxes_need_their_contact_and_go_with_it,
    settings_beside_a_contact_go_once_nothing_holds_its_id,
    updates_keep_a_contacts_mailbox_and_backoff,
    seen_envelopes_are_remembered_and_forgotten_by_age,
    pairings_round_trip_with_their_secrets_and_are_found_by_invite,
    pairing_secrets_cannot_be_read_without_the_key,
    pending_pairings_stop_at_the_cap,
    answered_invites_leave_the_pending_cap,
    a_pairing_that_cannot_be_opened_counts_as_waiting,
    contact_backup_round_trips_without_secrets_and_flags_imports,
    slots_count_up_per_account_from_the_callers_start,
    slots_run_out_at_65536,
    twin_records_share_a_slot_but_not_a_peer_key,
    contact_backup_rejects_unknown_versions_and_malformed_records,
    contact_backup_refuses_the_other_network,
    contact_backup_takes_card_fields_from_the_card_bytes,
    api_event_ids_rise_and_are_not_reused_after_a_prune,
    api_events_are_read_after_an_id_with_a_limit_and_a_kind_filter,
    api_event_inputs_are_bounded,
    a_deleted_api_request_can_be_recorded_again,
    api_requests_are_stored_once_and_pruned_by_time,
    imported_transactions_round_trip_and_are_replaced,
    imported_records_need_their_transaction_and_bounded_messages,
    imported_outputs_are_found_by_commitment_and_status,
    deleting_a_transaction_removes_what_was_imported_with_it,
    transaction_records_round_trip_and_are_replaced,
    transaction_records_need_their_transaction_and_go_with_it,
    contact_links_are_replaced_and_a_transactions_goes_with_it,
    pairing_facts_round_trip_and_are_found_by_payments_key,
    cancelled_pairings_have_a_cap_of_their_own,
    contact_backup_leaves_out_ended_and_unheard_records,
    facts_round_trip_domain,
    backup_round_trips_domain,
    backup_v1_without_domain_imports,
    watch_rows_are_replaced_listed_by_relay_and_expire,
    native_outbox_lists_by_payment_and_due_time,
    native_outbox_is_listed_redirected_and_dropped_by_sender,
    outbox_copies_are_replaced_listed_when_due_and_go_with_their_entry,
    payment_delivery_is_found_by_id_and_alias_and_aliases_stay_unique,
    node_posts_need_their_transaction_and_go_with_it,
    recoveries_need_their_transactions_and_go_with_the_payment,
);

#[test]
fn context_key_is_not_needed_to_read_other_records() {
    let backend = <support::SqliteBackend as Backend>::create(context_key(1));
    write(backend.store(), |repos| repos.put_setting("k", "v")).unwrap();
    let other = context_key(2);
    let reopened = backend.reopen(other);
    assert_eq!(
        read(&reopened, |repos| repos.setting("k"))
            .unwrap()
            .as_deref(),
        Some("v")
    );
}
