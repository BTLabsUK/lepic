// SPDX-License-Identifier: Apache-2.0
//! One behavioural suite, run against the SQLite and the in-memory store.

// Test code may unwrap, index and use plain arithmetic (docs/rules.md); clippy's test
// exemptions do not reach helpers outside `#[test]` functions.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_store::{
    AccountIndex, AccountRecord, ApiRequest, CONTACT_SLOT_COUNT, ChainCheck, ContactCap,
    ContactOutboxState, ContactState, DomainClaimBytes, FoundDuring, ImportSummary, ImportedKind,
    ImportedMessage, ImportedOutput, ImportedOutputStatus, ImportedTransaction, InboxEntry,
    InboxStatus, InvoiceAddressIndex, InvoiceCap, KeyId, MAX_CANCELLED_PAIRINGS, MAX_CONTACTS,
    MAX_IMPORTED_MESSAGE_BYTES, MAX_PARKED_INVOICES, MAX_PARKED_INVOICES_PER_SENDER,
    MAX_PENDING_PAIRINGS, OpenReceipt, OtherWalletSpend, OutboxEntry, OutboxId, OutboxStatus,
    OutputStatus, PRIVATE_SLOT_END, PairRequest, PairingEndReason, PairingFacts, PairingId,
    PairingState, ParticipantId, PeerCard, PeerCompat, PeerPin, PendingInvoiceStatus,
    PrivateContext, Record, Repositories, ScanFoundRecord, SealMode, SlateStage, StatusKind,
    StatusNotice, StoreError, TransactionEntry, TxDirection, TxId, TxMarks, TxState, TxWatch,
    WalletStore, WatchPhase, WatchedOutput, export_contacts, import_contacts,
};
use uuid::Uuid;

use support::{
    Backend, account, contact, contact_id, contact_mailbox, contact_outbox_entry, context_key,
    invoice, invoice_id, output, pairing, peer_card, peer_key, slate, transaction,
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
        repos.put_setting("helm.a", "3")
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.settings_with_prefix("held.")).unwrap(),
        vec![
            ("held.a".to_owned(), "1".to_owned()),
            ("held.b".to_owned(), "2".to_owned()),
        ]
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
        repos.put_peer_compat(
            &peer_key(1),
            &PeerCompat {
                last_marked_at: Some(support::time(1)),
                ..PeerCompat::default()
            },
        )?;
        repos.set_invoice_address_index(InvoiceAddressIndex::FIRST)?;
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
            && repos.contacts()?.is_empty()
            && repos.peer_compat(&peer_key(1))?.is_none()
            && repos.invoice_address_index()?.is_none())
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

fn prune_removes_only_parked_invoices_received_before_the_cutoff<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let pruned = write(store, |repos| {
        repos.park_invoice(&invoice(invoice_id(1), 1, 10))?;
        repos.park_invoice(&invoice(invoice_id(2), 1, 10))?;
        repos.set_pending_invoice_status(invoice_id(2), PendingInvoiceStatus::Paid)?;
        repos.park_invoice(&invoice(invoice_id(3), 2, 99))?;
        repos.park_invoice(&invoice(invoice_id(4), 2, 100))?;
        repos.prune_parked_invoices(support::time(100))
    })
    .unwrap();
    assert_eq!(pruned, 2);
    let kept: Vec<_> = read(store, |repos| repos.pending_invoices())
        .unwrap()
        .into_iter()
        .map(|kept| kept.slate_id)
        .collect();
    assert_eq!(kept, vec![invoice_id(2), invoice_id(4)]);
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

fn invoice_address_index_is_unset_until_set_then_replaced<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    assert_eq!(
        read(store, |repos| repos.invoice_address_index()).unwrap(),
        None
    );
    let last = InvoiceAddressIndex::new(u32::MAX).unwrap();
    write(store, |repos| {
        repos.set_invoice_address_index(InvoiceAddressIndex::FIRST)?;
        repos.set_invoice_address_index(last)
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.invoice_address_index()).unwrap(),
        Some(last)
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
        assert_eq!(
            repos.contact_by_peer_hint_key(&card.hint_key)?,
            Some(first.clone())
        );
        assert_eq!(repos.contact_by_peer_sig_key(&[77; 32])?, None);
        assert_eq!(
            repos.contacts()?,
            vec![waiting.clone(), first.clone(), contact(3, 9)]
        );
        assert_eq!(repos.contacts_allowing_invoices()?, vec![first.clone()]);
        // Current and previous mailboxes both find the contact.
        let current = repos.contacts_by_our_mailbox("our1@relay.example:443")?;
        let previous = repos.contacts_by_our_mailbox("oldour1@old.example:443")?;
        assert_eq!(current, vec![first.clone()]);
        assert_eq!(previous, vec![first.clone()]);
        assert!(
            repos
                .contacts_by_our_mailbox("nobody@relay.example")?
                .is_empty()
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
        repos.enqueue_contact_outbox(&contact_outbox_entry(1, 5))?;
        Ok((
            repos.delete_contact(contact_id(1))?,
            repos.delete_contact(contact_id(1))?,
        ))
    })
    .unwrap();
    assert_eq!(removed, (true, false));
    read(store, |repos| {
        assert_eq!(repos.contact_mailbox(contact_id(1))?, None);
        assert!(repos.contact_outbox(contact_id(1))?.is_empty());
        Ok(())
    })
    .unwrap();
}

/// Updating a contact, its mailbox or its pairing changes that row in place: the contact's
/// mailbox, relay backoff and outbox entries survive, as they would not if the row were
/// deleted and inserted again with its cascades.
fn updates_keep_a_contacts_mailbox_backoff_and_outbox<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    write(store, |repos| {
        repos.put_contact(&contact(1, 1))?;
        repos.put_contact_mailbox(&contact_mailbox(1))?;
        repos.put_pending_pairing(&pairing(1, 1))?;
        repos.enqueue_contact_outbox(&contact_outbox_entry(1, 5))?;
        Ok(())
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
        assert_eq!(repos.contact_outbox(contact_id(1))?.len(), 1);
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
        assert_eq!(repos.contact_outbox(contact_id(1))?.len(), 1);
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

    let (pruned, left) = write(store, |repos| {
        Ok((
            repos.prune_expired_pairings(support::time(610))?,
            repos.pending_pairings()?,
        ))
    })
    .unwrap();
    assert_eq!((pruned, left), (1, vec![reply]));
    let removed = write(store, |repos| {
        Ok((
            repos.delete_pending_pairing(PairingId([2; 16]))?,
            repos.delete_pending_pairing(PairingId([2; 16]))?,
        ))
    })
    .unwrap();
    assert_eq!(removed, (true, false));
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

fn pair_request(n: u8, received: i64) -> PairRequest {
    PairRequest {
        sender_key: [n; 33],
        sender_address: format!("sender{n}@relay.example"),
        invite_id: [n; 8],
        invite: vec![n; 30],
        expires_at: support::time(received + 600),
        received_at: support::time(received),
        dismissed_at: None,
        answered_at: None,
    }
}

fn pair_requests_are_kept_one_per_sender_key<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut newer = pair_request(1, 30);
    newer.invite_id = [9; 8];
    write(store, |repos| {
        repos.put_pair_request(&pair_request(1, 20))?;
        repos.put_pair_request(&pair_request(2, 10))?;
        repos.put_pair_request(&newer)
    })
    .unwrap();
    read(store, |repos| {
        assert_eq!(
            repos.pair_requests()?,
            vec![pair_request(2, 10), newer.clone()]
        );
        assert_eq!(repos.pair_request(&[1; 33])?, Some(newer.clone()));
        assert_eq!(repos.pair_request_by_invite(&[9; 8])?, Some(newer.clone()));
        assert_eq!(repos.pair_request_by_invite(&[1; 8])?, None);
        Ok(())
    })
    .unwrap();
    let mut dismissed = newer.clone();
    dismissed.dismissed_at = Some(support::time(40));
    write(store, |repos| repos.put_pair_request(&dismissed)).unwrap();
    assert!(
        !read(store, |repos| repos.pair_request(&[1; 33]))
            .unwrap()
            .unwrap()
            .live()
    );
    assert!(write(store, |repos| repos.delete_pair_request(&[2; 33])).unwrap());
    assert!(!write(store, |repos| repos.delete_pair_request(&[2; 33])).unwrap());
    assert_eq!(
        read(store, |repos| repos.pair_requests()).unwrap(),
        vec![dismissed]
    );
}

fn status_notice(n: u8, next_try: i64) -> StatusNotice {
    StatusNotice {
        contact_id: contact_id(n),
        kind: StatusKind::Mismatch,
        payload: format!("payload {n}"),
        destination: format!("peer{n}@relay.example:443"),
        attempts: 0,
        next_try_at: support::time(next_try),
        created_at: support::time(1),
        expires_at: support::time(7 * 86_400),
        delivered_at: None,
    }
}

fn status_notices_list_due_ones_and_outlive_their_contact<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let (late, soon, later) = write(store, |repos| {
        repos.put_contact(&contact(1, 1))?;
        Ok((
            repos.enqueue_status_notice(&status_notice(1, 90))?,
            repos.enqueue_status_notice(&status_notice(1, 50))?,
            repos.enqueue_status_notice(&status_notice(2, 500))?,
        ))
    })
    .unwrap();
    let due = |at| {
        read(store, |repos| repos.due_status_notices(support::time(at)))
            .unwrap()
            .iter()
            .map(|stored| stored.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(due(100), vec![soon, late]);
    let mut delivered = status_notice(1, 50);
    delivered.delivered_at = Some(support::time(60));
    delivered.attempts = 1;
    write(store, |repos| {
        repos.update_status_notice(soon, &delivered)?;
        repos.delete_contact(contact_id(1))
    })
    .unwrap();
    assert_eq!(due(1000), vec![late, later]);
    let kept = read(store, |repos| repos.status_notices(contact_id(1))).unwrap();
    assert_eq!(
        kept.len(),
        2,
        "a verdict goes out after the contact was removed"
    );
    assert_eq!(kept[1].notice, delivered);
    write(store, |repos| repos.delete_status_notice(late)).unwrap();
    assert_eq!(due(1000), vec![later]);
    assert!(matches!(
        write(store, |repos| repos
            .update_status_notice(late, &status_notice(1, 1))),
        Err(StoreError::NotFound {
            record: Record::StatusNotice
        })
    ));
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

fn contact_outbox_lists_due_entries_and_follows_a_home_relay_move<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let now = support::time(100);
    let (late, soon, later, id_delivered) = write(store, |repos| {
        repos.put_contact(&contact(1, 1))?;
        repos.put_contact(&contact(2, 1))?;
        let late = repos.enqueue_contact_outbox(&contact_outbox_entry(1, 90))?;
        let soon = repos.enqueue_contact_outbox(&contact_outbox_entry(1, 50))?;
        let later = repos.enqueue_contact_outbox(&contact_outbox_entry(2, 500))?;
        let mut delivered = contact_outbox_entry(2, 10);
        delivered.state = ContactOutboxState::Delivered;
        delivered.delivered_at = Some(support::time(11));
        let id_delivered = repos.enqueue_contact_outbox(&delivered)?;
        Ok((late, soon, later, id_delivered))
    })
    .unwrap();
    assert_eq!(
        read(store, |repos| repos.due_contact_outbox(now))
            .unwrap()
            .iter()
            .map(|stored| stored.id)
            .collect::<Vec<_>>(),
        vec![soon, late]
    );

    let changed = write(store, |repos| {
        repos.redirect_contact_outbox(contact_id(2), "peer2@new.example:443")
    })
    .unwrap();
    assert_eq!(changed, 1);
    read(store, |repos| {
        let moved = repos.contact_outbox_entry(later)?.unwrap();
        assert_eq!(moved.entry.destination, "peer2@new.example:443");
        let delivered = repos.contact_outbox_entry(id_delivered)?.unwrap();
        assert_eq!(delivered.entry.destination, "peer2@relay.example:443");
        Ok(())
    })
    .unwrap();

    let mut sent = read(store, |repos| repos.contact_outbox_entry(soon))
        .unwrap()
        .unwrap()
        .entry;
    sent.state = ContactOutboxState::Delivered;
    sent.attempts = 2;
    sent.delivered_at = Some(now);
    write(store, |repos| repos.update_contact_outbox(soon, &sent)).unwrap();
    assert_eq!(
        read(store, |repos| repos.contact_outbox_entry(soon))
            .unwrap()
            .unwrap()
            .entry,
        sent
    );
    assert_eq!(
        read(store, |repos| repos.contact_outbox(contact_id(1)))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        read(store, |repos| repos.due_contact_outbox(now))
            .unwrap()
            .len(),
        1
    );
    let missing = write(store, |repos| {
        repos.update_contact_outbox(lepic_store::ContactOutboxId(999), &sent)
    })
    .unwrap_err();
    assert!(matches!(
        missing,
        StoreError::NotFound {
            record: Record::ContactOutbox
        }
    ));
    write(store, |repos| repos.delete_contact_outbox(late)).unwrap();
    assert_eq!(
        read(store, |repos| repos.contact_outbox_entry(late)).unwrap(),
        None
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

/// What is known of each peer key stays out of the contact backup: a restore relearns it.
fn contact_backup_carries_nothing_known_of_peer_keys<B: Backend>() {
    let source = B::create(context_key(1));
    let compat = PeerCompat {
        last_marked_at: Some(support::time(1)),
        last_unmarked_at: Some(support::time(2)),
        claimed: 0b11,
        works: 0b1,
        features_at: Some(support::time(1)),
        native_key: None,
    };
    write(source.store(), |repos| {
        repos.put_contact(&contact(1, 1))?;
        repos.put_contact_mailbox(&contact_mailbox(1))?;
        repos.put_peer_compat(&peer_key(7), &compat)
    })
    .unwrap();
    let json = read(source.store(), |repos| {
        export_contacts(repos, Network::Floonet)
    })
    .unwrap();
    assert!(!json.contains(&peer_key(7)));
    assert!(!json.contains("marked") && !json.contains("claimed") && !json.contains("works"));

    // The same keys, so a row that came along would be found.
    let restored = B::create(context_key(1));
    let summary = write(restored.store(), |repos| import(repos, &json)).unwrap();
    assert_eq!(summary.imported, 1);
    assert_eq!(
        read(restored.store(), |repos| repos.peer_compat(&peer_key(7))).unwrap(),
        None
    );
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

fn peer_compat_is_replaced_by_later_evidence<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let stock = PeerCompat {
        last_unmarked_at: Some(support::time(1)),
        ..PeerCompat::default()
    };
    let lepic = PeerCompat {
        last_marked_at: Some(support::time(2)),
        claimed: 0b11,
        works: 0b1,
        features_at: Some(support::time(2)),
        ..stock
    };
    write(store, |repos| repos.put_peer_compat(&peer_key(1), &stock)).unwrap();
    assert_eq!(
        read(store, |repos| repos.peer_compat(&peer_key(1))).unwrap(),
        Some(stock)
    );
    write(store, |repos| repos.put_peer_compat(&peer_key(1), &lepic)).unwrap();
    let (found, unknown) = read(store, |repos| {
        Ok((
            repos.peer_compat(&peer_key(1))?,
            repos.peer_compat(&peer_key(2))?,
        ))
    })
    .unwrap();
    assert_eq!(found, Some(lepic));
    assert_eq!(unknown, None);
}

/// Rows are found by a keyed hash of the peer key: under another peer tag key, no row is found.
fn peer_compat_is_found_only_under_its_tag_key<B: Backend>() {
    let backend = B::create(context_key(1));
    let compat = PeerCompat {
        last_marked_at: Some(support::time(1)),
        ..PeerCompat::default()
    };
    write(backend.store(), |repos| {
        repos.put_peer_compat(&peer_key(1), &compat)
    })
    .unwrap();
    let other = backend.reopen(context_key(2));
    assert_eq!(
        read(&other, |repos| repos.peer_compat(&peer_key(1))).unwrap(),
        None
    );
    let same = backend.reopen(context_key(1));
    assert_eq!(
        read(&same, |repos| repos.peer_compat(&peer_key(1))).unwrap(),
        Some(compat)
    );
}

fn forget_peers_deletes_rows_whose_newest_date_is_older<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let day = 24 * 60 * 60;
    let now = support::time(400 * day);
    let days_ago = |days: i64| Some(support::time((400 - days) * day));
    let rows = [
        (
            1,
            PeerCompat {
                last_marked_at: days_ago(181),
                ..PeerCompat::default()
            },
        ),
        (
            2,
            PeerCompat {
                last_marked_at: days_ago(179),
                ..PeerCompat::default()
            },
        ),
        (
            3,
            PeerCompat {
                last_marked_at: days_ago(300),
                last_unmarked_at: days_ago(10),
                ..PeerCompat::default()
            },
        ),
        (4, PeerCompat::default()),
    ];
    write(store, |repos| {
        for (n, compat) in &rows {
            repos.put_peer_compat(&peer_key(*n), compat)?;
        }
        Ok(())
    })
    .unwrap();
    let cutoff = support::time(220 * day);
    assert_eq!(now.duration_since(cutoff).as_secs(), 180 * day);

    let forgotten = write(store, |repos| repos.forget_peers(cutoff)).unwrap();

    assert_eq!(forgotten, 2);
    let left = read(store, |repos| {
        (1..=4)
            .map(|n| repos.peer_compat(&peer_key(n)).map(|row| row.is_some()))
            .collect::<Result<Vec<_>, _>>()
    })
    .unwrap();
    assert_eq!(left, [false, true, true, false]);
    assert_eq!(
        write(store, |repos| repos.forget_peers(cutoff)).unwrap(),
        0,
        "forgetting again deletes nothing"
    );
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

fn peer_pins_are_kept_per_account_and_origin<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let pin = |account: u32, origin: &str, key: u8, seen: i64| PeerPin {
        account: AccountIndex(account),
        origin: origin.to_owned(),
        seal_key: [key; 32],
        first_seen: support::time(1),
        last_seen: support::time(seen),
    };
    let web = "https://wallet.example:443";
    let onion = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    write(store, |repos| {
        repos.put_peer_pin(&pin(0, web, 1, 1))?;
        repos.put_peer_pin(&pin(0, onion, 2, 1))?;
        repos.put_peer_pin(&pin(1, web, 3, 1))?;
        repos.put_peer_pin(&pin(0, web, 1, 5))
    })
    .unwrap();
    let (found, other_account, listed, missing) = read(store, |repos| {
        Ok((
            repos.peer_pin(DEFAULT, web)?,
            repos.peer_pin(AccountIndex(1), web)?,
            repos.peer_pins(DEFAULT)?,
            repos.peer_pin(DEFAULT, "http://wallet.example:80")?,
        ))
    })
    .unwrap();
    assert_eq!(found, Some(pin(0, web, 1, 5)));
    assert_eq!(other_account, Some(pin(1, web, 3, 1)));
    assert_eq!(listed, vec![pin(0, web, 1, 5), pin(0, onion, 2, 1)]);
    assert_eq!(missing, None);

    let (forgot, again) = write(store, |repos| {
        Ok((
            repos.forget_peer_pin(DEFAULT, web)?,
            repos.forget_peer_pin(DEFAULT, web)?,
        ))
    })
    .unwrap();
    assert!(forgot);
    assert!(!again);
    let (gone, kept) = read(store, |repos| {
        Ok((
            repos.peer_pin(DEFAULT, web)?,
            repos.peer_pin(AccountIndex(1), web)?,
        ))
    })
    .unwrap();
    assert_eq!(gone, None);
    assert_eq!(kept, Some(pin(1, web, 3, 1)));

    for origin in [String::new(), "a".repeat(301)] {
        let error = write(store, |repos| repos.put_peer_pin(&pin(0, &origin, 1, 1))).unwrap_err();
        assert!(
            matches!(
                error,
                StoreError::OutOfRange {
                    field: "pin origin"
                }
            ),
            "{error:?}"
        );
    }
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
        answer_marked: true,
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
    counterparty_is_recorded_and_survives_updates,
    receive_listing_is_recorded_and_survives_updates,
    open_receipts_lists_answered_incoming_payments_oldest_first,
    delete_transaction_removes_an_unlinked_entry_only,
    pending_invoices_round_trip_oldest_first,
    rejects_a_second_invoice_with_the_same_slate_id,
    pending_invoice_status_changes_and_delete_removes,
    park_invoice_accepts_only_a_parked_invoice,
    pending_invoice_status_moves_only_from_parked_to_paid_or_declined,
    a_settled_invoice_cannot_return_past_the_per_sender_cap,
    parking_stops_at_the_per_sender_cap,
    parking_stops_at_the_total_cap,
    prune_removes_only_parked_invoices_received_before_the_cutoff,
    pending_invoice_bytes_cannot_be_read_without_the_key,
    invoice_address_index_is_unset_until_set_then_replaced,
    contacts_round_trip_and_are_found_by_every_lookup,
    put_contact_replaces_by_id_and_keeps_the_peer_key_unique,
    contacts_stop_at_the_cap,
    mailboxes_need_their_contact_and_go_with_it,
    updates_keep_a_contacts_mailbox_backoff_and_outbox,
    seen_envelopes_are_remembered_and_forgotten_by_age,
    pairings_round_trip_with_their_secrets_and_are_found_by_invite,
    pairing_secrets_cannot_be_read_without_the_key,
    pending_pairings_stop_at_the_cap,
    contact_outbox_lists_due_entries_and_follows_a_home_relay_move,
    contact_backup_round_trips_without_secrets_and_flags_imports,
    contact_backup_carries_nothing_known_of_peer_keys,
    slots_count_up_per_account_from_the_callers_start,
    slots_run_out_at_65536,
    twin_records_share_a_slot_but_not_a_peer_key,
    contact_backup_rejects_unknown_versions_and_malformed_records,
    contact_backup_refuses_the_other_network,
    contact_backup_takes_card_fields_from_the_card_bytes,
    peer_compat_is_replaced_by_later_evidence,
    peer_compat_is_found_only_under_its_tag_key,
    forget_peers_deletes_rows_whose_newest_date_is_older,
    peer_pins_are_kept_per_account_and_origin,
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
    pair_requests_are_kept_one_per_sender_key,
    status_notices_list_due_ones_and_outlive_their_contact,
    contact_backup_leaves_out_ended_and_unheard_records,
    facts_round_trip_domain,
    backup_round_trips_domain,
    backup_v1_without_domain_imports,
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
