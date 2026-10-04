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
use lepic_store::{
    AccountIndex, AccountRecord, ContextKey, InboxEntry, InboxStatus, InvoiceAddressIndex,
    InvoiceCap, MAX_PARKED_INVOICES, MAX_PARKED_INVOICES_PER_SENDER, OutboxEntry, OutboxId,
    OutboxStatus, OutputStatus, ParticipantId, PeerCapability, PeerSupport, PendingInvoiceStatus,
    PrivateContext, Record, Repositories, SlateStage, StoreError, TxDirection, TxId, TxState,
    WalletStore,
};
use uuid::Uuid;

use support::{
    Backend, account, allowed_peer, context_key, invoice, invoice_id, output, peer_key, slate,
    transaction,
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
    let (stages, one, missing) = read(store, |repos| {
        Ok((
            repos.slates(SLATE_A)?,
            repos.slate(SLATE_A, SlateStage::Standard2)?,
            repos.slate(SLATE_A, SlateStage::Standard3)?,
        ))
    })
    .unwrap();
    assert_eq!(stages, vec![s1, s2.clone()]);
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
        repos.put_allowed_peer(&allowed_peer(1, 1))?;
        repos.put_peer_capability(&PeerCapability {
            key: peer_key(1),
            support: PeerSupport::Lepic,
            learned_at: support::time(1),
        })?;
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
            && repos.allowed_peers()?.is_empty()
            && repos.peer_capability(&peer_key(1))?.is_none()
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
    paid.status = PendingInvoiceStatus::Paid;
    paid.codec = "legacy-v2".to_owned();
    write(store, |repos| {
        repos.park_invoice(&newest)?;
        repos.park_invoice(&oldest)?;
        repos.park_invoice(&paid)
    })
    .unwrap();
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
    let mut paid = invoice(invoice_id(total), fresh_sender, 0);
    paid.status = PendingInvoiceStatus::Paid;
    write(store, |repos| repos.park_invoice(&paid)).unwrap();
    let stored = read(store, |repos| repos.pending_invoices()).unwrap();
    assert_eq!(stored.len(), MAX_PARKED_INVOICES + 1);
}

fn prune_removes_only_parked_invoices_received_before_the_cutoff<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut old_paid = invoice(invoice_id(2), 1, 10);
    old_paid.status = PendingInvoiceStatus::Paid;
    let pruned = write(store, |repos| {
        repos.park_invoice(&invoice(invoice_id(1), 1, 10))?;
        repos.park_invoice(&old_paid)?;
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

fn allowed_peers_are_replaced_by_key_listed_in_order_and_removed<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let mut moved = allowed_peer(1, 5);
    moved.address = format!("{}@other.example:13420", peer_key(1));
    moved.label = "renamed".to_owned();
    write(store, |repos| {
        repos.put_allowed_peer(&allowed_peer(1, 5))?;
        repos.put_allowed_peer(&allowed_peer(2, 1))?;
        repos.put_allowed_peer(&moved)
    })
    .unwrap();
    let (all, found, missing) = read(store, |repos| {
        Ok((
            repos.allowed_peers()?,
            repos.allowed_peer(&peer_key(1))?,
            repos.allowed_peer(&peer_key(3))?,
        ))
    })
    .unwrap();
    assert_eq!(all, vec![allowed_peer(2, 1), moved.clone()]);
    assert_eq!(found, Some(moved));
    assert_eq!(missing, None);
    let removed = write(store, |repos| {
        Ok((
            repos.remove_allowed_peer(&peer_key(1))?,
            repos.remove_allowed_peer(&peer_key(1))?,
        ))
    })
    .unwrap();
    assert_eq!(removed, (true, false));
    assert_eq!(
        read(store, |repos| repos.allowed_peers()).unwrap(),
        vec![allowed_peer(2, 1)]
    );
}

fn peer_capability_is_replaced_by_later_evidence<B: Backend>() {
    let backend = B::create(context_key(1));
    let store = backend.store();
    let stock = PeerCapability {
        key: peer_key(1),
        support: PeerSupport::NoInvoices,
        learned_at: support::time(1),
    };
    let lepic = PeerCapability {
        support: PeerSupport::Lepic,
        learned_at: support::time(2),
        ..stock.clone()
    };
    write(store, |repos| repos.put_peer_capability(&stock)).unwrap();
    assert_eq!(
        read(store, |repos| repos.peer_capability(&peer_key(1))).unwrap(),
        Some(stock)
    );
    write(store, |repos| repos.put_peer_capability(&lepic)).unwrap();
    let (found, unknown) = read(store, |repos| {
        Ok((
            repos.peer_capability(&peer_key(1))?,
            repos.peer_capability(&peer_key(2))?,
        ))
    })
    .unwrap();
    assert_eq!(found, Some(lepic));
    assert_eq!(unknown, None);
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

for_each_backend!(
    accounts_round_trip_in_index_order,
    put_account_replaces_label_and_child_counter,
    rejects_label_used_by_another_account,
    outputs_round_trip_and_filter_by_account_and_status,
    put_output_replaces_and_delete_removes,
    rejects_output_for_unknown_account_or_transaction,
    outputs_of_transaction_lists_linked_outputs,
    transactions_get_sequential_ids_and_round_trip,
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
    delete_transaction_removes_an_unlinked_entry_only,
    pending_invoices_round_trip_oldest_first,
    rejects_a_second_invoice_with_the_same_slate_id,
    pending_invoice_status_changes_and_delete_removes,
    parking_stops_at_the_per_sender_cap,
    parking_stops_at_the_total_cap,
    prune_removes_only_parked_invoices_received_before_the_cutoff,
    pending_invoice_bytes_cannot_be_read_without_the_key,
    invoice_address_index_is_unset_until_set_then_replaced,
    allowed_peers_are_replaced_by_key_listed_in_order_and_removed,
    peer_capability_is_replaced_by_later_evidence,
);

#[test]
fn context_key_is_not_needed_to_read_other_records() {
    let backend = <support::SqliteBackend as Backend>::create(context_key(1));
    write(backend.store(), |repos| repos.put_setting("k", "v")).unwrap();
    let other: ContextKey = context_key(2);
    let reopened = backend.reopen(other);
    assert_eq!(
        read(&reopened, |repos| repos.setting("k"))
            .unwrap()
            .as_deref(),
        Some("v")
    );
}
