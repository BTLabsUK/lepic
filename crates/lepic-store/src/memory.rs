// SPDX-License-Identifier: Apache-2.0
//! An in-memory [`WalletStore`] with the same behaviour as the SQLite one, for engine tests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use lepic_primitives::amount::Height;
use uuid::Uuid;

use crate::account::{AccountIndex, AccountRecord, AccountRepository};
use crate::api_log::{self, ApiEvent, ApiLogRepository, ApiRequest};
use crate::contact::{
    self, CARD_KEY_LEN, ContactCap, ContactId, ContactMailbox, ContactRecord, ContactRepository,
    INVITE_ID_LEN, MAX_CANCELLED_PAIRINGS, MAX_CONTACTS, MAX_PENDING_PAIRINGS, PAYMENTS_KEY_LEN,
    PairingId, PairingSecrets, PendingPairing,
};
use crate::context::{
    self, ContextKey, ContextRepository, ParticipantId, PrivateContext, StoreKeys,
};
use crate::delivery::{
    self, CopyState, NativeOutboxEntry, NativeOutboxId, NativeOutboxRepository, OutboxCopy,
    OutboxState, PaymentDelivery, PaymentDeliveryRepository, StoredNativeOutbox, StoredOutboxCopy,
    WatchRow, WatchSetRepository,
};
use crate::encoding::timestamp_to_column;
use crate::error::{Record, StoreError};
use crate::imported::{
    self, ChainCheck, ImportedOutput, ImportedOutputStatus, ImportedRepository, ImportedTransaction,
};
use crate::invoice::{self, InvoiceRepository, PendingInvoice, PendingInvoiceStatus};
use crate::node_post::{self, NodePost, NodePostRepository};
use crate::output::{CommitmentBytes, OutputRecord, OutputRepository, OutputStatus};
use crate::recovery::{self, Recovery, RecoveryRepository};
use crate::relay::{
    InboxEntry, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
use crate::settings::SettingsRepository;
use crate::slate::{SlateRepository, SlateStage, StoredSlate};
use crate::store::{Repositories, WalletStore};
use crate::transaction::{
    OpenReceipt, StateTally, StoredTransaction, TransactionEntry, TransactionRepository,
    TxDirection, TxId, TxState, next_transaction_id,
};
use crate::tx_record::{OtherWalletSpend, ScanFoundRecord, TxMarks, TxRecordRepository, TxWatch};

type SlateKey = ([u8; 16], &'static str);

#[derive(Debug, Clone, Default)]
struct State {
    accounts: BTreeMap<AccountIndex, AccountRecord>,
    outputs: BTreeMap<CommitmentBytes, OutputRecord>,
    output_touches: BTreeMap<CommitmentBytes, u64>,
    transactions: BTreeMap<TxId, TransactionEntry>,
    confirmed_heights: BTreeMap<TxId, Height>,
    counterparties: BTreeMap<TxId, String>,
    receive_listings: BTreeMap<TxId, crate::transaction::ReceiveListing>,
    slates: BTreeMap<SlateKey, StoredSlate>,
    contexts: BTreeMap<([u8; 16], ParticipantId), Vec<u8>>,
    inbox: BTreeMap<String, InboxEntry>,
    outbox: BTreeMap<OutboxId, OutboxEntry>,
    settings: BTreeMap<String, String>,
    pending_invoices: BTreeMap<[u8; 16], SealedInvoice>,
    api_events: BTreeMap<u64, ApiEvent>,
    api_event_last_id: u64,
    api_requests: BTreeMap<(String, String), ApiRequest>,
    contacts: BTreeMap<ContactId, ContactRecord>,
    contact_slot_counters: BTreeMap<AccountIndex, u32>,
    contact_mailboxes: BTreeMap<ContactId, ContactMailbox>,
    pairings: BTreeMap<PairingId, SealedPairing>,
    seen_envelopes: BTreeMap<[u8; 32], Timestamp>,
    imported_transactions: BTreeMap<TxId, ImportedTransaction>,
    imported_outputs: BTreeMap<CommitmentBytes, ImportedOutput>,
    tx_marks: BTreeMap<TxId, TxMarks>,
    tx_watches: BTreeMap<TxId, TxWatch>,
    other_wallet_spends: BTreeMap<TxId, OtherWalletSpend>,
    scan_found: BTreeMap<TxId, ScanFoundRecord>,
    slate_contacts: BTreeMap<[u8; 16], ContactId>,
    tx_contacts: BTreeMap<TxId, ContactId>,
    /// By relay then key reference, the order the watch set is listed in.
    watch_set: BTreeMap<(String, String), WatchRow>,
    native_outbox: BTreeMap<NativeOutboxId, NativeOutboxEntry>,
    /// By entry then mailbox, the order the copies of an entry are listed in.
    outbox_copies: BTreeMap<(NativeOutboxId, String), OutboxCopy>,
    payment_deliveries: BTreeMap<Uuid, PaymentDelivery>,
    node_posts: BTreeMap<TxId, NodePost>,
    recoveries: BTreeMap<TxId, Recovery>,
}

/// A pending invoice as the SQLite row holds it: its bytes sealed, the other fields in clear.
#[derive(Debug, Clone)]
struct SealedInvoice {
    fields: PendingInvoice,
    sealed: Vec<u8>,
}

/// A pending pairing as the SQLite row holds it: its secrets sealed, the other fields in clear.
#[derive(Debug, Clone)]
struct SealedPairing {
    fields: PendingPairing,
    sealed: Vec<u8>,
}

/// Holds all data in memory. Clones made with [`MemoryStore::reopen`] share it, which lets a test
/// reopen "the same database" with another key.
#[derive(Debug)]
pub struct MemoryStore {
    state: Arc<Mutex<State>>,
    key: ContextKey,
}

impl MemoryStore {
    pub fn new(keys: StoreKeys) -> Self {
        Self {
            state: Arc::default(),
            key: keys.context,
        }
    }

    /// A second handle on the same data, sealing and opening records under `keys`.
    pub fn reopen(&self, keys: StoreKeys) -> Self {
        Self {
            state: Arc::clone(&self.state),
            key: keys.context,
        }
    }
}

impl WalletStore for MemoryStore {
    fn read<R, E>(&self, operation: impl FnOnce(&dyn Repositories) -> Result<R, E>) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        let mut state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
        let repos = MemoryRepos {
            state: &mut state,
            key: &self.key,
        };
        operation(&repos)
    }

    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        let mut state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
        let mut draft = state.clone();
        let result = operation(&mut MemoryRepos {
            state: &mut draft,
            key: &self.key,
        })?;
        *state = draft;
        Ok(result)
    }
}

struct MemoryRepos<'a> {
    state: &'a mut State,
    key: &'a ContextKey,
}

impl MemoryRepos<'_> {
    /// Drops the settings kept beside contact `id` once neither the contact nor a pairing in
    /// progress for it is stored.
    fn forget_unused_extras(&mut self, id: ContactId) {
        let state = &mut *self.state;
        if state.contacts.contains_key(&id)
            || state
                .pairings
                .values()
                .any(|stored| stored.fields.contact_id == id)
        {
            return;
        }
        let prefix = contact::contact_extras_prefix(id);
        state.settings.retain(|key, _| !key.starts_with(&prefix));
    }

    fn require_account(&self, index: AccountIndex) -> Result<(), StoreError> {
        if self.state.accounts.contains_key(&index) {
            Ok(())
        } else {
            Err(StoreError::UnknownAccount(index))
        }
    }

    fn require_transaction(&self, id: TxId) -> Result<(), StoreError> {
        if self.state.transactions.contains_key(&id) {
            Ok(())
        } else {
            Err(StoreError::UnknownTransaction(id))
        }
    }

    fn check_transaction(
        &self,
        id: Option<TxId>,
        entry: &TransactionEntry,
    ) -> Result<(), StoreError> {
        self.require_account(entry.account)?;
        let taken = entry.slate_id.is_some()
            && self.state.transactions.iter().any(|(other_id, other)| {
                Some(*other_id) != id
                    && other.slate_id == entry.slate_id
                    && other.direction == entry.direction
            });
        if taken {
            return Err(StoreError::Duplicate {
                record: Record::Transaction,
            });
        }
        timestamp_to_column(entry.created_at)?;
        timestamp_to_column(entry.updated_at)?;
        Ok(())
    }
}

fn next_key<K: Copy + Ord>(
    map: &BTreeMap<K, impl Sized>,
    first: K,
    next: impl Fn(K) -> Option<K>,
) -> Option<K> {
    match map.last_key_value() {
        Some((last, _)) => next(*last),
        None => Some(first),
    }
}

impl AccountRepository for MemoryRepos<'_> {
    fn put_account(&mut self, account: &AccountRecord) -> Result<(), StoreError> {
        let taken = self
            .state
            .accounts
            .values()
            .any(|other| other.index != account.index && other.label == account.label);
        if taken {
            return Err(StoreError::LabelTaken);
        }
        self.state.accounts.insert(account.index, account.clone());
        Ok(())
    }

    fn account(&self, index: AccountIndex) -> Result<Option<AccountRecord>, StoreError> {
        Ok(self.state.accounts.get(&index).cloned())
    }

    fn account_by_label(&self, label: &str) -> Result<Option<AccountRecord>, StoreError> {
        Ok(self
            .state
            .accounts
            .values()
            .find(|account| account.label == label)
            .cloned())
    }

    fn accounts(&self) -> Result<Vec<AccountRecord>, StoreError> {
        Ok(self.state.accounts.values().cloned().collect())
    }
}

impl OutputRepository for MemoryRepos<'_> {
    fn put_output(&mut self, output: &OutputRecord) -> Result<(), StoreError> {
        self.require_account(output.account)?;
        if let Some(tx) = output.tx
            && !self.state.transactions.contains_key(&tx)
        {
            return Err(StoreError::UnknownTransaction(tx));
        }
        self.state
            .outputs
            .insert(*output.commitment(), output.clone());
        Ok(())
    }

    fn insert_output(&mut self, output: &OutputRecord) -> Result<(), StoreError> {
        if self.state.outputs.contains_key(output.commitment()) {
            return Err(StoreError::Duplicate {
                record: Record::Output,
            });
        }
        self.put_output(output)
    }

    fn output(&self, commitment: &CommitmentBytes) -> Result<Option<OutputRecord>, StoreError> {
        Ok(self.state.outputs.get(commitment).cloned())
    }

    fn outputs(
        &self,
        account: AccountIndex,
        status: Option<OutputStatus>,
    ) -> Result<Vec<OutputRecord>, StoreError> {
        Ok(self
            .state
            .outputs
            .values()
            .filter(|output| {
                output.account == account && status.is_none_or(|status| output.status == status)
            })
            .cloned()
            .collect())
    }

    fn outputs_of_transaction(&self, tx: TxId) -> Result<Vec<OutputRecord>, StoreError> {
        Ok(self
            .state
            .outputs
            .values()
            .filter(|output| output.tx == Some(tx))
            .cloned()
            .collect())
    }

    fn touch_output(&mut self, commitment: &CommitmentBytes) -> Result<(), StoreError> {
        if self.state.outputs.contains_key(commitment) {
            let last = self.state.output_touches.values().max().copied();
            let touch = last.unwrap_or(0).saturating_add(1);
            self.state.output_touches.insert(*commitment, touch);
        }
        Ok(())
    }

    fn outputs_by_touch(&self, status: OutputStatus) -> Result<Vec<OutputRecord>, StoreError> {
        let touch = |output: &OutputRecord| {
            let touch = self.state.output_touches.get(output.commitment());
            (touch.copied().unwrap_or(0), *output.commitment())
        };
        let mut outputs: Vec<OutputRecord> = self
            .state
            .outputs
            .values()
            .filter(|output| output.status == status)
            .cloned()
            .collect();
        outputs.sort_by_key(touch);
        Ok(outputs)
    }

    fn delete_output(&mut self, commitment: &CommitmentBytes) -> Result<(), StoreError> {
        self.state.outputs.remove(commitment);
        self.state.output_touches.remove(commitment);
        Ok(())
    }
}

impl TransactionRepository for MemoryRepos<'_> {
    fn insert_transaction(&mut self, entry: &TransactionEntry) -> Result<TxId, StoreError> {
        self.check_transaction(None, entry)?;
        let in_table = self.state.transactions.last_key_value().map(|(id, _)| *id);
        let id = next_transaction_id(self, in_table)?;
        self.state.transactions.insert(id, entry.clone());
        Ok(id)
    }

    fn update_transaction(&mut self, id: TxId, entry: &TransactionEntry) -> Result<(), StoreError> {
        if !self.state.transactions.contains_key(&id) {
            return Err(StoreError::NotFound {
                record: Record::Transaction,
            });
        }
        self.check_transaction(Some(id), entry)?;
        self.state.transactions.insert(id, entry.clone());
        Ok(())
    }

    fn transaction(&self, id: TxId) -> Result<Option<TransactionEntry>, StoreError> {
        Ok(self.state.transactions.get(&id).cloned())
    }

    fn delete_transaction(&mut self, id: TxId) -> Result<(), StoreError> {
        if !self.state.transactions.contains_key(&id) {
            return Err(StoreError::UnknownTransaction(id));
        }
        if self
            .state
            .outputs
            .values()
            .any(|output| output.tx == Some(id))
        {
            return Err(StoreError::InUse {
                record: Record::Transaction,
            });
        }
        self.state.transactions.remove(&id);
        self.state.confirmed_heights.remove(&id);
        self.state.counterparties.remove(&id);
        self.state.imported_transactions.remove(&id);
        self.state
            .imported_outputs
            .retain(|_, output| output.tx != id);
        self.state.tx_marks.remove(&id);
        self.state.tx_watches.remove(&id);
        self.state.other_wallet_spends.remove(&id);
        self.state.scan_found.remove(&id);
        self.state.tx_contacts.remove(&id);
        self.state.node_posts.remove(&id);
        self.state.recoveries.retain(|payment, recovery| {
            *payment != id && recovery.sent_tx != id && recovery.received_tx != id
        });
        Ok(())
    }

    fn transaction_by_slate(
        &self,
        slate_id: Uuid,
        direction: TxDirection,
    ) -> Result<Option<StoredTransaction>, StoreError> {
        Ok(self
            .state
            .transactions
            .iter()
            .find(|(_, entry)| entry.slate_id == Some(slate_id) && entry.direction == direction)
            .map(|(id, entry)| StoredTransaction {
                id: *id,
                entry: entry.clone(),
            }))
    }

    fn transactions(&self, account: AccountIndex) -> Result<Vec<StoredTransaction>, StoreError> {
        Ok(self
            .state
            .transactions
            .iter()
            .filter(|(_, entry)| entry.account == account)
            .map(|(id, entry)| StoredTransaction {
                id: *id,
                entry: entry.clone(),
            })
            .collect())
    }

    fn transactions_before(
        &self,
        before: Option<Timestamp>,
        at_least: u32,
    ) -> Result<Vec<StoredTransaction>, StoreError> {
        let mut found: Vec<StoredTransaction> = self
            .state
            .transactions
            .iter()
            .filter(|(_, entry)| before.is_none_or(|before| entry.created_at < before))
            .map(|(id, entry)| StoredTransaction {
                id: *id,
                entry: entry.clone(),
            })
            .collect();
        found.sort_by_key(|stored| std::cmp::Reverse((stored.entry.created_at, stored.id.0)));
        let wanted = usize::try_from(at_least).unwrap_or(usize::MAX).max(1);
        if let Some(last) = found.get(wanted.saturating_sub(1)) {
            let floor = last.entry.created_at.as_millisecond();
            found.retain(|stored| stored.entry.created_at.as_millisecond() >= floor);
        }
        Ok(found)
    }

    fn set_confirmed_height(&mut self, id: TxId, height: Height) -> Result<(), StoreError> {
        if !self.state.transactions.contains_key(&id) {
            return Err(StoreError::UnknownTransaction(id));
        }
        self.state.confirmed_heights.insert(id, height);
        Ok(())
    }

    fn confirmed_height(&self, id: TxId) -> Result<Option<Height>, StoreError> {
        Ok(self.state.confirmed_heights.get(&id).copied())
    }

    fn clear_confirmed_height(&mut self, id: TxId) -> Result<(), StoreError> {
        if !self.state.transactions.contains_key(&id) {
            return Err(StoreError::UnknownTransaction(id));
        }
        self.state.confirmed_heights.remove(&id);
        Ok(())
    }

    fn confirmed_from(&self, from: Height) -> Result<Vec<(TxId, Height)>, StoreError> {
        Ok(self
            .state
            .confirmed_heights
            .iter()
            .filter(|(id, height)| {
                **height >= from
                    && self
                        .state
                        .transactions
                        .get(id)
                        .is_some_and(|entry| entry.state == TxState::Confirmed)
            })
            .map(|(id, height)| (*id, *height))
            .collect())
    }

    fn set_counterparty(&mut self, id: TxId, address: &str) -> Result<(), StoreError> {
        if !self.state.transactions.contains_key(&id) {
            return Err(StoreError::UnknownTransaction(id));
        }
        self.state.counterparties.insert(id, address.to_owned());
        Ok(())
    }

    fn counterparty(&self, id: TxId) -> Result<Option<String>, StoreError> {
        Ok(self.state.counterparties.get(&id).cloned())
    }

    fn set_receive_listing(
        &mut self,
        id: TxId,
        listing: &crate::transaction::ReceiveListing,
    ) -> Result<(), StoreError> {
        if !self.state.transactions.contains_key(&id) {
            return Err(StoreError::UnknownTransaction(id));
        }
        self.state.receive_listings.insert(id, *listing);
        Ok(())
    }

    fn receive_listing(
        &self,
        id: TxId,
    ) -> Result<Option<crate::transaction::ReceiveListing>, StoreError> {
        Ok(self.state.receive_listings.get(&id).copied())
    }

    fn open_receipts(&self, transport: &str) -> Result<Vec<OpenReceipt>, StoreError> {
        Ok(self
            .state
            .transactions
            .iter()
            .filter(|(_, entry)| {
                entry.direction == TxDirection::Incoming
                    && entry.state == TxState::Received
                    && entry.transport.as_deref() == Some(transport)
                    && entry.slate_id.is_some_and(|slate_id| {
                        self.state
                            .slates
                            .contains_key(&slate_key(slate_id, SlateStage::Standard2))
                    })
            })
            .map(|(id, _)| OpenReceipt {
                id: *id,
                counterparty: self.state.counterparties.get(id).cloned(),
            })
            .collect())
    }

    fn transactions_in_state(
        &self,
        state: TxState,
        skip_incoming_transport: &str,
        oldest: u32,
    ) -> Result<StateTally, StoreError> {
        let mut matching: Vec<(TxId, Timestamp)> = self
            .state
            .transactions
            .iter()
            .filter(|(_, entry)| {
                entry.state == state
                    && !(entry.direction == TxDirection::Incoming
                        && entry.transport.as_deref() == Some(skip_incoming_transport))
            })
            .map(|(id, entry)| (*id, entry.created_at))
            .collect();
        matching.sort_by_key(|(id, created_at)| (*created_at, id.0));
        let count =
            u64::try_from(matching.len()).map_err(|_| StoreError::OutOfRange { field: "count" })?;
        matching.truncate(usize::try_from(oldest).unwrap_or(usize::MAX));
        Ok(StateTally {
            count,
            oldest: matching,
        })
    }
}

fn slate_key(slate_id: Uuid, stage: SlateStage) -> SlateKey {
    (slate_id.into_bytes(), stage.code())
}

impl TxRecordRepository for MemoryRepos<'_> {
    fn tx_marks(&self, id: TxId) -> Result<TxMarks, StoreError> {
        Ok(self.state.tx_marks.get(&id).copied().unwrap_or_default())
    }

    fn put_tx_marks(&mut self, id: TxId, marks: &TxMarks) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        for at in [marks.sender_posted_at, marks.sender_cancelled_at]
            .into_iter()
            .flatten()
        {
            timestamp_to_column(at)?;
        }
        if *marks == TxMarks::default() {
            self.state.tx_marks.remove(&id);
        } else {
            self.state.tx_marks.insert(id, *marks);
        }
        Ok(())
    }

    fn tx_watch(&self, id: TxId) -> Result<Option<TxWatch>, StoreError> {
        Ok(self.state.tx_watches.get(&id).cloned())
    }

    fn tx_watches(&self) -> Result<Vec<(TxId, TxWatch)>, StoreError> {
        Ok(self
            .state
            .tx_watches
            .iter()
            .map(|(id, watch)| (*id, watch.clone()))
            .collect())
    }

    fn put_tx_watch(&mut self, id: TxId, watch: &TxWatch) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        self.state.tx_watches.insert(id, watch.clone());
        Ok(())
    }

    fn delete_tx_watch(&mut self, id: TxId) -> Result<(), StoreError> {
        self.state.tx_watches.remove(&id);
        Ok(())
    }

    fn other_wallet_spend(&self, id: TxId) -> Result<Option<OtherWalletSpend>, StoreError> {
        Ok(self.state.other_wallet_spends.get(&id).cloned())
    }

    fn other_wallet_spends(&self) -> Result<Vec<(TxId, OtherWalletSpend)>, StoreError> {
        Ok(self
            .state
            .other_wallet_spends
            .iter()
            .map(|(id, spend)| (*id, spend.clone()))
            .collect())
    }

    fn put_other_wallet_spend(
        &mut self,
        id: TxId,
        spend: &OtherWalletSpend,
    ) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        self.state.other_wallet_spends.insert(id, spend.clone());
        Ok(())
    }

    fn scan_found(&self, id: TxId) -> Result<Option<ScanFoundRecord>, StoreError> {
        Ok(self.state.scan_found.get(&id).copied())
    }

    fn put_scan_found(&mut self, id: TxId, found: &ScanFoundRecord) -> Result<(), StoreError> {
        self.require_transaction(id)?;
        self.state.scan_found.insert(id, *found);
        Ok(())
    }
}

impl SlateRepository for MemoryRepos<'_> {
    fn insert_slate(&mut self, slate: &StoredSlate) -> Result<(), StoreError> {
        let key = slate_key(slate.slate_id, slate.stage);
        if self.state.slates.contains_key(&key) {
            return Err(StoreError::Duplicate {
                record: Record::Slate,
            });
        }
        self.state.slates.insert(key, slate.clone());
        Ok(())
    }

    fn slate(&self, slate_id: Uuid, stage: SlateStage) -> Result<Option<StoredSlate>, StoreError> {
        Ok(self.state.slates.get(&slate_key(slate_id, stage)).cloned())
    }

    fn slates(&self, slate_id: Uuid) -> Result<Vec<StoredSlate>, StoreError> {
        let id = slate_id.into_bytes();
        Ok(self
            .state
            .slates
            .range((id, "")..)
            .take_while(|((other, _), _)| *other == id)
            .map(|(_, slate)| slate.clone())
            .collect())
    }

    fn slate_stages(&self, slate_id: Uuid) -> Result<Vec<(SlateStage, usize)>, StoreError> {
        let id = slate_id.into_bytes();
        Ok(self
            .state
            .slates
            .range((id, "")..)
            .take_while(|((other, _), _)| *other == id)
            .map(|(_, slate)| (slate.stage, slate.bytes.len()))
            .collect())
    }
}

impl ContextRepository for MemoryRepos<'_> {
    fn put_context(
        &mut self,
        slate_id: Uuid,
        participant: ParticipantId,
        context: &PrivateContext,
    ) -> Result<(), StoreError> {
        let sealed = context::seal(self.key, slate_id, participant, context)?;
        self.state
            .contexts
            .insert((slate_id.into_bytes(), participant), sealed);
        Ok(())
    }

    fn context(
        &self,
        slate_id: Uuid,
        participant: ParticipantId,
    ) -> Result<Option<PrivateContext>, StoreError> {
        self.state
            .contexts
            .get(&(slate_id.into_bytes(), participant))
            .map(|sealed| context::open(self.key, slate_id, participant, sealed))
            .transpose()
    }

    fn delete_context(
        &mut self,
        slate_id: Uuid,
        participant: ParticipantId,
    ) -> Result<(), StoreError> {
        self.state
            .contexts
            .remove(&(slate_id.into_bytes(), participant));
        Ok(())
    }
}

fn check_outbox(entry: &OutboxEntry) -> Result<(), StoreError> {
    timestamp_to_column(entry.created_at)?;
    timestamp_to_column(entry.updated_at)?;
    Ok(())
}

impl RelayRepository for MemoryRepos<'_> {
    fn put_inbox(&mut self, entry: &InboxEntry) -> Result<(), StoreError> {
        timestamp_to_column(entry.received_at)?;
        timestamp_to_column(entry.updated_at)?;
        self.state.inbox.insert(entry.msg_id.clone(), entry.clone());
        Ok(())
    }

    fn inbox(&self, msg_id: &str) -> Result<Option<InboxEntry>, StoreError> {
        Ok(self.state.inbox.get(msg_id).cloned())
    }

    fn prune_inbox(&mut self, received_before: Timestamp) -> Result<usize, StoreError> {
        let before = self.state.inbox.len();
        self.state
            .inbox
            .retain(|_, entry| entry.received_at >= received_before);
        Ok(before.saturating_sub(self.state.inbox.len()))
    }

    fn enqueue_outbox(&mut self, entry: &OutboxEntry) -> Result<OutboxId, StoreError> {
        check_outbox(entry)?;
        let id = next_key(&self.state.outbox, OutboxId(1), |OutboxId(last)| {
            last.checked_add(1).map(OutboxId)
        })
        .ok_or(StoreError::OutOfRange { field: "outbox id" })?;
        self.state.outbox.insert(id, entry.clone());
        Ok(id)
    }

    fn update_outbox(&mut self, id: OutboxId, entry: &OutboxEntry) -> Result<(), StoreError> {
        check_outbox(entry)?;
        match self.state.outbox.get_mut(&id) {
            Some(stored) => {
                *stored = entry.clone();
                Ok(())
            }
            None => Err(StoreError::NotFound {
                record: Record::OutboxMessage,
            }),
        }
    }

    fn outbox(&self, status: OutboxStatus) -> Result<Vec<StoredOutbox>, StoreError> {
        Ok(self
            .state
            .outbox
            .iter()
            .filter(|(_, entry)| entry.status == status)
            .map(|(id, entry)| StoredOutbox {
                id: *id,
                entry: entry.clone(),
            })
            .collect())
    }

    fn delete_outbox(&mut self, id: OutboxId) -> Result<(), StoreError> {
        self.state.outbox.remove(&id);
        Ok(())
    }
}

impl SettingsRepository for MemoryRepos<'_> {
    fn put_setting(&mut self, key: &str, value: &str) -> Result<(), StoreError> {
        self.state.settings.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.state.settings.get(key).cloned())
    }

    fn settings_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>, StoreError> {
        Ok(self
            .state
            .settings
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn delete_setting(&mut self, key: &str) -> Result<(), StoreError> {
        self.state.settings.remove(key);
        Ok(())
    }
}

impl MemoryRepos<'_> {
    fn open_invoice(&self, stored: &SealedInvoice) -> Result<PendingInvoice, StoreError> {
        let fields = &stored.fields;
        Ok(PendingInvoice {
            bytes: invoice::open(
                self.key,
                fields.slate_id,
                &fields.sender_key,
                &stored.sealed,
            )?,
            ..fields.clone()
        })
    }

    fn parked_invoices(&self) -> impl Iterator<Item = &PendingInvoice> {
        self.state
            .pending_invoices
            .values()
            .map(|stored| &stored.fields)
            .filter(|fields| fields.status == PendingInvoiceStatus::Parked)
    }
}

impl InvoiceRepository for MemoryRepos<'_> {
    fn park_invoice(&mut self, invoice: &PendingInvoice) -> Result<(), StoreError> {
        let id = invoice.slate_id.into_bytes();
        if self.state.pending_invoices.contains_key(&id) {
            return Err(StoreError::Duplicate {
                record: Record::PendingInvoice,
            });
        }
        invoice::check_parkable(
            invoice,
            self.parked_invoices().count(),
            self.parked_invoices()
                .filter(|parked| parked.sender_key == invoice.sender_key)
                .count(),
        )?;
        timestamp_to_column(invoice.received_at)?;
        let sealed = invoice::seal(self.key, invoice)?;
        self.state.pending_invoices.insert(
            id,
            SealedInvoice {
                fields: PendingInvoice {
                    bytes: Vec::new(),
                    ..invoice.clone()
                },
                sealed,
            },
        );
        Ok(())
    }

    fn pending_invoice(&self, slate_id: Uuid) -> Result<Option<PendingInvoice>, StoreError> {
        self.state
            .pending_invoices
            .get(&slate_id.into_bytes())
            .map(|stored| self.open_invoice(stored))
            .transpose()
    }

    fn pending_invoices(&self) -> Result<Vec<PendingInvoice>, StoreError> {
        let mut stored: Vec<&SealedInvoice> = self.state.pending_invoices.values().collect();
        stored.sort_by_key(|stored| (stored.fields.received_at, stored.fields.slate_id));
        stored
            .into_iter()
            .map(|stored| self.open_invoice(stored))
            .collect()
    }

    fn set_pending_invoice_status(
        &mut self,
        slate_id: Uuid,
        status: PendingInvoiceStatus,
    ) -> Result<(), StoreError> {
        match self.state.pending_invoices.get_mut(&slate_id.into_bytes()) {
            Some(stored) => {
                invoice::check_status_change(stored.fields.status, status)?;
                stored.fields.status = status;
                Ok(())
            }
            None => Err(StoreError::NotFound {
                record: Record::PendingInvoice,
            }),
        }
    }

    fn delete_pending_invoice(&mut self, slate_id: Uuid) -> Result<(), StoreError> {
        self.state.pending_invoices.remove(&slate_id.into_bytes());
        Ok(())
    }

    fn parked_invoice_count(&self) -> Result<usize, StoreError> {
        Ok(self.parked_invoices().count())
    }
}

impl ApiLogRepository for MemoryRepos<'_> {
    fn append_api_event(
        &mut self,
        kind: &str,
        created_at: Timestamp,
        data: &[u8],
    ) -> Result<u64, StoreError> {
        api_log::check_kind(kind)?;
        api_log::check_event_data(data)?;
        timestamp_to_column(created_at)?;
        let id = self
            .state
            .api_event_last_id
            .checked_add(1)
            .ok_or(StoreError::OutOfRange {
                field: "api event id",
            })?;
        self.state.api_event_last_id = id;
        self.state.api_events.insert(
            id,
            ApiEvent {
                id,
                kind: kind.to_owned(),
                created_at,
                data: data.to_vec(),
            },
        );
        Ok(id)
    }

    fn api_events_after(
        &self,
        after: u64,
        limit: usize,
        kinds: &[String],
    ) -> Result<Vec<ApiEvent>, StoreError> {
        api_log::check_limit(limit)?;
        let patterns = api_log::parse_patterns(kinds)?;
        Ok(self
            .state
            .api_events
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .map(|(_, event)| event)
            .filter(|event| {
                patterns.is_empty() || patterns.iter().any(|pattern| pattern.matches(&event.kind))
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn api_event_bounds(&self) -> Result<Option<(u64, u64)>, StoreError> {
        let low = self.state.api_events.keys().next();
        let high = self.state.api_events.keys().next_back();
        Ok(low.zip(high).map(|(low, high)| (*low, *high)))
    }

    fn api_event_last_id(&self) -> Result<u64, StoreError> {
        Ok(self.state.api_event_last_id)
    }

    fn prune_api_events(&mut self, before: Timestamp) -> Result<u64, StoreError> {
        timestamp_to_column(before)?;
        let count = self.state.api_events.len();
        self.state
            .api_events
            .retain(|_, event| event.created_at >= before);
        Ok(u64::try_from(count.saturating_sub(self.state.api_events.len())).unwrap_or(u64::MAX))
    }

    fn put_api_request(&mut self, request: &ApiRequest) -> Result<(), StoreError> {
        api_log::check_request_key(&request.scope, &request.id)?;
        timestamp_to_column(request.created_at)?;
        let key = (request.scope.clone(), request.id.clone());
        if self.state.api_requests.contains_key(&key) {
            return Err(StoreError::Duplicate {
                record: Record::ApiRequest,
            });
        }
        self.state.api_requests.insert(key, request.clone());
        Ok(())
    }

    fn api_request(&self, scope: &str, id: &str) -> Result<Option<ApiRequest>, StoreError> {
        Ok(self
            .state
            .api_requests
            .get(&(scope.to_owned(), id.to_owned()))
            .cloned())
    }

    fn delete_api_request(&mut self, scope: &str, id: &str) -> Result<bool, StoreError> {
        Ok(self
            .state
            .api_requests
            .remove(&(scope.to_owned(), id.to_owned()))
            .is_some())
    }

    fn prune_api_requests(&mut self, before: Timestamp) -> Result<u64, StoreError> {
        timestamp_to_column(before)?;
        let count = self.state.api_requests.len();
        self.state
            .api_requests
            .retain(|_, request| request.created_at >= before);
        Ok(u64::try_from(count.saturating_sub(self.state.api_requests.len())).unwrap_or(u64::MAX))
    }
}

impl ImportedRepository for MemoryRepos<'_> {
    fn put_imported_transaction(
        &mut self,
        tx: TxId,
        imported: &ImportedTransaction,
    ) -> Result<(), StoreError> {
        self.require_transaction(tx)?;
        imported::check_messages(&imported.messages)?;
        if let Some(confirmed_at) = imported.confirmed_at {
            timestamp_to_column(confirmed_at)?;
        }
        self.state
            .imported_transactions
            .insert(tx, imported.clone());
        Ok(())
    }

    fn imported_transaction(&self, tx: TxId) -> Result<Option<ImportedTransaction>, StoreError> {
        Ok(self.state.imported_transactions.get(&tx).cloned())
    }

    fn set_chain_check(&mut self, tx: TxId, check: ChainCheck) -> Result<(), StoreError> {
        let imported =
            self.state
                .imported_transactions
                .get_mut(&tx)
                .ok_or(StoreError::NotFound {
                    record: Record::ImportedTransaction,
                })?;
        imported.check = check;
        Ok(())
    }

    fn put_imported_output(&mut self, output: &ImportedOutput) -> Result<(), StoreError> {
        self.require_transaction(output.tx)?;
        self.state
            .imported_outputs
            .insert(output.commitment, output.clone());
        Ok(())
    }

    fn imported_output(
        &self,
        commitment: &CommitmentBytes,
    ) -> Result<Option<ImportedOutput>, StoreError> {
        Ok(self.state.imported_outputs.get(commitment).cloned())
    }

    fn imported_outputs(
        &self,
        status: ImportedOutputStatus,
    ) -> Result<Vec<ImportedOutput>, StoreError> {
        Ok(self
            .state
            .imported_outputs
            .values()
            .filter(|output| output.status == status)
            .cloned()
            .collect())
    }
}

impl MemoryRepos<'_> {
    fn open_pairing(&self, stored: &SealedPairing) -> Result<PendingPairing, StoreError> {
        let mut pairing = stored.fields.clone();
        pairing.secrets = contact::open_secrets(
            self.key,
            pairing.pairing_id,
            &pairing.invite_id,
            &stored.sealed,
        )?;
        Ok(pairing)
    }

    fn answered(&self, stored: &SealedPairing) -> bool {
        let fields = &stored.fields;
        contact::answered(
            self.key,
            fields.role,
            fields.pairing_id,
            &fields.invite_id,
            &stored.sealed,
        )
    }

    fn contacts_where(&self, keep: impl Fn(&ContactRecord) -> bool) -> Vec<ContactRecord> {
        let mut found: Vec<ContactRecord> = self
            .state
            .contacts
            .values()
            .filter(|contact| keep(contact))
            .cloned()
            .collect();
        found.sort_by_key(|contact| (contact.created_at, contact.contact_id));
        found
    }
}

impl ContactRepository for MemoryRepos<'_> {
    fn put_contact(&mut self, contact: &ContactRecord) -> Result<(), StoreError> {
        contact::check_contact(contact)?;
        if let Some(peer) = &contact.peer {
            let taken = self.state.contacts.values().any(|other| {
                other.contact_id != contact.contact_id
                    && other.peer.as_ref().map(|card| card.sig_key) == Some(peer.sig_key)
            });
            if taken {
                return Err(StoreError::Duplicate {
                    record: Record::Contact,
                });
            }
        }
        if !self.state.contacts.contains_key(&contact.contact_id)
            && self.state.contacts.len() >= MAX_CONTACTS
        {
            return Err(StoreError::ContactCapReached {
                cap: ContactCap::Contacts,
            });
        }
        self.state
            .contacts
            .insert(contact.contact_id, contact.clone());
        Ok(())
    }

    fn contact(&self, id: ContactId) -> Result<Option<ContactRecord>, StoreError> {
        Ok(self.state.contacts.get(&id).cloned())
    }

    fn contact_by_peer_sig_key(
        &self,
        key: &[u8; CARD_KEY_LEN],
    ) -> Result<Option<ContactRecord>, StoreError> {
        Ok(self
            .contacts_where(|contact| contact.peer.as_ref().is_some_and(|c| &c.sig_key == key))
            .into_iter()
            .next())
    }

    fn contacts(&self) -> Result<Vec<ContactRecord>, StoreError> {
        Ok(self.contacts_where(|_| true))
    }

    fn contact_slot_counters(&self) -> Result<Vec<(AccountIndex, u32)>, StoreError> {
        Ok(self
            .state
            .contact_slot_counters
            .iter()
            .map(|(account, next)| (*account, *next))
            .collect())
    }

    fn contact_slot_counter(&self, account: AccountIndex) -> Result<Option<u32>, StoreError> {
        Ok(self.state.contact_slot_counters.get(&account).copied())
    }

    fn take_contact_slot(&mut self, account: AccountIndex, start: u32) -> Result<u32, StoreError> {
        contact::check_slot_start(start)?;
        let current = self
            .state
            .contact_slot_counters
            .get(&account)
            .copied()
            .unwrap_or(start);
        let (slot, next) = contact::next_slot(current)?;
        self.state.contact_slot_counters.insert(account, next);
        Ok(slot)
    }

    fn raise_contact_slot_counter(
        &mut self,
        account: AccountIndex,
        next: u32,
    ) -> Result<(), StoreError> {
        contact::check_slot_counter(next)?;
        let counter = self
            .state
            .contact_slot_counters
            .entry(account)
            .or_insert(next);
        *counter = (*counter).max(next);
        Ok(())
    }

    fn delete_contact(&mut self, id: ContactId) -> Result<bool, StoreError> {
        self.state.contact_mailboxes.remove(&id);
        let removed = self.state.contacts.remove(&id).is_some();
        self.forget_unused_extras(id);
        Ok(removed)
    }

    fn put_contact_mailbox(&mut self, mailbox: &ContactMailbox) -> Result<(), StoreError> {
        contact::check_mailbox(mailbox)?;
        if !self.state.contacts.contains_key(&mailbox.contact_id) {
            return Err(StoreError::NotFound {
                record: Record::Contact,
            });
        }
        self.state
            .contact_mailboxes
            .insert(mailbox.contact_id, mailbox.clone());
        Ok(())
    }

    fn contact_mailbox(&self, id: ContactId) -> Result<Option<ContactMailbox>, StoreError> {
        Ok(self.state.contact_mailboxes.get(&id).cloned())
    }

    fn put_pending_pairing(&mut self, pairing: &PendingPairing) -> Result<(), StoreError> {
        contact::check_pairing(pairing)?;
        let taken = self.state.pairings.values().any(|other| {
            other.fields.pairing_id != pairing.pairing_id
                && other.fields.invite_id == pairing.invite_id
        });
        if taken {
            return Err(StoreError::Duplicate {
                record: Record::PendingPairing,
            });
        }
        let cancelled = pairing.cancelled_at.is_some();
        let was_cancelled = self
            .state
            .pairings
            .get(&pairing.pairing_id)
            .map(|stored| stored.fields.cancelled_at.is_some());
        if was_cancelled != Some(cancelled) {
            let cap = if cancelled {
                MAX_CANCELLED_PAIRINGS
            } else {
                MAX_PENDING_PAIRINGS
            };
            let held = self
                .state
                .pairings
                .values()
                .filter(|stored| stored.fields.cancelled_at.is_some() == cancelled)
                .filter(|stored| cancelled || !self.answered(stored))
                .take(cap)
                .count();
            if held >= cap {
                return Err(StoreError::ContactCapReached {
                    cap: ContactCap::PendingPairings,
                });
            }
        }
        let sealed = contact::seal_secrets(self.key, pairing)?;
        let mut fields = pairing.clone();
        fields.secrets = PairingSecrets::default();
        self.state
            .pairings
            .insert(pairing.pairing_id, SealedPairing { fields, sealed });
        Ok(())
    }

    fn pending_pairing(&self, id: PairingId) -> Result<Option<PendingPairing>, StoreError> {
        self.state
            .pairings
            .get(&id)
            .map(|stored| self.open_pairing(stored))
            .transpose()
    }

    fn pending_pairing_by_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> Result<Option<PendingPairing>, StoreError> {
        self.state
            .pairings
            .values()
            .find(|stored| &stored.fields.invite_id == invite_id)
            .map(|stored| self.open_pairing(stored))
            .transpose()
    }

    fn pending_pairings(&self) -> Result<Vec<PendingPairing>, StoreError> {
        let mut stored: Vec<&SealedPairing> = self.state.pairings.values().collect();
        stored.sort_by_key(|s| (s.fields.created_at, s.fields.pairing_id));
        stored.into_iter().map(|s| self.open_pairing(s)).collect()
    }

    fn delete_pending_pairing(&mut self, id: PairingId) -> Result<bool, StoreError> {
        let Some(removed) = self.state.pairings.remove(&id) else {
            return Ok(false);
        };
        self.forget_unused_extras(removed.fields.contact_id);
        Ok(true)
    }

    fn envelope_seen(&self, hash: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self.state.seen_envelopes.contains_key(hash))
    }

    fn remember_envelope(&mut self, hash: &[u8; 32], at: Timestamp) -> Result<(), StoreError> {
        crate::encoding::timestamp_to_column(at)?;
        self.state.seen_envelopes.insert(*hash, at);
        Ok(())
    }

    fn forget_envelopes_before(&mut self, cutoff: Timestamp) -> Result<usize, StoreError> {
        let before = self.state.seen_envelopes.len();
        self.state.seen_envelopes.retain(|_, at| *at >= cutoff);
        Ok(before.saturating_sub(self.state.seen_envelopes.len()))
    }

    fn slate_contact(&self, slate_id: Uuid) -> Result<Option<ContactId>, StoreError> {
        Ok(self.state.slate_contacts.get(slate_id.as_bytes()).copied())
    }

    fn set_slate_contact(&mut self, slate_id: Uuid, contact: ContactId) -> Result<(), StoreError> {
        self.state
            .slate_contacts
            .insert(*slate_id.as_bytes(), contact);
        Ok(())
    }

    fn tx_contact(&self, tx_id: TxId) -> Result<Option<ContactId>, StoreError> {
        Ok(self.state.tx_contacts.get(&tx_id).copied())
    }

    fn set_tx_contact(&mut self, tx_id: TxId, contact: ContactId) -> Result<(), StoreError> {
        self.require_transaction(tx_id)?;
        self.state.tx_contacts.insert(tx_id, contact);
        Ok(())
    }

    fn contacts_by_payments_key(
        &self,
        key: &[u8; PAYMENTS_KEY_LEN],
    ) -> Result<Vec<ContactRecord>, StoreError> {
        Ok(self.contacts_where(|contact| contact.facts.payments_key.as_ref() == Some(key)))
    }
}

impl WatchSetRepository for MemoryRepos<'_> {
    fn put_watch(&mut self, row: &WatchRow) -> Result<(), StoreError> {
        delivery::check_watch(row)?;
        self.state
            .watch_set
            .insert((row.relay.clone(), row.key_ref.clone()), row.clone());
        Ok(())
    }

    fn delete_watch(&mut self, key_ref: &str, relay: &str) -> Result<bool, StoreError> {
        Ok(self
            .state
            .watch_set
            .remove(&(relay.to_owned(), key_ref.to_owned()))
            .is_some())
    }

    fn watch_set(&self) -> Result<Vec<WatchRow>, StoreError> {
        Ok(self.state.watch_set.values().cloned().collect())
    }

    fn remove_expired_watches(&mut self, now: Timestamp) -> Result<usize, StoreError> {
        let before = self.state.watch_set.len();
        self.state
            .watch_set
            .retain(|_, row| row.expires_at.is_none_or(|expires| expires > now));
        Ok(before.saturating_sub(self.state.watch_set.len()))
    }
}

impl NativeOutboxRepository for MemoryRepos<'_> {
    fn enqueue_native_outbox(
        &mut self,
        entry: &NativeOutboxEntry,
    ) -> Result<NativeOutboxId, StoreError> {
        delivery::check_native_outbox(entry)?;
        let id = next_key(
            &self.state.native_outbox,
            NativeOutboxId(1),
            |NativeOutboxId(last)| last.checked_add(1).map(NativeOutboxId),
        )
        .ok_or(StoreError::OutOfRange {
            field: "native outbox id",
        })?;
        self.state.native_outbox.insert(id, entry.clone());
        Ok(id)
    }

    fn update_native_outbox(
        &mut self,
        id: NativeOutboxId,
        entry: &NativeOutboxEntry,
    ) -> Result<(), StoreError> {
        delivery::check_native_outbox(entry)?;
        let stored = self
            .state
            .native_outbox
            .get_mut(&id)
            .ok_or(StoreError::NotFound {
                record: Record::NativeOutbox,
            })?;
        *stored = entry.clone();
        Ok(())
    }

    fn native_outbox_entry(
        &self,
        id: NativeOutboxId,
    ) -> Result<Option<StoredNativeOutbox>, StoreError> {
        Ok(self
            .state
            .native_outbox
            .get(&id)
            .map(|entry| StoredNativeOutbox {
                id,
                entry: entry.clone(),
            }))
    }

    fn native_outbox_of(&self, payment_id: Uuid) -> Result<Vec<StoredNativeOutbox>, StoreError> {
        Ok(self
            .state
            .native_outbox
            .iter()
            .filter(|(_, entry)| entry.payment_id == payment_id)
            .map(|(id, entry)| StoredNativeOutbox {
                id: *id,
                entry: entry.clone(),
            })
            .collect())
    }

    fn due_native_outbox(&self, now: Timestamp) -> Result<Vec<StoredNativeOutbox>, StoreError> {
        let mut due: Vec<StoredNativeOutbox> = self
            .state
            .native_outbox
            .iter()
            .filter(|(_, entry)| {
                matches!(entry.state, OutboxState::Queued | OutboxState::Uncertain)
                    && entry.next_at <= now
            })
            .map(|(id, entry)| StoredNativeOutbox {
                id: *id,
                entry: entry.clone(),
            })
            .collect();
        due.sort_by_key(|stored| (stored.entry.next_at, stored.id));
        Ok(due)
    }

    fn delete_native_outbox(&mut self, id: NativeOutboxId) -> Result<bool, StoreError> {
        self.state
            .outbox_copies
            .retain(|(entry, _), _| *entry != id);
        Ok(self.state.native_outbox.remove(&id).is_some())
    }

    fn native_outbox_from(&self, from_ref: &str) -> Result<Vec<StoredNativeOutbox>, StoreError> {
        Ok(self
            .state
            .native_outbox
            .iter()
            .filter(|(_, entry)| entry.from_ref == from_ref)
            .map(|(id, entry)| StoredNativeOutbox {
                id: *id,
                entry: entry.clone(),
            })
            .collect())
    }

    fn redirect_native_outbox(
        &mut self,
        from_ref: &str,
        old: &str,
        new: &str,
    ) -> Result<usize, StoreError> {
        delivery::check_route_value(new)?;
        let mut changed = 0usize;
        for entry in self.state.native_outbox.values_mut() {
            if entry.from_ref == from_ref
                && entry.route_value == old
                && entry.state == OutboxState::Queued
            {
                new.clone_into(&mut entry.route_value);
                changed = changed.saturating_add(1);
            }
        }
        Ok(changed)
    }

    fn delete_native_outbox_from(&mut self, from_ref: &str) -> Result<usize, StoreError> {
        let before = self.state.native_outbox.len();
        self.state
            .native_outbox
            .retain(|_, entry| entry.from_ref != from_ref);
        let entries = &self.state.native_outbox;
        self.state
            .outbox_copies
            .retain(|(id, _), _| entries.contains_key(id));
        Ok(before.saturating_sub(self.state.native_outbox.len()))
    }

    fn put_outbox_copy(&mut self, id: NativeOutboxId, copy: &OutboxCopy) -> Result<(), StoreError> {
        delivery::check_outbox_copy(copy)?;
        if !self.state.native_outbox.contains_key(&id) {
            return Err(StoreError::NotFound {
                record: Record::NativeOutbox,
            });
        }
        self.state
            .outbox_copies
            .insert((id, copy.mailbox.clone()), copy.clone());
        Ok(())
    }

    fn delete_outbox_copy(
        &mut self,
        id: NativeOutboxId,
        mailbox: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .state
            .outbox_copies
            .remove(&(id, mailbox.to_owned()))
            .is_some())
    }

    fn outbox_copies(&self, id: NativeOutboxId) -> Result<Vec<OutboxCopy>, StoreError> {
        Ok(self
            .state
            .outbox_copies
            .iter()
            .filter(|((entry, _), _)| *entry == id)
            .map(|(_, copy)| copy.clone())
            .collect())
    }

    fn due_outbox_copies(&self, now: Timestamp) -> Result<Vec<StoredOutboxCopy>, StoreError> {
        let mut due: Vec<StoredOutboxCopy> = self
            .state
            .outbox_copies
            .iter()
            .filter(|(_, copy)| {
                matches!(copy.state, CopyState::Owed | CopyState::Cancel) && copy.next_at <= now
            })
            .map(|((id, _), copy)| StoredOutboxCopy {
                id: *id,
                copy: copy.clone(),
            })
            .collect();
        due.sort_by(|a, b| {
            (a.copy.next_at, a.id, &a.copy.mailbox).cmp(&(b.copy.next_at, b.id, &b.copy.mailbox))
        });
        Ok(due)
    }
}

impl PaymentDeliveryRepository for MemoryRepos<'_> {
    fn put_payment_delivery(&mut self, delivery: &PaymentDelivery) -> Result<(), StoreError> {
        delivery::check_payment_delivery(delivery)?;
        if let Some(alias) = &delivery.alias
            && self.state.payment_deliveries.values().any(|other| {
                other.payment_id != delivery.payment_id && other.alias.as_ref() == Some(alias)
            })
        {
            return Err(StoreError::Duplicate {
                record: Record::PaymentDelivery,
            });
        }
        self.state
            .payment_deliveries
            .insert(delivery.payment_id, delivery.clone());
        Ok(())
    }

    fn payment_delivery(&self, payment_id: Uuid) -> Result<Option<PaymentDelivery>, StoreError> {
        Ok(self.state.payment_deliveries.get(&payment_id).cloned())
    }

    fn payment_delivery_by_alias(
        &self,
        alias: &str,
    ) -> Result<Option<PaymentDelivery>, StoreError> {
        Ok(self
            .state
            .payment_deliveries
            .values()
            .find(|delivery| delivery.alias.as_deref() == Some(alias))
            .cloned())
    }
}

impl NodePostRepository for MemoryRepos<'_> {
    fn put_node_post(&mut self, post: &NodePost) -> Result<(), StoreError> {
        node_post::check_node_post(post)?;
        self.require_transaction(post.tx_id)?;
        self.state.node_posts.insert(post.tx_id, post.clone());
        Ok(())
    }

    fn node_post(&self, tx_id: TxId) -> Result<Option<NodePost>, StoreError> {
        Ok(self.state.node_posts.get(&tx_id).cloned())
    }
}

impl RecoveryRepository for MemoryRepos<'_> {
    fn put_recovery(&mut self, recovery: &Recovery) -> Result<(), StoreError> {
        recovery::check_recovery(recovery)?;
        self.require_transaction(recovery.tx_id)?;
        self.require_transaction(recovery.sent_tx)?;
        self.require_transaction(recovery.received_tx)?;
        self.state
            .recoveries
            .insert(recovery.tx_id, recovery.clone());
        Ok(())
    }

    fn recovery(&self, tx_id: TxId) -> Result<Option<Recovery>, StoreError> {
        Ok(self.state.recoveries.get(&tx_id).cloned())
    }

    fn recoveries(&self) -> Result<Vec<Recovery>, StoreError> {
        Ok(self.state.recoveries.values().cloned().collect())
    }
}
