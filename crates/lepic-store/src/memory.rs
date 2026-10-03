//! An in-memory [`WalletStore`] with the same behaviour as the SQLite one, for engine tests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use uuid::Uuid;

use crate::account::{AccountIndex, AccountRecord, AccountRepository};
use crate::context::{self, ContextKey, ContextRepository, ParticipantId, PrivateContext};
use crate::encoding::timestamp_to_column;
use crate::error::{Record, StoreError};
use crate::output::{CommitmentBytes, OutputRecord, OutputRepository, OutputStatus};
use crate::relay::{
    InboxEntry, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
use crate::settings::SettingsRepository;
use crate::slate::{SlateRepository, SlateStage, StoredSlate};
use crate::store::{Repositories, WalletStore};
use crate::transaction::{
    StoredTransaction, TransactionEntry, TransactionRepository, TxDirection, TxId,
};

type SlateKey = ([u8; 16], &'static str);

#[derive(Debug, Clone, Default)]
struct State {
    accounts: BTreeMap<AccountIndex, AccountRecord>,
    outputs: BTreeMap<CommitmentBytes, OutputRecord>,
    transactions: BTreeMap<TxId, TransactionEntry>,
    slates: BTreeMap<SlateKey, StoredSlate>,
    contexts: BTreeMap<([u8; 16], ParticipantId), Vec<u8>>,
    inbox: BTreeMap<String, InboxEntry>,
    outbox: BTreeMap<OutboxId, OutboxEntry>,
    settings: BTreeMap<String, String>,
}

/// Holds all data in memory. Clones made with [`MemoryStore::reopen`] share it, which lets a test
/// reopen "the same database" with another key.
#[derive(Debug)]
pub struct MemoryStore {
    state: Arc<Mutex<State>>,
    key: ContextKey,
}

impl MemoryStore {
    pub fn new(key: ContextKey) -> Self {
        Self {
            state: Arc::default(),
            key,
        }
    }

    /// A second handle on the same data, sealing and opening contexts under `key`.
    pub fn reopen(&self, key: ContextKey) -> Self {
        Self {
            state: Arc::clone(&self.state),
            key,
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
    fn require_account(&self, index: AccountIndex) -> Result<(), StoreError> {
        if self.state.accounts.contains_key(&index) {
            Ok(())
        } else {
            Err(StoreError::UnknownAccount(index))
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

    fn delete_output(&mut self, commitment: &CommitmentBytes) -> Result<(), StoreError> {
        self.state.outputs.remove(commitment);
        Ok(())
    }
}

impl TransactionRepository for MemoryRepos<'_> {
    fn insert_transaction(&mut self, entry: &TransactionEntry) -> Result<TxId, StoreError> {
        self.check_transaction(None, entry)?;
        let id = next_key(&self.state.transactions, TxId(1), |TxId(last)| {
            last.checked_add(1).map(TxId)
        })
        .ok_or(StoreError::OutOfRange {
            field: "transaction id",
        })?;
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
}

fn slate_key(slate_id: Uuid, stage: SlateStage) -> SlateKey {
    (slate_id.into_bytes(), stage.code())
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

    fn delete_setting(&mut self, key: &str) -> Result<(), StoreError> {
        self.state.settings.remove(key);
        Ok(())
    }
}
