//! An in-memory [`WalletStore`] with the same behaviour as the SQLite one, for engine tests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use lepic_primitives::amount::Height;
use uuid::Uuid;

use crate::account::{AccountIndex, AccountRecord, AccountRepository};
use crate::contact::{
    self, CARD_KEY_LEN, ContactCap, ContactId, ContactMailbox, ContactOutboxEntry, ContactOutboxId,
    ContactOutboxState, ContactRecord, ContactRepository, INVITE_ID_LEN, MAX_CONTACTS,
    MAX_PENDING_PAIRINGS, PairingId, PairingSecrets, PendingPairing, StoredContactOutbox,
};
use crate::context::{self, ContextKey, ContextRepository, ParticipantId, PrivateContext};
use crate::encoding::timestamp_to_column;
use crate::error::{Record, StoreError};
use crate::imported::{
    self, ChainCheck, ImportedOutput, ImportedOutputStatus, ImportedRepository, ImportedTransaction,
};
use crate::invoice::{
    self, InvoiceAddressIndex, InvoiceRepository, PendingInvoice, PendingInvoiceStatus,
};
use crate::output::{CommitmentBytes, OutputRecord, OutputRepository, OutputStatus};
use crate::peer::{PeerCapability, PeerRepository};
use crate::relay::{
    InboxEntry, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
use crate::settings::SettingsRepository;
use crate::slate::{SlateRepository, SlateStage, StoredSlate};
use crate::store::{Repositories, WalletStore};
use crate::transaction::{
    OpenReceipt, StoredTransaction, TransactionEntry, TransactionRepository, TxDirection, TxId,
    TxState,
};

type SlateKey = ([u8; 16], &'static str);

#[derive(Debug, Clone, Default)]
struct State {
    accounts: BTreeMap<AccountIndex, AccountRecord>,
    outputs: BTreeMap<CommitmentBytes, OutputRecord>,
    transactions: BTreeMap<TxId, TransactionEntry>,
    confirmed_heights: BTreeMap<TxId, Height>,
    counterparties: BTreeMap<TxId, String>,
    slates: BTreeMap<SlateKey, StoredSlate>,
    contexts: BTreeMap<([u8; 16], ParticipantId), Vec<u8>>,
    inbox: BTreeMap<String, InboxEntry>,
    outbox: BTreeMap<OutboxId, OutboxEntry>,
    settings: BTreeMap<String, String>,
    pending_invoices: BTreeMap<[u8; 16], SealedInvoice>,
    peer_capabilities: BTreeMap<String, PeerCapability>,
    contacts: BTreeMap<ContactId, ContactRecord>,
    contact_slot_counters: BTreeMap<AccountIndex, u32>,
    contact_mailboxes: BTreeMap<ContactId, ContactMailbox>,
    pairings: BTreeMap<PairingId, SealedPairing>,
    contact_outbox: BTreeMap<ContactOutboxId, ContactOutboxEntry>,
    seen_envelopes: BTreeMap<[u8; 32], Timestamp>,
    invoice_address_index: Option<InvoiceAddressIndex>,
    imported_transactions: BTreeMap<TxId, ImportedTransaction>,
    imported_outputs: BTreeMap<CommitmentBytes, ImportedOutput>,
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

    fn prune_parked_invoices(&mut self, received_before: Timestamp) -> Result<usize, StoreError> {
        timestamp_to_column(received_before)?;
        let before = self.state.pending_invoices.len();
        self.state.pending_invoices.retain(|_, stored| {
            stored.fields.status != PendingInvoiceStatus::Parked
                || stored.fields.received_at >= received_before
        });
        Ok(before.saturating_sub(self.state.pending_invoices.len()))
    }

    fn invoice_address_index(&self) -> Result<Option<InvoiceAddressIndex>, StoreError> {
        Ok(self.state.invoice_address_index)
    }

    fn set_invoice_address_index(&mut self, index: InvoiceAddressIndex) -> Result<(), StoreError> {
        self.state.invoice_address_index = Some(index);
        Ok(())
    }
}

impl PeerRepository for MemoryRepos<'_> {
    fn put_peer_capability(&mut self, capability: &PeerCapability) -> Result<(), StoreError> {
        timestamp_to_column(capability.learned_at)?;
        self.state
            .peer_capabilities
            .insert(capability.key.clone(), capability.clone());
        Ok(())
    }

    fn peer_capability(&self, key: &str) -> Result<Option<PeerCapability>, StoreError> {
        Ok(self.state.peer_capabilities.get(key).cloned())
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

    fn outbox_where(&self, keep: impl Fn(&ContactOutboxEntry) -> bool) -> Vec<StoredContactOutbox> {
        self.state
            .contact_outbox
            .iter()
            .filter(|(_, entry)| keep(entry))
            .map(|(id, entry)| StoredContactOutbox {
                id: *id,
                entry: entry.clone(),
            })
            .collect()
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

    fn contact_by_peer_hint_key(
        &self,
        key: &[u8; CARD_KEY_LEN],
    ) -> Result<Option<ContactRecord>, StoreError> {
        Ok(self
            .contacts_where(|contact| contact.peer.as_ref().is_some_and(|c| &c.hint_key == key))
            .into_iter()
            .next())
    }

    fn contacts_by_our_mailbox(&self, address: &str) -> Result<Vec<ContactRecord>, StoreError> {
        Ok(self.contacts_where(|contact| {
            self.state
                .contact_mailboxes
                .get(&contact.contact_id)
                .is_some_and(|mailbox| {
                    mailbox.our_mailbox == address
                        || mailbox
                            .previous
                            .as_ref()
                            .is_some_and(|previous| previous.our_mailbox == address)
                })
        }))
    }

    fn contacts(&self) -> Result<Vec<ContactRecord>, StoreError> {
        Ok(self.contacts_where(|_| true))
    }

    fn contacts_allowing_invoices(&self) -> Result<Vec<ContactRecord>, StoreError> {
        Ok(self.contacts_where(|contact| contact.allow_invoices))
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
        self.state
            .contact_outbox
            .retain(|_, entry| entry.contact_id != id);
        Ok(self.state.contacts.remove(&id).is_some())
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
        if !self.state.pairings.contains_key(&pairing.pairing_id)
            && self.state.pairings.len() >= MAX_PENDING_PAIRINGS
        {
            return Err(StoreError::ContactCapReached {
                cap: ContactCap::PendingPairings,
            });
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
        Ok(self.state.pairings.remove(&id).is_some())
    }

    fn prune_expired_pairings(&mut self, now: Timestamp) -> Result<usize, StoreError> {
        let before = self.state.pairings.len();
        self.state
            .pairings
            .retain(|_, stored| stored.fields.expires_at > now);
        Ok(before.saturating_sub(self.state.pairings.len()))
    }

    fn enqueue_contact_outbox(
        &mut self,
        entry: &ContactOutboxEntry,
    ) -> Result<ContactOutboxId, StoreError> {
        contact::check_outbox(entry)?;
        if !self.state.contacts.contains_key(&entry.contact_id) {
            return Err(StoreError::NotFound {
                record: Record::Contact,
            });
        }
        let id = next_key(
            &self.state.contact_outbox,
            ContactOutboxId(1),
            |ContactOutboxId(last)| last.checked_add(1).map(ContactOutboxId),
        )
        .ok_or(StoreError::OutOfRange { field: "outbox id" })?;
        self.state.contact_outbox.insert(id, entry.clone());
        Ok(id)
    }

    fn update_contact_outbox(
        &mut self,
        id: ContactOutboxId,
        entry: &ContactOutboxEntry,
    ) -> Result<(), StoreError> {
        contact::check_outbox(entry)?;
        if !self.state.contacts.contains_key(&entry.contact_id) {
            return Err(StoreError::NotFound {
                record: Record::Contact,
            });
        }
        match self.state.contact_outbox.get_mut(&id) {
            Some(stored) => {
                *stored = entry.clone();
                Ok(())
            }
            None => Err(StoreError::NotFound {
                record: Record::ContactOutbox,
            }),
        }
    }

    fn contact_outbox_entry(
        &self,
        id: ContactOutboxId,
    ) -> Result<Option<StoredContactOutbox>, StoreError> {
        Ok(self
            .state
            .contact_outbox
            .get(&id)
            .map(|entry| StoredContactOutbox {
                id,
                entry: entry.clone(),
            }))
    }

    fn contact_outbox(&self, contact: ContactId) -> Result<Vec<StoredContactOutbox>, StoreError> {
        Ok(self.outbox_where(|entry| entry.contact_id == contact))
    }

    fn due_contact_outbox(&self, now: Timestamp) -> Result<Vec<StoredContactOutbox>, StoreError> {
        let mut due = self.outbox_where(|entry| {
            entry.state == ContactOutboxState::Queued && entry.next_try_at <= now
        });
        due.sort_by_key(|stored| (stored.entry.next_try_at, stored.id));
        Ok(due)
    }

    fn redirect_contact_outbox(
        &mut self,
        contact: ContactId,
        destination: &str,
    ) -> Result<usize, StoreError> {
        let mut changed = 0_usize;
        for entry in self.state.contact_outbox.values_mut() {
            if entry.contact_id == contact
                && entry.state != ContactOutboxState::Delivered
                && entry.destination != destination
            {
                destination.clone_into(&mut entry.destination);
                changed = changed.saturating_add(1);
            }
        }
        Ok(changed)
    }

    fn delete_contact_outbox(&mut self, id: ContactOutboxId) -> Result<(), StoreError> {
        self.state.contact_outbox.remove(&id);
        Ok(())
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
}
