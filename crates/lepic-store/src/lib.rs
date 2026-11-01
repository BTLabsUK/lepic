// SPDX-License-Identifier: Apache-2.0
//! SQLite wallet storage behind repository traits.
//!
//! The engine sees only [`WalletStore`] and the repository traits. [`SqliteStore`] is the product
//! implementation; [`MemoryStore`] behaves the same without a file, for tests of the layers above.

mod account;
mod at_rest;
mod contact;
#[cfg(feature = "sqlite")]
mod contact_backup;
mod context;
mod encoding;
mod error;
#[cfg(feature = "sqlite")]
#[doc(hidden)]
pub mod fuzz;
mod imported;
mod invoice;
#[cfg(feature = "sqlite")]
pub mod legacy;
mod memory;
mod output;
mod peer;
mod relay;
mod settings;
mod slate;
#[cfg(feature = "sqlite")]
mod sqlite;
mod store;
mod transaction;
mod tx_record;

pub use account::{AccountIndex, AccountRecord, AccountRepository};
pub use at_rest::{
    AtRest, AtRestReport, AtRestState, MIGRATED_FROM_SETTING, MigrationObserver, MigrationProgress,
    MigrationStage, ROLLBACK_SCAN_SETTING, STORE_KEY_LEN, StoreKey,
};
pub use contact::{
    BOX_SALT_LEN, CARD_KEY_LEN, CONTACT_ID_LEN, CONTACT_SLOT_COUNT, ContactCap, ContactId,
    ContactKind, ContactMailbox, ContactOutboxEntry, ContactOutboxId, ContactOutboxState,
    ContactRecord, ContactRepository, ContactState, INVITE_ID_LEN, MAX_CANCELLED_PAIRINGS,
    MAX_CONTACTS, MAX_PENDING_PAIRINGS, PAYMENTS_KEY_LEN, PRIVATE_SLOT_END, PairRequest,
    PairingEndReason, PairingFacts, PairingId, PairingRole, PairingSecrets, PairingState, PeerCard,
    PendingPairing, PreviousHome, RelayBackoff, SAS_LEN, SealMode, StatusKind, StatusNotice,
    StatusNoticeId, StoredContactOutbox, StoredStatusNotice, VERDICT_LEN,
};
#[cfg(feature = "sqlite")]
pub use contact_backup::{
    CONTACT_BACKUP_VERSION, CardReader, ImportSummary, export_contacts, export_contacts_where,
    import_contacts,
};
pub use context::{
    CONTEXT_KEY_LEN, ContextKey, ContextRepository, ParticipantId, PrivateContext, StoreKeys,
};
pub use error::{DatabaseError, Record, StoreError};
pub use imported::{
    ChainCheck, ImportedKind, ImportedMessage, ImportedOutput, ImportedOutputStatus,
    ImportedRepository, ImportedTransaction, MAX_IMPORTED_MESSAGE_BYTES, MAX_IMPORTED_MESSAGES,
};
pub use invoice::{
    InvoiceAddressIndex, InvoiceCap, InvoiceRepository, MAX_PARKED_INVOICES,
    MAX_PARKED_INVOICES_PER_SENDER, PendingInvoice, PendingInvoiceStatus,
};
pub use memory::MemoryStore;
pub use output::{
    COMMITMENT_LEN, CommitmentBytes, KEY_ID_LEN, KeyId, OutputRecord, OutputRepository,
    OutputStatus,
};
#[doc(hidden)]
pub use peer::vectors as peer_vectors;
pub use peer::{PEER_TAG_KEY_LEN, PEER_TAG_LEN, PeerCompat, PeerRepository, PeerTag, PeerTagKey};
pub use relay::{
    InboxEntry, InboxStatus, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
pub use settings::SettingsRepository;
pub use slate::{SlateRepository, SlateStage, StoredSlate};
#[cfg(feature = "sqlite")]
pub use sqlite::{
    DATABASE_FILE, ENCRYPTED_DATABASE_FILE, RetireSummary, SCHEMA_VERSION, SqliteStore,
    migration_in_progress, open_existing_wallet_dir, open_wallet_dir, remove_database_leftovers,
    retire_plain_store,
};
pub use store::{Repositories, WalletStore};
pub use transaction::{
    OpenReceipt, ReceiveListing, StoredTransaction, TransactionEntry, TransactionRepository,
    TxDirection, TxId, TxState,
};
pub use tx_record::{
    FoundDuring, OtherWalletSpend, ScanFoundRecord, TxMarks, TxRecordRepository, TxWatch,
    WatchPhase, WatchedOutput,
};
