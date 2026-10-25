//! SQLite wallet storage behind repository traits.
//!
//! The engine sees only [`WalletStore`] and the repository traits. [`SqliteStore`] is the product
//! implementation; [`MemoryStore`] behaves the same without a file, for tests of the layers above.

mod account;
mod contact;
#[cfg(feature = "sqlite")]
mod contact_backup;
mod context;
mod encoding;
mod error;
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

pub use account::{AccountIndex, AccountRecord, AccountRepository};
pub use contact::{
    BOX_SALT_LEN, CARD_KEY_LEN, CONTACT_ID_LEN, CONTACT_SLOT_COUNT, ContactCap, ContactId,
    ContactKind, ContactMailbox, ContactOutboxEntry, ContactOutboxId, ContactOutboxState,
    ContactRecord, ContactRepository, ContactState, INVITE_ID_LEN, MAX_CONTACTS,
    MAX_PENDING_PAIRINGS, PairingId, PairingRole, PairingSecrets, PairingState, PeerCard,
    PendingPairing, PreviousHome, RelayBackoff, SAS_LEN, SealMode, StoredContactOutbox,
};
#[cfg(feature = "sqlite")]
pub use contact_backup::{
    CONTACT_BACKUP_VERSION, CardReader, ImportSummary, export_contacts, import_contacts,
};
pub use context::{CONTEXT_KEY_LEN, ContextKey, ContextRepository, ParticipantId, PrivateContext};
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
pub use peer::{PeerCapability, PeerRepository, PeerSupport};
pub use relay::{
    InboxEntry, InboxStatus, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
pub use settings::SettingsRepository;
pub use slate::{SlateRepository, SlateStage, StoredSlate};
#[cfg(feature = "sqlite")]
pub use sqlite::{SCHEMA_VERSION, SqliteStore};
pub use store::{Repositories, WalletStore};
pub use transaction::{
    OpenReceipt, StoredTransaction, TransactionEntry, TransactionRepository, TxDirection, TxId,
    TxState,
};
