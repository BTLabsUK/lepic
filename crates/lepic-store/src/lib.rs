//! SQLite wallet storage behind repository traits.
//!
//! The engine sees only [`WalletStore`] and the repository traits. [`SqliteStore`] is the product
//! implementation; [`MemoryStore`] behaves the same without a file, for tests of the layers above.

mod account;
mod context;
mod encoding;
mod error;
mod invoice;
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
pub use context::{CONTEXT_KEY_LEN, ContextKey, ContextRepository, ParticipantId, PrivateContext};
pub use error::{DatabaseError, Record, StoreError};
pub use invoice::{
    InvoiceAddressIndex, InvoiceCap, InvoiceRepository, MAX_PARKED_INVOICES,
    MAX_PARKED_INVOICES_PER_SENDER, PendingInvoice, PendingInvoiceStatus,
};
pub use memory::MemoryStore;
pub use output::{
    COMMITMENT_LEN, CommitmentBytes, KEY_ID_LEN, KeyId, OutputRecord, OutputRepository,
    OutputStatus,
};
pub use peer::{AllowedPeer, PeerCapability, PeerRepository, PeerSupport};
pub use relay::{
    InboxEntry, InboxStatus, OutboxEntry, OutboxId, OutboxStatus, RelayRepository, StoredOutbox,
};
pub use settings::SettingsRepository;
pub use slate::{SlateRepository, SlateStage, StoredSlate};
#[cfg(feature = "sqlite")]
pub use sqlite::{SCHEMA_VERSION, SqliteStore};
pub use store::{Repositories, WalletStore};
pub use transaction::{
    StoredTransaction, TransactionEntry, TransactionRepository, TxDirection, TxId, TxState,
};
