// SPDX-License-Identifier: Apache-2.0
use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

use crate::account::AccountIndex;
use crate::contact::ContactCap;
use crate::invoice::InvoiceCap;
use crate::transaction::TxId;

/// The kind of stored record an error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    Account,
    Output,
    Transaction,
    Slate,
    Context,
    InboxMessage,
    OutboxMessage,
    Setting,
    SchemaVersion,
    PendingInvoice,
    Contact,
    ContactMailbox,
    PendingPairing,
    PeerCompat,
    InvoiceAddress,
    ImportedTransaction,
    ImportedOutput,
    TransactionRecord,
    ApiEvent,
    ApiRequest,
    WatchRow,
    NativeOutbox,
    PaymentDelivery,
    NodePost,
    Recovery,
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Account => "account",
            Self::Output => "output",
            Self::Transaction => "transaction",
            Self::Slate => "slate",
            Self::Context => "private context",
            Self::InboxMessage => "inbox message",
            Self::OutboxMessage => "outbox message",
            Self::Setting => "setting",
            Self::SchemaVersion => "schema version",
            Self::PendingInvoice => "pending invoice",
            Self::Contact => "contact",
            Self::ContactMailbox => "contact mailbox",
            Self::PendingPairing => "pending pairing",
            Self::PeerCompat => "peer compat",
            Self::InvoiceAddress => "invoice address",
            Self::ImportedTransaction => "imported transaction",
            Self::ImportedOutput => "imported output",
            Self::TransactionRecord => "transaction record",
            Self::ApiEvent => "api event",
            Self::ApiRequest => "api request",
            Self::WatchRow => "watched mailbox",
            Self::NativeOutbox => "native outbox entry",
            Self::PaymentDelivery => "payment delivery",
            Self::NodePost => "node post",
            Self::Recovery => "recovery",
        })
    }
}

/// A failure of the underlying database engine.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct DatabaseError(#[from] pub(crate) DatabaseSource);

#[cfg(feature = "sqlite")]
type DatabaseSource = rusqlite::Error;

// Without a database backend no database operation exists, so the error cannot occur.
#[cfg(not(feature = "sqlite"))]
type DatabaseSource = std::convert::Infallible;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Database(#[source] DatabaseError),
    #[error("database schema version {found} is newer than the supported version {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("database did not switch to write-ahead logging")]
    WalUnavailable,
    /// The database file was damaged. It was renamed, with its log files, to `set_aside`
    /// (`<name>.damaged-<unix seconds>` beside it) and is kept. Opening again fails with
    /// [`StoreError::DamagedKept`] until a new database is asked for
    /// ([`crate::SqliteStore::start_over`]).
    #[error("database file is damaged and was moved aside to {}", set_aside.display())]
    DamagedSetAside { set_aside: PathBuf },
    /// No database exists, and a damaged one set aside by an earlier open is kept beside its
    /// name at `set_aside`. Nothing was made: a new, empty database is made only when asked
    /// for ([`crate::SqliteStore::start_over`]), or once the file set aside is moved away.
    #[error(
        "no database exists and a damaged one is kept at {}; a new one is made only when asked for",
        set_aside.display()
    )]
    DamagedKept { set_aside: PathBuf },
    /// The database file is damaged. An open that sets nothing aside left it where it is.
    #[error("database file is damaged")]
    Damaged,
    /// The encrypted database is not this key's: its key check refuses the key, or it has no
    /// check and does not open with it. Nothing was changed.
    #[error("database does not open with this key")]
    WrongKey,
    #[error("stored {record} has a malformed {field}")]
    Corrupt { record: Record, field: &'static str },
    #[error("{field} is outside the storable range")]
    OutOfRange { field: &'static str },
    #[error("account {0} does not exist")]
    UnknownAccount(AccountIndex),
    #[error("transaction {0} does not exist")]
    UnknownTransaction(TxId),
    #[error("account label is already used by another account")]
    LabelTaken,
    #[error("{record} is already stored")]
    Duplicate { record: Record },
    #[error("{record} does not exist")]
    NotFound { record: Record },
    #[error("{record} is still referred to by another record")]
    InUse { record: Record },
    #[error("private context could not be decrypted")]
    ContextUndecryptable,
    #[error("private context could not be encrypted")]
    ContextUnsealable,
    #[error("stored {record} could not be decrypted")]
    Undecryptable { record: Record },
    #[error("{record} could not be encrypted")]
    Unsealable { record: Record },
    #[error("{record} cannot take the requested status")]
    InvalidStatus { record: Record },
    #[error("{cap} cap on parked invoices is reached")]
    InvoiceCapReached { cap: InvoiceCap },
    #[error("cap on {cap} is reached")]
    ContactCapReached { cap: ContactCap },
    #[error("contact backup is version {found}, which this build cannot read")]
    UnsupportedBackup { found: u64 },
    #[error("contact backup is for the other network")]
    BackupOfOtherNetwork,
    #[error("operating system randomness is unavailable")]
    Randomness(#[source] getrandom::Error),
    #[error("store is unusable after a panic in another thread")]
    Poisoned,
    #[error("could not {operation}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(DatabaseError(error))
    }
}
