use std::fmt;

use thiserror::Error;

use crate::account::AccountIndex;
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
        })
    }
}

/// A failure of the underlying database engine.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct DatabaseError(#[from] DatabaseSource);

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
    #[error("private context could not be decrypted")]
    ContextUndecryptable,
    #[error("private context could not be encrypted")]
    ContextUnsealable,
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
