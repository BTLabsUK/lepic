//! Read-only import of the transaction history an `epic-wallet` (CLI or GUI) keeps in its SQLite
//! database, as `docs/compat/epic-wallet-db.md` describes it.
//!
//! The source folder is only ever read with plain file reads: the database and its write-ahead
//! log are copied into a caller-owned work directory, and SQLite opens the copy.

mod copy;
mod locate;
mod reader;
mod rows;
#[cfg(test)]
mod tests;
mod wire;

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use jiff::Timestamp;
use lepic_primitives::amount::{Amount, Fee, Height};
use thiserror::Error;
use uuid::Uuid;

use crate::output::{CommitmentBytes, KeyId};

pub use self::locate::locate;

/// Bounds on what one import may read. Every count and size from the source is untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyLimits {
    /// The database plus its write-ahead log.
    pub max_db_bytes: u64,
    /// The JSON of one row. Larger rows are skipped and counted.
    pub max_row_bytes: usize,
    pub max_transactions: usize,
    pub max_outputs: usize,
    /// Also bounds the derivation counters, which upstream keeps one per account.
    pub max_accounts: usize,
}

impl Default for LegacyLimits {
    fn default() -> Self {
        Self {
            max_db_bytes: 1 << 30,
            max_row_bytes: 256 * 1024,
            max_transactions: 500_000,
            max_outputs: 2_000_000,
            max_accounts: 1_000,
        }
    }
}

/// Where a wallet folder keeps its database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyDbLocation {
    Sqlite {
        db: PathBuf,
    },
    /// A wallet from before `epic-wallet` 3.3, which kept its data in LMDB.
    LmdbUnsupported,
    Missing,
}

/// The kind of legacy record a bound or a skipped row refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyRecord {
    Account,
    Transaction,
    Output,
    ChildCounter,
}

impl fmt::Display for LegacyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Account => "account",
            Self::Transaction => "transaction",
            Self::Output => "output",
            Self::ChildCounter => "derivation counter",
        })
    }
}

#[derive(Debug, Error)]
pub enum LegacyDbError {
    #[error("no wallet database found")]
    NotFound,
    #[error("wallet database is in the LMDB format, which is not supported")]
    LmdbUnsupported,
    #[error("wallet database is {bytes} bytes, more than the import allows")]
    TooLarge { bytes: u64 },
    #[error("wallet database kept changing while it was copied")]
    SourceChanging,
    #[error("work directory is not empty")]
    WorkDirNotEmpty,
    #[error("could not read or copy the wallet database")]
    Io(#[source] std::io::Error),
    #[error("file is not a readable sqlite database")]
    NotADatabase,
    #[error("database has no epic-wallet data table")]
    MissingTable,
    #[error("database query failed")]
    Sqlite(#[source] rusqlite::Error),
    #[error("database holds {found} {record} records, more than the limit of {limit}")]
    TooMany {
        record: LegacyRecord,
        found: u64,
        limit: usize,
    },
}

impl From<std::io::Error> for LegacyDbError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for LegacyDbError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {
                Self::NotADatabase
            }
            _ => Self::Sqlite(error),
        }
    }
}

/// Everything an import needs from a legacy wallet database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyHistory {
    /// Ordered by path, then label.
    pub accounts: Vec<LegacyAccount>,
    /// Ordered by parent key id, then local id.
    pub transactions: Vec<LegacyTxLogEntry>,
    /// Ordered by key id, then MMR index.
    pub outputs: Vec<LegacyOutput>,
    /// Ordered by parent key id.
    pub next_child: Vec<LegacyChildCounter>,
    pub skipped: LegacySkipped,
    /// SHA-256 of the database bytes followed by the write-ahead log bytes, as read.
    pub source_fingerprint: [u8; 32],
}

/// Rows that failed to parse or broke a bound. They are left out of the history, never fatal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacySkipped {
    pub transactions: u32,
    pub outputs: u32,
    pub accounts: u32,
    pub counters: u32,
}

impl LegacySkipped {
    pub fn total(&self) -> u64 {
        u64::from(self.transactions)
            .saturating_add(u64::from(self.outputs))
            .saturating_add(u64::from(self.accounts))
            .saturating_add(u64::from(self.counters))
    }

    fn count(&mut self, record: LegacyRecord, rows: u32) {
        let counter = match record {
            LegacyRecord::Account => &mut self.accounts,
            LegacyRecord::Transaction => &mut self.transactions,
            LegacyRecord::Output => &mut self.outputs,
            LegacyRecord::ChildCounter => &mut self.counters,
        };
        *counter = counter.saturating_add(rows);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyAccount {
    pub label: String,
    pub path: KeyId,
}

/// The next unused child index under a parent path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyChildCounter {
    pub parent: KeyId,
    pub next_child: u32,
}

/// `TxLogEntryType` of `epic-wallet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyTxKind {
    ConfirmedCoinbase,
    TxReceived,
    TxSent,
    TxReceivedCancelled,
    TxSentCancelled,
    TxSentMempool,
    TxReceivedMempool,
    TxSentCreated,
}

/// `TxLogEntry` of `epic-wallet`. The payment proof is not carried over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyTxLogEntry {
    pub id: u32,
    pub parent_key_id: KeyId,
    pub slate_id: Option<Uuid>,
    pub kind: LegacyTxKind,
    pub created_at: Timestamp,
    pub confirmed_at: Option<Timestamp>,
    pub confirmed: bool,
    pub confirmation_height: Option<Height>,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub amount_credited: Amount,
    pub amount_debited: Amount,
    pub fee: Option<Fee>,
    pub ttl_cutoff_height: Option<Height>,
    pub messages: Vec<LegacyMessage>,
    /// File name of the transaction upstream saved beside the database.
    pub stored_tx: Option<String>,
    pub kernel_excess: Option<CommitmentBytes>,
    pub kernel_lookup_min_height: Option<Height>,
    pub public_addr: Option<String>,
}

/// A participant message. Neither the key nor the signature is checked here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMessage {
    pub participant: u64,
    /// Compressed secp256k1 public key.
    pub public_key: [u8; 33],
    pub text: Option<String>,
    /// The 64-byte compact signature encoding, as slates carry it.
    pub signature: Option<[u8; 64]>,
}

/// `OutputStatus` of `epic-wallet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyOutputStatus {
    Unconfirmed,
    Unspent,
    Locked,
    Spent,
    Deleted,
}

/// `OutputData` of `epic-wallet`. The commitment is not checked to be a curve point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyOutput {
    pub root_key_id: KeyId,
    pub key_id: KeyId,
    pub n_child: u32,
    pub commitment: Option<CommitmentBytes>,
    pub mmr_index: Option<u64>,
    pub value: Amount,
    pub status: LegacyOutputStatus,
    pub height: Height,
    pub lock_height: Height,
    pub is_coinbase: bool,
    pub tx_log_entry: Option<u32>,
}

/// Copies the database of the wallet at `wallet_dir` (the folder holding `wallet_data`, or
/// `wallet_data` itself) into `work_dir` and reads the copy.
///
/// `work_dir` must be an empty directory the caller owns. The copy and the files SQLite adds
/// beside it are removed before this returns, whether the read succeeded or not. Nothing in the source folder is opened for writing, locked or opened by
/// SQLite. A source that changes during the copy is copied again, up to three attempts in all.
pub fn read_copy(
    wallet_dir: &Path,
    work_dir: &Path,
    limits: &LegacyLimits,
) -> Result<LegacyHistory, LegacyDbError> {
    let started = Instant::now();
    let source = match locate(wallet_dir) {
        LegacyDbLocation::Sqlite { db } => db,
        LegacyDbLocation::LmdbUnsupported => return Err(LegacyDbError::LmdbUnsupported),
        LegacyDbLocation::Missing => return Err(LegacyDbError::NotFound),
    };
    let copied = copy::copy_stable(&source, work_dir, limits.max_db_bytes)?;
    let history = reader::read(&copied.db, copied.fingerprint, limits);
    copy::remove_copy(&copied.db);
    let history = history?;
    log_read(&history, started);
    Ok(history)
}

/// Reads a database file that is already a private copy. SQLite may add, replay and remove the
/// `-wal` and `-shm` files beside it, so never point this at a wallet's own file.
pub fn read_db_file(db: &Path, limits: &LegacyLimits) -> Result<LegacyHistory, LegacyDbError> {
    let started = Instant::now();
    let fingerprint = copy::fingerprint(db, limits.max_db_bytes)?;
    let history = reader::read(db, fingerprint, limits)?;
    log_read(&history, started);
    Ok(history)
}

fn log_read(history: &LegacyHistory, started: Instant) {
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if history.skipped.total() > 0 {
        tracing::warn!(elapsed_ms, "legacy wallet history read with skipped rows");
    } else {
        tracing::info!(elapsed_ms, "legacy wallet history read");
    }
}
