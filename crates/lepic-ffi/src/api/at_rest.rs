// SPDX-License-Identifier: Apache-2.0
//! The wallet database encrypted at rest: how an unlock found it, the progress of the one-off
//! copy of a plain database into an encrypted one, and the removal of the plain copies left
//! behind.

use crate::api::error::WalletError;
use crate::api::runtime::LepicRuntime;
use crate::api::wallet::EpicWallet;
use crate::frb_generated::StreamSink;

/// How the wallet's database was found on disk when the wallet was unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreAtRestState {
    /// The database is encrypted, as it was, or as a new wallet's is made.
    Encrypted,
    /// This unlock copied the plain database of an earlier version into an encrypted one and
    /// switched to it. The plain file was kept aside until [`EpicWallet::retire_plain_store`].
    MigratedNow,
    /// The copy failed (for example the disk is full), so this session runs on the plain
    /// database, which is unchanged in place. The next unlock tries again.
    FellBackToPlain,
}

/// [`EpicWallet::store_at_rest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreAtRest {
    pub state: StoreAtRestState,
    /// For `FellBackToPlain`, why the copy failed, in English for logs. Empty otherwise.
    pub reason: String,
    /// A plain database an older version made after a downgrade was set aside, and a scan from
    /// genesis is required: [`EpicWallet::restore_scan_required`] is true until one completes.
    pub rollback_set_aside: bool,
}

impl From<&lepic_store::AtRestReport> for StoreAtRest {
    fn from(report: &lepic_store::AtRestReport) -> Self {
        let (state, reason) = match &report.state {
            lepic_store::AtRestState::Encrypted => (StoreAtRestState::Encrypted, String::new()),
            lepic_store::AtRestState::MigratedNow => (StoreAtRestState::MigratedNow, String::new()),
            lepic_store::AtRestState::FellBackToPlain { reason } => {
                (StoreAtRestState::FellBackToPlain, reason.clone())
            }
        };
        Self {
            state,
            reason,
            rollback_set_aside: report.rollback_set_aside,
        }
    }
}

/// What the copy of a plain database is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMigrationStage {
    /// Pages are copied into the encrypted database.
    Copying,
    /// The copy is complete and checked against the plain database.
    Checking,
    /// The encrypted database is in use; the copy is over.
    Finished,
}

/// Progress of the copy of a plain database into an encrypted one during an open: `done` of
/// `total` database pages. It can end short of `total` (free pages are not copied) until
/// `Finished`, where `done` equals `total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreMigrationProgress {
    pub stage: StoreMigrationStage,
    pub done: u32,
    pub total: u32,
}

impl From<lepic_store::MigrationProgress> for StoreMigrationProgress {
    fn from(progress: lepic_store::MigrationProgress) -> Self {
        Self {
            stage: match progress.stage {
                lepic_store::MigrationStage::Copying => StoreMigrationStage::Copying,
                lepic_store::MigrationStage::Checking => StoreMigrationStage::Checking,
                lepic_store::MigrationStage::Finished => StoreMigrationStage::Finished,
            },
            done: u32::try_from(progress.done).unwrap_or(u32::MAX),
            total: u32::try_from(progress.total).unwrap_or(u32::MAX),
        }
    }
}

/// [`EpicWallet::retire_plain_store`]: the file names deleted from the data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredPlainStore {
    pub deleted: Vec<String>,
}

impl LepicRuntime {
    /// Sends the progress of every copy of a plain database into an encrypted one, made by an
    /// open, create or unlock of this runtime from now on, to `sink`, replacing the stream
    /// subscribed before. Most opens copy nothing and send nothing; the first unlock after the
    /// update that encrypts the database sends a few events per second while it copies.
    pub fn store_migration_progress(&self, sink: StreamSink<StoreMigrationProgress>) {
        self.inner.migration.replace(Some(sink));
    }
}

impl EpicWallet {
    /// How the wallet's database was found on disk when it was unlocked. Fails with `Locked`.
    pub async fn store_at_rest(&self) -> Result<StoreAtRest, WalletError> {
        self.run(
            "store_at_rest",
            |session| async move { session.store_at_rest() },
        )
        .await
    }

    /// Deletes the plain copies of the database kept in the data directory after the move to
    /// encryption: every `wallet.sqlite3.pre-encryption` file, and every
    /// `wallet.sqlite3.after-rollback-<unix>` file older than `older_than_days`, each with its
    /// log files. Nothing else. For the release after the one that encrypts; the app decides
    /// when. Deletes nothing while the session runs on the plain database. Fails with `Locked`
    /// and `Io`.
    pub async fn retire_plain_store(
        &self,
        older_than_days: u32,
    ) -> Result<RetiredPlainStore, WalletError> {
        self.run("retire_plain_store", |session| async move {
            session.retire_plain_store(older_than_days).await
        })
        .await
    }
}
