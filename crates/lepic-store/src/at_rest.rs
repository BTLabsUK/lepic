// SPDX-License-Identifier: Apache-2.0
//! Whether a wallet database file is encrypted at rest, and the key it is encrypted under.

use zeroize::Zeroizing;

pub const STORE_KEY_LEN: usize = 32;

/// The key a whole database file, with its write-ahead log, is encrypted under. It has no
/// `Debug`, so it cannot reach a log by accident.
pub struct StoreKey(Zeroizing<[u8; STORE_KEY_LEN]>);

impl StoreKey {
    pub fn from_bytes(bytes: [u8; STORE_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A key that `fill` writes straight into its own wiped buffer, so a key derived here
    /// leaves no copy behind. Fails with the error of `fill`.
    pub fn filled_by<E>(
        fill: impl FnOnce(&mut [u8; STORE_KEY_LEN]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut key = Self(Zeroizing::new([0; STORE_KEY_LEN]));
        fill(&mut key.0)?;
        Ok(key)
    }

    #[cfg(feature = "sqlite")]
    pub(crate) fn expose(&self) -> &[u8; STORE_KEY_LEN] {
        &self.0
    }
}

/// The setting of an encrypted database that records the plain database it was copied from.
pub const MIGRATED_FROM_SETTING: &str = "store.migrated_from";

/// The setting of an encrypted database that says a plain database an older build made was
/// set aside, so a restore scan must run. The wallet turns it into its own restore-scan flag.
pub const ROLLBACK_SCAN_SETTING: &str = "store.rollback_scan_required";

/// How the wallet database of a data directory was found and opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtRestState {
    /// The encrypted database was there, or a new one was made.
    Encrypted,
    /// A plain database was copied into a new encrypted one by this open, which then switched
    /// to it; the plain file was set aside as `wallet.sqlite3.pre-encryption`.
    MigratedNow,
    /// The copy of the plain database failed, so this session runs on the plain file, which
    /// was left in place. The next open tries the copy again. `reason` names the failure,
    /// without paths.
    FellBackToPlain { reason: String },
}

/// What opening a data directory's wallet database did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtRestReport {
    pub state: AtRestState,
    /// A plain database beside the encrypted one, not the one it was copied from, was set
    /// aside as `wallet.sqlite3.after-rollback-<unix seconds>`: an older build made it after a
    /// rollback. Outputs it made are found only by a restore scan, which the open requires.
    pub rollback_set_aside: bool,
}

/// What a copy of a plain database is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStage {
    /// Pages are being copied into the encrypted file.
    Copying,
    /// The copy is complete and being checked against the plain file.
    Checking,
    /// The encrypted database is in use.
    Finished,
}

/// Progress of the copy of a plain database into an encrypted one: `done` of `total` pages.
/// `done` reaches `total` only with [`MigrationStage::Finished`]: the copy leaves out free
/// pages, so it can end short of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationProgress {
    pub stage: MigrationStage,
    pub done: u64,
    pub total: u64,
}

/// Where a long copy reports its progress, from the thread that runs the open or one beside
/// it.
pub type MigrationObserver = dyn Fn(MigrationProgress) + Send + Sync;

/// How a database file is kept on disk.
#[derive(Clone, Copy)]
pub enum AtRest<'k> {
    /// A plain SQLite file.
    Plain,
    /// Every page of the file and its write-ahead log sealed with ChaCha20-Poly1305 under the
    /// key (SQLite3 Multiple Ciphers), with a key check file beside it.
    Encrypted(&'k StoreKey),
}
