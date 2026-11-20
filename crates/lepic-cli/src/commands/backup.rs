// SPDX-License-Identifier: Apache-2.0
//! `lepic wallet backup`: a copy of the vault and the encrypted database in a new folder.
//!
//! It does not wait for the data directory lock, so it runs next to `lepic serve` and any other
//! command that has the wallet open. It takes the lock when it is free, and then also removes the
//! empty write-ahead log its reader made; when the lock is busy it leaves every log file alone.
//! The database is copied by SQLite's own snapshot, through a read-only connection of its own
//! (see `lepic_store::backup_database`); the vault is one file that is only ever replaced whole.

use std::path::Path;

use lepic_keychain::{KdfParams, VaultStorage as _};
use lepic_store::{ENCRYPTED_DATABASE_FILE, StoreError, backup_database, file};
use lepic_wallet::{Password, WalletError, store_key_from_vault};

use super::{check_private_dir, password_from};
use crate::cli::BackupArgs;
use crate::exit::CliError;
use crate::host::Host;
use crate::output::{BackupReport, Report};
use crate::vault::{FileVault, FileVaultStorage, VAULT_FILE};

/// What a backup holds beside the database: the key check `lepic-store` writes for it.
const CHECK_FILE: &str = "wallet.enc.sqlite3.check";

impl<H: Host> super::Run<'_, H> {
    pub(super) async fn backup(&mut self, args: &BackupArgs) -> Result<Report, CliError> {
        let data_dir = self.settings.data_dir.clone();
        if !data_dir.join(VAULT_FILE).exists() {
            return Err(WalletError::NoWallet.into());
        }
        check_private_dir(&data_dir)?;
        if lepic_store::migration_in_progress(&data_dir) {
            return Err(CliError::BackupNotReady {
                reason: "it is being encrypted; try again when that has finished",
            });
        }
        if !data_dir.join(ENCRYPTED_DATABASE_FILE).exists() {
            return Err(CliError::BackupNotReady {
                reason: "it is not encrypted yet",
            });
        }
        // Refused before the password is asked for, which would be typed for nothing.
        if std::fs::symlink_metadata(&args.dir).is_ok() {
            return Err(CliError::BackupExists {
                path: args.dir.clone(),
            });
        }
        let password = self
            .console
            .secrets
            .wallet_password(
                &mut self.console.env,
                self.settings.password_file.as_deref(),
                false,
            )
            .await?;
        // The data directory lock is tried without waiting. Held, nobody else has the wallet open
        // and the reader's empty logs can go; busy, a live process may own them, so they stay.
        let lock = lepic_store::try_lock_data_dir(&data_dir);
        let report = write_backup(
            self.host.vault_kdf(),
            &data_dir,
            &args.dir,
            &password_from(password),
            lock.is_ok(),
        );
        drop(lock);
        report
    }
}

/// Writes the backup folder `destination`, and removes what it wrote if any step fails.
fn write_backup(
    kdf: KdfParams,
    data_dir: &Path,
    destination: &Path,
    password: &Password,
    remove_reader_logs: bool,
) -> Result<Report, CliError> {
    create_backup_dir(destination)?;
    let written = fill(kdf, data_dir, destination, password, remove_reader_logs);
    if written.is_err() {
        for name in [VAULT_FILE, ENCRYPTED_DATABASE_FILE, CHECK_FILE] {
            drop(std::fs::remove_file(destination.join(name)));
        }
        drop(std::fs::remove_dir(destination));
    }
    written
}

fn fill(
    kdf: KdfParams,
    data_dir: &Path,
    destination: &Path,
    password: &Password,
    remove_reader_logs: bool,
) -> Result<Report, CliError> {
    let vault = FileVaultStorage::new(data_dir.join(VAULT_FILE))
        .load()
        .map_err(|error| CliError::Io {
            what: "read the wallet vault",
            source: std::io::Error::other(error),
        })?
        .ok_or(WalletError::NoWallet)?;
    file::write_owner_only_atomic(&destination.join(VAULT_FILE), &vault)
        .map_err(CliError::io("write the vault backup"))?;
    // The copy of the vault proves the password opens the backup, and gives the database key.
    let key = store_key_from_vault(&FileVault::new(destination, kdf), password)?;
    backup_database(
        &data_dir.join(ENCRYPTED_DATABASE_FILE),
        &key,
        &destination.join(ENCRYPTED_DATABASE_FILE),
        remove_reader_logs,
    )
    .map_err(|error| match error {
        // The vault's seed does not open the database: it belongs to another wallet.
        StoreError::WrongKey => CliError::from(WalletError::ForeignDatabase),
        other => CliError::from(other),
    })?;
    Ok(Report::Backup(BackupReport {
        dir: destination.display().to_string(),
        files: [VAULT_FILE, ENCRYPTED_DATABASE_FILE, CHECK_FILE]
            .map(str::to_owned)
            .to_vec(),
    }))
}

/// Creates `dir` as a new owner-only folder; its parent must exist. A path that exists, also
/// one made after the check in the command, is refused and left as it is.
#[cfg(unix)]
fn create_backup_dir(dir: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|error| refuse_existing(dir, error))
}

#[cfg(not(unix))]
fn create_backup_dir(dir: &Path) -> Result<(), CliError> {
    std::fs::create_dir(dir).map_err(|error| refuse_existing(dir, error))
}

fn refuse_existing(dir: &Path, error: std::io::Error) -> CliError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        CliError::BackupExists {
            path: dir.to_path_buf(),
        }
    } else {
        CliError::io("create the backup folder")(error)
    }
}
