//! The desktop secret storage: the `lepic-keychain` vault in a file in the data directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use lepic_keychain::vault::{BackendError, MAX_VAULT_LEN};
use lepic_keychain::{KdfParams, Vault, VaultError, VaultStorage};
use lepic_wallet::{Password, SecretVault, SecretVaultError};
use rand::SeedableRng as _;
use rand::rngs::{StdRng, SysRng};

/// File name of the vault inside the data directory.
pub const VAULT_FILE: &str = "wallet.vault";

const TEMPORARY_SUFFIX: &str = ".tmp";

/// The vault file, replaced atomically on every change.
#[derive(Debug, Clone)]
pub struct FileVaultStorage {
    path: PathBuf,
}

impl FileVaultStorage {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl VaultStorage for FileVaultStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, BackendError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Box::new(error)),
        };
        let mut bytes = Vec::new();
        // One byte over the limit is enough for the vault to refuse the file as too long.
        let limit = u64::try_from(MAX_VAULT_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        file.take(limit).read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn replace(&mut self, contents: &[u8]) -> Result<(), BackendError> {
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(TEMPORARY_SUFFIX);
        let temporary = PathBuf::from(temporary);
        // A leftover from an interrupted write, or a link planted there, is removed rather than
        // reused, so the new file is always this process's own, owner-only file.
        if let Err(error) = fs::remove_file(&temporary)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(Box::new(error));
        }
        let mut file = owner_only().open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &self.path)?;
        sync_directory(&self.path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn owner_only() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options
}

#[cfg(not(unix))]
fn owner_only() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options
}

/// Makes the rename durable. Windows offers no directory handle to sync; its rename is durable
/// once it returns on NTFS.
#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) => File::open(dir)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> io::Result<()> {
    Ok(())
}

/// The wallet's [`SecretVault`]: one vault file, keyed by the wallet password through Argon2id.
#[derive(Debug, Clone)]
pub struct FileVault {
    path: PathBuf,
    kdf: KdfParams,
}

impl FileVault {
    pub fn new(data_dir: &Path, kdf: KdfParams) -> Self {
        Self {
            path: data_dir.join(VAULT_FILE),
            kdf,
        }
    }

    fn storage(&self) -> FileVaultStorage {
        FileVaultStorage::new(self.path.clone())
    }
}

fn os_rng() -> Result<StdRng, SecretVaultError> {
    StdRng::try_from_rng(&mut SysRng).map_err(|error| SecretVaultError::Backend(Box::new(error)))
}

fn vault_error(error: VaultError) -> SecretVaultError {
    match error {
        VaultError::NotFound => SecretVaultError::NotFound,
        VaultError::AlreadyExists => SecretVaultError::AlreadyExists,
        VaultError::Decryption => SecretVaultError::WrongPassword,
        other => SecretVaultError::Backend(Box::new(other)),
    }
}

impl SecretVault for FileVault {
    type Secrets = Vault<FileVaultStorage, StdRng>;

    fn exists(&self) -> Result<bool, SecretVaultError> {
        self.storage()
            .load()
            .map(|contents| contents.is_some())
            .map_err(SecretVaultError::Backend)
    }

    fn create(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError> {
        Vault::create(self.storage(), os_rng()?, password.expose_bytes(), self.kdf)
            .map_err(vault_error)
    }

    fn unlock(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError> {
        Vault::open(self.storage(), os_rng()?, password.expose_bytes()).map_err(vault_error)
    }
}

#[cfg(test)]
mod tests {
    use lepic_keychain::{SecretBytes, SecretName, SecretStore as _};

    use super::*;

    fn cheap() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    #[test]
    fn a_created_vault_reopens_from_its_file_with_the_same_password() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FileVault::new(dir.path(), cheap());
        assert!(!vault.exists().unwrap());
        let password = Password::new("pw".to_owned());
        let name = SecretName::new("test/secret").unwrap();
        vault
            .create(&password)
            .unwrap()
            .put(&name, &SecretBytes::from_slice(b"value"))
            .unwrap();
        assert!(vault.exists().unwrap());
        assert!(!dir.path().join("wallet.vault.tmp").exists());
        let reopened = vault.unlock(&password).unwrap();
        assert_eq!(
            reopened.get(&name).unwrap().unwrap().expose_bytes(),
            b"value"
        );
        assert!(matches!(
            vault.unlock(&Password::new("other".to_owned())),
            Err(SecretVaultError::WrongPassword)
        ));
        assert!(matches!(
            vault.create(&password),
            Err(SecretVaultError::AlreadyExists)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn the_vault_file_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let vault = FileVault::new(dir.path(), cheap());
        vault.create(&Password::new("pw".to_owned())).unwrap();
        let mode = fs::metadata(dir.path().join(VAULT_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_stale_temporary_file_does_not_pass_its_mode_to_the_vault() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("wallet.vault.tmp");
        fs::write(&stale, b"stale").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).unwrap();
        FileVault::new(dir.path(), cheap())
            .create(&Password::new("pw".to_owned()))
            .unwrap();
        let mode = fs::metadata(dir.path().join(VAULT_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_at_the_temporary_path_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, b"untouched").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("wallet.vault.tmp")).unwrap();
        let vault = FileVault::new(dir.path(), cheap());
        let password = Password::new("pw".to_owned());
        vault.create(&password).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
        let stored = fs::symlink_metadata(dir.path().join(VAULT_FILE)).unwrap();
        assert!(stored.file_type().is_file());
        vault.unlock(&password).unwrap();
    }

    #[test]
    fn an_oversized_vault_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(VAULT_FILE), vec![0; MAX_VAULT_LEN + 10]).unwrap();
        let vault = FileVault::new(dir.path(), cheap());
        assert!(matches!(
            vault.unlock(&Password::new("pw".to_owned())),
            Err(SecretVaultError::Backend(_))
        ));
    }
}
