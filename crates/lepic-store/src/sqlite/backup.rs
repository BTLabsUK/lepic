//! A consistent copy of the encrypted wallet database, made while the wallet may be open.
//!
//! The copy is `VACUUM INTO` from a read-only connection of its own. That is one read
//! transaction, so it sees one state of the database, write-ahead log included, even while
//! `lepic serve` writes; it takes no lock the owner holds and writes only the copy. The copy
//! is encrypted under the same store key, so the password that opens the wallet opens it.

use std::path::Path;

use rusqlite::{Connection, ErrorCode, OpenFlags};

use super::migrate_encrypted::{code_only, forget_reader_logs, keyed_uri};
use super::{BUSY_TIMEOUT, cipher, passes_quick_check, restrict_to_owner, with_suffix};
use crate::at_rest::StoreKey;
use crate::error::StoreError;

/// Copies the encrypted database at `source` to the new file `destination`, encrypted under
/// `store_key`, and writes the key check beside it.
///
/// The source is opened read-only and is not migrated, checkpointed or locked, so this is safe
/// while another process has the wallet open. With `remove_reader_logs` the empty `-wal` and
/// `-shm` the reader made beside a database that had none are removed afterwards; pass it only
/// while holding the data directory lock, as a live process may own a log that appeared
/// meanwhile. `destination` must not exist: an existing path fails with an
/// [`std::io::ErrorKind::AlreadyExists`] error and is left as it was. The copy is
/// an owner-only file. A wrong `store_key` fails with [`StoreError::WrongKey`]. Whatever fails,
/// no part of the copy stays behind.
///
/// # Errors
/// [`StoreError::Io`] when the source is missing or the copy cannot be written,
/// [`StoreError::WrongKey`] when the key does not open the source.
pub fn backup_database(
    source: &Path,
    store_key: &StoreKey,
    destination: &Path,
    remove_reader_logs: bool,
) -> Result<(), StoreError> {
    if !source.is_file() {
        return Err(StoreError::Io {
            operation: "find the wallet database",
            source: std::io::ErrorKind::NotFound.into(),
        });
    }
    if cipher::verify(source, store_key)? == cipher::Check::Differs {
        return Err(StoreError::WrongKey);
    }
    create_new_owner_only(destination)?;
    let copied = copy(source, store_key, destination, remove_reader_logs);
    if copied.is_err() {
        remove_copy(destination);
    }
    copied
}

fn create_new_owner_only(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|source| StoreError::Io {
        operation: "create the backup database",
        source,
    })?;
    if let Err(error) = restrict_to_owner(path) {
        drop(std::fs::remove_file(path));
        return Err(error);
    }
    Ok(())
}

fn remove_copy(destination: &Path) {
    for suffix in ["", "-journal", "-wal", "-shm"] {
        drop(std::fs::remove_file(with_suffix(destination, suffix)));
    }
    let check = cipher::check_path(destination);
    drop(std::fs::remove_file(with_suffix(&check, ".tmp")));
    drop(std::fs::remove_file(check));
}

fn copy(
    source: &Path,
    store_key: &StoreKey,
    destination: &Path,
    remove_reader_logs: bool,
) -> Result<(), StoreError> {
    let exists = |suffix| std::fs::metadata(with_suffix(source, suffix)).is_ok();
    let logs_before = [exists("-wal"), exists("-shm")];
    let result = copy_from_reader(source, store_key, destination);
    if remove_reader_logs {
        drop(forget_reader_logs(source, logs_before));
    }
    result?;
    check_copy(destination, store_key)?;
    cipher::write(destination, store_key)
}

fn copy_from_reader(
    source: &Path,
    store_key: &StoreKey,
    destination: &Path,
) -> Result<(), StoreError> {
    let reader = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Closing never checkpoints, so the owner's write-ahead log stays as it was.
    reader.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )?;
    cipher::set_key(&reader, store_key)?;
    reader.busy_timeout(BUSY_TIMEOUT)?;
    reader.pragma_update(None, "temp_store", "MEMORY")?;
    // The first read is where a wrong key shows.
    reader
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| match error.sqlite_error_code() {
            Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt) => StoreError::WrongKey,
            _ => StoreError::from(error),
        })?;
    let target = keyed_uri(destination, store_key)?;
    reader
        .execute("VACUUM INTO ?1", [target.as_str()])
        .map_err(|error| code_only(&error))?;
    Ok(())
}

/// Opens the copy with the key and checks it is whole. It is left in rollback-journal mode with
/// no log of its own, so it is one file.
fn check_copy(destination: &Path, store_key: &StoreKey) -> Result<(), StoreError> {
    let refused = |operation| StoreError::Io {
        operation,
        source: std::io::ErrorKind::InvalidData.into(),
    };
    let conn = Connection::open_with_flags(
        destination,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    cipher::set_key(&conn, store_key)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let _mode: String = conn.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
    if !passes_quick_check(&conn)? {
        return Err(refused("check the backup database"));
    }
    conn.close().map_err(|(_, error)| StoreError::from(error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountIndex, AccountRecord};
    use crate::at_rest::{AtRest, STORE_KEY_LEN};
    use crate::context::StoreKeys;
    use crate::store::WalletStore;

    use super::super::SqliteStore;

    const LABEL: &str = "backup-marker-label";

    fn keys() -> StoreKeys {
        StoreKeys::from_bytes([1; 32], [2; 32])
    }

    fn store_key() -> StoreKey {
        StoreKey::from_bytes([9; STORE_KEY_LEN])
    }

    fn open_wallet(dir: &Path) -> SqliteStore {
        let store = SqliteStore::open(
            &dir.join("wallet.enc.sqlite3"),
            keys(),
            AtRest::Encrypted(&store_key()),
        )
        .unwrap();
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: AccountIndex(0),
                    label: LABEL.to_owned(),
                    next_child: 7,
                })
            })
            .unwrap();
        store
    }

    #[test]
    fn a_copy_made_while_the_wallet_is_open_opens_with_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let open = open_wallet(dir.path());
        let copy = dir.path().join("copy.sqlite3");
        backup_database(
            &dir.path().join("wallet.enc.sqlite3"),
            &store_key(),
            &copy,
            true,
        )
        .unwrap();
        // The owner keeps working after the copy.
        open.write(|repos| {
            repos.put_account(&AccountRecord {
                index: AccountIndex(1),
                label: "later".to_owned(),
                next_child: 0,
            })
        })
        .unwrap();

        let bytes = std::fs::read(&copy).unwrap();
        assert!(!bytes.windows(LABEL.len()).any(|w| w == LABEL.as_bytes()));
        assert!(!bytes.starts_with(b"SQLite format 3"));
        let copied = SqliteStore::open(&copy, keys(), AtRest::Encrypted(&store_key())).unwrap();
        let accounts = copied.read(|repos| repos.accounts()).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].label, LABEL);
        assert_eq!(accounts[0].next_child, 7);
    }

    #[test]
    fn a_wrong_key_fails_and_leaves_no_copy() {
        let dir = tempfile::tempdir().unwrap();
        let open = open_wallet(dir.path());
        let copy = dir.path().join("copy.sqlite3");
        let other = StoreKey::from_bytes([8; STORE_KEY_LEN]);
        let result = backup_database(&dir.path().join("wallet.enc.sqlite3"), &other, &copy, true);
        assert!(matches!(result, Err(StoreError::WrongKey)), "{result:?}");
        assert!(!copy.exists());
        assert!(!cipher::check_path(&copy).exists());
        drop(open);

        // Without the key check, the first read still refuses the key.
        std::fs::remove_file(cipher::check_path(&dir.path().join("wallet.enc.sqlite3"))).unwrap();
        let result = backup_database(&dir.path().join("wallet.enc.sqlite3"), &other, &copy, true);
        assert!(matches!(result, Err(StoreError::WrongKey)), "{result:?}");
        assert!(!copy.exists());
    }

    #[test]
    fn an_existing_destination_is_refused_and_left_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let _open = open_wallet(dir.path());
        let copy = dir.path().join("copy.sqlite3");
        std::fs::write(&copy, b"keep me").unwrap();
        let result = backup_database(
            &dir.path().join("wallet.enc.sqlite3"),
            &store_key(),
            &copy,
            true,
        );
        let Err(StoreError::Io { source, .. }) = result else {
            panic!("{result:?}");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&copy).unwrap(), b"keep me");
    }

    #[test]
    fn a_missing_source_fails_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("copy.sqlite3");
        let result = backup_database(
            &dir.path().join("absent.sqlite3"),
            &store_key(),
            &copy,
            true,
        );
        assert!(matches!(result, Err(StoreError::Io { .. })), "{result:?}");
        assert!(!copy.exists());
    }

    #[test]
    fn the_copy_is_one_owner_only_file_with_a_key_check() {
        let dir = tempfile::tempdir().unwrap();
        let _open = open_wallet(dir.path());
        let copy = dir.path().join("copy.sqlite3");
        backup_database(
            &dir.path().join("wallet.enc.sqlite3"),
            &store_key(),
            &copy,
            true,
        )
        .unwrap();
        assert_eq!(
            cipher::verify(&copy, &store_key()).unwrap(),
            cipher::Check::Matches
        );
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(!with_suffix(&copy, suffix).exists(), "{suffix}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for path in [copy.clone(), cipher::check_path(&copy)] {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{}", path.display());
            }
        }
    }

    #[test]
    fn the_reader_logs_are_removed_only_when_asked() {
        for (remove, expected) in [(true, false), (false, true)] {
            let dir = tempfile::tempdir().unwrap();
            drop(open_wallet(dir.path()));
            let source = dir.path().join("wallet.enc.sqlite3");
            for suffix in ["-wal", "-shm"] {
                drop(std::fs::remove_file(with_suffix(&source, suffix)));
            }
            let copy = dir.path().join("copy.sqlite3");
            backup_database(&source, &store_key(), &copy, remove).unwrap();
            assert_eq!(
                with_suffix(&source, "-wal").exists(),
                expected,
                "remove = {remove}"
            );
        }
    }
}
