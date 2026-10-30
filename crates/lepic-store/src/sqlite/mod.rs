// SPDX-License-Identifier: Apache-2.0
//! The SQLite [`WalletStore`].

#[cfg(windows)]
mod acl;
mod repos;
pub(crate) mod schema;
mod v8;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, TransactionBehavior};

use crate::context::ContextKey;
use crate::error::StoreError;
use crate::store::{Repositories, WalletStore};

use self::repos::SqliteRepos;
pub use self::schema::SCHEMA_VERSION;

/// How long a writer waits for another process holding the database lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The files SQLite keeps beside a database, which belong to it.
const LOG_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// A wallet database file. One handle serialises its own callers; other processes may open the
/// same file and wait up to the busy timeout for its lock.
#[derive(Debug)]
pub struct SqliteStore {
    conn: Mutex<Connection>,
    key: ContextKey,
}

impl SqliteStore {
    /// Opens or creates the database at `path` and migrates it to [`SCHEMA_VERSION`]. A
    /// database written by a newer version is refused with [`StoreError::SchemaTooNew`] and left
    /// unchanged.
    ///
    /// A database that is not one, or fails SQLite's `quick_check`, is renamed with its log
    /// files to `<name>.damaged-<unix seconds>` and kept, and the open fails with
    /// [`StoreError::DamagedSetAside`]; opening again creates a new, empty database. Log files
    /// found without their database are set aside the same way before a new one is made.
    pub fn open(path: &Path, key: ContextKey) -> Result<Self, StoreError> {
        if !path.try_exists().map_err(io("look for the database"))? {
            set_aside_logs_without_database(path)?;
        }
        restrict_to_owner(path)?;
        match open_checked(path, OpenFlags::SQLITE_OPEN_CREATE)? {
            Some(conn) => {
                // SQLite has just made the `-wal` and `-shm` files; on Windows they took the
                // folder's access list, not the database's.
                #[cfg(windows)]
                restrict_to_owner(path)?;
                Ok(Self {
                    conn: Mutex::new(conn),
                    key,
                })
            }
            None => {
                set_aside(path)?;
                Err(StoreError::DamagedSetAside)
            }
        }
    }

    /// Opens the database at `path` and migrates it, as [`SqliteStore::open`] does, but only
    /// when it exists and without setting anything aside: `None` when there is no database, and
    /// [`StoreError::Damaged`] when the file is not one or fails `quick_check`, with it and its
    /// log files left where they are. For a caller that must leave a damaged wallet as it
    /// found it. It opens read-write, as recovery needs: a hot `-journal` may be rolled back
    /// and a `-shm` file created, but no file is moved.
    pub fn open_existing(path: &Path, key: ContextKey) -> Result<Option<Self>, StoreError> {
        if !path.try_exists().map_err(io("look for the database"))? {
            return Ok(None);
        }
        match open_checked(path, OpenFlags::empty())? {
            Some(conn) => Ok(Some(Self {
                conn: Mutex::new(conn),
                key,
            })),
            None => Err(StoreError::Damaged),
        }
    }
}

/// The open, migrated connection, or `None` when the file is damaged. The damaged file is
/// closed without a checkpoint, so its write-ahead log stays as it was. `create` is
/// `SQLITE_OPEN_CREATE` to make a missing file, or empty.
fn open_checked(path: &Path, create: OpenFlags) -> Result<Option<Connection>, StoreError> {
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | create | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    let checked = configure(&conn).and_then(|()| {
        if passes_quick_check(&conn)? {
            schema::migrate_to(&mut conn, SCHEMA_VERSION).map(|()| true)
        } else {
            Ok(false)
        }
    });
    match checked {
        Ok(true) => {
            conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)?;
            Ok(Some(conn))
        }
        Ok(false) => Ok(None),
        Err(error) if is_damage(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn passes_quick_check(conn: &Connection) -> Result<bool, StoreError> {
    let mut statement = conn.prepare("PRAGMA quick_check")?;
    let mut rows = statement.query([])?;
    let first: Option<String> = match rows.next()? {
        Some(row) => Some(row.get(0)?),
        None => None,
    };
    Ok(first.as_deref() == Some("ok") && rows.next()?.is_none())
}

/// Whether SQLite refused the file as damaged, rather than busy, full or unreadable.
fn is_damage(error: &StoreError) -> bool {
    let StoreError::Database(error) = error else {
        return false;
    };
    matches!(
        error.0.sqlite_error_code(),
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase)
    )
}

/// Renames the database at `path` and its log files to one free `<name>.damaged-<seconds>`
/// name. The database goes first: if its rename fails, it keeps its logs and nothing has moved,
/// whereas a database moved without its logs would drop the commits still in its write-ahead
/// log. Logs left behind without their database are set aside on the next open.
fn set_aside(path: &Path) -> Result<(), StoreError> {
    let aside = free_set_aside_name(path)?;
    rename_if_present(path, &aside)?;
    for suffix in LOG_SUFFIXES {
        rename_if_present(&with_suffix(path, suffix), &with_suffix(&aside, suffix))?;
    }
    Ok(())
}

fn set_aside_logs_without_database(path: &Path) -> Result<(), StoreError> {
    let mut aside = None;
    for suffix in LOG_SUFFIXES {
        let log = with_suffix(path, suffix);
        if log.try_exists().map_err(io("look for a database log"))? {
            let aside = match &aside {
                Some(aside) => aside,
                None => aside.insert(free_set_aside_name(path)?),
            };
            rename_if_present(&log, &with_suffix(aside, suffix))?;
        }
    }
    Ok(())
}

/// `<path>.damaged-<unix seconds>`, with `-<n>` added while that name or one of its log names
/// is taken.
fn free_set_aside_name(path: &Path) -> Result<PathBuf, StoreError> {
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let base = with_suffix(path, &format!(".damaged-{seconds}"));
    for attempt in 0u32..1000 {
        let candidate = if attempt == 0 {
            base.clone()
        } else {
            with_suffix(&base, &format!("-{attempt}"))
        };
        let mut taken = candidate
            .try_exists()
            .map_err(io("name the damaged database"))?;
        for suffix in LOG_SUFFIXES {
            taken |= with_suffix(&candidate, suffix)
                .try_exists()
                .map_err(io("name the damaged database"))?;
        }
        if !taken {
            return Ok(candidate);
        }
    }
    Err(StoreError::Io {
        operation: "name the damaged database",
        source: std::io::ErrorKind::AlreadyExists.into(),
    })
}

fn rename_if_present(from: &Path, to: &Path) -> Result<(), StoreError> {
    match std::fs::rename(from, to) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(StoreError::Io {
            operation: "move the damaged database aside",
            source: error,
        }),
        _ => Ok(()),
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

fn io(operation: &'static str) -> impl FnOnce(std::io::Error) -> StoreError {
    move |source| StoreError::Io { operation, source }
}

/// Creates the database file owner-only, or makes an existing one so, before SQLite opens it.
/// SQLite would create it with the process umask, and gives its `-wal` and `-shm` files the
/// mode of the database file.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let restricted = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .and_then(|file| file.set_permissions(std::fs::Permissions::from_mode(0o600)))
        .and_then(|()| {
            // SQLite copies the database's mode only when it creates these, so a log left by an
            // earlier run keeps whatever mode it had.
            for suffix in ["-wal", "-shm"] {
                let mut side = path.as_os_str().to_owned();
                side.push(suffix);
                match std::fs::set_permissions(&side, std::fs::Permissions::from_mode(0o600)) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(error);
                    }
                    _ => {}
                }
            }
            Ok(())
        });
    restricted.map_err(|source| StoreError::Io {
        operation: "restrict the database to its owner",
        source,
    })
}

/// Creates the database file if missing and keeps it, and its `-wal` and `-shm` files, to the
/// process's user and `SYSTEM` ([`acl`]). A file system without access lists (FAT, some network
/// shares) cannot be restricted; the wallet still opens, with a warning, rather than being locked
/// out of its own data.
#[cfg(windows)]
fn restrict_to_owner(path: &Path) -> Result<(), StoreError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| StoreError::Io {
            operation: "create the database file",
            source,
        })?;
    for file in [
        path.to_owned(),
        with_suffix(path, "-wal"),
        with_suffix(path, "-shm"),
    ] {
        if !file.exists() {
            continue;
        }
        if let Err(error) = acl::restrict(&file) {
            tracing::warn!(error = %error, "database not restricted to its owner");
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn restrict_to_owner(_: &Path) -> Result<(), StoreError> {
    Ok(())
}

fn configure(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::WalUnavailable);
    }
    // FULL keeps every commit durable across power loss. A relay message is acknowledged right
    // after its effect is committed, so a commit that WAL's NORMAL mode could roll back would lose
    // a slate the relay no longer holds.
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

impl WalletStore for SqliteStore {
    fn read<R, E>(&self, operation: impl FnOnce(&dyn Repositories) -> Result<R, E>) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        let mut conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(StoreError::from)?;
        operation(&SqliteRepos::new(&tx, &self.key))
    }

    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        let mut conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let result = operation(&mut SqliteRepos::new(&tx, &self.key))?;
        tx.commit().map_err(StoreError::from)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
