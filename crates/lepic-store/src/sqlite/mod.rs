//! The SQLite [`WalletStore`].

mod repos;
pub(crate) mod schema;

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use crate::context::ContextKey;
use crate::error::StoreError;
use crate::store::{Repositories, WalletStore};

use self::repos::SqliteRepos;
pub use self::schema::SCHEMA_VERSION;

/// How long a writer waits for another process holding the database lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
    pub fn open(path: &Path, key: ContextKey) -> Result<Self, StoreError> {
        restrict_to_owner(path)?;
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&conn)?;
        schema::migrate_to(&mut conn, SCHEMA_VERSION)?;
        Ok(Self {
            conn: Mutex::new(conn),
            key,
        })
    }
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
        .and_then(|file| file.set_permissions(std::fs::Permissions::from_mode(0o600)));
    // StoreError has no I/O variant, so the failure is reported as SQLite's own "cannot open",
    // with the OS error text kept as its message.
    restricted.map_err(|error| {
        StoreError::from(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
            Some(error.to_string()),
        ))
    })
}

#[cfg(not(unix))]
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
