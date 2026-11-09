// SPDX-License-Identifier: Apache-2.0
//! The wallet database of a data directory, encrypted at rest (ADR 0032), and the move of a
//! plain one into it: copy, check, switch.
//!
//! The files, all in the data directory:
//!
//! | Name | Meaning |
//! |---|---|
//! | `wallet.sqlite3` (`-wal`, `-shm`) | the plain database of builds before encryption |
//! | `wallet.enc.sqlite3` (`-wal`, `-shm`, `.check`) | the encrypted database and its key check |
//! | `wallet.enc.sqlite3.tmp` | a copy in progress, removed when a copy starts |
//! | `wallet.enc.sqlite3.check.tmp` | a key check being written, removed with a copy's files |
//! | `wallet.sqlite3.pre-encryption` (`-wal`) | the plain database after it was copied |
//! | `wallet.sqlite3.after-rollback-<unix>` (`-wal`) | a plain database an older build made |
//! | `wallet.sqlite3.damaged-<unix>` (`-wal`) | a damaged plain database, set aside |
//!
//! The copy never writes the plain file, and its schema is never migrated before the switch:
//! an older build must be able to read it. Every step can be interrupted and the next open
//! continues: before the rename of the copy nothing but the copy has changed and the copy
//! starts again; after it, the encrypted database is complete and checked, and a plain file
//! left beside it is recognised by the record of its contents and set aside.
//!
//! Callers hold the data directory's claim (`.lepic.lock`) across every function here.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::schema::{SCHEMA_VERSION, stored_version};
use super::{
    BUSY_TIMEOUT, SqliteStore, cipher, io, is_damage, passes_quick_check, restrict_to_owner,
    with_suffix,
};
use crate::at_rest::{
    AtRest, AtRestReport, AtRestState, MIGRATED_FROM_SETTING, MigrationObserver, MigrationProgress,
    MigrationStage, ROLLBACK_SCAN_SETTING, StoreKey,
};
use crate::context::StoreKeys;
use crate::error::StoreError;
use crate::store::WalletStore;

/// File name of the plain wallet database inside the data directory.
pub const DATABASE_FILE: &str = "wallet.sqlite3";

/// File name of the encrypted wallet database inside the data directory. Its key check is
/// beside it, with `.check` added to the name.
pub const ENCRYPTED_DATABASE_FILE: &str = "wallet.enc.sqlite3";

/// The copy in progress, beside the encrypted database's name.
const COPY_FILE: &str = "wallet.enc.sqlite3.tmp";
/// The temporary file of a key check being written, before its rename.
const CHECK_COPY_FILE: &str = "wallet.enc.sqlite3.check.tmp";
const PRE_ENCRYPTION_SUFFIX: &str = ".pre-encryption";
/// A damaged database set aside by [`SqliteStore::open`].
const DAMAGED_SUFFIX: &str = ".damaged-";
const CHECK_SUFFIX: &str = cipher::CHECK_SUFFIX;
const AFTER_ROLLBACK_SUFFIX: &str = ".after-rollback-";
/// The log files that move with a plain database set aside. `-shm` holds nothing durable and
/// is removed.
const MOVED_LOGS: [&str; 2] = ["-wal", "-journal"];
const COPY_LOGS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// The plain database's main cache while it is copied, in KiB (negative in the pragma). The
/// copy takes the same, so it writes as it goes and its size tells its progress.
const COPY_CACHE_KIB: i64 = 2048;
/// How often the size of a copy in progress is reported.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Whether a copy of a plain database is in progress in `dir`, or one was interrupted and is
/// removed by the next open. A second opener that finds the directory claimed waits while
/// this holds.
pub fn migration_in_progress(dir: &Path) -> bool {
    dir.join(COPY_FILE).exists()
}

/// Opens the wallet database in `dir`, encrypted at rest under `store_key`:
///
/// 1. With `wallet.enc.sqlite3`, opens it ([`SqliteStore::open`] with
///    [`AtRest::Encrypted`]), then settles a plain `wallet.sqlite3` beside it: the one it was
///    copied from is set aside as `.pre-encryption`, finishing an interrupted switch; any other
///    is an older build's after a rollback, set aside as `.after-rollback-<unix>` with a restore
///    scan required (`ROLLBACK_SCAN_SETTING`).
/// 2. Else with a plain `wallet.sqlite3`, copies it into a new encrypted database, checks the
///    copy (`quick_check`, schema and user version, rows of every table), switches to it by
///    rename and sets the plain one aside as `.pre-encryption`; the schema migrations then run
///    on the encrypted database only. A copy that fails leaves the plain file in place and
///    opens it plain for this session ([`AtRestState::FellBackToPlain`]), which migrates its
///    schema there, as an open before encryption did; the next open tries again. A damaged plain file is set aside as [`SqliteStore::open`] does, and one of a
///    newer schema refused, unchanged.
/// 3. Else makes a new encrypted database.
///
/// Fails with [`StoreError::WrongKey`], with nothing moved, when the encrypted database's key
/// check refuses `store_key`. `observer` hears the progress of a copy.
pub fn open_wallet_dir(
    dir: &Path,
    keys: StoreKeys,
    store_key: &StoreKey,
    observer: Option<&MigrationObserver>,
) -> Result<(SqliteStore, AtRestReport), StoreError> {
    open_wallet_dir_with(dir, keys, store_key, observer, &NoFaults)
}

/// [`open_wallet_dir`] for a check of a recovery phrase, which must not create, move or migrate
/// anything: the encrypted database as [`SqliteStore::open_existing`] opens it, or, without
/// one, a throwaway encrypted copy of the plain database, migrated and removed when the store
/// is dropped, so the plain file's schema stays as it is. `None` when there is neither. A copy
/// that fails reads the plain file in place instead, as an open that falls back does, which
/// migrates its schema there.
pub fn open_existing_wallet_dir(
    dir: &Path,
    keys: StoreKeys,
    store_key: &StoreKey,
) -> Result<Option<SqliteStore>, StoreError> {
    let encrypted = dir.join(ENCRYPTED_DATABASE_FILE);
    if exists(&encrypted)? {
        return SqliteStore::open_existing(&encrypted, keys, AtRest::Encrypted(store_key));
    }
    let plain = dir.join(DATABASE_FILE);
    if !exists(&plain)? {
        return Ok(None);
    }
    match copy_plain(dir, store_key, None, &NoFaults, Purpose::Probe) {
        Ok(()) => {
            let copy = dir.join(COPY_FILE);
            let mut store =
                match SqliteStore::open_existing(&copy, keys, AtRest::Encrypted(store_key)) {
                    Ok(store) => store,
                    Err(error) => {
                        remove_copy_files(dir)?;
                        return Err(error);
                    }
                };
            if let Some(store) = &mut store {
                store.discard = copy_files(dir);
            }
            Ok(store)
        }
        Err(Failure::PlainDamaged) => {
            remove_copy_files(dir)?;
            Err(StoreError::Damaged)
        }
        Err(Failure::PlainTooNew(found)) => {
            remove_copy_files(dir)?;
            Err(StoreError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            })
        }
        Err(Failure::Failed(error) | Failure::Crashed(error) | Failure::AfterSwitch(error)) => {
            tracing::warn!(error = %error, "plain wallet database checked in place");
            drop(remove_copy_files(dir));
            SqliteStore::open_existing(&plain, keys, AtRest::Plain)
        }
    }
}

pub(crate) fn open_wallet_dir_with(
    dir: &Path,
    keys: StoreKeys,
    store_key: &StoreKey,
    observer: Option<&MigrationObserver>,
    faults: &dyn Faults,
) -> Result<(SqliteStore, AtRestReport), StoreError> {
    let encrypted = dir.join(ENCRYPTED_DATABASE_FILE);
    let plain = dir.join(DATABASE_FILE);
    let report = |state| AtRestReport {
        state,
        rollback_set_aside: false,
    };
    if exists(&encrypted)? {
        let store = SqliteStore::open(&encrypted, keys, AtRest::Encrypted(store_key))?;
        // A copy left by a check of a phrase, or by a copy interrupted after its switch.
        remove_copy_files(dir)?;
        let rollback_set_aside = settle_plain_beside(dir, &store)?;
        return Ok((
            store,
            AtRestReport {
                state: AtRestState::Encrypted,
                rollback_set_aside,
            },
        ));
    }
    if !exists(&plain)? {
        remove_copy_files(dir)?;
        let store = SqliteStore::open(&encrypted, keys, AtRest::Encrypted(store_key))?;
        return Ok((store, report(AtRestState::Encrypted)));
    }
    match copy_plain(dir, store_key, observer, faults, Purpose::Switch) {
        Ok(()) => {
            let store = SqliteStore::open(&encrypted, keys, AtRest::Encrypted(store_key))?;
            if let Some(observer) = observer {
                observer(MigrationProgress {
                    stage: MigrationStage::Finished,
                    done: 1,
                    total: 1,
                });
            }
            tracing::info!("wallet database encrypted at rest");
            Ok((store, report(AtRestState::MigratedNow)))
        }
        // The encrypted database is complete; the next open finishes setting the plain one
        // aside, and no session runs while it is still under its name.
        Err(Failure::Crashed(error) | Failure::AfterSwitch(error)) => Err(error),
        Err(Failure::PlainDamaged | Failure::PlainTooNew(_)) => {
            remove_copy_files(dir)?;
            // Sets a damaged file aside, or refuses a newer schema, as every open does.
            let store = SqliteStore::open(&plain, keys, AtRest::Plain)?;
            Ok((
                store,
                report(AtRestState::FellBackToPlain {
                    reason: "the plain database could not be read for the copy".to_owned(),
                }),
            ))
        }
        Err(Failure::Failed(error)) => {
            tracing::warn!(
                error = %error,
                "wallet database stays unencrypted for this session; the copy is tried again at the next open"
            );
            if let Err(removal) = remove_copy_files(dir) {
                tracing::warn!(error = %removal, "unfinished copy of the wallet database not removed");
            }
            let reason = error.to_string();
            let store = SqliteStore::open(&plain, keys, AtRest::Plain)?;
            Ok((store, report(AtRestState::FellBackToPlain { reason })))
        }
    }
}

/// The steps of a copy, after each of which a test can stop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Step {
    /// An earlier copy was removed and the new one's file made.
    Cleared,
    /// About to copy.
    Copying,
    /// The copy is complete; nothing checked yet.
    Copied,
    /// The copy is checked, flushed and holds its record.
    Checked,
    /// The key check of the encrypted database is written.
    KeyChecked,
    /// The copy was renamed to the encrypted database.
    Switched,
    /// The plain database was set aside.
    SetAside,
}

/// What a test makes happen at a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code, reason = "only tests stop a copy"))]
pub(crate) enum Fault {
    /// The process stops: nothing more runs, nothing is cleaned up.
    Crash,
    /// The disk is full.
    DiskFull,
    /// Another program holds the plain database open without letting it be renamed, as an
    /// indexer, antivirus or backup tool can on Windows, for as long as the open retries.
    Held,
}

pub(crate) trait Faults {
    fn at(&self, step: Step) -> Option<Fault>;
}

struct NoFaults;

impl Faults for NoFaults {
    fn at(&self, _: Step) -> Option<Fault> {
        None
    }
}

enum Failure {
    /// The plain file is damaged; nothing was copied.
    PlainDamaged,
    /// The plain file's schema is newer than this build's; nothing was copied.
    PlainTooNew(u32),
    /// The copy failed before the switch; the plain file is as it was.
    Failed(StoreError),
    /// The switch is done and the encrypted database complete, but the plain file could not
    /// be set aside: this open fails and the next one finishes it.
    AfterSwitch(StoreError),
    /// A test stopped the process.
    Crashed(StoreError),
}

impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Self {
        Self::Failed(error)
    }
}

impl From<rusqlite::Error> for Failure {
    fn from(error: rusqlite::Error) -> Self {
        Self::Failed(StoreError::from(error))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// Copy, check and switch.
    Switch,
    /// Copy and check only, for a check of a phrase.
    Probe,
}

fn step(faults: &dyn Faults, at: Step, copy: &Path) -> Result<(), Failure> {
    match faults.at(at) {
        None | Some(Fault::Held) => Ok(()),
        Some(Fault::Crash) => Err(Failure::Crashed(StoreError::Io {
            operation: "continue after a simulated crash",
            source: std::io::ErrorKind::Interrupted.into(),
        })),
        Some(Fault::DiskFull) => {
            // What a full disk leaves: part of a copy.
            drop(std::fs::write(copy, [0u8; 4096]));
            Err(Failure::Failed(StoreError::from(
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                    None,
                ),
            )))
        }
    }
}

/// What a plain database held when it was copied, kept in the copy's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationRecord {
    schema: u32,
    user_version: i64,
    bytes: u64,
    sha256: String,
    wal_sha256: Option<String>,
    rows: BTreeMap<String, u64>,
    at: u64,
}

/// The bytes of a plain database and its write-ahead log, which the copy leaves as they were.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlainFiles {
    bytes: u64,
    sha256: String,
    wal_sha256: Option<String>,
}

impl PlainFiles {
    fn of(plain: &Path) -> Result<Self, StoreError> {
        Self::with_wal(plain, &with_suffix(plain, "-wal"))
    }

    /// [`PlainFiles::of`] the database at `plain` with the log at `wal`, which may have been
    /// set aside before it.
    fn with_wal(plain: &Path, wal: &Path) -> Result<Self, StoreError> {
        let (bytes, sha256) = digest(plain)?.ok_or(StoreError::Io {
            operation: "read the plain database",
            source: std::io::ErrorKind::NotFound.into(),
        })?;
        Ok(Self {
            bytes,
            sha256,
            wal_sha256: digest(wal)?.map(|(_, sha256)| sha256),
        })
    }

    fn is_recorded(&self, record: &MigrationRecord) -> bool {
        self.bytes == record.bytes
            && self.sha256 == record.sha256
            && self.wal_sha256 == record.wal_sha256
    }
}

/// Length and SHA-256 of a file, `None` when there is none.
fn digest(path: &Path) -> Result<Option<(u64, String)>, StoreError> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreError::Io {
                operation: "read the plain database",
                source,
            });
        }
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut length = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(io("read the plain database"))?;
        let Some(chunk) = buffer.get(..read) else {
            break;
        };
        if chunk.is_empty() {
            break;
        }
        hasher.update(chunk);
        length = length.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    let hash = hasher.finalize();
    Ok(Some((
        length,
        hash.iter().map(|byte| format!("{byte:02x}")).collect(),
    )))
}

/// Steps 1 to 7 of the move of a plain database, or 1 to 4 for a probe.
fn copy_plain(
    dir: &Path,
    store_key: &StoreKey,
    observer: Option<&MigrationObserver>,
    faults: &dyn Faults,
    purpose: Purpose,
) -> Result<(), Failure> {
    let plain = dir.join(DATABASE_FILE);
    let copy = dir.join(COPY_FILE);
    let encrypted = dir.join(ENCRYPTED_DATABASE_FILE);

    // 1. A crashed earlier copy goes; the new one starts as an empty owner-only file, which
    //    also tells a second opener that a copy is in progress.
    remove_copy_files(dir)?;
    restrict_to_owner(&copy)?;
    step(faults, Step::Cleared, &copy)?;

    // 2. The plain database, read-only: never written, never migrated.
    let logs_before = [
        exists(&with_suffix(&plain, "-wal"))?,
        exists(&with_suffix(&plain, "-shm"))?,
    ];
    let reader = match open_reader(&plain) {
        Ok(reader) => reader,
        Err(error) if is_damage(&error) => return Err(Failure::PlainDamaged),
        Err(error) => return Err(Failure::Failed(error)),
    };
    let plain_state = match inspect_plain(&reader) {
        Ok(state) => state,
        Err(failure) => {
            drop(reader);
            drop(forget_reader_logs(&plain, logs_before));
            return Err(failure);
        }
    };
    let PlainState {
        schema,
        user_version,
        rows,
        pages,
        page_size,
    } = plain_state;
    step(faults, Step::Copying, &copy)?;

    // 3. A consistent snapshot of it, its write-ahead log included, encrypted under the key.
    let copied = copy_into(
        &reader,
        &copy,
        store_key,
        Progress {
            observer,
            total: u64::try_from(pages).unwrap_or(0),
            page_size: u64::try_from(page_size).unwrap_or(4096).max(1),
        },
    );
    drop(reader);
    forget_reader_logs(&plain, logs_before)?;
    copied?;
    step(faults, Step::Copied, &copy)?;
    let source = PlainFiles::of(&plain)?;

    // 4. The copy, flushed, must read back as the plain database did; it keeps the record of
    //    the plain database's bytes, by which a later open knows it.
    sync_file(&copy)?;
    if let Some(observer) = observer {
        observer(MigrationProgress {
            stage: MigrationStage::Checking,
            done: u64::try_from(pages).unwrap_or(0),
            total: u64::try_from(pages).unwrap_or(0),
        });
    }
    let record = MigrationRecord {
        schema,
        user_version,
        bytes: source.bytes,
        sha256: source.sha256,
        wal_sha256: source.wal_sha256,
        rows,
        at: unix_seconds(SystemTime::now()),
    };
    check_copy(&copy, store_key, &record)?;
    sync_file(&copy)?;
    step(faults, Step::Checked, &copy)?;
    if purpose == Purpose::Probe {
        return Ok(());
    }

    // 5. The key check, before the database it checks exists.
    cipher::write(&encrypted, store_key)?;
    step(faults, Step::KeyChecked, &copy)?;

    // 6. The switch. Once the rename is done, nothing falls back to the plain file: a failure
    //    fails this open, and the next one opens the encrypted database.
    rename_retrying(&copy, &encrypted, fs_rename)
        .map_err(io("switch to the encrypted database"))?;
    crate::file::sync_folder(&encrypted)
        .map_err(io("switch to the encrypted database"))
        .map_err(Failure::AfterSwitch)?;
    step(faults, Step::Switched, &copy).map_err(after_switch)?;

    // 7. The plain database goes aside, retried while another program holds it. A failure
    //    fails this open, so no session writes to the encrypted database while the plain one
    //    is still under its name; the next open, which knows it by the record, finishes it.
    let rename: Rename = if faults.at(Step::SetAside) == Some(Fault::Held) {
        held_database_rename
    } else {
        fs_rename
    };
    set_aside_plain(dir, PRE_ENCRYPTION_SUFFIX, rename).map_err(Failure::AfterSwitch)?;
    step(faults, Step::SetAside, &copy).map_err(after_switch)?;
    Ok(())
}

/// A failure after the switch, which must not fall back to the plain file.
fn after_switch(failure: Failure) -> Failure {
    match failure {
        Failure::Failed(error) => Failure::AfterSwitch(error),
        other => other,
    }
}

struct PlainState {
    schema: u32,
    user_version: i64,
    rows: BTreeMap<String, u64>,
    pages: i64,
    page_size: i64,
}

/// What the copy is checked against, read before it is made.
fn inspect_plain(reader: &Connection) -> Result<PlainState, Failure> {
    match passes_quick_check(reader) {
        Ok(true) => {}
        Ok(false) => return Err(Failure::PlainDamaged),
        Err(error) if is_damage(&error) => return Err(Failure::PlainDamaged),
        Err(error) => return Err(Failure::Failed(error)),
    }
    let schema = stored_version(reader)?;
    if schema > SCHEMA_VERSION {
        return Err(Failure::PlainTooNew(schema));
    }
    Ok(PlainState {
        schema,
        user_version: reader.query_row("PRAGMA user_version", [], |row| row.get(0))?,
        rows: row_counts(reader)?,
        pages: reader.query_row("PRAGMA page_count", [], |row| row.get(0))?,
        page_size: reader.query_row("PRAGMA page_size", [], |row| row.get(0))?,
    })
}

fn open_reader(plain: &Path) -> Result<Connection, StoreError> {
    let reader = Connection::open_with_flags(
        plain,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Closing never checkpoints it, so its write-ahead log stays as it was.
    reader.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )?;
    reader.busy_timeout(BUSY_TIMEOUT)?;
    // The copy's URI, with the key, passes through this connection.
    cipher::wipe_freed_memory(&reader)?;
    reader.pragma_update(None, "temp_store", "MEMORY")?;
    reader.pragma_update(None, "cache_size", -COPY_CACHE_KIB)?;
    Ok(reader)
}

/// Removes the empty `-wal` and the `-shm` a read-only connection made beside a plain database
/// that had none, so a copy, or a check of a phrase, leaves the plain files as they were.
fn forget_reader_logs(plain: &Path, [had_wal, had_shm]: [bool; 2]) -> Result<(), StoreError> {
    let wal = with_suffix(plain, "-wal");
    if had_wal || std::fs::metadata(&wal).map_or(true, |meta| meta.len() != 0) {
        return Ok(());
    }
    remove_if_present(&wal)?;
    if !had_shm {
        remove_if_present(&with_suffix(plain, "-shm"))?;
    }
    Ok(())
}

/// Rows of every table, by name.
fn row_counts(conn: &Connection) -> Result<BTreeMap<String, u64>, StoreError> {
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let mut counts = BTreeMap::new();
    for name in names {
        let quoted = name.replace('"', "\"\"");
        let count: i64 =
            conn.query_row(&format!("SELECT count(*) FROM \"{quoted}\""), [], |row| {
                row.get(0)
            })?;
        counts.insert(name, u64::try_from(count).unwrap_or(0));
    }
    Ok(counts)
}

#[derive(Clone, Copy)]
struct Progress<'a> {
    observer: Option<&'a MigrationObserver>,
    total: u64,
    page_size: u64,
}

/// What follows the copy's path in its URI, before the key in hex.
const KEY_PARAMETERS: &str = "?cipher=chacha20&key=raw:";

/// The URI of `copy` with `store_key`, written into a buffer of exactly its final size, so it
/// never grows and leaves part of the key in memory it gave back.
fn keyed_uri(copy: &Path, store_key: &StoreKey) -> Result<Zeroizing<String>, StoreError> {
    use std::fmt::Write as _;
    let uri = file_uri(copy);
    let key = store_key.expose();
    let mut target = Zeroizing::new(String::with_capacity(
        uri.len()
            .saturating_add(KEY_PARAMETERS.len())
            .saturating_add(key.len().saturating_mul(2)),
    ));
    target.push_str(&uri);
    target.push_str(KEY_PARAMETERS);
    for byte in key {
        write!(&mut *target, "{byte:02x}")
            .map_err(|_| StoreError::OutOfRange { field: "store key" })?;
    }
    Ok(target)
}

/// An error of the statement that carries the key, with only its result code: SQLite's message
/// for it can quote the copy's URI, key included, and must never reach a log.
fn code_only(error: &rusqlite::Error) -> StoreError {
    let code = match error {
        rusqlite::Error::SqliteFailure(code, _) => *code,
        _ => rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
    };
    StoreError::from(rusqlite::Error::SqliteFailure(code, None))
}

/// `VACUUM INTO` the keyed copy (ADR 0032): it reads the plain database and its log through
/// `reader` and writes only the copy. The key reaches SQLite as a bound parameter in the
/// copy's URI. While it runs, the size of the copy is reported every [`PROGRESS_INTERVAL`].
fn copy_into(
    reader: &Connection,
    copy: &Path,
    store_key: &StoreKey,
    progress: Progress<'_>,
) -> Result<(), StoreError> {
    let target = keyed_uri(copy, store_key)?;
    let Some(observer) = progress.observer else {
        reader
            .execute("VACUUM INTO ?1", [target.as_str()])
            .map_err(|error| code_only(&error))?;
        return Ok(());
    };
    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut last = Instant::now();
            while !done.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::park_timeout(Duration::from_millis(20));
                if last.elapsed() < PROGRESS_INTERVAL {
                    continue;
                }
                last = Instant::now();
                let written = std::fs::metadata(copy).map_or(0, |meta| meta.len());
                observer(MigrationProgress {
                    stage: MigrationStage::Copying,
                    done: written
                        .checked_div(progress.page_size)
                        .unwrap_or(0)
                        .min(progress.total),
                    total: progress.total,
                });
            }
        });
        let copied = reader.execute("VACUUM INTO ?1", [target.as_str()]);
        done.store(true, std::sync::atomic::Ordering::Release);
        copied.map_err(|error| code_only(&error))
    })?;
    Ok(())
}

/// A `file:` URI of `path`, with every byte but unreserved ones and separators escaped. The
/// path is taken apart, not as text, so a Windows path in its verbatim form (`\\?\C:\...`,
/// as a canonicalised data directory is) gives `file:///C:/...`, a UNC one
/// `file:////server/share/...`, and a relative path stays relative.
fn file_uri(path: &Path) -> String {
    use std::path::{Component, Prefix};
    let mut text = String::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                    text.push('/');
                    text.push(char::from(drive));
                    text.push(':');
                }
                Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                    text.push_str("//");
                    text.push_str(&server.to_string_lossy());
                    text.push('/');
                    text.push_str(&share.to_string_lossy());
                }
                Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
                    text.push_str(&prefix.as_os_str().to_string_lossy().replace('\\', "/"));
                }
            },
            Component::RootDir => text.push('/'),
            Component::CurDir => {}
            Component::ParentDir | Component::Normal(_) => {
                if !text.is_empty() && !text.ends_with('/') {
                    text.push('/');
                }
                text.push_str(&component.as_os_str().to_string_lossy());
            }
        }
    }
    // An absolute path gets the empty authority, so its first `/` starts the path.
    let mut uri = String::from(if text.starts_with('/') {
        "file://"
    } else {
        "file:"
    });
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/:".contains(&byte) {
            uri.push(char::from(byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

/// Opens the copy with the key, checks it against `record` and stores the record in it.
fn check_copy(copy: &Path, store_key: &StoreKey, record: &MigrationRecord) -> Result<(), Failure> {
    let conn = Connection::open_with_flags(
        copy,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    cipher::set_key(&conn, store_key)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    // The copy keeps no write-ahead log of its own until it is opened as the database.
    let _mode: String = conn.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    let refused = |what: &'static str| {
        Failure::Failed(StoreError::Io {
            operation: what,
            source: std::io::ErrorKind::InvalidData.into(),
        })
    };
    if !passes_quick_check(&conn)? {
        return Err(refused("check the encrypted copy"));
    }
    if stored_version(&conn)? != record.schema {
        return Err(refused("match the schema of the encrypted copy"));
    }
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version != record.user_version {
        return Err(refused("match the user version of the encrypted copy"));
    }
    if row_counts(&conn)? != record.rows {
        return Err(refused("match the rows of the encrypted copy"));
    }
    let has_settings: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'settings')",
        [],
        |row| row.get(0),
    )?;
    if has_settings {
        let text = serde_json::to_string(record).map_err(|_| StoreError::OutOfRange {
            field: "migration record",
        })?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [MIGRATED_FROM_SETTING, text.as_str()],
        )?;
    }
    conn.close().map_err(|(_, error)| StoreError::from(error))?;
    Ok(())
}

/// Flushes the file at `path` to disk, through a handle that may write: Windows flushes no file
/// opened read-only.
fn sync_file(path: &Path) -> Result<(), StoreError> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(io("flush the encrypted copy"))
}

/// Sets aside a plain database beside the open encrypted `store`: the one it was copied from
/// as `.pre-encryption`, any other as `.after-rollback-<unix>` with a restore scan required.
/// Also finishes a set-aside an earlier open began, which moved the logs and not the database:
/// a set-aside log without its database is paired with the plain database only under the name
/// this open would choose, so the source of the copy, known by the record with that log, goes
/// to its `.pre-encryption` name and any other plain database to an `.after-rollback-` one.
/// Whether a plain database was set aside after a rollback.
fn settle_plain_beside(dir: &Path, store: &SqliteStore) -> Result<bool, StoreError> {
    let plain = dir.join(DATABASE_FILE);
    if !exists(&plain)? {
        return Ok(false);
    }
    let record = store
        .read(|repos| repos.setting(MIGRATED_FROM_SETTING))?
        .and_then(|text| serde_json::from_str::<MigrationRecord>(&text).ok());
    let recorded = |wal: &Path| -> Result<bool, StoreError> {
        Ok(match &record {
            Some(record) => PlainFiles::with_wal(&plain, wal)?.is_recorded(record),
            None => false,
        })
    };
    let orphans = orphan_logs(dir)?;
    for aside in orphans
        .iter()
        .filter(|aside| set_aside_suffix(aside).starts_with(PRE_ENCRYPTION_SUFFIX))
    {
        if recorded(&with_suffix(aside, "-wal"))? {
            move_plain(&plain, aside, fs_rename)?;
            tracing::info!("plain wallet database set aside after the switch");
            return Ok(false);
        }
    }
    if recorded(&with_suffix(&plain, "-wal"))? {
        set_aside_plain(dir, PRE_ENCRYPTION_SUFFIX, fs_rename)?;
        tracing::info!("plain wallet database set aside after the switch");
        return Ok(false);
    }
    // Before the file moves, so an interrupted open still requires the scan.
    store.write(|repos| repos.put_setting(ROLLBACK_SCAN_SETTING, "true"))?;
    let interrupted = orphans
        .iter()
        .find(|aside| set_aside_suffix(aside).starts_with(AFTER_ROLLBACK_SUFFIX));
    match interrupted {
        Some(aside) => move_plain(&plain, aside, fs_rename)?,
        None => {
            let suffix = format!("{AFTER_ROLLBACK_SUFFIX}{}", unix_seconds(SystemTime::now()));
            set_aside_plain(dir, &suffix, fs_rename)?;
        }
    }
    tracing::warn!("plain wallet database of an older build set aside; a restore scan is required");
    Ok(true)
}

/// The set-aside names in `dir` that have a moved log but no database.
fn orphan_logs(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let mut orphans = Vec::new();
    for aside in set_aside_bases(dir)? {
        let has_log = MOVED_LOGS
            .iter()
            .any(|log| with_suffix(&aside, log).exists());
        if has_log && !exists(&aside)? {
            orphans.push(aside);
        }
    }
    Ok(orphans)
}

/// What follows `wallet.sqlite3` in a set-aside name.
fn set_aside_suffix(aside: &Path) -> &str {
    aside
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(DATABASE_FILE))
        .unwrap_or("")
}

/// Moves `wallet.sqlite3` and its logs to a free `wallet.sqlite3<suffix>` name: the logs
/// first, the database last, and `-shm` removed. An interruption leaves a set-aside log without
/// its database, which [`settle_plain_beside`] recognises.
fn set_aside_plain(dir: &Path, suffix: &str, rename: Rename) -> Result<(), StoreError> {
    let plain = dir.join(DATABASE_FILE);
    let aside = free_name(&with_suffix(&plain, suffix))?;
    move_plain(&plain, &aside, rename)
}

/// Moves the plain database at `plain` and its logs to `aside`, the logs first, each rename
/// retried while another program holds the file.
fn move_plain(plain: &Path, aside: &Path, rename: Rename) -> Result<(), StoreError> {
    for log in MOVED_LOGS {
        let target = with_suffix(aside, log);
        if !exists(&target)? {
            rename_if_present(&with_suffix(plain, log), &target, rename)?;
        }
    }
    rename_retrying(plain, aside, rename).map_err(io("set the plain database aside"))?;
    remove_if_present(&with_suffix(plain, "-shm"))?;
    crate::file::sync_folder(plain).map_err(io("set the plain database aside"))
}

/// How a file is renamed: [`fs_rename`], or in tests one that fails.
type Rename = fn(&Path, &Path) -> std::io::Result<()>;

/// Waits between the attempts to rename a file another program holds: an indexer, antivirus or
/// backup tool on Windows lets go within moments.
const RENAME_BACKOFF: [Duration; 4] = [
    Duration::from_millis(20),
    Duration::from_millis(80),
    Duration::from_millis(200),
    Duration::from_millis(500),
];

/// `rename`, tried again after each wait of [`RENAME_BACKOFF`] unless the file is missing.
fn rename_retrying(from: &Path, to: &Path, rename: Rename) -> std::io::Result<()> {
    let mut waits = RENAME_BACKOFF.iter();
    loop {
        match rename(from, to) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => match waits.next() {
                Some(wait) => std::thread::sleep(*wait),
                None => return Err(error),
            },
            done => return done,
        }
    }
}

fn fs_rename(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

/// [`std::fs::rename`] while another program holds the plain database: its logs move, the
/// database itself does not.
fn held_database_rename(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.file_name().is_some_and(|name| name == DATABASE_FILE) {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    std::fs::rename(from, to)
}

/// Every set-aside plain database name in `dir`, with or without its file: the names that
/// have a database or a log file.
fn set_aside_bases(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    plain_bases(dir, &[PRE_ENCRYPTION_SUFFIX, AFTER_ROLLBACK_SUFFIX])
}

/// The names in `dir` of plain databases moved to `wallet.sqlite3` and one of `suffixes`, with
/// or without the file: the names that have a database or a log file.
fn plain_bases(dir: &Path, suffixes: &[&str]) -> Result<Vec<PathBuf>, StoreError> {
    let mut bases = std::collections::BTreeSet::new();
    let entries = std::fs::read_dir(dir).map_err(io("list the data directory"))?;
    for entry in entries {
        let entry = entry.map_err(io("list the data directory"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(DATABASE_FILE) else {
            continue;
        };
        if !suffixes.iter().any(|suffix| rest.starts_with(suffix)) {
            continue;
        }
        let base = ["-wal", "-shm", "-journal", CHECK_SUFFIX]
            .iter()
            .find_map(|log| name.strip_suffix(log))
            .unwrap_or(name);
        bases.insert(dir.join(base));
    }
    Ok(bases.into_iter().collect())
}

/// `path`, or `path-<n>`, whichever is free together with its log names.
fn free_name(path: &Path) -> Result<PathBuf, StoreError> {
    for attempt in 0u32..1000 {
        let candidate = if attempt == 0 {
            path.to_owned()
        } else {
            with_suffix(path, &format!("-{attempt}"))
        };
        let mut taken = exists(&candidate)?;
        for log in COPY_LOGS {
            taken |= exists(&with_suffix(&candidate, log))?;
        }
        if !taken {
            return Ok(candidate);
        }
    }
    Err(StoreError::Io {
        operation: "name the set-aside plain database",
        source: std::io::ErrorKind::AlreadyExists.into(),
    })
}

/// What [`retire_plain_store`] deleted and kept, by file name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetireSummary {
    pub deleted: Vec<String>,
    /// Set-aside plain databases kept because the encrypted database does not record them as
    /// its source, so they may hold history it does not.
    pub kept: Vec<String>,
}

/// Deletes the plain databases set aside in `dir` that the open encrypted database no longer
/// needs, each with its log files: the `wallet.sqlite3.pre-encryption` file it was copied from,
/// known by its size and SHA-256 in `migrated_from`, the encrypted database's
/// [`MIGRATED_FROM_SETTING`]; and every `wallet.sqlite3.after-rollback-<unix>` set aside more
/// than `older_than` before `now`. A `.pre-encryption` file the record does not match, as when
/// the encrypted database was rebuilt empty after damage, is kept and listed in
/// [`RetireSummary::kept`]. Nothing else is deleted, and nothing unless the encrypted database
/// is there. For the release after the one that encrypts, called by the app after a successful
/// open of the encrypted store, under the directory's claim. Plain deletion: flash storage
/// cannot be overwritten reliably.
pub fn retire_plain_store(
    dir: &Path,
    migrated_from: Option<&str>,
    older_than: Duration,
    now: SystemTime,
) -> Result<RetireSummary, StoreError> {
    let mut summary = RetireSummary::default();
    if !exists(&dir.join(ENCRYPTED_DATABASE_FILE))? {
        return Ok(summary);
    }
    let record = migrated_from.and_then(|text| serde_json::from_str::<MigrationRecord>(text).ok());
    let cutoff = unix_seconds(now).saturating_sub(older_than.as_secs());
    for base in set_aside_bases(dir)? {
        let name = file_name(&base);
        let Some(rest) = name.strip_prefix(DATABASE_FILE) else {
            continue;
        };
        // A log without its database belongs to a set-aside still in progress.
        if !exists(&base)? {
            continue;
        }
        let retire = if rest.starts_with(PRE_ENCRYPTION_SUFFIX) {
            let recorded = match &record {
                Some(record) => digest(&base)?.is_some_and(|(bytes, sha256)| {
                    bytes == record.bytes && sha256 == record.sha256
                }),
                None => false,
            };
            if !recorded {
                summary.kept.push(name);
                continue;
            }
            true
        } else if let Some(stamp) = rest.strip_prefix(AFTER_ROLLBACK_SUFFIX) {
            let seconds = stamp.split('-').next().and_then(|text| text.parse().ok());
            seconds.is_some_and(|seconds: u64| seconds < cutoff)
        } else {
            false
        };
        if retire {
            summary.deleted.extend(remove_with_logs(&base)?);
        }
    }
    Ok(summary)
}

/// Deletes every file but the databases themselves that `dir` keeps of its wallet database,
/// whatever the encrypted database holds: each plain database set aside, as
/// `.pre-encryption`, `.after-rollback-*` or `.damaged-*`, with its log files; a copy in
/// progress or left behind (`wallet.enc.sqlite3.tmp` and its logs); and the key check's
/// temporary file. For the deletion of a wallet, which leaves no readable history behind,
/// under the directory's claim. The deleted file names.
pub fn remove_database_leftovers(dir: &Path) -> Result<Vec<String>, StoreError> {
    let mut deleted = Vec::new();
    for base in plain_bases(
        dir,
        &[PRE_ENCRYPTION_SUFFIX, AFTER_ROLLBACK_SUFFIX, DAMAGED_SUFFIX],
    )? {
        deleted.extend(remove_with_logs(&base)?);
    }
    for path in copy_files(dir) {
        if remove_if_present(&path)? {
            deleted.push(file_name(&path));
        }
    }
    Ok(deleted)
}

/// Removes a database's log files, then the database: an interruption leaves the database
/// without its logs, never a log a later open could take for a set-aside in progress. The
/// names removed.
fn remove_with_logs(base: &Path) -> Result<Vec<String>, StoreError> {
    let mut removed = Vec::new();
    for suffix in ["-wal", "-shm", "-journal", CHECK_SUFFIX, ""] {
        let path = with_suffix(base, suffix);
        if remove_if_present(&path)? {
            removed.push(file_name(&path));
        }
    }
    Ok(removed)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
}

/// The files of a copy in progress, and the temporary file of a key check whose write stopped.
fn copy_files(dir: &Path) -> Vec<PathBuf> {
    let copy = dir.join(COPY_FILE);
    std::iter::once(copy.clone())
        .chain(COPY_LOGS.iter().map(|log| with_suffix(&copy, log)))
        .chain([dir.join(CHECK_COPY_FILE)])
        .collect()
}

fn remove_copy_files(dir: &Path) -> Result<(), StoreError> {
    for path in copy_files(dir) {
        remove_if_present(&path)?;
    }
    Ok(())
}

/// Whether there was a file to remove.
fn remove_if_present(path: &Path) -> Result<bool, StoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(StoreError::Io {
            operation: "remove a database file",
            source,
        }),
    }
}

fn rename_if_present(from: &Path, to: &Path, rename: Rename) -> Result<(), StoreError> {
    match rename_retrying(from, to, rename) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(StoreError::Io {
            operation: "set the plain database aside",
            source: error,
        }),
        _ => Ok(()),
    }
}

fn exists(path: &Path) -> Result<bool, StoreError> {
    path.try_exists().map_err(io("look for the database"))
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests;
