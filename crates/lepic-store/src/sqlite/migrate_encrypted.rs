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
//! | `wallet.sqlite3.pre-encryption` (`-wal`) | the plain database after it was copied |
//! | `wallet.sqlite3.after-rollback-<unix>` (`-wal`) | a plain database an older build made |
//!
//! The copy never writes the plain file, and its schema is never migrated before the switch:
//! an older build must still read it. Every step can be interrupted and the next open
//! continues: before the rename of the copy nothing but the copy has changed and the copy
//! starts again; after it, the encrypted database is complete and checked, and a plain file
//! still beside it is recognised by the record of its contents and set aside.
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
const PRE_ENCRYPTION_SUFFIX: &str = ".pre-encryption";
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
///    on the encrypted database only. A copy that fails leaves the plain file as it was and
///    opens it plain for this session ([`AtRestState::FellBackToPlain`]); the next open tries
///    again. A damaged plain file is set aside as [`SqliteStore::open`] does, and one of a
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
/// that fails reads the plain file in place instead, as an open that falls back does.
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
        Err(Failure::Failed(error) | Failure::Crashed(error)) => {
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
        Err(Failure::Crashed(error)) => Err(error),
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
        None => Ok(()),
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
        let (bytes, sha256) = digest(plain)?.ok_or(StoreError::Io {
            operation: "read the plain database",
            source: std::io::ErrorKind::NotFound.into(),
        })?;
        let wal_sha256 = digest(&with_suffix(plain, "-wal"))?.map(|(_, sha256)| sha256);
        Ok(Self {
            bytes,
            sha256,
            wal_sha256,
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

    // 6. The switch.
    std::fs::rename(&copy, &encrypted).map_err(io("switch to the encrypted database"))?;
    cipher::sync_folder(&encrypted).map_err(io("switch to the encrypted database"))?;
    step(faults, Step::Switched, &copy)?;

    // 7. The plain database goes aside. A failure here is finished by the next open, which
    //    knows it by the record.
    if let Err(error) = set_aside_plain(dir, PRE_ENCRYPTION_SUFFIX) {
        tracing::warn!(error = %error, "plain wallet database not yet set aside");
    }
    step(faults, Step::SetAside, &copy)?;
    Ok(())
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

/// `VACUUM INTO` the keyed copy (ADR 0032): it reads the plain database and its log through
/// `reader` and writes only the copy. The key reaches SQLite as a bound parameter in the
/// copy's URI. While it runs, the size of the copy is reported every [`PROGRESS_INTERVAL`].
fn copy_into(
    reader: &Connection,
    copy: &Path,
    store_key: &StoreKey,
    progress: Progress<'_>,
) -> Result<(), StoreError> {
    let mut target = Zeroizing::new(String::with_capacity(256));
    target.push_str(&file_uri(copy));
    target.push_str("?cipher=chacha20&key=raw:");
    for byte in store_key.expose() {
        target.push_str(&format!("{byte:02x}"));
    }
    let Some(observer) = progress.observer else {
        reader.execute("VACUUM INTO ?1", [target.as_str()])?;
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
        copied
    })?;
    Ok(())
}

/// A `file:` URI of `path`, with every byte but unreserved ones and separators escaped.
fn file_uri(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut uri = String::from("file:");
    if !text.starts_with('/') {
        uri.push('/');
    }
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

fn sync_file(path: &Path) -> Result<(), StoreError> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io("flush the encrypted copy"))
}

/// Sets aside a plain database beside the open encrypted `store`: the one it was copied from
/// as `.pre-encryption`, any other as `.after-rollback-<unix>` with a restore scan required.
/// Also finishes a set-aside an earlier open began. Whether a plain database was set aside
/// after a rollback.
fn settle_plain_beside(dir: &Path, store: &SqliteStore) -> Result<bool, StoreError> {
    let plain = dir.join(DATABASE_FILE);
    if finish_interrupted_set_aside(dir)? || !exists(&plain)? {
        return Ok(false);
    }
    let record = store
        .read(|repos| repos.setting(MIGRATED_FROM_SETTING))?
        .and_then(|text| serde_json::from_str::<MigrationRecord>(&text).ok());
    let files = PlainFiles::of(&plain)?;
    if record.is_some_and(|record| files.is_recorded(&record)) {
        set_aside_plain(dir, PRE_ENCRYPTION_SUFFIX)?;
        tracing::info!("plain wallet database set aside after the switch");
        return Ok(false);
    }
    // Before the file moves, so an interrupted open still requires the scan.
    store.write(|repos| repos.put_setting(ROLLBACK_SCAN_SETTING, "true"))?;
    let suffix = format!("{AFTER_ROLLBACK_SUFFIX}{}", unix_seconds(SystemTime::now()));
    set_aside_plain(dir, &suffix)?;
    tracing::warn!("plain wallet database of an older build set aside; a restore scan is required");
    Ok(true)
}

/// Moves `wallet.sqlite3` and its logs to a free `wallet.sqlite3<suffix>` name: the logs
/// first, the database last, and `-shm` removed. An interruption leaves a set-aside log without
/// its database, which [`finish_interrupted_set_aside`] recognises.
fn set_aside_plain(dir: &Path, suffix: &str) -> Result<(), StoreError> {
    let plain = dir.join(DATABASE_FILE);
    let aside = free_name(&with_suffix(&plain, suffix))?;
    for log in MOVED_LOGS {
        rename_if_present(&with_suffix(&plain, log), &with_suffix(&aside, log))?;
    }
    std::fs::rename(&plain, &aside).map_err(io("set the plain database aside"))?;
    remove_if_present(&with_suffix(&plain, "-shm"))?;
    cipher::sync_folder(&plain).map_err(io("set the plain database aside"))
}

/// Completes a set-aside that stopped after moving the logs: a set-aside `-wal` or `-journal`
/// without its database belongs to the plain database still in place. Whether one was found.
fn finish_interrupted_set_aside(dir: &Path) -> Result<bool, StoreError> {
    let plain = dir.join(DATABASE_FILE);
    if !exists(&plain)? {
        return Ok(false);
    }
    for aside in set_aside_bases(dir)? {
        let orphan_log = MOVED_LOGS
            .iter()
            .any(|log| with_suffix(&aside, log).exists());
        if orphan_log && !exists(&aside)? {
            std::fs::rename(&plain, &aside).map_err(io("set the plain database aside"))?;
            remove_if_present(&with_suffix(&plain, "-shm"))?;
            cipher::sync_folder(&plain).map_err(io("set the plain database aside"))?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every set-aside plain database name in `dir`, with or without its file: the names that
/// have a database or a log file.
fn set_aside_bases(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
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
        if !(rest.starts_with(PRE_ENCRYPTION_SUFFIX) || rest.starts_with(AFTER_ROLLBACK_SUFFIX)) {
            continue;
        }
        let base = ["-wal", "-shm", "-journal"]
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

/// What [`retire_plain_store`] deleted, by file name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetireSummary {
    pub deleted: Vec<String>,
}

/// Deletes the plain databases set aside in `dir`: every `wallet.sqlite3.pre-encryption`, and
/// every `wallet.sqlite3.after-rollback-<unix>` set aside more than `older_than` before `now`,
/// each with its log files. Nothing else. Deletes nothing unless the encrypted database is
/// there, so a set-aside file is never the last copy of a wallet's history. For the release
/// after the one that encrypts, called by the app after a successful open of the encrypted
/// store. Plain deletion: flash storage cannot be overwritten reliably.
pub fn retire_plain_store(
    dir: &Path,
    older_than: Duration,
    now: SystemTime,
) -> Result<RetireSummary, StoreError> {
    let mut summary = RetireSummary::default();
    if !exists(&dir.join(ENCRYPTED_DATABASE_FILE))? {
        return Ok(summary);
    }
    let cutoff = unix_seconds(now).saturating_sub(older_than.as_secs());
    for base in set_aside_bases(dir)? {
        let Some(name) = base.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(rest) = name.strip_prefix(DATABASE_FILE) else {
            continue;
        };
        let retire = if rest.starts_with(PRE_ENCRYPTION_SUFFIX) {
            true
        } else if let Some(stamp) = rest.strip_prefix(AFTER_ROLLBACK_SUFFIX) {
            let seconds = stamp.split('-').next().and_then(|text| text.parse().ok());
            seconds.is_some_and(|seconds: u64| seconds < cutoff)
        } else {
            false
        };
        if !retire {
            continue;
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = with_suffix(&base, suffix);
            if remove_if_present(&path)? {
                summary.deleted.push(
                    path.file_name()
                        .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
                );
            }
        }
    }
    Ok(summary)
}

fn copy_files(dir: &Path) -> Vec<PathBuf> {
    let copy = dir.join(COPY_FILE);
    std::iter::once(copy.clone())
        .chain(COPY_LOGS.iter().map(|log| with_suffix(&copy, log)))
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

fn rename_if_present(from: &Path, to: &Path) -> Result<(), StoreError> {
    match std::fs::rename(from, to) {
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
