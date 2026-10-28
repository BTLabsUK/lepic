// Portions Copyright 2019 The Epic Developers
// Portions Copyright 2023 The Epic Developers
// Ported from EpicCash/epic-wallet impls/src/backends/db.rs, impls/src/backends/lmdb.rs,
// impls/src/serialization.rs, libwallet/src/types.rs, libwallet/src/slate.rs (Apache-2.0); see
// NOTICE and upstream.toml.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use super::LegacyDbError;

const MAX_COPY_ATTEMPTS: u32 = 3;
const CHUNK_BYTES: usize = 64 * 1024;
const COPY_FILE: &str = "epic.db";

pub(super) struct Copied {
    pub(super) db: PathBuf,
    pub(super) fingerprint: [u8; 32],
}

/// What can be learned about a file without opening it. A writer that commits changes at least
/// one of them, or the content hash catches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileState {
    len: u64,
    modified: Option<SystemTime>,
}

struct Streamed {
    hash: [u8; 32],
    len: u64,
}

/// One attempt either copied a consistent snapshot or saw the source change.
enum Attempt {
    Stable([u8; 32]),
    Changed,
}

pub(super) fn copy_stable(
    source: &Path,
    work_dir: &Path,
    max_bytes: u64,
) -> Result<Copied, LegacyDbError> {
    if fs::read_dir(work_dir)?.next().is_some() {
        return Err(LegacyDbError::WorkDirNotEmpty);
    }
    let copy = work_dir.join(COPY_FILE);
    let copy_wal = wal_path(&copy);
    for attempt in 1..=MAX_COPY_ATTEMPTS {
        match copy_once(source, &copy, &copy_wal, max_bytes)? {
            Attempt::Stable(fingerprint) => {
                return Ok(Copied {
                    db: copy,
                    fingerprint,
                });
            }
            Attempt::Changed => {
                tracing::debug!(attempt, "legacy database changed during copy");
                remove_if_present(&copy)?;
                remove_if_present(&copy_wal)?;
            }
        }
    }
    Err(LegacyDbError::SourceChanging)
}

/// SHA-256 of `db` followed by its write-ahead log, if there is one.
pub(super) fn fingerprint(db: &Path, max_bytes: u64) -> Result<[u8; 32], LegacyDbError> {
    let mut combined = Sha256::new();
    let read = stream(db, None, max_bytes, Some(&mut combined)).map_err(not_found_as_missing)?;
    let remaining = max_bytes.saturating_sub(read.len);
    match stream(&wal_path(db), None, remaining, Some(&mut combined)) {
        Ok(_) => {}
        Err(LegacyDbError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Err(LegacyDbError::TooLarge { bytes }) => {
            return Err(LegacyDbError::TooLarge {
                bytes: bytes.saturating_add(read.len),
            });
        }
        Err(other) => return Err(other),
    }
    Ok(combined.finalize().into())
}

fn copy_once(
    source: &Path,
    copy: &Path,
    copy_wal: &Path,
    max_bytes: u64,
) -> Result<Attempt, LegacyDbError> {
    let source_wal = wal_path(source);
    let Some(db_before) = file_state(source)? else {
        return Err(LegacyDbError::NotFound);
    };
    let wal_before = file_state(&source_wal)?;
    let total = db_before
        .len
        .saturating_add(wal_before.map_or(0, |wal| wal.len));
    if total > max_bytes {
        return Err(LegacyDbError::TooLarge { bytes: total });
    }

    let db_hash = stream(source, None, max_bytes, None).map_err(not_found_as_missing)?;
    let wal_hash = match wal_before {
        Some(_) => match stream(&source_wal, None, max_bytes, None) {
            Ok(read) => Some(read.hash),
            Err(error) if is_not_found(&error) => return Ok(Attempt::Changed),
            Err(error) => return Err(error),
        },
        None => None,
    };

    let mut combined = Sha256::new();
    let db_copy =
        stream(source, Some(copy), max_bytes, Some(&mut combined)).map_err(not_found_as_missing)?;
    let wal_copy = match wal_before {
        Some(_) => {
            let remaining = max_bytes.saturating_sub(db_copy.len);
            match stream(&source_wal, Some(copy_wal), remaining, Some(&mut combined)) {
                Ok(read) => Some(read.hash),
                Err(error) if is_not_found(&error) => return Ok(Attempt::Changed),
                Err(error) => return Err(error),
            }
        }
        None => None,
    };

    let unchanged = file_state(source)? == Some(db_before)
        && file_state(&source_wal)? == wal_before
        && db_hash.hash == db_copy.hash
        && wal_hash == wal_copy;
    Ok(if unchanged {
        Attempt::Stable(combined.finalize().into())
    } else {
        Attempt::Changed
    })
}

fn file_state(path: &Path) -> Result<Option<FileState>, LegacyDbError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(FileState {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })),
        Ok(_) => Err(LegacyDbError::Io(io::Error::from(
            io::ErrorKind::InvalidInput,
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(LegacyDbError::Io(error)),
    }
}

/// Reads `source` once, hashing it, optionally writing it to a new file `copy` and feeding
/// `combined`. Reads at most one byte past `limit`, so a file that grows cannot make it unbounded.
fn stream(
    source: &Path,
    copy: Option<&Path>,
    limit: u64,
    mut combined: Option<&mut Sha256>,
) -> Result<Streamed, LegacyDbError> {
    let mut reader = File::open(source)?.take(limit.saturating_add(1));
    let mut writer = match copy {
        Some(path) => Some(private_options().open(path)?),
        None => None,
    };
    let mut own = Sha256::new();
    let mut len: u64 = 0;
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        let chunk = buffer.get(..read).unwrap_or_default();
        len = len.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if len > limit {
            return Err(LegacyDbError::TooLarge { bytes: len });
        }
        own.update(chunk);
        if let Some(hasher) = combined.as_deref_mut() {
            hasher.update(chunk);
        }
        if let Some(file) = writer.as_mut() {
            file.write_all(chunk)?;
        }
    }
    if let Some(file) = writer {
        file.sync_all()?;
    }
    Ok(Streamed {
        hash: own.finalize().into(),
        len,
    })
}

/// The copy holds the old wallet's private transaction keys too, so only its owner may read it.
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

/// Removes the copy and every file SQLite may have made beside it.
pub(super) fn remove_copy(db: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = OsString::from(db.as_os_str());
        name.push(suffix);
        if let Err(error) = remove_if_present(Path::new(&name)) {
            tracing::warn!(error = %error, "legacy database copy not removed");
        }
    }
}

fn wal_path(db: &Path) -> PathBuf {
    let mut name = OsString::from(db.as_os_str());
    name.push("-wal");
    PathBuf::from(name)
}

fn remove_if_present(path: &Path) -> Result<(), LegacyDbError> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

fn is_not_found(error: &LegacyDbError) -> bool {
    matches!(error, LegacyDbError::Io(error) if error.kind() == io::ErrorKind::NotFound)
}

fn not_found_as_missing(error: LegacyDbError) -> LegacyDbError {
    if is_not_found(&error) {
        LegacyDbError::NotFound
    } else {
        error
    }
}
