// SPDX-License-Identifier: Apache-2.0
//! Encryption at rest of a database file (SQLite3 Multiple Ciphers, ADR 0032) and the key check
//! kept beside it.
//!
//! SQLite3MC reports a wrong key and a damaged file alike, as "not a database". The check file
//! tells them apart, so a file is set aside as damaged only when the key is known to be its own.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use blake2::Blake2bMac;
use blake2::digest::consts::U16;
use blake2::digest::{KeyInit as _, Mac as _};
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::at_rest::{STORE_KEY_LEN, StoreKey};
use crate::error::StoreError;

use super::with_suffix;

/// Suffix of the key check file beside the database.
pub(super) const CHECK_SUFFIX: &str = ".check";

const CHECK_FORMAT_V1: u8 = 1;
const CHECK_DOMAIN: &[u8] = b"lepic-wallet store check v1";
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const CHECK_LEN: usize = 1 + SALT_LEN + TAG_LEN;

/// Tells SQLite3MC to take the bytes after it as the key itself, not as a password to stretch.
const RAW_KEY_PREFIX: &[u8; 4] = b"raw:";
const RAW_KEY_LEN: usize = RAW_KEY_PREFIX.len() + STORE_KEY_LEN;

/// Sets the key of the connection's main database. It must come before anything reads the
/// file. The key goes in as bytes, so SQLite never holds it in a SQL text.
pub(super) fn set_key(conn: &Connection, key: &StoreKey) -> Result<(), StoreError> {
    let mut raw = Zeroizing::new([0u8; RAW_KEY_LEN]);
    let (prefix, rest) = raw.split_at_mut(RAW_KEY_PREFIX.len());
    prefix.copy_from_slice(RAW_KEY_PREFIX);
    rest.copy_from_slice(key.expose());
    let length = i32::try_from(RAW_KEY_LEN).map_err(|_| StoreError::OutOfRange {
        field: "store key length",
    })?;
    // SAFETY: `conn.handle()` is the live connection `conn` borrows for this call. The name is a
    // NUL-terminated literal and `raw` is `length` readable bytes; SQLite3MC copies the key it
    // derives from them before returning and keeps no pointer to either.
    #[expect(
        unsafe_code,
        reason = "SQLite3MC's sqlite3_key_v2 has no safe binding (ADR 0032)"
    )]
    let code = unsafe {
        rusqlite::ffi::sqlite3_key_v2(conn.handle(), c"main".as_ptr(), raw.as_ptr().cast(), length)
    };
    if code == rusqlite::ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(StoreError::from(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            None,
        )))
    }
}

/// What the key check beside a database says about a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Check {
    /// The check was made with this key.
    Matches,
    /// The check was made with another key.
    Differs,
    /// There is no check, or not one this build reads: nothing is known about the key.
    Unknown,
}

pub(super) fn check_path(database: &Path) -> PathBuf {
    with_suffix(database, CHECK_SUFFIX)
}

/// Compares `key` with the check stored beside `database`.
pub(super) fn verify(database: &Path, key: &StoreKey) -> Result<Check, StoreError> {
    let bytes = match std::fs::read(check_path(database)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Check::Unknown),
        Err(source) => {
            return Err(StoreError::Io {
                operation: "read the database key check",
                source,
            });
        }
    };
    let Some((salt, stored)) = parse(&bytes) else {
        return Ok(Check::Unknown);
    };
    Ok(if tag(key, salt)?.verify_truncated_left(stored).is_ok() {
        Check::Matches
    } else {
        Check::Differs
    })
}

/// Writes a check of `key` with a fresh random salt beside `database`, replacing any other:
/// to a temporary file first, flushed, then renamed over the old one.
pub(super) fn write(database: &Path, key: &StoreKey) -> Result<(), StoreError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(StoreError::Randomness)?;
    let mut bytes = Vec::with_capacity(CHECK_LEN);
    bytes.push(CHECK_FORMAT_V1);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&tag(key, &salt)?.finalize().into_bytes());
    let path = check_path(database);
    let temporary = with_suffix(&path, ".tmp");
    let io = |operation| move |source| StoreError::Io { operation, source };
    let mut file = owner_only_file(&temporary).map_err(io("write the database key check"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(io("write the database key check"))?;
    drop(file);
    std::fs::rename(&temporary, &path).map_err(io("store the database key check"))?;
    sync_folder(database).map_err(io("store the database key check"))
}

fn parse(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (format, rest) = bytes.split_first()?;
    if *format != CHECK_FORMAT_V1 || rest.len() != SALT_LEN + TAG_LEN {
        return None;
    }
    Some(rest.split_at(SALT_LEN))
}

/// BLAKE2b-128 keyed by the store key, over the domain and the salt. The salt keeps checks of
/// one wallet's copies from matching each other.
fn tag(key: &StoreKey, salt: &[u8]) -> Result<Blake2bMac<U16>, StoreError> {
    let mut mac =
        <Blake2bMac<U16>>::new_from_slice(key.expose()).map_err(|_| StoreError::OutOfRange {
            field: "store key length",
        })?;
    mac.update(CHECK_DOMAIN);
    mac.update(salt);
    Ok(mac)
}

#[cfg(unix)]
fn owner_only_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn owner_only_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

/// Makes a rename inside the database's folder durable.
#[cfg(unix)]
fn sync_folder(database: &Path) -> std::io::Result<()> {
    match database.parent() {
        Some(folder) if !folder.as_os_str().is_empty() => std::fs::File::open(folder)?.sync_all(),
        _ => std::fs::File::open(".")?.sync_all(),
    }
}

/// Windows has no folder handle to flush; its renames are journalled by NTFS.
#[cfg(not(unix))]
fn sync_folder(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_is_keyed_blake2b_of_the_domain_and_salt() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("db");
        let key = StoreKey::from_bytes([7; STORE_KEY_LEN]);
        write(&database, &key).unwrap();
        let bytes = std::fs::read(check_path(&database)).unwrap();
        assert_eq!(bytes.len(), CHECK_LEN);
        assert_eq!(bytes[0], CHECK_FORMAT_V1);
        let mut mac = <Blake2bMac<U16>>::new_from_slice(&[7; STORE_KEY_LEN]).unwrap();
        mac.update(b"lepic-wallet store check v1");
        mac.update(&bytes[1..17]);
        assert_eq!(&bytes[17..], mac.finalize().into_bytes().as_slice());
        assert_eq!(verify(&database, &key).unwrap(), Check::Matches);
        let other = StoreKey::from_bytes([8; STORE_KEY_LEN]);
        assert_eq!(verify(&database, &other).unwrap(), Check::Differs);
    }

    #[test]
    fn every_check_draws_its_own_salt() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("db");
        let key = StoreKey::from_bytes([7; STORE_KEY_LEN]);
        write(&database, &key).unwrap();
        let first = std::fs::read(check_path(&database)).unwrap();
        write(&database, &key).unwrap();
        let second = std::fs::read(check_path(&database)).unwrap();
        assert_ne!(first, second);
        assert_eq!(verify(&database, &key).unwrap(), Check::Matches);
    }

    const PAGE: usize = 4096;
    /// SQLite3MC's ChaCha20 scheme keeps a 16-byte nonce and a 16-byte Poly1305 tag at the end
    /// of every page.
    const RESERVE: usize = 32;
    const MARKER: &str = "counterparty-marker-5f2a";

    fn keyed(path: &Path, key: &StoreKey) -> Connection {
        let conn = Connection::open(path).unwrap();
        set_key(&conn, key).unwrap();
        conn
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn nonces(file: &[u8]) -> Vec<[u8; 16]> {
        file.as_chunks::<PAGE>()
            .0
            .iter()
            .map(|page| page[PAGE - RESERVE..PAGE - 16].try_into().unwrap())
            .collect()
    }

    #[test]
    fn raw_key_seals_the_database_and_its_wal_with_chacha20() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e.db");
        let key = StoreKey::from_bytes([3; STORE_KEY_LEN]);
        let conn = keyed(&path, &key);
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let cipher: String = conn
            .query_row("PRAGMA cipher", [], |row| row.get(0))
            .unwrap();
        assert_eq!(cipher, "chacha20");
        conn.execute_batch(&format!(
            "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('{MARKER}');"
        ))
        .unwrap();
        // The row is still only in the write-ahead log.
        let wal = std::fs::read(with_suffix(&path, "-wal")).unwrap();
        assert!(!wal.is_empty());
        assert!(!contains(&wal, MARKER.as_bytes()));
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        drop(conn);
        let file = std::fs::read(&path).unwrap();
        assert!(!contains(&file, MARKER.as_bytes()));
        assert!(!contains(&file, b"SQLite format 3"));
        assert!(!contains(&file, b"CREATE TABLE"));

        let again = keyed(&path, &key);
        let value: String = again
            .query_row("SELECT v FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, MARKER);
        drop(again);
        let wrong = keyed(&path, &StoreKey::from_bytes([4; STORE_KEY_LEN]));
        let error = wrong
            .query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::NotADatabase)
        );
    }

    #[test]
    fn a_plain_database_still_opens_plain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA journal_mode = WAL; CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('{MARKER}');\
             PRAGMA wal_checkpoint(TRUNCATE);"
        ))
        .unwrap();
        drop(conn);
        let file = std::fs::read(&path).unwrap();
        assert!(file.starts_with(b"SQLite format 3\0"));
        assert!(contains(&file, MARKER.as_bytes()));
        let again = Connection::open(&path).unwrap();
        let value: String = again
            .query_row("SELECT v FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, MARKER);
    }

    #[test]
    fn vacuum_into_a_keyed_target_copies_a_plain_database_and_leaves_it_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("p.db");
        let copy = dir.path().join("e.db");
        // A writer that keeps rows in the write-ahead log, not yet checkpointed.
        let writer = Connection::open(&plain).unwrap();
        writer
            .set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
        writer
            .execute_batch(&format!(
                "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;\
                 CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('{MARKER}');"
            ))
            .unwrap();
        let snapshot = |path: &Path| {
            let bytes = std::fs::read(path).unwrap();
            let modified = std::fs::metadata(path).unwrap().modified().unwrap();
            (bytes, modified)
        };
        let before = (snapshot(&plain), snapshot(&with_suffix(&plain, "-wal")));
        assert!(!before.1.0.is_empty());

        let reader = Connection::open_with_flags(
            &plain,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        let hex_key: String = [6u8; STORE_KEY_LEN]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let target = format!("file:{}?cipher=chacha20&key=raw:{hex_key}", copy.display());
        reader.execute("VACUUM INTO ?1", [&target]).unwrap();
        drop(reader);

        let after = (snapshot(&plain), snapshot(&with_suffix(&plain, "-wal")));
        assert!(before == after, "the plain database or its log changed");
        drop(writer);

        let file = std::fs::read(&copy).unwrap();
        assert!(!contains(&file, MARKER.as_bytes()));
        assert!(!contains(&file, b"SQLite format 3"));
        let copied = keyed(&copy, &StoreKey::from_bytes([6; STORE_KEY_LEN]));
        let value: String = copied
            .query_row("SELECT v FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, MARKER);
    }

    #[test]
    fn every_page_write_draws_a_fresh_random_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let key = StoreKey::from_bytes([9; STORE_KEY_LEN]);
        // Two installs of one seed doing the same writes.
        let write = |name: &str| {
            let path = dir.path().join(name);
            let conn = keyed(&path, &key);
            conn.execute_batch(
                "PRAGMA journal_mode = DELETE; PRAGMA page_size = 4096;\
                 CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('same');",
            )
            .unwrap();
            drop(conn);
            path
        };
        let first = write("a.db");
        let second = write("b.db");
        let a = std::fs::read(&first).unwrap();
        let b = std::fs::read(&second).unwrap();
        assert_eq!(a.len(), b.len());
        for (left, right) in nonces(&a).iter().zip(nonces(&b).iter()) {
            assert_ne!(left, right, "the same page got the same nonce in two files");
        }
        // The same page of one file written again, ending with the content it had.
        let conn = keyed(&first, &key);
        conn.execute_batch("UPDATE t SET v = 'other'; UPDATE t SET v = 'same';")
            .unwrap();
        drop(conn);
        let rewritten = std::fs::read(&first).unwrap();
        let (old, new) = (nonces(&a), nonces(&rewritten));
        assert_ne!(old[1], new[1], "a rewritten page kept its nonce");
        let page = |file: &[u8]| file[PAGE..2 * PAGE - RESERVE].to_vec();
        assert_ne!(page(&a), page(&rewritten));
        let all: std::collections::BTreeSet<_> = old.iter().chain(&nonces(&b)).copied().collect();
        assert_eq!(
            all.len(),
            old.len() * 2,
            "a nonce repeated across pages or files"
        );
    }

    #[test]
    fn missing_or_unreadable_check_says_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("db");
        let key = StoreKey::from_bytes([7; STORE_KEY_LEN]);
        assert_eq!(verify(&database, &key).unwrap(), Check::Unknown);
        std::fs::write(check_path(&database), b"\x02short").unwrap();
        assert_eq!(verify(&database, &key).unwrap(), Check::Unknown);
    }
}
