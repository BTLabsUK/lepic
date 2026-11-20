// SPDX-License-Identifier: Apache-2.0
//! The data-directory claim: one OS lock, taken by every opener of a wallet directory, so a CLI
//! command and an app never open one database at once.

use std::fs::{File, TryLockError};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::migration_in_progress;

/// The file in a data directory that holds the directory lock. It stays when the lock is
/// released: removing it would let two openers lock different files.
pub const LOCK_FILE: &str = ".lepic.lock";

/// How often a busy directory is tried again while a copy of a plain database is waited for.
const RETRY_WAIT: Duration = Duration::from_millis(100);

/// An exclusive OS lock on [`LOCK_FILE`], released when it is dropped. The file is opened
/// close-on-exec, as the standard library opens every file, so a child process does not
/// inherit the lock.
#[derive(Debug)]
pub struct DataDirLock {
    _file: File,
}

/// Why a data directory could not be claimed.
#[derive(Debug, Error)]
pub enum DataDirLockError {
    /// Another opener holds the lock.
    #[error("the data directory is in use")]
    Busy,
    /// The lock file could not be opened. A missing directory reports `NotFound`.
    #[error("the data directory lock is not usable: {0}")]
    Open(#[source] io::Error),
    /// The lock could not be taken for a reason other than another holder.
    #[error("the data directory could not be locked: {0}")]
    Lock(#[source] io::Error),
}

/// Takes the lock once, without waiting. A symbolic link in place of the lock file is refused
/// rather than followed, so the lock never creates a file elsewhere. Any failure other than
/// another holder fails closed.
pub fn try_lock_data_dir(dir: &Path) -> Result<DataDirLock, DataDirLockError> {
    let mut options = File::options();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(lepic_primitives::open_flags::O_NOFOLLOW);
    }
    let file = options
        .open(dir.join(LOCK_FILE))
        .map_err(DataDirLockError::Open)?;
    match file.try_lock() {
        Ok(()) => Ok(DataDirLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(DataDirLockError::Busy),
        Err(TryLockError::Error(error)) => Err(DataDirLockError::Lock(error)),
    }
}

/// Takes the lock, waiting up to `migration_wait` while the holder copies its plain database
/// into an encrypted one, and not at all otherwise. The wait sleeps on the runtime, so it
/// holds no thread. Fails with [`DataDirLockError::Busy`] when the directory is still in use
/// after the wait.
pub async fn lock_data_dir(
    dir: &Path,
    migration_wait: Duration,
) -> Result<DataDirLock, DataDirLockError> {
    let started = Instant::now();
    loop {
        match try_lock_data_dir(dir) {
            Err(DataDirLockError::Busy)
                if migration_in_progress(dir) && started.elapsed() < migration_wait =>
            {
                tokio::time::sleep(RETRY_WAIT).await;
            }
            claimed => return claimed,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_locked_directory_is_busy_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let held = try_lock_data_dir(dir.path()).unwrap();
        assert!(matches!(
            try_lock_data_dir(dir.path()),
            Err(DataDirLockError::Busy)
        ));
        drop(held);
        assert!(try_lock_data_dir(dir.path()).is_ok());
    }

    #[test]
    fn a_missing_directory_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let error = try_lock_data_dir(&dir.path().join("missing")).unwrap_err();
        assert!(
            matches!(error, DataDirLockError::Open(ref e) if e.kind() == io::ErrorKind::NotFound),
            "{error:?}"
        );
    }

    #[test]
    fn a_symbolic_link_in_place_of_the_lock_file_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = elsewhere.path().join("created-through-the-link");
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE)).unwrap();
        assert!(matches!(
            try_lock_data_dir(dir.path()),
            Err(DataDirLockError::Open(_))
        ));
        assert!(!target.exists(), "the lock followed the link");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_lock_is_not_inherited_by_child_processes() {
        use std::os::fd::AsRawFd as _;

        const O_CLOEXEC: u32 = 0o2000000;
        let dir = tempfile::tempdir().unwrap();
        let lock = try_lock_data_dir(dir.path()).unwrap();
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", lock._file.as_raw_fd()))
            .unwrap();
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .map(|flags| u32::from_str_radix(flags.trim(), 8).unwrap())
            .unwrap();
        assert_eq!(flags & O_CLOEXEC, O_CLOEXEC, "{info}");
    }

    /// A second opener waits for a holder that copies the plain database into an encrypted
    /// one, and is refused at once by a holder that does not.
    #[tokio::test]
    async fn a_second_opener_waits_only_while_a_copy_is_in_progress() {
        let dir = tempfile::tempdir().unwrap();
        let held = try_lock_data_dir(dir.path()).unwrap();
        assert!(matches!(
            lock_data_dir(dir.path(), Duration::from_secs(5)).await,
            Err(DataDirLockError::Busy)
        ));

        std::fs::write(dir.path().join("wallet.enc.sqlite3.tmp"), b"").unwrap();
        assert!(migration_in_progress(dir.path()));
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(held);
        });
        let started = Instant::now();
        lock_data_dir(dir.path(), Duration::from_secs(5))
            .await
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(250));
        release.join().unwrap();
    }
}
