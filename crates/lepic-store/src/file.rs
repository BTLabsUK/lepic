// SPDX-License-Identifier: Apache-2.0
//! Owner-only files, written so a crash leaves the old content or the new, never part of it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

const TEMPORARY_SUFFIX: &str = ".tmp";

/// Replaces the file at `path` with `contents`, readable by its owner only. The bytes go to a
/// temporary file in the same directory, are synced, renamed over `path`, and the directory is
/// synced. A leftover temporary file from an interrupted write, or a link planted there, is
/// removed rather than reused, so the new file is always this call's own, owner-only file. A
/// symbolic link at `path` is replaced, not followed.
pub fn write_owner_only_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(TEMPORARY_SUFFIX);
    let temporary = PathBuf::from(temporary);
    if let Err(error) = fs::remove_file(&temporary)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(error);
    }
    let mut file = owner_only_new().open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_folder(path)
}

#[cfg(unix)]
fn owner_only_new() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options
}

#[cfg(not(unix))]
fn owner_only_new() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options
}

/// Makes a rename inside the folder of `path` durable.
#[cfg(unix)]
pub(crate) fn sync_folder(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(folder) if !folder.as_os_str().is_empty() => File::open(folder)?.sync_all(),
        _ => File::open(".")?.sync_all(),
    }
}

/// Windows has no folder handle to flush; its renames are journalled by NTFS.
#[cfg(not(unix))]
pub(crate) fn sync_folder(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn writes_owner_only_and_replaces_the_old_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_owner_only_atomic(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_planted_temporary_file_is_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, b"untouched").unwrap();
        let path = dir.path().join("secret");
        std::os::unix::fs::symlink(&outside, dir.path().join("secret.tmp")).unwrap();
        write_owner_only_atomic(&path, b"new").unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
        assert_eq!(fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn a_stale_temporary_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let stale = dir.path().join("secret.tmp");
        fs::write(&stale, b"stale").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).unwrap();
        write_owner_only_atomic(&path, b"new").unwrap();
        assert!(!stale.exists());
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
