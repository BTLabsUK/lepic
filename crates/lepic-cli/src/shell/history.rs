// SPDX-License-Identifier: Apache-2.0
//! The shell's history: a file in the data directory, readable by its owner only, that never
//! keeps a line which may hold secret material.

use std::io;
use std::path::Path;

use reedline::{
    FileBackedHistory, History, HistoryItem, HistoryItemId, HistorySessionId, SearchDirection,
    SearchQuery,
};

use crate::shell::words::keep_in_history;

/// The history file, in the data directory.
pub(crate) const HISTORY_FILE: &str = "shell-history";

/// How many lines the file keeps.
const CAPACITY: usize = 1000;

/// [`FileBackedHistory`] that drops the lines [`keep_in_history`] refuses.
pub(crate) struct FilteredHistory(FileBackedHistory);

impl FilteredHistory {
    /// The history of the data directory `data_dir`, created owner-only when it is missing.
    pub(crate) fn open(data_dir: &Path) -> io::Result<Self> {
        let path = data_dir.join(HISTORY_FILE);
        create_private(&path)?;
        FileBackedHistory::with_file(CAPACITY, path)
            .map(Self)
            .map_err(io::Error::other)
    }

    /// Kept in memory only, for when the file cannot be opened.
    pub(crate) fn in_memory() -> Self {
        Self(FileBackedHistory::default())
    }
}

/// The lines `history` holds, oldest first.
pub(crate) fn lines(history: &dyn History) -> Vec<String> {
    history
        .search(SearchQuery::everything(SearchDirection::Forward, None))
        .map(|items| items.into_iter().map(|item| item.command_line).collect())
        .unwrap_or_default()
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    // A file made by an older run, or by hand, is narrowed too.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Windows has no mode bits: the file gets a protected DACL with one entry, full control for
/// the user running the shell, as 0600 gives on Unix. `icacls` sets it because the workspace
/// denies the unsafe code a direct `SetNamedSecurityInfoW` call needs.
#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let user = acl::user_sid()?;
    // `/reset` drops the explicit entries a file made by hand may carry; `/inheritance:r` then
    // drops the inherited ones and protects the DACL, and `/grant:r` leaves the user's entry
    // as the only one. Between the two calls the file has only what its directory passes on.
    acl::icacls(path, &["/reset"])?;
    acl::icacls(
        path,
        &["/inheritance:r", "/grant:r", &format!("*{user}:(F)")],
    )
}

#[cfg(not(unix))]
mod acl {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// The longest SID text: `S-1-` and up to 15 numbers of at most 20 digits.
    const MAX_SID_LEN: usize = 4 + 15 * 21;

    /// A tool of `System32`, named by its full path so no directory on `PATH` stands in for it.
    fn system_tool(name: &str) -> io::Result<PathBuf> {
        let root = std::env::var_os("SystemRoot")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SystemRoot is not set"))?;
        Ok(PathBuf::from(root).join("System32").join(name))
    }

    fn run(tool: &str, args: &[&std::ffi::OsStr]) -> io::Result<Vec<u8>> {
        let output = Command::new(system_tool(tool)?)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{tool} failed: {}",
                output.status
            )));
        }
        Ok(output.stdout)
    }

    pub(super) fn icacls(path: &Path, args: &[&str]) -> io::Result<()> {
        let mut all = vec![path.as_os_str()];
        all.extend(args.iter().map(std::ffi::OsStr::new));
        run("icacls.exe", &all).map(drop)
    }

    /// The SID of the user the process runs as, from `whoami /user`: `"name","S-1-…"`.
    pub(super) fn user_sid() -> io::Result<String> {
        let args = ["/user", "/fo", "csv", "/nh"].map(std::ffi::OsStr::new);
        let output = run("whoami.exe", &args)?;
        parse_whoami_sid(&String::from_utf8_lossy(&output))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "whoami gave no user SID"))
    }

    pub(super) fn parse_whoami_sid(output: &str) -> Option<String> {
        let sid = output.trim().rsplit(',').next()?.trim_matches('"');
        let numbers = sid.strip_prefix("S-1-")?;
        let well_formed = sid.len() <= MAX_SID_LEN
            && numbers
                .split('-')
                .all(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()));
        well_formed.then(|| sid.to_owned())
    }
}

impl History for FilteredHistory {
    fn save(&mut self, item: HistoryItem) -> reedline::Result<HistoryItem> {
        if keep_in_history(&item.command_line) {
            self.0.save(item)
        } else {
            Ok(item)
        }
    }

    fn load(&self, id: HistoryItemId) -> reedline::Result<HistoryItem> {
        self.0.load(id)
    }

    fn count(&self, query: SearchQuery) -> reedline::Result<i64> {
        self.0.count(query)
    }

    fn search(&self, query: SearchQuery) -> reedline::Result<Vec<HistoryItem>> {
        self.0.search(query)
    }

    fn update(
        &mut self,
        id: HistoryItemId,
        updater: &dyn Fn(HistoryItem) -> HistoryItem,
    ) -> reedline::Result<()> {
        self.0.update(id, updater)
    }

    fn clear(&mut self) -> reedline::Result<()> {
        self.0.clear()
    }

    fn delete(&mut self, id: HistoryItemId) -> reedline::Result<()> {
        self.0.delete(id)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.0.sync()
    }

    fn session(&self) -> Option<HistorySessionId> {
        self.0.session()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn item(line: &str) -> HistoryItem {
        HistoryItem::from_command_line(line)
    }

    #[test]
    fn secret_lines_never_reach_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut history = FilteredHistory::open(dir.path()).unwrap();
        history.save(item("tx list")).unwrap();
        history
            .save(item("contact enter epiccash://pair?k=abc"))
            .unwrap();
        history.save(item("in-person pay --hex 00ff")).unwrap();
        history.save(item("wallet info")).unwrap();
        history.sync().unwrap();
        assert_eq!(lines(&history), ["tx list", "wallet info"]);
        let file = std::fs::read_to_string(dir.path().join(HISTORY_FILE)).unwrap();
        assert!(file.contains("tx list"));
        assert!(!file.contains("epiccash"));
        assert!(!file.contains("00ff"));
        let reopened = FilteredHistory::open(dir.path()).unwrap();
        assert_eq!(lines(&reopened), ["tx list", "wallet info"]);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_the_owners_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HISTORY_FILE);
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _history = FilteredHistory::open(dir.path()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// An older file that others could read is narrowed to one entry: the user, full control,
    /// not inherited, with inheritance off.
    #[cfg(not(unix))]
    #[test]
    fn the_file_is_the_owners_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HISTORY_FILE);
        std::fs::write(&path, "").unwrap();
        // Everyone may read it.
        acl::icacls(&path, &["/grant", "*S-1-1-0:(R)"]).unwrap();
        let _history = FilteredHistory::open(dir.path()).unwrap();
        let user = acl::user_sid().unwrap();
        let script = "$acl = Get-Acl -LiteralPath $env:LEPIC_ACL_PATH; \
            'protected=' + $acl.AreAccessRulesProtected; \
            foreach ($rule in $acl.Access) { \
              $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]); \
              'rule=' + $sid.Value + '|' + $rule.FileSystemRights + '|' + \
                $rule.AccessControlType + '|' + $rule.IsInherited }";
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("LEPIC_ACL_PATH", &path)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            lines,
            [
                "protected=True".to_owned(),
                format!("rule={user}|FullControl|Allow|False")
            ]
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn the_user_sid_is_the_last_whoami_field() {
        assert_eq!(
            acl::parse_whoami_sid("\"host\\a,b\",\"S-1-5-21-1-2-3-1001\"\r\n").as_deref(),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(acl::parse_whoami_sid("\"host\\a\",\"S-1-5--1\""), None);
        assert_eq!(acl::parse_whoami_sid("\"host\\a\",\"1-5-21\""), None);
        assert_eq!(acl::parse_whoami_sid(""), None);
    }
}
