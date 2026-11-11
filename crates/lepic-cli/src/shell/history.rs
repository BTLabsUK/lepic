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

#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(drop)
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
}
