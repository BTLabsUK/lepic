// SPDX-License-Identifier: Apache-2.0
//! Tracked text names no home directory of a real machine: a path such as `/home/<name>/...` or
//! `C:\Users\<name>\...` ties the repository to one developer's checkout and leaks the account
//! name. Examples use one of the placeholder names below.

use std::fmt;

use crate::sources::SourceFile;

/// The text files the gate reads, as git pathspecs.
pub(crate) const PATHSPECS: [&str; 9] = [
    "*.md", "*.rs", "*.toml", "*.sh", "*.yml", "*.yaml", "*.txt", "*.dart", "*.ps1",
];

/// Account names that are plainly examples, and the CI runner's.
const PLACEHOLDERS: &[&str] = &[
    "a", "alice", "bob", "dev", "example", "me", "runner", "test", "u", "user", "you",
];

/// Audit reports quote the findings they record, local paths included.
const EXEMPT_PREFIXES: &[&str] = &["docs/audit/"];

const PREFIXES: &[&str] = &["/home/", "/Users/", "C:\\Users\\", "C:\\\\Users\\\\"];

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    file: String,
    line: usize,
    path: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: `{}` is a home directory of a real machine; use a relative path or a placeholder name",
            self.file, self.line, self.path
        )
    }
}

pub(crate) fn check(files: &[SourceFile]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for file in files
        .iter()
        .filter(|file| !EXEMPT_PREFIXES.iter().any(|p| file.path.starts_with(p)))
    {
        for (index, line) in file.text.lines().enumerate() {
            for path in home_paths(line) {
                violations.push(Violation {
                    file: file.path.clone(),
                    line: index.saturating_add(1),
                    path,
                });
            }
        }
    }
    violations
}

/// Every home directory in `line` whose account name is not a placeholder, as written.
fn home_paths(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for prefix in PREFIXES {
        let mut rest = line;
        while let Some(start) = rest.find(prefix) {
            let after = rest
                .get(start.saturating_add(prefix.len())..)
                .unwrap_or_default();
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                .collect();
            if !name.is_empty() && !PLACEHOLDERS.contains(&name.to_ascii_lowercase().as_str()) {
                found.push(format!("{prefix}{name}"));
            }
            rest = after;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn refuses_a_real_home_directory() {
        let violations = check(&[file(
            "docs/notes.md",
            concat!("intro\nsee `/home", "/jane/wallet/docs/README.md`\n"),
        )]);
        assert_eq!(
            violations,
            vec![Violation {
                file: "docs/notes.md".to_owned(),
                line: 2,
                path: concat!("/home", "/jane").to_owned(),
            }]
        );
    }

    #[test]
    fn refuses_windows_and_macos_homes_in_either_escaping() {
        let text = concat!(
            "a C:\\Users",
            "\\Jane\\x b C:\\\\Users",
            "\\\\Jane\\\\x c /Users",
            "/jane/x"
        );
        assert_eq!(check(&[file("tool.ps1", text)]).len(), 3);
    }

    #[test]
    fn takes_placeholder_names_and_the_audit_reports() {
        let text = "/home/u/.local/bin C:\\Users\\dev\\x /home/runner/work /Users/me";
        assert!(check(&[file("xtask/src/install.rs", text)]).is_empty());
        let audit = file("docs/audit/report.md", concat!("/home", "/jane/x"));
        assert!(check(&[audit]).is_empty());
        assert!(check(&[file("docs/x.md", "/home/ and /home/")]).is_empty());
    }
}
