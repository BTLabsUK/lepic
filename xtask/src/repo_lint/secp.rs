// SPDX-License-Identifier: Apache-2.0
//! The secp256k1-zkp wrapper is the only git dependency, and it must resolve to the commit
//! ADR 0009 records. cargo-deny allows the repository but cannot pin the commit.

use std::fmt;

pub(crate) const SECP_REPOSITORY: &str = "https://github.com/EpicCash/rust-secp256k1-zkp";
pub(crate) const SECP_COMMIT: &str = "42fcb29d4b635ea771d1984be0d11b0e64b15a93";
const SECP_PACKAGE: &str = "grin_secp256k1zkp";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    WrongGitSource { package: String, source: String },
    SecpMissing,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongGitSource { package, source } => write!(
                f,
                "Cargo.lock resolves {package} from `{source}`; the only git source allowed is \
                 {SECP_REPOSITORY} at {SECP_COMMIT}"
            ),
            Self::SecpMissing => write!(
                f,
                "Cargo.lock has no {SECP_PACKAGE} from {SECP_REPOSITORY} at {SECP_COMMIT}"
            ),
        }
    }
}

pub(crate) fn check(lockfile: &str) -> Vec<Violation> {
    let expected = format!("git+{SECP_REPOSITORY}?rev={SECP_COMMIT}#{SECP_COMMIT}");
    let mut violations = Vec::new();
    let mut secp_found = false;
    for (name, source) in packages(lockfile) {
        let Some(source) = source else { continue };
        if !source.starts_with("git+") {
            continue;
        }
        if source == expected {
            secp_found |= name == SECP_PACKAGE;
        } else {
            violations.push(Violation::WrongGitSource {
                package: name.to_owned(),
                source: source.to_owned(),
            });
        }
    }
    if !secp_found {
        violations.push(Violation::SecpMissing);
    }
    violations
}

/// `(name, source)` of every `[[package]]` entry. Cargo writes one `key = "value"` per line.
fn packages(lockfile: &str) -> Vec<(&str, Option<&str>)> {
    let mut entries = Vec::new();
    let mut current: Option<(&str, Option<&str>)> = None;
    for line in lockfile.lines().map(str::trim) {
        if line == "[[package]]" {
            entries.extend(current.take());
            current = Some(("", None));
        } else if line.starts_with('[') {
            entries.extend(current.take());
        } else if let Some((name, source)) = current.as_mut() {
            if let Some(value) = string_value(line, "name") {
                *name = value;
            } else if let Some(value) = string_value(line, "source") {
                *source = Some(value);
            }
        }
    }
    entries.extend(current);
    entries
}

fn string_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim()
        .strip_prefix('"')?
        .strip_suffix('"')
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    fn lock(entries: &[(&str, &str)]) -> String {
        let mut text = "version = 4\n".to_owned();
        for (name, source) in entries {
            text.push_str(&format!(
                "\n[[package]]\nname = \"{name}\"\nversion = \"0.1.0\"\n"
            ));
            if !source.is_empty() {
                text.push_str(&format!("source = \"{source}\"\n"));
            }
            text.push_str("dependencies = [\n \"zeroize\",\n]\n");
        }
        text
    }

    fn pinned() -> String {
        format!("git+{SECP_REPOSITORY}?rev={SECP_COMMIT}#{SECP_COMMIT}")
    }

    #[test]
    fn accepts_the_wrapper_at_the_recorded_commit() {
        let text = lock(&[
            ("lepic-crypto", ""),
            (SECP_PACKAGE, &pinned()),
            (
                "zeroize",
                "registry+https://github.com/rust-lang/crates.io-index",
            ),
        ]);
        assert_eq!(check(&text), []);
    }

    #[test]
    fn rejects_the_wrapper_at_another_commit_and_other_git_sources() {
        let other = "1111111111111111111111111111111111111111";
        let moved = format!("git+{SECP_REPOSITORY}?rev={other}#{other}");
        let branch = format!("git+{SECP_REPOSITORY}?branch=master#{SECP_COMMIT}");
        let text = lock(&[
            (SECP_PACKAGE, &moved),
            ("secp-sys", &branch),
            ("other", "git+https://example.org/other#abc"),
        ]);
        assert_eq!(
            check(&text),
            [
                Violation::WrongGitSource {
                    package: SECP_PACKAGE.to_owned(),
                    source: moved
                },
                Violation::WrongGitSource {
                    package: "secp-sys".to_owned(),
                    source: branch
                },
                Violation::WrongGitSource {
                    package: "other".to_owned(),
                    source: "git+https://example.org/other#abc".to_owned()
                },
                Violation::SecpMissing,
            ]
        );
    }

    #[test]
    fn rejects_a_lockfile_without_the_wrapper() {
        assert_eq!(
            check(&lock(&[("lepic-crypto", "")])),
            [Violation::SecpMissing]
        );
    }

    #[test]
    fn commit_matches_adr_0009_and_the_workspace_manifest() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let adr = fs::read_to_string(root.join("docs/adr/0009-conformance.md")).unwrap();
        assert!(adr.contains(SECP_COMMIT));
        let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let declared = manifest
            .lines()
            .find(|line| line.starts_with(&format!("{SECP_PACKAGE} =")))
            .unwrap();
        assert!(declared.contains(&format!("git = \"{SECP_REPOSITORY}\"")));
        assert!(declared.contains(&format!("rev = \"{SECP_COMMIT}\"")));
    }
}
