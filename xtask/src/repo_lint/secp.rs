// SPDX-License-Identifier: Apache-2.0
//! The secp256k1-zkp wrapper is built from the vendored copy of the commit ADR 0009 records, and
//! the product workspace has no git dependency at all. cargo-deny denies unknown git sources but
//! does not check where the wrapper comes from.

use std::fmt;

const SECP_PATH: &str = "third_party/grin_secp256k1zkp";
const SECP_PACKAGE: &str = "grin_secp256k1zkp";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    GitSource { package: String, source: String },
    SecpNotVendored { source: String },
    SecpMissing,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GitSource { package, source } => write!(
                f,
                "Cargo.lock resolves {package} from `{source}`; the product workspace has no git \
                 dependencies"
            ),
            Self::SecpNotVendored { source } => write!(
                f,
                "Cargo.lock resolves {SECP_PACKAGE} from `{source}`; it must be the path package \
                 {SECP_PATH}"
            ),
            Self::SecpMissing => write!(f, "Cargo.lock has no {SECP_PACKAGE} from {SECP_PATH}"),
        }
    }
}

pub(crate) fn check(lockfile: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut secp_found = false;
    for (name, source) in packages(lockfile) {
        let Some(source) = source else {
            // Cargo writes no source for a path package.
            secp_found |= name == SECP_PACKAGE;
            continue;
        };
        if name == SECP_PACKAGE {
            violations.push(Violation::SecpNotVendored {
                source: source.to_owned(),
            });
        } else if source.starts_with("git+") {
            violations.push(Violation::GitSource {
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

    /// The fork commit the vendored copy was taken from (`PATCHES.md` beside it).
    const SECP_COMMIT: &str = "42fcb29d4b635ea771d1984be0d11b0e64b15a93";
    const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

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

    #[test]
    fn accepts_the_vendored_wrapper() {
        let text = lock(&[
            ("lepic-crypto", ""),
            (SECP_PACKAGE, ""),
            ("zeroize", REGISTRY),
        ]);
        assert_eq!(check(&text), []);
    }

    #[test]
    fn rejects_the_wrapper_from_git_and_other_git_sources() {
        let git = format!(
            "git+https://github.com/EpicCash/rust-secp256k1-zkp?rev={SECP_COMMIT}#{SECP_COMMIT}"
        );
        let text = lock(&[
            (SECP_PACKAGE, &git),
            ("other", "git+https://example.org/other#abc"),
        ]);
        assert_eq!(
            check(&text),
            [
                Violation::SecpNotVendored { source: git },
                Violation::GitSource {
                    package: "other".to_owned(),
                    source: "git+https://example.org/other#abc".to_owned()
                },
                Violation::SecpMissing,
            ]
        );
    }

    #[test]
    fn rejects_the_wrapper_from_a_registry() {
        assert_eq!(
            check(&lock(&[(SECP_PACKAGE, REGISTRY)])),
            [
                Violation::SecpNotVendored {
                    source: REGISTRY.to_owned()
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
    fn vendored_copy_matches_adr_0009_and_the_workspace_manifest() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let adr = fs::read_to_string(root.join("docs/adr/0009-conformance.md")).unwrap();
        assert!(adr.contains(SECP_COMMIT));
        let patches = fs::read_to_string(root.join(SECP_PATH).join("PATCHES.md")).unwrap();
        assert!(patches.contains(SECP_COMMIT));
        let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let declared = manifest
            .lines()
            .find(|line| line.starts_with(&format!("{SECP_PACKAGE} =")))
            .unwrap();
        assert!(declared.contains(&format!("path = \"{SECP_PATH}\"")));
        assert!(!declared.contains("git ="));
    }
}
