// SPDX-License-Identifier: Apache-2.0
//! Pure crates do no I/O, read no clock and create no randomness of their own
//! (`docs/architecture.md`). deps-check keeps I/O crates out of their manifests; this gate keeps
//! the standard library's I/O, clock and process access out of their sources.

use std::fmt;

use crate::deps_check::PURE_CRATES;
use crate::sources::{SourceFile, code_only, is_ident_char, line_of, word_offsets};

/// The library sources of every pure crate. Tests and benches may read files and clocks.
pub(crate) const SOURCE_PATHSPECS: [&str; 5] = [
    "crates/lepic-crypto/src/*.rs",
    "crates/lepic-primitives/src/*.rs",
    "crates/lepic-keychain/src/*.rs",
    "crates/lepic-slate/src/*.rs",
    "crates/lepic-contact/src/*.rs",
];

/// Paths and names that reach the filesystem, network, environment, processes, threads, a clock
/// or an operating-system random source.
const FORBIDDEN: &[&str] = &[
    "std::fs",
    "std::net",
    "std::env",
    "std::process",
    "std::thread",
    "SystemTime",
    "Instant",
    "UNIX_EPOCH",
    "tokio",
    "getrandom",
    "thread_rng",
    "ThreadRng",
    "OsRng",
    "SysRng",
    "rand::rng",
];

/// Modules of `std` that grouped imports such as `use std::{fs, io};` may name.
const FORBIDDEN_STD_MODULES: &[&str] = &["fs", "net", "env", "process", "thread"];

/// Clock reads through any type, such as `Timestamp::now()` or `Zoned::now()`.
const CLOCK_CALL: &str = "::now";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    file: String,
    line: usize,
    what: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: `{}` in a pure crate, which must take I/O, time and randomness from its caller",
            self.file, self.line, self.what
        )
    }
}

pub(crate) fn check_sources(sources: &[SourceFile]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for source in sources.iter().filter(|file| is_pure_source(&file.path)) {
        let code = code_only(&source.text);
        let mut report = |offset: usize, what: &str| {
            violations.push(Violation {
                file: source.path.clone(),
                line: line_of(&code, offset),
                what: what.to_owned(),
            });
        };
        for name in FORBIDDEN {
            for offset in word_offsets(&code, name) {
                report(offset, name);
            }
        }
        for (offset, _) in code.match_indices(CLOCK_CALL) {
            let after = code
                .get(offset.saturating_add(CLOCK_CALL.len())..)
                .and_then(|rest| rest.chars().next());
            if after.is_none_or(|c| !is_ident_char(c)) {
                report(offset, CLOCK_CALL);
            }
        }
        for (offset, module) in grouped_std_modules(&code) {
            report(offset, &format!("std::{{{module}}}"));
        }
    }
    violations.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    violations
}

fn is_pure_source(path: &str) -> bool {
    PURE_CRATES.iter().any(|name| {
        path.strip_prefix("crates/")
            .and_then(|rest| rest.strip_prefix(name))
            .is_some_and(|rest| rest.starts_with("/src/") && rest.ends_with(".rs"))
    })
}

/// Forbidden modules named inside `std::{...}` groups, at the offset of the group.
fn grouped_std_modules(code: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for offset in word_offsets(code, "std") {
        let Some(group) = code
            .get(offset.saturating_add(3)..)
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix("::"))
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('{'))
        else {
            continue;
        };
        let mut depth = 0usize;
        let end = group
            .char_indices()
            .find(|&(_, c)| match c {
                '{' => {
                    depth = depth.saturating_add(1);
                    false
                }
                '}' if depth == 0 => true,
                '}' => {
                    depth = depth.saturating_sub(1);
                    false
                }
                _ => false,
            })
            .map_or(group.len(), |(index, _)| index);
        let group = group.get(..end).unwrap_or("");
        for item in group.split(',') {
            let head: String = item
                .trim_start()
                .chars()
                .take_while(|c| is_ident_char(*c))
                .collect();
            if let Some(module) = FORBIDDEN_STD_MODULES.iter().find(|module| **module == head) {
                found.push((offset, *module));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(path: &str, text: &str) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    fn whats(sources: &[SourceFile]) -> Vec<(usize, String)> {
        check_sources(sources)
            .into_iter()
            .map(|violation| (violation.line, violation.what))
            .collect()
    }

    #[test]
    fn accepts_code_that_takes_its_inputs_from_the_caller() {
        let text = "//! Reads no std::fs.\nuse std::io::Read;\nuse rand_core::CryptoRng;\nconst S: &str = \"Instant::now()\";\nfn known(now: Timestamp) {}\nstruct Instantiation;\n";
        assert_eq!(whats(&[source("crates/lepic-slate/src/lib.rs", text)]), []);
    }

    #[test]
    fn rejects_io_clocks_and_os_randomness_in_pure_crates() {
        let text = "use std::fs::File;\nlet t = std::time::SystemTime::now();\nlet i = Instant::now();\nlet z = jiff::Timestamp::now();\nlet r = rand::rng();\nlet o = rand::rngs::OsRng;\nuse std::{env, io::{self, Read}, net::TcpStream};\n";
        assert_eq!(
            whats(&[source("crates/lepic-crypto/src/context.rs", text)]),
            [
                (1, "std::fs".to_owned()),
                (2, "SystemTime".to_owned()),
                (2, "::now".to_owned()),
                (3, "Instant".to_owned()),
                (3, "::now".to_owned()),
                (4, "::now".to_owned()),
                (5, "rand::rng".to_owned()),
                (6, "OsRng".to_owned()),
                (7, "std::{env}".to_owned()),
                (7, "std::{net}".to_owned()),
            ]
        );
    }

    #[test]
    fn checks_only_library_sources_of_pure_crates() {
        let text = "use std::fs;\n";
        let sources = [
            source("crates/lepic-keychain/tests/vectors.rs", text),
            source("crates/lepic-keychain/benches/argon2.rs", text),
            source("crates/lepic-store/src/lib.rs", text),
            source("crates/lepic-keychain-extra/src/lib.rs", text),
            source("crates/lepic-keychain/src/vault/mod.rs", text),
        ];
        assert_eq!(
            check_sources(&sources),
            [Violation {
                file: "crates/lepic-keychain/src/vault/mod.rs".to_owned(),
                line: 1,
                what: "std::fs".to_owned(),
            }]
        );
    }
}
