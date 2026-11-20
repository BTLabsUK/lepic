// SPDX-License-Identifier: Apache-2.0
//! Every workspace member inherits `[workspace.lints]`, which denies `unsafe_code`. The only
//! relaxations allowed are the attribute on the module flutter_rust_bridge generates, and one
//! `expect` in the store's cipher module around SQLite3MC's key call (ADR 0032).

use std::fmt;

use crate::sources::{SourceFile, code_only, is_ident_char, line_of, word_offsets};

const UNSAFE_LINT: &str = "unsafe_code";
const WORKSPACE_RUST_LINTS: &str = "[workspace.lints.rust]";
const GENERATED_MODULE_FILE: &str = "crates/lepic-ffi/src/frb_generated.rs";
const GENERATED_MODULE_PARENT: &str = "crates/lepic-ffi/src/lib.rs";
const GENERATED_MODULE_ITEM: &str = "mod frb_generated;";
const RELAXING_LEVELS: &[&str] = &["allow", "expect", "warn"];
/// The one hand-written file that may relax the lint, once, with `expect`: SQLite3MC's
/// `sqlite3_key_v2` has no safe binding.
const KEY_CALL_FILE: &str = "crates/lepic-store/src/sqlite/cipher.rs";

pub(crate) struct Member {
    pub(crate) name: String,
    pub(crate) manifest: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    UnsafeNotDenied,
    NoWorkspaceLints { member: String },
    OwnLintTable { member: String, header: String },
    UnsafeAllowed { file: String, line: usize },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeNotDenied => write!(
                f,
                "Cargo.toml {WORKSPACE_RUST_LINTS} must set {UNSAFE_LINT} = \"deny\""
            ),
            Self::NoWorkspaceLints { member } => write!(
                f,
                "{member} must inherit the workspace lints with `[lints]` and `workspace = true`"
            ),
            Self::OwnLintTable { member, header } => write!(
                f,
                "{member} declares its own `{header}`; lints come only from the workspace table"
            ),
            Self::UnsafeAllowed { file, line } => write!(
                f,
                "{file}:{line}: relaxes {UNSAFE_LINT}; only the generated module in \
                 {GENERATED_MODULE_PARENT} and one `expect` in {KEY_CALL_FILE} may"
            ),
        }
    }
}

pub(crate) fn check(
    root_manifest: &str,
    members: &[Member],
    sources: &[SourceFile],
) -> Vec<Violation> {
    let mut violations = Vec::new();
    if !table_lines(root_manifest, WORKSPACE_RUST_LINTS)
        .any(|line| line == format!("{UNSAFE_LINT}=\"deny\""))
    {
        violations.push(Violation::UnsafeNotDenied);
    }
    for member in members {
        violations.extend(member_violations(member));
    }
    for source in sources
        .iter()
        .filter(|file| file.path != GENERATED_MODULE_FILE)
    {
        violations.extend(unsafe_allowances(source));
    }
    violations
}

/// The `key=value` lines of one table, without whitespace or comments.
fn table_lines<'a>(manifest: &'a str, header: &'a str) -> impl Iterator<Item = String> + 'a {
    manifest
        .lines()
        .skip_while(move |line| line.trim() != header)
        .skip(1)
        .map(str::trim)
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_whitespace().collect())
}

fn member_violations(member: &Member) -> Vec<Violation> {
    let mut violations = Vec::new();
    let inherits = table_lines(&member.manifest, "[lints]")
        .collect::<Vec<_>>()
        .eq(&["workspace=true".to_owned()]);
    if !inherits {
        violations.push(Violation::NoWorkspaceLints {
            member: member.name.clone(),
        });
    }
    for line in member.manifest.lines().map(str::trim) {
        if line.starts_with("[lints.") {
            violations.push(Violation::OwnLintTable {
                member: member.name.clone(),
                header: line.to_owned(),
            });
        }
    }
    violations
}

/// Attributes in `source` that set `unsafe_code` to a level below deny.
fn unsafe_allowances(source: &SourceFile) -> Vec<Violation> {
    let code = code_only(&source.text);
    let mut key_call_allowed = source.path == KEY_CALL_FILE;
    word_offsets(&code, UNSAFE_LINT)
        .filter(|&offset| relaxes(&code, offset))
        .filter(|&offset| {
            !(source.path == GENERATED_MODULE_PARENT && on_generated_module(&code, offset))
        })
        .filter(|&offset| {
            let allowed = key_call_allowed && is_outer_expect(&code, offset);
            if allowed {
                key_call_allowed = false;
            }
            !allowed
        })
        .map(|offset| Violation::UnsafeAllowed {
            file: source.path.clone(),
            line: line_of(&code, offset),
        })
        .collect()
}

/// Whether the lint name at `offset` is an argument of a plain outer `#[expect(...)]`.
fn is_outer_expect(code: &str, offset: usize) -> bool {
    code.get(..offset)
        .and_then(|before| before.rfind('#').and_then(|hash| before.get(hash..)))
        .is_some_and(|attribute| {
            attribute
                .strip_prefix("#[")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix("expect"))
                .map(str::trim_start)
                .is_some_and(|rest| rest.starts_with('('))
        })
}

/// Whether the lint name at `offset` is an argument of an `allow`, `expect` or `warn` call inside
/// an attribute, including one nested in `cfg_attr`.
fn relaxes(code: &str, offset: usize) -> bool {
    let Some(attribute) = code
        .get(..offset)
        .and_then(|before| before.rfind('#').and_then(|hash| before.get(hash..)))
    else {
        return false;
    };
    let Some(call) = attribute
        .rfind('(')
        .and_then(|open| attribute.get(..open))
        .map(str::trim_end)
    else {
        return false;
    };
    RELAXING_LEVELS.iter().any(|level| {
        call.strip_suffix(level)
            .is_some_and(|before| before.chars().next_back().is_none_or(|c| !is_ident_char(c)))
    })
}

/// Whether the attribute containing `offset` is an outer attribute of the generated module.
fn on_generated_module(code: &str, offset: usize) -> bool {
    let is_inner = code
        .get(..offset)
        .and_then(|before| before.rfind('#').and_then(|hash| before.get(hash..)))
        .is_some_and(|attribute| attribute.starts_with("#!"));
    if is_inner {
        return false;
    }
    let Some(mut rest) = code.get(offset..).and_then(|after| {
        after
            .find(']')
            .and_then(|close| after.get(close.saturating_add(1)..))
    }) else {
        return false;
    };
    // Other outer attributes may sit between this one and the item.
    loop {
        rest = rest.trim_start();
        match rest.strip_prefix("#[") {
            Some(attribute) => match attribute.find(']') {
                Some(close) => rest = attribute.get(close.saturating_add(1)..).unwrap_or(""),
                None => return false,
            },
            None => return rest.starts_with(GENERATED_MODULE_ITEM),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "[workspace]\n\n[workspace.lints.rust]\nunsafe_code = \"deny\"\n\n[workspace.lints.clippy]\npanic = \"deny\"\n";
    const INHERITS: &str = "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n";

    fn member(name: &str, manifest: &str) -> Member {
        Member {
            name: name.to_owned(),
            manifest: manifest.to_owned(),
        }
    }

    fn source(path: &str, text: &str) -> SourceFile {
        SourceFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn accepts_members_that_inherit_the_workspace_lints() {
        assert_eq!(check(ROOT, &[member("a", INHERITS)], &[]), []);
    }

    #[test]
    fn rejects_a_workspace_table_that_does_not_deny_unsafe_code() {
        let root = ROOT.replace("unsafe_code = \"deny\"", "unsafe_code = \"warn\"");
        assert_eq!(check(&root, &[], &[]), [Violation::UnsafeNotDenied]);
    }

    #[test]
    fn rejects_a_member_without_workspace_lints() {
        let manifest = "[package]\nname = \"b\"\n\n[dependencies]\n";
        let opted_out = "[package]\nname = \"c\"\n\n[lints]\nworkspace = false\n";
        assert_eq!(
            check(ROOT, &[member("b", manifest), member("c", opted_out)], &[]),
            [
                Violation::NoWorkspaceLints {
                    member: "b".to_owned()
                },
                Violation::NoWorkspaceLints {
                    member: "c".to_owned()
                },
            ]
        );
    }

    #[test]
    fn rejects_a_member_with_its_own_lint_table() {
        let manifest = "[package]\nname = \"ffi\"\n\n[lints.clippy]\npanic = \"deny\"\n";
        assert_eq!(
            check(ROOT, &[member("ffi", manifest)], &[]),
            [
                Violation::NoWorkspaceLints {
                    member: "ffi".to_owned()
                },
                Violation::OwnLintTable {
                    member: "ffi".to_owned(),
                    header: "[lints.clippy]".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn allows_unsafe_code_only_on_the_generated_module() {
        let lib = "pub mod api;\n// The generator writes this module.\n#[allow(\n    unsafe_code,\n    clippy::all\n)]\n#[rustfmt::skip]\nmod frb_generated;\nmod pin;\n";
        let sources = [
            source(GENERATED_MODULE_PARENT, lib),
            source(
                GENERATED_MODULE_FILE,
                "#![allow(unsafe_code)]\nunsafe fn f() {}\n",
            ),
        ];
        assert_eq!(check(ROOT, &[], &sources), []);
    }

    #[test]
    fn rejects_unsafe_code_relaxed_anywhere_else() {
        let lib = "#![allow(unsafe_code)]\n#[allow(unsafe_code)]\nmod pin;\n#[expect(clippy::panic, unsafe_code)]\nmod frb_generated_copy;\n";
        let other =
            "#[cfg_attr(test, allow(unsafe_code))]\nfn f() {}\n#[warn(unsafe_code)]\nfn g() {}\n";
        let sources = [
            source(GENERATED_MODULE_PARENT, lib),
            source("crates/lepic-ffi/src/pin.rs", other),
            source(
                "crates/lepic-cli/src/main.rs",
                "#[allow(unsafe_code)]\nmod frb_generated;\n",
            ),
        ];
        let lines: Vec<(String, usize)> = check(ROOT, &[], &sources)
            .into_iter()
            .map(|violation| match violation {
                Violation::UnsafeAllowed { file, line } => (file, line),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(
            lines,
            [
                (GENERATED_MODULE_PARENT.to_owned(), 1),
                (GENERATED_MODULE_PARENT.to_owned(), 2),
                (GENERATED_MODULE_PARENT.to_owned(), 4),
                ("crates/lepic-ffi/src/pin.rs".to_owned(), 1),
                ("crates/lepic-ffi/src/pin.rs".to_owned(), 3),
                ("crates/lepic-cli/src/main.rs".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn allows_one_expect_in_the_store_cipher_module_only() {
        let one = "fn key() {\n    #[expect(\n        unsafe_code,\n        reason = \"x\"\n    )]\n    let c = unsafe { f() };\n}\n";
        assert_eq!(check(ROOT, &[], &[source(KEY_CALL_FILE, one)]), []);
        let two = format!("{one}#[expect(unsafe_code)]\nfn g() {{}}\n");
        let allowing = "#[allow(unsafe_code)]\nfn g() {}\n";
        let elsewhere = source("crates/lepic-store/src/sqlite/mod.rs", one);
        let lines: Vec<(String, usize)> = check(
            ROOT,
            &[],
            &[
                source(KEY_CALL_FILE, &two),
                source("crates/lepic-store/src/sqlite/cipher.rs", allowing),
                elsewhere,
            ],
        )
        .into_iter()
        .map(|violation| match violation {
            Violation::UnsafeAllowed { file, line } => (file, line),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
        assert_eq!(
            lines,
            [
                (KEY_CALL_FILE.to_owned(), 8),
                (KEY_CALL_FILE.to_owned(), 1),
                ("crates/lepic-store/src/sqlite/mod.rs".to_owned(), 3),
            ]
        );
    }

    #[test]
    fn ignores_the_lint_name_in_comments_strings_and_deny_attributes() {
        let text = "// #[allow(unsafe_code)]\nconst S: &str = \"#[allow(unsafe_code)]\";\n#[deny(unsafe_code)]\nfn f() {}\n";
        assert_eq!(check(ROOT, &[], &[source("xtask/src/a.rs", text)]), []);
    }
}
