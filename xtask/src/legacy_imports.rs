// SPDX-License-Identifier: Apache-2.0
//! The legacy lane depends on no native crate (ADR 0062 §2). This scan starts at
//! `lepic_wallet::inbox::legacy`, follows every module of lepic-wallet the code names through
//! `use` items and paths (`crate::…`, `super::…`, `self::…`, imported names and child
//! modules), and reports each place that names a native crate or module. It checks `use` lines
//! and paths only: it cannot see a native item reached through a method call or re-exported
//! under another path. The lane's own files, `inbox/legacy.rs` and its child modules, also name
//! no notice: the lane sends none.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Result, bail};

use crate::sources::{code_only, is_ident_char, line_of};

/// The sources of lepic-wallet's library.
const SRC: &str = "crates/lepic-wallet/src";

/// Where the scan starts.
const START: &str = "crates/lepic-wallet/src/inbox/legacy.rs";

/// The native crates and lepic-wallet modules the legacy lane must not name. `native_epicbox`
/// is gone and stays listed so it cannot come back.
const NATIVE: &[&str] = &[
    "lepic_peer",
    "lepic_epic1",
    "lepic_wallet_contacts",
    "native_epicbox",
];

/// The modules only the lane's own files must not name. Notices on a payment's own route, a
/// contact mailbox or an epic1 reply mailbox live in them, and the wallet core names them.
const NOT_IN_LANE: &[&str] = &["extension", "notice"];

/// The module of the lane's own files.
const LANE: [&str; 2] = ["inbox", "legacy"];

/// Names that start a path but are neither a crate nor a module: primitive types and the
/// tools of lint attributes such as `#[expect(clippy::…)]`.
const NOT_CRATES: &[&str] = &[
    "clippy", "rustdoc", "rustfmt", "bool", "char", "str", "u8", "u16", "u32", "u64", "u128",
    "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Finding {
    file: String,
    line: usize,
    name: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.name)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Report {
    /// The module files read, in the order they were reached.
    modules: Vec<String>,
    findings: BTreeSet<Finding>,
    external_crates: BTreeSet<String>,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let report = scan(START, |path| fs::read_to_string(root.join(path)).ok());
    if report.modules.is_empty() {
        bail!("{START} not found");
    }
    println!(
        "legacy-imports: {} module(s) reached from {START}",
        report.modules.len()
    );
    for module in &report.modules {
        println!("  {module}");
    }
    println!(
        "external crates: {}",
        report
            .external_crates
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
    for finding in &report.findings {
        println!("{finding}");
    }
    verdict(&report)
}

/// Fails on any finding.
fn verdict(report: &Report) -> Result<()> {
    let count = report.findings.len();
    if count > 0 {
        bail!("{count} native name(s) in the legacy lane");
    }
    println!("legacy-imports: ok");
    Ok(())
}

/// Scans from the module file `start`, reading each file through `read` (paths relative to the
/// repository root; `None` when there is no such file).
pub(crate) fn scan(start: &str, read: impl Fn(&str) -> Option<String>) -> Report {
    let mut files: HashMap<String, Option<String>> = HashMap::new();
    let mut load = |path: &str| -> Option<String> {
        files
            .entry(path.to_owned())
            .or_insert_with(|| read(path))
            .clone()
    };
    let mut report = Report::default();
    let Some(start_module) = module_of(start) else {
        return report;
    };
    let mut queue = VecDeque::from([start_module]);
    let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
    while let Some(module) = queue.pop_front() {
        if !seen.insert(module.clone()) {
            continue;
        }
        let Some((file, text)) = module_files(&module)
            .into_iter()
            .find_map(|file| load(&file).map(|text| (file, text)))
        else {
            continue;
        };
        report.modules.push(file.clone());
        let in_lane = module.starts_with(&LANE.map(String::from));
        let code = code_only(&text);
        let parsed = parse(&code);
        let mut exists =
            |module: &[String]| module_files(module).iter().any(|file| load(file).is_some());
        let imports = imports(&parsed.uses, &module, &mut exists);
        let paths = parsed.uses.iter().map(|u| &u.path).chain(&parsed.paths);
        for path in paths {
            let target = resolve(path, &module, &imports, &mut exists);
            match &target {
                Target::Local(local) => {
                    if let Some(next) = (1..=local.len())
                        .rev()
                        .filter_map(|len| local.get(..len))
                        .find(|prefix| exists(prefix))
                        && !next.iter().any(|segment| is_native(segment))
                    {
                        queue.push_back(next.to_vec());
                    }
                }
                Target::External(name) => {
                    report.external_crates.insert(name.clone());
                }
                Target::Other => continue,
            }
            let forbidden =
                |name: &str| is_native(name) || (in_lane && NOT_IN_LANE.contains(&name));
            for segment in path.iter().filter(|segment| forbidden(&segment.name)) {
                report.findings.insert(Finding {
                    file: file.clone(),
                    line: line_of(&code, segment.offset),
                    name: segment.name.clone(),
                });
            }
        }
    }
    report
}

fn is_native(name: &str) -> bool {
    NATIVE.contains(&name)
}

/// The module path of a file under [`SRC`]: `inbox/legacy.rs` is `[inbox, legacy]`.
fn module_of(file: &str) -> Option<Vec<String>> {
    let rest = file.strip_prefix(SRC)?.strip_prefix('/')?;
    let rest = rest.strip_suffix(".rs")?;
    let rest = rest.strip_suffix("/mod").unwrap_or(rest);
    if rest == "lib" {
        return Some(Vec::new());
    }
    Some(rest.split('/').map(str::to_owned).collect())
}

/// The files a module can live in. The crate root is not scanned: it only declares and
/// re-exports, so reading it would reach every module.
fn module_files(module: &[String]) -> Vec<String> {
    if module.is_empty() {
        return Vec::new();
    }
    let joined = module.join("/");
    vec![
        format!("{SRC}/{joined}.rs"),
        format!("{SRC}/{joined}/mod.rs"),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    name: String,
    offset: usize,
}

#[derive(Debug)]
struct Use {
    path: Vec<Segment>,
    /// The name the item is bound to, when renamed with `as`.
    alias: Option<String>,
}

#[derive(Debug, Default)]
struct Parsed {
    /// Every `use` tree, expanded into one path per leaf.
    uses: Vec<Use>,
    /// Every path of two segments or more outside `use` items.
    paths: Vec<Vec<Segment>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    PathSep,
    Punct(char),
}

fn tokenize(code: &str) -> Vec<(Token, usize)> {
    let mut tokens = Vec::new();
    let mut chars = code.char_indices().peekable();
    while let Some((offset, c)) = chars.next() {
        if is_ident_char(c) {
            let mut end = offset.saturating_add(c.len_utf8());
            while let Some(&(at, next)) = chars.peek() {
                if !is_ident_char(next) {
                    break;
                }
                end = at.saturating_add(next.len_utf8());
                chars.next();
            }
            let word = code.get(offset..end).unwrap_or_default();
            if !word.starts_with(|c: char| c.is_ascii_digit()) {
                tokens.push((Token::Ident(word.to_owned()), offset));
            }
        } else if c == ':' && chars.peek().is_some_and(|&(_, next)| next == ':') {
            chars.next();
            tokens.push((Token::PathSep, offset));
        } else if !c.is_whitespace() {
            tokens.push((Token::Punct(c), offset));
        }
    }
    tokens
}

fn parse(code: &str) -> Parsed {
    let tokens = tokenize(code);
    let at = |i: usize| tokens.get(i).map(|(token, _)| token);
    let ident = |i: usize| match tokens.get(i) {
        Some((Token::Ident(name), offset)) => Some(Segment {
            name: name.clone(),
            offset: *offset,
        }),
        _ => None,
    };
    let mut parsed = Parsed::default();
    let mut i = 0;
    while i < tokens.len() {
        if let Some(end) = cfg_test_module_end(&tokens, i) {
            i = end;
            continue;
        }
        let Some(first) = ident(i) else {
            i = i.saturating_add(1);
            continue;
        };
        let after_sep = i > 0 && at(i.saturating_sub(1)) == Some(&Token::PathSep);
        let after_dot = i > 0 && at(i.saturating_sub(1)) == Some(&Token::Punct('.'));
        if first.name == "use" && !after_sep {
            i = parse_use(&tokens, i.saturating_add(1), Vec::new(), &mut parsed.uses);
            continue;
        }
        let mut path = vec![first];
        i = i.saturating_add(1);
        while at(i) == Some(&Token::PathSep) {
            let Some(next) = ident(i.saturating_add(1)) else {
                break;
            };
            path.push(next);
            i = i.saturating_add(2);
        }
        if path.len() > 1 && !after_sep && !after_dot {
            parsed.paths.push(path);
        }
    }
    parsed
}

/// The token after a `#[cfg(test)] mod name { … }` starting at `i`, when one starts there.
fn cfg_test_module_end(tokens: &[(Token, usize)], i: usize) -> Option<usize> {
    let word = |name: &str| Token::Ident(name.to_owned());
    let head = [
        Token::Punct('#'),
        Token::Punct('['),
        word("cfg"),
        Token::Punct('('),
        word("test"),
        Token::Punct(')'),
        Token::Punct(']'),
        word("mod"),
    ];
    let window = tokens.get(i..i.checked_add(head.len().saturating_add(2))?)?;
    let matches = window
        .iter()
        .zip(&head)
        .all(|((token, _), expected)| token == expected);
    let opens = matches!(window.last(), Some((Token::Punct('{'), _)));
    if !matches || !opens {
        return None;
    }
    let mut depth = 0usize;
    for (index, (token, _)) in tokens.iter().enumerate().skip(i) {
        match token {
            Token::Punct('{') => depth = depth.saturating_add(1),
            Token::Punct('}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index.saturating_add(1));
                }
            }
            _ => {}
        }
    }
    Some(tokens.len())
}

/// Expands the `use` tree starting at token `i` under `prefix`; returns the token after it.
fn parse_use(
    tokens: &[(Token, usize)],
    mut i: usize,
    prefix: Vec<Segment>,
    out: &mut Vec<Use>,
) -> usize {
    let mut path = prefix;
    loop {
        match tokens.get(i) {
            Some((Token::Ident(name), _)) if name == "as" => {
                let alias = match tokens.get(i.saturating_add(1)) {
                    Some((Token::Ident(alias), _)) => Some(alias.clone()),
                    _ => None,
                };
                out.push(Use { path, alias });
                return i.saturating_add(2);
            }
            Some((Token::Ident(name), offset)) => {
                path.push(Segment {
                    name: name.clone(),
                    offset: *offset,
                });
                i = i.saturating_add(1);
                if tokens.get(i).map(|(token, _)| token) == Some(&Token::PathSep) {
                    i = i.saturating_add(1);
                    continue;
                }
                out.push(Use { path, alias: None });
                return i;
            }
            Some((Token::Punct('*'), _)) => {
                out.push(Use { path, alias: None });
                return i.saturating_add(1);
            }
            Some((Token::Punct('{'), _)) => {
                i = i.saturating_add(1);
                loop {
                    match tokens.get(i) {
                        Some((Token::Punct('}'), _)) => return i.saturating_add(1),
                        Some((Token::Punct(','), _)) => i = i.saturating_add(1),
                        Some(_) => i = parse_use(tokens, i, path.clone(), out),
                        None => return i,
                    }
                }
            }
            _ => return i,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// A path inside lepic-wallet, from the crate root.
    Local(Vec<String>),
    External(String),
    /// A type, a primitive or a name this scan cannot place.
    Other,
}

/// The names the `use` items of `module` bind, and what each one is.
fn imports(
    uses: &[Use],
    module: &[String],
    exists: &mut impl FnMut(&[String]) -> bool,
) -> BTreeMap<String, Target> {
    let mut names = BTreeMap::new();
    let none = BTreeMap::new();
    for item in uses {
        let target = resolve(&item.path, module, &none, exists);
        let bound = item.alias.clone().or_else(|| {
            let mut segments = item.path.iter().rev();
            let last = segments.next()?;
            if last.name == "self" {
                segments.next().map(|segment| segment.name.clone())
            } else {
                Some(last.name.clone())
            }
        });
        if let Some(bound) = bound {
            names.insert(bound, target);
        }
    }
    names
}

/// Where `path`, written in `module`, points.
fn resolve(
    path: &[Segment],
    module: &[String],
    imports: &BTreeMap<String, Target>,
    exists: &mut impl FnMut(&[String]) -> bool,
) -> Target {
    let Some((first, rest)) = path.split_first() else {
        return Target::Other;
    };
    let rest: Vec<String> = rest
        .iter()
        .map(|segment| segment.name.clone())
        .filter(|name| name != "self")
        .collect();
    let local = |mut base: Vec<String>, rest: &[String]| {
        base.extend(rest.iter().cloned());
        Target::Local(base)
    };
    match first.name.as_str() {
        "crate" => local(Vec::new(), &rest),
        "self" => local(module.to_vec(), &rest),
        "super" => {
            let mut base = module.to_vec();
            base.pop();
            let supers = rest.iter().take_while(|name| *name == "super").count();
            for _ in 0..supers {
                base.pop();
            }
            local(base, rest.get(supers..).unwrap_or_default())
        }
        name => {
            if let Some(target) = imports.get(name) {
                return match target {
                    Target::Local(base) => local(base.clone(), &rest),
                    other => other.clone(),
                };
            }
            let mut child = module.to_vec();
            child.push(name.to_owned());
            if exists(&child) {
                return local(child, &rest);
            }
            let lowercase = name.starts_with(|c: char| c.is_ascii_lowercase());
            if lowercase && !NOT_CRATES.contains(&name) {
                Target::External(name.to_owned())
            } else {
                Target::Other
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn scan_of(files: &[(&str, &str)]) -> Report {
        let files: HashMap<String, String> = files
            .iter()
            .map(|(path, text)| (format!("{SRC}/{path}"), (*text).to_owned()))
            .collect();
        scan(START, |path| files.get(path).cloned())
    }

    fn found(report: &Report) -> Vec<String> {
        report.findings.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn legacy_imports_passes_a_clean_module() {
        let report = scan_of(&[
            (
                "inbox/legacy.rs",
                "use super::Hold;\nuse crate::receive::ReceiveRequest;\nuse lepic_store::TxId;\n\
                 #[expect(clippy::unwrap_used)]\n\
                 fn f() { let _ = std::mem::size_of::<u8>(); }\n",
            ),
            ("inbox.rs", "pub enum Hold {}\n"),
            ("receive.rs", "pub struct ReceiveRequest;\n"),
        ]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(
            report.modules,
            [
                "crates/lepic-wallet/src/inbox/legacy.rs",
                "crates/lepic-wallet/src/inbox.rs",
                "crates/lepic-wallet/src/receive.rs",
            ]
        );
        assert_eq!(
            report.external_crates.iter().collect::<Vec<_>>(),
            ["lepic_store", "std"]
        );
        verdict(&report).unwrap();
    }

    #[test]
    fn legacy_imports_finds_each_native_name() {
        let report = scan_of(&[(
            "inbox/legacy.rs",
            "use lepic_peer::Peer;\n\
             use lepic_epic1::Address;\n\
             use lepic_wallet_contacts::Contacts;\n\
             use crate::extension::ReplyKeys;\n\
             use crate::notice::{self, Payload};\n\
             fn f() { native_epicbox::is_native(); }\n",
        )]);
        let legacy = "crates/lepic-wallet/src/inbox/legacy.rs";
        assert_eq!(
            found(&report),
            [
                format!("{legacy}:1: lepic_peer"),
                format!("{legacy}:2: lepic_epic1"),
                format!("{legacy}:3: lepic_wallet_contacts"),
                format!("{legacy}:4: extension"),
                format!("{legacy}:5: notice"),
                format!("{legacy}:6: native_epicbox"),
            ]
        );
    }

    #[test]
    fn legacy_imports_ignores_comments_and_strings() {
        let report = scan_of(&[(
            "inbox/legacy.rs",
            "// use crate::notice::Payload;\n\
             /// Not [`crate::extension::ReplyKeys`].\n\
             /* lepic_peer::Peer */\n\
             const A: &str = \"native_epicbox::is_native\";\n\
             const B: &str = r#\"lepic_epic1::Address\"#;\n\
             fn notice(extension: u8) -> u8 { extension }\n",
        )]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn legacy_imports_follows_a_use_through_a_second_module() {
        let report = scan_of(&[
            (
                "inbox/legacy.rs",
                "use super::{Hold, ledger::begin_inbox};\n",
            ),
            (
                "inbox.rs",
                "mod ledger;\nuse crate::native_epicbox::NativeRefusal;\npub enum Hold {}\n",
            ),
            (
                "inbox/ledger.rs",
                "use crate::wallet::Wallet;\npub fn begin_inbox() {}\n",
            ),
            ("wallet.rs", "use lepic_epic1::Address;\n"),
            ("native_epicbox.rs", "use lepic_peer::Peer;\n"),
        ]);
        assert_eq!(
            found(&report),
            [
                "crates/lepic-wallet/src/inbox.rs:2: native_epicbox",
                "crates/lepic-wallet/src/wallet.rs:1: lepic_epic1",
            ]
        );
        assert!(
            !report
                .modules
                .iter()
                .any(|module| module.ends_with("native_epicbox.rs")),
            "a native module is reported, not read"
        );
    }

    #[test]
    fn legacy_imports_follows_imported_module_names_and_skips_test_modules() {
        let report = scan_of(&[
            (
                "inbox/legacy.rs",
                "use crate::twin_answer;\nfn f() { twin_answer::step(); }\n\
                 #[cfg(test)]\nmod tests { use crate::notice::Payload; }\n",
            ),
            ("twin_answer.rs", "fn step() { lepic_peer::keys(); }\n"),
        ]);
        assert_eq!(
            found(&report),
            ["crates/lepic-wallet/src/twin_answer.rs:1: lepic_peer"]
        );
    }

    #[test]
    fn legacy_imports_forbids_notices_only_in_the_lane_s_own_files() {
        let report = scan_of(&[
            (
                "inbox/legacy.rs",
                "mod reply;\nuse self::reply::answer;\nuse crate::wallet::Wallet;\n",
            ),
            ("inbox/legacy/reply.rs", "use crate::notice::Payload;\n"),
            (
                "wallet.rs",
                "use crate::extension::ContactNotices;\nuse crate::notice::Notice;\n",
            ),
            ("notice.rs", "pub struct Notice;\n"),
            ("extension.rs", "pub trait ContactNotices {}\n"),
        ]);
        assert_eq!(
            found(&report),
            ["crates/lepic-wallet/src/inbox/legacy/reply.rs:1: notice"]
        );
        assert!(
            report
                .modules
                .iter()
                .any(|module| module.ends_with("src/notice.rs")),
            "a module the core names is followed"
        );
    }

    #[test]
    fn legacy_imports_fails_on_a_finding() {
        let report = scan_of(&[("inbox/legacy.rs", "use crate::notice::Payload;\n")]);
        assert_eq!(report.findings.len(), 1);
        let error = verdict(&report).unwrap_err();
        assert_eq!(error.to_string(), "1 native name(s) in the legacy lane");
    }
}
