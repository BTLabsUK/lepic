// SPDX-License-Identifier: Apache-2.0
//! A tag or branch can be moved to different code after review; a full commit SHA cannot.
//! This keeps every external action and reusable workflow under `.github` pinned to one, and
//! keeps Dependabot pointed only at directories that exist, since it fails on the others.
//!
//! Workflows run with read-only tokens: each sets `permissions` at the top level, so a job
//! without its own block never gets the repository default; a job may hold a write scope only
//! when `ALLOWED_WRITE_SCOPES` lists it; and every checkout drops its token from the git config
//! with `persist-credentials: false`, so later steps cannot reuse it.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const GITHUB_DIR: &str = ".github";
const WORKFLOWS_DIR: &str = ".github/workflows";
const SHA_LEN: usize = 40;
const USES_KEY: &str = "uses";
const PERMISSIONS_KEY: &str = "permissions";
const PERSIST_CREDENTIALS_KEY: &str = "persist-credentials";
const CHECKOUT_ACTION: &str = "actions/checkout";
const DEPENDABOT_CONFIG: &str = ".github/dependabot.yml";

/// The write scopes a job may hold, as (workflow file name, job id, scope). Anything else that
/// writes needs a reviewed entry here.
const ALLOWED_WRITE_SCOPES: &[(&str, &str, &str)] = &[
    // Opens or updates the upstream drift issue.
    ("scheduled.yml", "drift-issue", "issues"),
    // Uploads the Scorecard SARIF and signs the published result.
    ("scorecard.yml", "analysis", "security-events"),
    ("scorecard.yml", "analysis", "id-token"),
];

#[derive(Debug, PartialEq, Eq)]
enum Problem {
    NotPinned,
    /// A key spelled with escapes may decode to `uses`, so its value cannot be trusted unchecked.
    EscapedKey,
    NoSuchDirectory,
    NoTopLevelPermissions,
    WriteScopeNotAllowed,
    /// A value GitHub may read as a grant that this check cannot classify.
    UnrecognizedPermission,
    CheckoutPersistsCredentials,
}

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    file: PathBuf,
    line: usize,
    reference: String,
    problem: Problem,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: `{}` ",
            self.file.display(),
            self.line,
            self.reference
        )?;
        match self.problem {
            Problem::NotPinned => write!(f, "is not pinned to a {SHA_LEN}-character commit sha"),
            Problem::EscapedKey => write!(f, "is a quoted key written with escapes"),
            Problem::NoSuchDirectory => write!(f, "is not a directory in the repository"),
            Problem::NoTopLevelPermissions => write!(f, "is not set at the top level"),
            Problem::WriteScopeNotAllowed => {
                write!(f, "is not in ALLOWED_WRITE_SCOPES in xtask/src/ci_lint.rs")
            }
            Problem::UnrecognizedPermission => write!(f, "is not a permission ci-lint can check"),
            Problem::CheckoutPersistsCredentials => {
                write!(f, "does not set `{PERSIST_CREDENTIALS_KEY}: false`")
            }
        }
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let findings = check(root)?;
    if findings.is_empty() {
        eprintln!("ci-lint: ok");
        return Ok(());
    }
    for finding in &findings {
        eprintln!("ci-lint: {finding}");
    }
    bail!("{} problem(s) under {GITHUB_DIR}", findings.len())
}

fn check(root: &Path) -> Result<Vec<Finding>> {
    let github = root.join(GITHUB_DIR);
    if !github.is_dir() {
        bail!("{} does not exist", github.display());
    }
    let mut files = Vec::new();
    collect_yaml(&github, &mut files)?;
    files.sort();

    let mut findings = Vec::new();
    for file in files {
        let text =
            fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
        let relative = file.strip_prefix(root).unwrap_or(&file).to_path_buf();
        for (line, content) in (1..).zip(text.lines()) {
            let mut report = |reference: &str, problem| {
                findings.push(Finding {
                    file: relative.clone(),
                    line,
                    reference: reference.to_owned(),
                    problem,
                });
            };
            for reference in uses_values(content) {
                if !is_pinned(reference) {
                    report(reference, Problem::NotPinned);
                }
            }
            for key in escaped_double_quoted_keys(content) {
                report(key, Problem::EscapedKey);
            }
        }
        if relative == Path::new(DEPENDABOT_CONFIG) {
            for (line, directory) in dependabot_directories(&text) {
                let relative_dir = directory.trim_start_matches('/');
                if !root.join(relative_dir).is_dir() {
                    findings.push(Finding {
                        file: relative.clone(),
                        line,
                        reference: directory.to_owned(),
                        problem: Problem::NoSuchDirectory,
                    });
                }
            }
        }
        let lines = code_lines(&text);
        let mut report = |line: usize, reference: &str, problem: Problem| {
            findings.push(Finding {
                file: relative.clone(),
                line,
                reference: reference.to_owned(),
                problem,
            });
        };
        check_checkouts(&lines, &mut report);
        if relative.starts_with(WORKFLOWS_DIR) {
            let workflow = relative
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            check_permissions(workflow, &lines, &mut report);
        }
    }
    Ok(findings)
}

/// A line of YAML without its comment, skipped when nothing is left.
struct Line<'a> {
    number: usize,
    indent: usize,
    code: &'a str,
}

fn code_lines(text: &str) -> Vec<Line<'_>> {
    (1..)
        .zip(text.lines())
        .filter_map(|(number, content)| {
            let code = content.split(" #").next().unwrap_or(content).trim_end();
            let trimmed = code.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            Some(Line {
                number,
                indent: code.len().saturating_sub(trimmed.len()),
                code,
            })
        })
        .collect()
}

type Report<'r> = dyn FnMut(usize, &str, Problem) + 'r;

/// Reports every `actions/checkout` step that leaves its token in the checkout's git config.
fn check_checkouts(lines: &[Line<'_>], report: &mut Report<'_>) {
    for (index, line) in lines.iter().enumerate() {
        for (column, rest) in key_values(line.code, USES_KEY) {
            let Some(reference) = first_scalar(rest) else {
                continue;
            };
            if !is_checkout(reference) {
                continue;
            }
            let drops_token = step_around(lines, index, column).iter().any(|line| {
                key_values(line.code, PERSIST_CREDENTIALS_KEY)
                    .into_iter()
                    .any(|(_, value)| first_scalar(value) == Some("false"))
            });
            if !drops_token {
                report(line.number, reference, Problem::CheckoutPersistsCredentials);
            }
        }
    }
}

fn is_checkout(reference: &str) -> bool {
    reference
        .split_once('@')
        .map_or(reference, |(action, _)| action)
        == CHECKOUT_ACTION
}

/// The lines of the sequence item (a step) holding the key that starts at `column` on line
/// `index`: from its `- ` to the next line indented no deeper than that dash.
fn step_around<'l, 'a>(lines: &'l [Line<'a>], index: usize, column: usize) -> &'l [Line<'a>] {
    let start = (0..=index)
        .rev()
        .find(|&i| {
            lines.get(i).is_some_and(|line| {
                line.code.trim_start().starts_with("- ") && line.indent < column
            })
        })
        .unwrap_or(index);
    let dash_indent = lines.get(start).map_or(0, |line| line.indent);
    let end = lines
        .iter()
        .enumerate()
        .skip(index.saturating_add(1))
        .find(|(_, line)| line.indent <= dash_indent)
        .map_or(lines.len(), |(i, _)| i);
    lines.get(start..end).unwrap_or_default()
}

/// The job whose keys the current line belongs to, read from the indentation under `jobs:`.
#[derive(Default)]
struct JobTracker<'a> {
    in_jobs: bool,
    job_indent: Option<usize>,
    job: Option<&'a str>,
}

impl<'a> JobTracker<'a> {
    fn observe(&mut self, line: &Line<'a>) {
        if line.indent == 0 {
            self.in_jobs = key_values(line.code, "jobs")
                .first()
                .is_some_and(|(column, _)| *column == 0);
            self.job_indent = None;
            self.job = None;
            return;
        }
        if !self.in_jobs {
            return;
        }
        let job_indent = *self.job_indent.get_or_insert(line.indent);
        if line.indent == job_indent {
            self.job = line
                .code
                .trim()
                .strip_suffix(':')
                .map(|id| id.trim_matches(['"', '\'']));
        }
    }
}

/// Reports a workflow without top-level permissions, any write scope that
/// `ALLOWED_WRITE_SCOPES` does not grant to its job, and any value it cannot classify.
fn check_permissions(workflow: &str, lines: &[Line<'_>], report: &mut Report<'_>) {
    let mut top_level = false;
    let mut jobs = JobTracker::default();
    for (index, line) in lines.iter().enumerate() {
        jobs.observe(line);
        for (column, rest) in key_values(line.code, PERMISSIONS_KEY) {
            if line.indent == 0 && column == 0 {
                top_level = true;
            }
            for (number, grant) in grants(lines, index, rest) {
                if !grant_allowed(workflow, jobs.job, &grant) {
                    let problem = match grant {
                        Grant::Unrecognized(_) => Problem::UnrecognizedPermission,
                        _ => Problem::WriteScopeNotAllowed,
                    };
                    report(number, &grant.to_string(), problem);
                }
            }
        }
    }
    if !top_level {
        report(1, PERMISSIONS_KEY, Problem::NoTopLevelPermissions);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Grant<'a> {
    /// `read-all`, `write-all` or `{}` for every scope.
    All(&'a str),
    Scope {
        scope: &'a str,
        level: &'a str,
    },
    Unrecognized(&'a str),
}

impl fmt::Display for Grant<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All(level) | Self::Unrecognized(level) => f.write_str(level),
            Self::Scope { scope, level } => write!(f, "{scope}: {level}"),
        }
    }
}

fn grant_allowed(workflow: &str, job: Option<&str>, grant: &Grant<'_>) -> bool {
    match *grant {
        Grant::All(level) => level == "read-all",
        Grant::Scope {
            level: "read" | "none",
            ..
        } => true,
        Grant::Scope {
            scope,
            level: "write",
        } => job.is_some_and(|job| ALLOWED_WRITE_SCOPES.contains(&(workflow, job, scope))),
        Grant::Scope { .. } | Grant::Unrecognized(_) => false,
    }
}

/// The grants of the `permissions` key on line `index`, whose value starts with `rest`: a
/// block of `scope: level` lines below it, a flow mapping, or one value for every scope.
fn grants<'a>(lines: &[Line<'a>], index: usize, rest: &'a str) -> Vec<(usize, Grant<'a>)> {
    let Some(line) = lines.get(index) else {
        return Vec::new();
    };
    if rest.is_empty() {
        return lines
            .iter()
            .skip(index.saturating_add(1))
            .take_while(|child| child.indent > line.indent)
            .map(|child| (child.number, scope_grant(child.code.trim())))
            .collect();
    }
    if let Some(flow) = rest.strip_prefix('{') {
        let Some((pairs, _)) = flow.split_once('}') else {
            return vec![(line.number, Grant::Unrecognized(rest))];
        };
        return pairs
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .map(|pair| (line.number, scope_grant(pair)))
            .collect();
    }
    match first_scalar(rest) {
        Some(level @ ("read-all" | "write-all")) => vec![(line.number, Grant::All(level))],
        _ => vec![(line.number, Grant::Unrecognized(rest))],
    }
}

fn scope_grant(pair: &str) -> Grant<'_> {
    let Some((scope, level)) = pair.split_once(':') else {
        return Grant::Unrecognized(pair);
    };
    match first_scalar(level.trim_start()) {
        Some(level @ ("read" | "write" | "none")) => Grant::Scope {
            scope: scope.trim().trim_matches(['"', '\'']),
            level,
        },
        _ => Grant::Unrecognized(pair),
    }
}

/// The values of `directory:` keys and of the items of `directories:` lists, with their lines.
fn dependabot_directories<'a>(text: &'a str) -> Vec<(usize, &'a str)> {
    let unquote = |value: &'a str| -> &'a str { value.trim().trim_matches(['"', '\'']) };
    let mut found = Vec::new();
    let mut in_list = false;
    for (line, content) in (1..).zip(text.lines()) {
        let code = content.split(" #").next().unwrap_or(content).trim();
        if code.is_empty() || code.starts_with('#') {
            continue;
        }
        if let Some(item) = code.strip_prefix("- ").filter(|_| in_list) {
            found.push((line, unquote(item)));
            continue;
        }
        in_list = code == "directories:";
        if let Some(value) = code.strip_prefix("directory:") {
            found.push((line, unquote(value)));
        }
    }
    found
}

fn collect_yaml(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_yaml(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
        {
            files.push(path);
        }
    }
    Ok(())
}

/// The values of every `uses` key on this line, in block or flow style, with the key bare or
/// quoted, and without quotes. A value that is not on the same line comes back as whatever
/// follows the colon, which is never a pinned reference, so the line is reported.
fn uses_values(line: &str) -> Vec<&str> {
    key_values(line, USES_KEY)
        .into_iter()
        .filter_map(|(_, rest)| first_scalar(rest))
        .collect()
}

/// For every `key` on this line, in block or flow style, bare or quoted: the column where the
/// key starts and everything after its colon.
fn key_values<'a>(line: &'a str, key: &str) -> Vec<(usize, &'a str)> {
    if line.trim_start().starts_with('#') {
        return Vec::new();
    }
    line.match_indices(key)
        .filter_map(|(start, _)| {
            let before = line.get(..start)?;
            let after = line.get(start.checked_add(key.len())?..)?;
            value_after_key(before, after)
        })
        .collect()
}

fn value_after_key<'a>(before: &str, after: &'a str) -> Option<(usize, &'a str)> {
    let (before, after) = match before.chars().next_back() {
        Some(quote @ ('"' | '\'')) => (before.strip_suffix(quote)?, after.strip_prefix(quote)?),
        _ => (before, after),
    };
    let starts_key = before
        .chars()
        .next_back()
        .is_none_or(|c| c.is_whitespace() || matches!(c, '-' | '{' | ','));
    if !starts_key {
        return None;
    }
    Some((
        before.len(),
        after.trim_start().strip_prefix(':')?.trim_start(),
    ))
}

/// The plain or quoted scalar a value starts with.
fn first_scalar(value: &str) -> Option<&str> {
    let end = value
        .find(|c: char| c.is_whitespace() || matches!(c, ',' | '}' | '#'))
        .unwrap_or(value.len());
    Some(value.get(..end)?.trim_matches(['"', '\'']))
}

/// Every double-quoted scalar on this line that contains an escape and is followed by a colon,
/// that is, every key whose decoded name the plain text search for `uses` cannot see.
fn escaped_double_quoted_keys(line: &str) -> Vec<&str> {
    let mut keys = Vec::new();
    let mut chars = line.char_indices();
    while let Some((start, c)) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut escaped = false;
        let mut close = None;
        while let Some((index, c)) = chars.next() {
            match c {
                '\\' => {
                    escaped = true;
                    chars.next();
                }
                '"' => {
                    close = Some(index);
                    break;
                }
                _ => {}
            }
        }
        let Some(after_close) = close.and_then(|index| index.checked_add(1)) else {
            break;
        };
        let is_key = line
            .get(after_close..)
            .is_some_and(|rest| rest.trim_start().starts_with(':'));
        if escaped
            && is_key
            && let Some(key) = line.get(start..after_close)
        {
            keys.push(key);
        }
    }
    keys
}

fn is_pinned(reference: &str) -> bool {
    if reference.starts_with("./") {
        return true;
    }
    reference.rsplit_once('@').is_some_and(|(_, revision)| {
        revision.len() == SHA_LEN && revision.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

    fn fixture(files: &[(&str, &str)]) -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (relative, contents) in files {
            let path = dir.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        dir
    }

    fn workflow(steps: &str) -> String {
        format!(
            "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"
        )
    }

    /// The pin findings only, for the tests about pinning.
    fn references(dir: &TempDir) -> Vec<String> {
        check(dir.path())
            .unwrap()
            .into_iter()
            .filter(|finding| finding.problem == Problem::NotPinned)
            .map(|entry| entry.reference)
            .collect()
    }

    /// Every finding in `.github/workflows/<name>` as (line, reference, problem).
    fn workflow_findings(name: &str, text: &str) -> Vec<(usize, String, Problem)> {
        let path = format!(".github/workflows/{name}");
        let dir = fixture(&[(path.as_str(), text)]);
        check(dir.path())
            .unwrap()
            .into_iter()
            .map(|finding| (finding.line, finding.reference, finding.problem))
            .collect()
    }

    #[test]
    fn rejects_a_workflow_without_top_level_permissions() {
        let text = "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n";
        assert_eq!(
            workflow_findings("ci.yml", text),
            [(1, "permissions".to_owned(), Problem::NoTopLevelPermissions)]
        );
        let quoted = "on: push\n\"permissions\": read-all\njobs: {}\n";
        assert_eq!(workflow_findings("ci.yml", quoted), []);
        let nested_only =
            "on: push\njobs:\n  a:\n    steps:\n      - run: echo\n        permissions: {}\n";
        assert_eq!(
            workflow_findings("ci.yml", nested_only),
            [(1, "permissions".to_owned(), Problem::NoTopLevelPermissions)]
        );
    }

    #[test]
    fn accepts_read_scopes_and_allowlisted_write_scopes() {
        let scheduled = "on: push\npermissions:\n  contents: read\njobs:\n  drift-issue:\n    permissions:\n      issues: write # the drift issue\n      contents: none\n";
        assert_eq!(workflow_findings("scheduled.yml", scheduled), []);
        let scorecard = "on: push\npermissions: read-all\njobs:\n  analysis:\n    permissions: {contents: read, security-events: write, 'id-token': write}\n";
        assert_eq!(workflow_findings("scorecard.yml", scorecard), []);
        let empty = "on: push\npermissions: {}\njobs:\n  a:\n    permissions: {}\n";
        assert_eq!(workflow_findings("ci.yml", empty), []);
    }

    #[test]
    fn rejects_write_scopes_outside_the_allowlist() {
        let text = "on: push\npermissions:\n  contents: write\njobs:\n  drift-issue:\n    permissions:\n      issues: write\n      pull-requests: write\n  other:\n    permissions: {issues: write}\n  all:\n    permissions: write-all\n";
        let not_allowed =
            |line, reference: &str| (line, reference.to_owned(), Problem::WriteScopeNotAllowed);
        assert_eq!(
            workflow_findings("scheduled.yml", text),
            [
                not_allowed(3, "contents: write"),
                not_allowed(8, "pull-requests: write"),
                not_allowed(10, "issues: write"),
                not_allowed(12, "write-all"),
            ]
        );
        let elsewhere = "on: push\npermissions: write-all\njobs:\n  drift-issue:\n    permissions:\n      issues: write\n";
        assert_eq!(
            workflow_findings("ci.yml", elsewhere),
            [not_allowed(2, "write-all"), not_allowed(6, "issues: write")]
        );
    }

    #[test]
    fn rejects_permission_values_it_cannot_classify() {
        let text = "on: push\npermissions: ${{ vars.P }}\njobs:\n  a:\n    permissions:\n      contents: ${{ vars.L }}\n      issues\n";
        assert_eq!(
            workflow_findings("ci.yml", text)
                .into_iter()
                .map(|(line, _, problem)| (line, problem))
                .collect::<Vec<_>>(),
            [
                (2, Problem::UnrecognizedPermission),
                (6, Problem::UnrecognizedPermission),
                (7, Problem::UnrecognizedPermission),
            ]
        );
    }

    #[test]
    fn rejects_checkouts_that_keep_their_credentials() {
        let steps = format!(
            "      - uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: 0\n      - run: echo persist-credentials: false\n      - name: second\n        uses: actions/checkout@{SHA}\n        with:\n          persist-credentials: true\n      - uses: actions/checkout@{SHA}\n        with:\n          persist-credentials: false\n      - {{uses: actions/checkout@{SHA}, with: {{persist-credentials: false}}}}\n      - name: last\n        uses: \"actions/checkout@{SHA}\"\n        with: {{persist-credentials: 'false'}}\n      - uses: actions/cache@{SHA}\n"
        );
        let checkout = format!("actions/checkout@{SHA}");
        assert_eq!(
            workflow_findings("ci.yml", &workflow(&steps)),
            [
                (8, checkout.clone(), Problem::CheckoutPersistsCredentials),
                (13, checkout, Problem::CheckoutPersistsCredentials),
            ]
        );
    }

    #[test]
    fn rejects_checkouts_in_actions_that_keep_their_credentials() {
        let dir = fixture(&[(
            ".github/actions/setup/action.yml",
            &format!("runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@{SHA}\n"),
        )]);
        assert_eq!(
            check(dir.path())
                .unwrap()
                .into_iter()
                .map(|finding| (finding.line, finding.problem))
                .collect::<Vec<_>>(),
            [(4, Problem::CheckoutPersistsCredentials)]
        );
    }

    #[test]
    fn accepts_actions_pinned_to_a_full_sha() {
        let steps = format!(
            "      - uses: actions/checkout@{SHA} # v7.0.1\n      - name: q\n        uses: \"github/codeql-action/upload-sarif@{SHA}\"\n"
        );
        let dir = fixture(&[(".github/workflows/ci.yml", &workflow(&steps))]);
        assert_eq!(references(&dir), Vec::<String>::new());
    }

    #[test]
    fn accepts_local_actions() {
        let dir = fixture(&[(
            ".github/workflows/ci.yml",
            &workflow("      - uses: ./.github/actions/setup\n"),
        )]);
        assert_eq!(references(&dir), Vec::<String>::new());
    }

    #[test]
    fn rejects_tags_branches_short_shas_and_images() {
        let steps = format!(
            "      - uses: actions/checkout@v7\n      - uses: 'ossf/scorecard-action@main'\n      - uses: actions/cache@{}\n      - uses: actions/cache@{}\n      - uses: docker://alpine:3\n      - uses: actions/checkout\n",
            &SHA[..7],
            SHA.to_uppercase(),
        );
        let dir = fixture(&[(".github/workflows/ci.yml", &workflow(&steps))]);
        assert_eq!(
            references(&dir),
            [
                "actions/checkout@v7".to_owned(),
                "ossf/scorecard-action@main".to_owned(),
                format!("actions/cache@{}", &SHA[..7]),
                format!("actions/cache@{}", SHA.to_uppercase()),
                "docker://alpine:3".to_owned(),
                "actions/checkout".to_owned(),
            ]
        );
    }

    #[test]
    fn rejects_unpinned_references_in_flow_mappings_and_quoted_keys() {
        let steps = "      - {uses: actions/checkout@v7}\n      - \"uses\": actions/cache@v3\n      - 'uses': actions/cache@v2\n      - {name: x, uses: \"org/a@main\", with: {k: v}}\n      - uses: >-\n          actions/checkout@v7\n";
        let dir = fixture(&[(".github/workflows/ci.yml", &workflow(steps))]);
        assert_eq!(
            references(&dir),
            [
                "actions/checkout@v7",
                "actions/cache@v3",
                "actions/cache@v2",
                "org/a@main",
                ">-",
            ]
        );
    }

    #[test]
    fn accepts_pinned_flow_mappings_and_ignores_other_keys_and_comments() {
        let steps = format!(
            "      - {{uses: actions/checkout@{SHA}, with: {{fetch-depth: 0}}}}\n      - \"uses\": 'actions/cache@{SHA}'\n      # uses: actions/checkout@v7\n      - causes: actions/checkout@v7\n"
        );
        let dir = fixture(&[(".github/workflows/ci.yml", &workflow(&steps))]);
        assert_eq!(references(&dir), Vec::<String>::new());
    }

    #[test]
    fn rejects_double_quoted_keys_written_with_escapes() {
        let steps = format!(
            "      - \"\\x75ses\": actions/checkout@v7\n      - {{\"u\\u0073es\": actions/checkout@{SHA}}}\n      - run: \"echo \\\"a\\\": b\"\n"
        );
        let dir = fixture(&[(".github/workflows/ci.yml", &workflow(&steps))]);
        assert_eq!(
            check(dir.path())
                .unwrap()
                .into_iter()
                .map(|finding| (finding.problem, finding.reference))
                .collect::<Vec<_>>(),
            [
                (Problem::EscapedKey, "\"\\x75ses\"".to_owned()),
                (Problem::EscapedKey, "\"u\\u0073es\"".to_owned()),
            ]
        );
    }

    #[test]
    fn rejects_unpinned_reusable_workflow_at_job_level() {
        let dir = fixture(&[(
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@v1\n",
        )]);
        assert_eq!(
            references(&dir),
            ["org/repo/.github/workflows/x.yml@v1".to_owned()]
        );
    }

    #[test]
    fn reports_file_and_line_in_nested_yaml_files() {
        let dir = fixture(&[
            (
                ".github/actions/setup/action.yaml",
                "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n",
            ),
            (".github/workflows/ci.yml", &workflow("")),
        ]);
        assert_eq!(
            check(dir.path()).unwrap(),
            [Finding {
                file: PathBuf::from(".github/actions/setup/action.yaml"),
                line: 4,
                reference: "actions/cache@v4".to_owned(),
                problem: Problem::NotPinned,
            }]
        );
    }

    #[test]
    fn rejects_dependabot_directories_that_do_not_exist() {
        let config = "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directories:\n      - \"/\"\n      - \"/conformance\"\n      - '/fuzz' # until it exists\n    schedule:\n      interval: weekly\n  - package-ecosystem: github-actions\n    directory: \"/missing\"\n";
        let dir = fixture(&[
            (".github/dependabot.yml", config),
            ("conformance/Cargo.toml", ""),
        ]);
        assert_eq!(
            check(dir.path())
                .unwrap()
                .into_iter()
                .map(|finding| (finding.line, finding.reference, finding.problem))
                .collect::<Vec<_>>(),
            [
                (7, "/fuzz".to_owned(), Problem::NoSuchDirectory),
                (11, "/missing".to_owned(), Problem::NoSuchDirectory),
            ]
        );
    }

    #[test]
    fn fails_without_a_github_directory() {
        let dir = fixture(&[]);
        assert!(check(dir.path()).is_err());
    }

    #[test]
    fn repository_workflows_pass_every_rule() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert_eq!(check(root).unwrap(), []);
    }
}
