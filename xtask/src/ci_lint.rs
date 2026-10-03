//! A tag or branch can be moved to different code after review; a full commit SHA cannot.
//! This keeps every external action and reusable workflow under `.github` pinned to one, and
//! keeps Dependabot pointed only at directories that exist, since it fails on the others.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const GITHUB_DIR: &str = ".github";
const SHA_LEN: usize = 40;
const USES_KEY: &str = "uses";
const DEPENDABOT_CONFIG: &str = ".github/dependabot.yml";

#[derive(Debug, PartialEq, Eq)]
enum Problem {
    NotPinned,
    /// A key spelled with escapes may decode to `uses`, so its value cannot be trusted unchecked.
    EscapedKey,
    NoSuchDirectory,
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
    }
    Ok(findings)
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
    if line.trim_start().starts_with('#') {
        return Vec::new();
    }
    line.match_indices(USES_KEY)
        .filter_map(|(start, _)| {
            let before = line.get(..start)?;
            let after = line.get(start.checked_add(USES_KEY.len())?..)?;
            value_after_key(before, after)
        })
        .collect()
}

fn value_after_key<'a>(before: &str, after: &'a str) -> Option<&'a str> {
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
    let value = after.trim_start().strip_prefix(':')?.trim_start();
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
        format!("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n{steps}")
    }

    fn references(dir: &TempDir) -> Vec<String> {
        check(dir.path())
            .unwrap()
            .into_iter()
            .map(|entry| entry.reference)
            .collect()
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
    fn repository_workflows_are_pinned() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        assert_eq!(check(root).unwrap(), []);
    }
}
