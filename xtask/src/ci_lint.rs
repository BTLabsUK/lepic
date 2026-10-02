//! A tag or branch can be moved to different code after review; a full commit SHA cannot.
//! This keeps every external action and reusable workflow under `.github` pinned to one.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const GITHUB_DIR: &str = ".github";
const SHA_LEN: usize = 40;
const USES_KEY: &str = "uses";

#[derive(Debug, PartialEq, Eq)]
struct Unpinned {
    file: PathBuf,
    line: usize,
    reference: String,
}

impl fmt::Display for Unpinned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: `{}` is not pinned to a {SHA_LEN}-character commit sha",
            self.file.display(),
            self.line,
            self.reference
        )
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let unpinned = check(root)?;
    if unpinned.is_empty() {
        eprintln!("ci-lint: ok");
        return Ok(());
    }
    for entry in &unpinned {
        eprintln!("ci-lint: {entry}");
    }
    bail!("{} unpinned `uses:` reference(s)", unpinned.len())
}

fn check(root: &Path) -> Result<Vec<Unpinned>> {
    let github = root.join(GITHUB_DIR);
    if !github.is_dir() {
        bail!("{} does not exist", github.display());
    }
    let mut files = Vec::new();
    collect_yaml(&github, &mut files)?;
    files.sort();

    let mut unpinned = Vec::new();
    for file in files {
        let text =
            fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
        let relative = file.strip_prefix(root).unwrap_or(&file).to_path_buf();
        for (line, content) in (1..).zip(text.lines()) {
            for reference in uses_values(content) {
                if !is_pinned(reference) {
                    unpinned.push(Unpinned {
                        file: relative.clone(),
                        line,
                        reference: reference.to_owned(),
                    });
                }
            }
        }
    }
    Ok(unpinned)
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
            [Unpinned {
                file: PathBuf::from(".github/actions/setup/action.yaml"),
                line: 4,
                reference: "actions/cache@v4".to_owned(),
            }]
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
