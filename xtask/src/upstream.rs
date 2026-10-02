use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, bail};

const MANIFEST: &str = "upstream.toml";
const CACHE_DIR: &str = "target/upstream-cache";
const UPSTREAM_HEAD: &str = "refs/upstream/head";

/// Exit status when drift was found, distinct from the status 1 that every
/// xtask failure uses, so a scheduled job can tell drift from an outage.
pub(crate) const DRIFT_EXIT_CODE: u8 = 2;

pub(crate) fn run(root: &Path) -> Result<()> {
    let manifest_path = root.join(MANIFEST);
    let text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("could not read {}", manifest_path.display()))?;
    let manifest = Manifest::parse(&text).with_context(|| format!("bad {MANIFEST}"))?;
    let reports = check_drift(&manifest, &root.join(CACHE_DIR), &Git::user())?;
    for report in &reports {
        print!("{report}");
    }
    let drift = DriftFound::count(&reports);
    if drift.drifted == 0 {
        println!("upstream-drift: no upstream changes since the recorded commits");
        return Ok(());
    }
    Err(drift.into())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DriftFound {
    drifted: usize,
    total: usize,
}

impl DriftFound {
    fn count(reports: &[RepoReport<'_>]) -> Self {
        let modules = || reports.iter().flat_map(|report| &report.modules);
        Self {
            drifted: modules()
                .filter(|module| !module.commits.is_empty())
                .count(),
            total: modules().count(),
        }
    }
}

impl fmt::Display for DriftFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of {} module(s) have upstream changes to review",
            self.drifted, self.total
        )
    }
}

impl std::error::Error for DriftFound {}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Manifest {
    modules: Vec<Module>,
}

#[derive(Debug, PartialEq, Eq)]
struct Module {
    path: String,
    task: String,
    upstream: Upstream,
}

#[derive(Debug, PartialEq, Eq)]
struct Upstream {
    repo: String,
    paths: Vec<String>,
    commit: CommitId,
}

/// A full 40-digit lowercase hex commit id, so it can never be read as a git
/// option or an abbreviated, ambiguous revision.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitId(String);

impl CommitId {
    fn parse(text: &str) -> Option<Self> {
        let valid = text.len() == 40
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        valid.then(|| Self(text.to_owned()))
    }

    fn short(&self) -> &str {
        self.0.get(..10).unwrap_or(&self.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestError {
    line: usize,
    kind: ManifestErrorKind,
}

#[derive(Debug, PartialEq, Eq)]
enum ManifestErrorKind {
    UnsupportedTable(String),
    ExpectedKeyValue,
    KeyOutsideModule,
    UnknownKey(String),
    DuplicateKey(String),
    ExpectedString(String),
    ExpectedArray(String),
    InvalidValue,
    UnterminatedString,
    UnterminatedArray,
    MissingKey(&'static str),
    EmptyPaths,
    InvalidPath(String),
    InvalidCommit(String),
    DuplicateModule(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: ", self.line)?;
        match &self.kind {
            ManifestErrorKind::UnsupportedTable(header) => {
                write!(f, "table `{header}` is not supported, only `[[module]]`")
            }
            ManifestErrorKind::ExpectedKeyValue => f.write_str("expected `key = value`"),
            ManifestErrorKind::KeyOutsideModule => f.write_str("key outside a `[[module]]` table"),
            ManifestErrorKind::UnknownKey(key) => write!(f, "unknown key `{key}`"),
            ManifestErrorKind::DuplicateKey(key) => write!(f, "key `{key}` is set twice"),
            ManifestErrorKind::ExpectedString(key) => write!(f, "`{key}` must be a string"),
            ManifestErrorKind::ExpectedArray(key) => {
                write!(f, "`{key}` must be an array of strings")
            }
            ManifestErrorKind::InvalidValue => {
                f.write_str("value is not a string or an array of strings")
            }
            ManifestErrorKind::UnterminatedString => f.write_str("string is not terminated"),
            ManifestErrorKind::UnterminatedArray => f.write_str("array is not terminated"),
            ManifestErrorKind::MissingKey(key) => write!(f, "module is missing `{key}`"),
            ManifestErrorKind::EmptyPaths => f.write_str("`upstream.paths` is empty"),
            ManifestErrorKind::InvalidPath(path) => {
                write!(
                    f,
                    "path `{path}` is not a relative path inside the repository"
                )
            }
            ManifestErrorKind::InvalidCommit(commit) => {
                write!(
                    f,
                    "`{commit}` is not a full 40-digit lowercase hex commit id"
                )
            }
            ManifestErrorKind::DuplicateModule(path) => {
                write!(f, "module `{path}` is listed twice")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

#[derive(Debug, PartialEq, Eq)]
enum Value {
    String(String),
    Array(Vec<String>),
}

#[derive(Debug, PartialEq, Eq)]
enum ValueError {
    Invalid,
    UnterminatedString,
    UnterminatedArray,
}

impl Manifest {
    /// Parses the subset of TOML that `upstream.toml` uses: comments,
    /// `[[module]]` headers, and keys holding a basic string or an array of
    /// basic strings. Anything else is rejected rather than guessed at.
    pub(crate) fn parse(text: &str) -> Result<Self, ManifestError> {
        let mut builders: Vec<ModuleBuilder> = Vec::new();
        let mut lines = text
            .lines()
            .enumerate()
            .map(|(index, line)| (index.saturating_add(1), line));

        while let Some((line_number, raw)) = lines.next() {
            let error = |kind| ManifestError {
                line: line_number,
                kind,
            };
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && !line.contains('=') {
                if line != "[[module]]" {
                    return Err(error(ManifestErrorKind::UnsupportedTable(line.to_owned())));
                }
                builders.push(ModuleBuilder::new(line_number));
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| error(ManifestErrorKind::ExpectedKeyValue))?;
            let key = key.trim();
            let mut value_text = value.trim().to_owned();
            let value = loop {
                match parse_value(&value_text) {
                    Ok(value) => break value,
                    Err(ValueError::UnterminatedArray) => {
                        let Some((_, next)) = lines.next() else {
                            return Err(error(ManifestErrorKind::UnterminatedArray));
                        };
                        let next = next.trim();
                        if !next.starts_with('#') {
                            value_text.push(' ');
                            value_text.push_str(next);
                        }
                    }
                    Err(ValueError::UnterminatedString) => {
                        return Err(error(ManifestErrorKind::UnterminatedString));
                    }
                    Err(ValueError::Invalid) => return Err(error(ManifestErrorKind::InvalidValue)),
                }
            };
            let builder = builders
                .last_mut()
                .ok_or_else(|| error(ManifestErrorKind::KeyOutsideModule))?;
            builder.set(key, value).map_err(error)?;
        }

        let mut seen = BTreeSet::new();
        let mut modules = Vec::with_capacity(builders.len());
        for builder in builders {
            let line = builder.line;
            let module = builder.build()?;
            if !seen.insert(module.path.clone()) {
                return Err(ManifestError {
                    line,
                    kind: ManifestErrorKind::DuplicateModule(module.path),
                });
            }
            modules.push(module);
        }
        Ok(Self { modules })
    }
}

struct ModuleBuilder {
    line: usize,
    path: Option<String>,
    task: Option<String>,
    repo: Option<String>,
    paths: Option<Vec<String>>,
    commit: Option<String>,
}

impl ModuleBuilder {
    fn new(line: usize) -> Self {
        Self {
            line,
            path: None,
            task: None,
            repo: None,
            paths: None,
            commit: None,
        }
    }

    fn set(&mut self, key: &str, value: Value) -> Result<(), ManifestErrorKind> {
        match key {
            "path" => set_once(&mut self.path, key, expect_string(key, value)?),
            "task" => set_once(&mut self.task, key, expect_string(key, value)?),
            "upstream.repo" => set_once(&mut self.repo, key, expect_string(key, value)?),
            "upstream.commit" => set_once(&mut self.commit, key, expect_string(key, value)?),
            "upstream.paths" => match value {
                Value::Array(paths) => set_once(&mut self.paths, key, paths),
                Value::String(_) => Err(ManifestErrorKind::ExpectedArray(key.to_owned())),
            },
            other => Err(ManifestErrorKind::UnknownKey(other.to_owned())),
        }
    }

    fn build(self) -> Result<Module, ManifestError> {
        let error = |kind| ManifestError {
            line: self.line,
            kind,
        };
        let path = self
            .path
            .ok_or_else(|| error(ManifestErrorKind::MissingKey("path")))?;
        let task = self
            .task
            .ok_or_else(|| error(ManifestErrorKind::MissingKey("task")))?;
        let repo = self
            .repo
            .ok_or_else(|| error(ManifestErrorKind::MissingKey("upstream.repo")))?;
        let paths = self
            .paths
            .ok_or_else(|| error(ManifestErrorKind::MissingKey("upstream.paths")))?;
        let commit = self
            .commit
            .ok_or_else(|| error(ManifestErrorKind::MissingKey("upstream.commit")))?;

        if paths.is_empty() {
            return Err(error(ManifestErrorKind::EmptyPaths));
        }
        if let Some(bad) = std::iter::once(&path)
            .chain(&paths)
            .find(|candidate| !is_repository_path(candidate))
        {
            return Err(error(ManifestErrorKind::InvalidPath(bad.clone())));
        }
        let commit = CommitId::parse(&commit)
            .ok_or_else(|| error(ManifestErrorKind::InvalidCommit(commit)))?;
        Ok(Module {
            path,
            task,
            upstream: Upstream {
                repo,
                paths,
                commit,
            },
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, key: &str, value: T) -> Result<(), ManifestErrorKind> {
    if slot.is_some() {
        return Err(ManifestErrorKind::DuplicateKey(key.to_owned()));
    }
    *slot = Some(value);
    Ok(())
}

fn expect_string(key: &str, value: Value) -> Result<String, ManifestErrorKind> {
    match value {
        Value::String(text) => Ok(text),
        Value::Array(_) => Err(ManifestErrorKind::ExpectedString(key.to_owned())),
    }
}

/// Relative, forward-slash, no `.` or `..` segments: the form git prints, and
/// one that cannot be read as an option.
fn is_repository_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('-')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && !path.contains('\\')
}

fn parse_value(text: &str) -> Result<Value, ValueError> {
    let mut chars = text.chars().peekable();
    let value = match chars.next() {
        Some('"') => Value::String(parse_string(&mut chars)?),
        Some('[') => Value::Array(parse_array(&mut chars)?),
        _ => return Err(ValueError::Invalid),
    };
    let rest: String = chars.collect();
    let rest = rest.trim_start();
    if rest.is_empty() || rest.starts_with('#') {
        Ok(value)
    } else {
        Err(ValueError::Invalid)
    }
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Reads a basic string after its opening quote. Only `\"` and `\\` escapes
/// are accepted, which is all repository URLs and paths need.
fn parse_string(chars: &mut Chars<'_>) -> Result<String, ValueError> {
    let mut text = String::new();
    loop {
        match chars.next() {
            None => return Err(ValueError::UnterminatedString),
            Some('"') => return Ok(text),
            Some('\\') => match chars.next() {
                Some(escaped @ ('"' | '\\')) => text.push(escaped),
                None => return Err(ValueError::UnterminatedString),
                Some(_) => return Err(ValueError::Invalid),
            },
            Some(control) if control.is_control() => return Err(ValueError::Invalid),
            Some(other) => text.push(other),
        }
    }
}

/// Reads an array of basic strings after its opening bracket. A trailing comma
/// is allowed, as in TOML.
fn parse_array(chars: &mut Chars<'_>) -> Result<Vec<String>, ValueError> {
    let mut items = Vec::new();
    loop {
        skip_whitespace(chars);
        match chars.next() {
            None => return Err(ValueError::UnterminatedArray),
            Some(']') => return Ok(items),
            Some('"') => items.push(parse_string(chars)?),
            Some(_) => return Err(ValueError::Invalid),
        }
        skip_whitespace(chars);
        match chars.next() {
            None => return Err(ValueError::UnterminatedArray),
            Some(',') => {}
            Some(']') => return Ok(items),
            Some(_) => return Err(ValueError::Invalid),
        }
    }
}

fn skip_whitespace(chars: &mut Chars<'_>) {
    while chars.next_if(|c| c.is_whitespace()).is_some() {}
}

#[derive(Debug)]
struct RepoReport<'a> {
    repo: &'a str,
    head: CommitId,
    modules: Vec<ModuleDrift<'a>>,
}

#[derive(Debug)]
struct ModuleDrift<'a> {
    module: &'a Module,
    commits: Vec<UpstreamCommit>,
}

#[derive(Debug, PartialEq, Eq)]
struct UpstreamCommit {
    id: String,
    subject: String,
}

impl fmt::Display for RepoReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "upstream-drift: {} (default branch at {})",
            self.repo,
            self.head.short()
        )?;
        for drift in &self.modules {
            let module = drift.module;
            let since = module.upstream.commit.short();
            if drift.commits.is_empty() {
                writeln!(
                    f,
                    "  ok     {} ({}) since {since}",
                    module.path, module.task
                )?;
                continue;
            }
            writeln!(
                f,
                "  drift  {} ({}): {} commit(s) since {since} touch {}",
                module.path,
                module.task,
                drift.commits.len(),
                module.upstream.paths.join(", ")
            )?;
            for commit in &drift.commits {
                writeln!(f, "         {} {}", commit.id, commit.subject)?;
            }
        }
        Ok(())
    }
}

/// Fetches each upstream repository once into `cache_root` and lists, per
/// module, the commits on the upstream default branch that touched the
/// recorded paths after the recorded commit.
fn check_drift<'a>(
    manifest: &'a Manifest,
    cache_root: &Path,
    git: &Git,
) -> Result<Vec<RepoReport<'a>>> {
    let mut by_repo: BTreeMap<&str, Vec<&Module>> = BTreeMap::new();
    for module in &manifest.modules {
        by_repo
            .entry(module.upstream.repo.as_str())
            .or_default()
            .push(module);
    }

    let mut reports = Vec::with_capacity(by_repo.len());
    for (repo, modules) in by_repo {
        let cache = UpstreamCache::sync(cache_root, repo, git)?;
        let mut drifts = Vec::with_capacity(modules.len());
        for module in modules {
            let commits = cache
                .commits_touching(module)
                .with_context(|| format!("could not check module `{}`", module.path))?;
            drifts.push(ModuleDrift { module, commits });
        }
        reports.push(RepoReport {
            repo,
            head: cache.head,
            modules: drifts,
        });
    }
    Ok(reports)
}

/// A bare, blobless clone: commits and trees are enough for path history, and
/// skipping file contents keeps the cache small.
struct UpstreamCache<'g> {
    git: &'g Git,
    dir: PathBuf,
    head: CommitId,
}

impl<'g> UpstreamCache<'g> {
    fn sync(cache_root: &Path, repo: &str, git: &'g Git) -> Result<Self> {
        let dir = cache_root.join(cache_dir_name(repo)?);
        if dir.join("HEAD").is_file() {
            let origin = git.output(&dir, ["config", "--get", "remote.origin.url"])?;
            if origin.trim() != repo {
                bail!(
                    "cache {} belongs to {}, not {repo}; delete it",
                    dir.display(),
                    origin.trim()
                );
            }
        } else {
            fs::create_dir_all(cache_root)
                .with_context(|| format!("could not create {}", cache_root.display()))?;
            git.output(
                cache_root,
                [
                    OsStr::new("clone"),
                    OsStr::new("--bare"),
                    OsStr::new("--quiet"),
                    OsStr::new("--filter=blob:none"),
                    OsStr::new("--"),
                    OsStr::new(repo),
                    dir.as_os_str(),
                ],
            )?;
        }
        let head_refspec = format!("+HEAD:{UPSTREAM_HEAD}");
        git.output(&dir, ["fetch", "--quiet", "origin", head_refspec.as_str()])
            .with_context(|| format!("could not fetch {repo}"))?;
        let head_spec = format!("{UPSTREAM_HEAD}^{{commit}}");
        let head = git.output(
            &dir,
            ["rev-parse", "--verify", "--quiet", head_spec.as_str()],
        )?;
        let head = CommitId::parse(head.trim())
            .with_context(|| format!("unexpected upstream head `{}`", head.trim()))?;
        Ok(Self { git, dir, head })
    }

    fn commits_touching(&self, module: &Module) -> Result<Vec<UpstreamCommit>> {
        let commit = &module.upstream.commit;
        self.ensure_on_default_branch(commit)?;
        for path in &module.upstream.paths {
            let listing = self
                .git
                .output(&self.dir, ["ls-tree", "--name-only", &commit.0, "--", path])?;
            if listing.trim().is_empty() {
                return Err(MissingUpstreamPath {
                    path: path.clone(),
                    commit: commit.clone(),
                }
                .into());
            }
        }
        let range = format!("{}..{UPSTREAM_HEAD}", commit.0);
        let mut args = vec!["log", "--format=%H%x09%s", range.as_str(), "--"];
        args.extend(module.upstream.paths.iter().map(String::as_str));
        let log = self.git.output(&self.dir, args)?;
        Ok(log
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (id, subject) = line.split_once('\t').unwrap_or((line, ""));
                UpstreamCommit {
                    id: id.to_owned(),
                    subject: subject.to_owned(),
                }
            })
            .collect())
    }

    /// `<commit>..head` means "changes since the port" only when the recorded
    /// commit is in the default branch's history. For any other commit it
    /// would also list older branch commits, so it is refused.
    fn ensure_on_default_branch(&self, commit: &CommitId) -> Result<()> {
        let object = format!("{}^{{commit}}", commit.0);
        let present = self
            .git
            .status(&self.dir, ["cat-file", "-e", object.as_str()])?
            .success();
        let on_branch = present && {
            let status = self.git.status(
                &self.dir,
                [
                    "merge-base",
                    "--is-ancestor",
                    commit.0.as_str(),
                    UPSTREAM_HEAD,
                ],
            )?;
            match status.code() {
                Some(0) => true,
                Some(1) => false,
                _ => bail!("`git merge-base --is-ancestor {}` failed", commit.0),
            }
        };
        if on_branch {
            Ok(())
        } else {
            Err(RecordedCommitOffBranch {
                commit: commit.clone(),
            }
            .into())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RecordedCommitOffBranch {
    commit: CommitId,
}

impl fmt::Display for RecordedCommitOffBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "recorded commit {} is not on the upstream default branch",
            self.commit.0
        )
    }
}

impl std::error::Error for RecordedCommitOffBranch {}

#[derive(Debug, PartialEq, Eq)]
struct MissingUpstreamPath {
    path: String,
    commit: CommitId,
}

impl fmt::Display for MissingUpstreamPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` does not exist upstream at {}",
            self.path, self.commit.0
        )
    }
}

impl std::error::Error for MissingUpstreamPath {}

/// `https://github.com/EpicCash/epic` becomes `github.com-EpicCash-epic`.
fn cache_dir_name(repo: &str) -> Result<String> {
    let without_scheme = repo.split_once("://").map_or(repo, |(_, rest)| rest);
    let name: String = without_scheme
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches(|c| c == '-' || c == '.');
    if name.is_empty() {
        bail!("repository `{repo}` gives an empty cache directory name");
    }
    Ok(name.to_owned())
}

/// How git is run. Production uses the developer's git configuration; tests
/// point it at an empty file so local settings cannot change the result.
struct Git {
    global_config: Option<PathBuf>,
}

impl Git {
    fn user() -> Self {
        Self {
            global_config: None,
        }
    }

    fn command(&self, dir: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(dir)
            // Never wait on a credential prompt; a public upstream needs none.
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null());
        if let Some(config) = &self.global_config {
            command
                .env("GIT_CONFIG_GLOBAL", config)
                .env("GIT_CONFIG_NOSYSTEM", "1");
        }
        command
    }

    fn output<I, S>(&self, dir: &Path, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args: Vec<S> = args.into_iter().collect();
        let shown = args
            .iter()
            .map(|arg| arg.as_ref().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let output = self
            .command(dir)
            .args(&args)
            .output()
            .context("could not start `git`")?;
        if !output.status.success() {
            bail!(
                "`git {shown}` failed in {}: {}",
                dir.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        String::from_utf8(output.stdout).with_context(|| format!("`git {shown}` printed non-UTF-8"))
    }

    fn status<I, S>(&self, dir: &Path, args: I) -> Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command(dir)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("could not start `git`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const COMMIT_A: &str = "9d022b1d521d3f705532e12ab77e0a429f6fde1f";

    fn module_text(path: &str, commit: &str) -> String {
        format!(
            "[[module]]\npath = \"{path}\"\ntask = \"P-01\"\nupstream.repo = \"https://example.org/up\"\nupstream.paths = [\"core/src/ser.rs\"]\nupstream.commit = \"{commit}\"\n"
        )
    }

    fn parse_error(text: &str) -> ManifestErrorKind {
        Manifest::parse(text).unwrap_err().kind
    }

    #[test]
    fn repository_manifest_parses_with_adr_0009_commits() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let text = fs::read_to_string(root.join(MANIFEST)).unwrap();
        let manifest = Manifest::parse(&text).unwrap();
        assert!(!manifest.modules.is_empty());
        for module in &manifest.modules {
            let expected = match module.upstream.repo.as_str() {
                "https://github.com/EpicCash/epic" => "9d022b1d521d3f705532e12ab77e0a429f6fde1f",
                "https://github.com/EpicCash/epic-wallet" => {
                    "465d499f01aad7e570b6cc220d52c6bfcf6a9a44"
                }
                other => panic!("{} records unexpected repository {other}", module.path),
            };
            assert_eq!(module.upstream.commit.0, expected, "{}", module.path);
        }
    }

    #[test]
    fn parses_multiline_arrays_comments_and_trailing_commas() {
        let text = format!(
            "# header\n\n[[module]]\npath = \"crates/a/src/ser\" # trailing\ntask = \"P-01\"\nupstream.repo = \"https://example.org/up\"\nupstream.paths = [\n  \"core/src/ser.rs\",\n  # comment\n  \"core/src/core/hash.rs\",\n]\nupstream.commit = \"{COMMIT_A}\"\n"
        );
        let manifest = Manifest::parse(&text).unwrap();
        assert_eq!(
            manifest.modules,
            vec![Module {
                path: "crates/a/src/ser".to_owned(),
                task: "P-01".to_owned(),
                upstream: Upstream {
                    repo: "https://example.org/up".to_owned(),
                    paths: vec![
                        "core/src/ser.rs".to_owned(),
                        "core/src/core/hash.rs".to_owned()
                    ],
                    commit: CommitId(COMMIT_A.to_owned()),
                },
            }]
        );
    }

    #[test]
    fn rejects_key_outside_module() {
        assert_eq!(
            parse_error("path = \"a\"\n"),
            ManifestErrorKind::KeyOutsideModule
        );
    }

    #[test]
    fn rejects_unsupported_table() {
        assert_eq!(
            parse_error("[module]\n"),
            ManifestErrorKind::UnsupportedTable("[module]".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_key() {
        let text = module_text("crates/a", COMMIT_A) + "upstream.branch = \"master\"\n";
        assert_eq!(
            parse_error(&text),
            ManifestErrorKind::UnknownKey("upstream.branch".to_owned())
        );
    }

    #[test]
    fn rejects_duplicate_key() {
        let text = module_text("crates/a", COMMIT_A) + "task = \"P-02\"\n";
        assert_eq!(
            parse_error(&text),
            ManifestErrorKind::DuplicateKey("task".to_owned())
        );
    }

    #[test]
    fn rejects_missing_key() {
        let text = "[[module]]\npath = \"crates/a\"\n";
        assert_eq!(parse_error(text), ManifestErrorKind::MissingKey("task"));
    }

    #[test]
    fn rejects_abbreviated_commit() {
        assert_eq!(
            parse_error(&module_text("crates/a", "9d022b1d")),
            ManifestErrorKind::InvalidCommit("9d022b1d".to_owned())
        );
    }

    #[test]
    fn rejects_duplicate_module() {
        let text = module_text("crates/a", COMMIT_A) + &module_text("crates/a", COMMIT_A);
        let error = Manifest::parse(&text).unwrap_err();
        assert_eq!(
            error.kind,
            ManifestErrorKind::DuplicateModule("crates/a".to_owned())
        );
        assert_eq!(error.line, 7);
    }

    #[test]
    fn rejects_path_that_leaves_the_repository() {
        assert_eq!(
            parse_error(&module_text("../outside", COMMIT_A)),
            ManifestErrorKind::InvalidPath("../outside".to_owned())
        );
    }

    #[test]
    fn rejects_string_where_array_expected() {
        let text = "[[module]]\nupstream.paths = \"core/src/ser.rs\"\n";
        assert_eq!(
            parse_error(text),
            ManifestErrorKind::ExpectedArray("upstream.paths".to_owned())
        );
    }

    #[test]
    fn rejects_unterminated_array_and_string() {
        assert_eq!(
            parse_error("[[module]]\nupstream.paths = [\n\"a\",\n"),
            ManifestErrorKind::UnterminatedArray
        );
        assert_eq!(
            parse_error("[[module]]\npath = \"a\n"),
            ManifestErrorKind::UnterminatedString
        );
    }

    #[test]
    fn rejects_bare_and_trailing_values() {
        assert_eq!(
            parse_error("[[module]]\npath = crates\n"),
            ManifestErrorKind::InvalidValue
        );
        assert_eq!(
            parse_error("[[module]]\npath = \"a\" \"b\"\n"),
            ManifestErrorKind::InvalidValue
        );
    }

    #[test]
    fn cache_dir_name_drops_scheme_and_separators() {
        assert_eq!(
            cache_dir_name("https://github.com/EpicCash/epic").unwrap(),
            "github.com-EpicCash-epic"
        );
        assert!(cache_dir_name("https://").is_err());
    }

    /// A git repository in a temporary directory, isolated from the
    /// developer's global and system git configuration.
    struct Fixture {
        temp: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TempDir::new().unwrap();
            fs::write(temp.path().join("gitconfig"), "").unwrap();
            fs::create_dir(temp.path().join("upstream")).unwrap();
            let fixture = Self { temp };
            fixture.git(&["init", "--quiet", "--initial-branch=master"]);
            fixture
        }

        fn upstream(&self) -> PathBuf {
            self.temp.path().join("upstream")
        }

        fn cache(&self) -> PathBuf {
            self.temp.path().join("cache")
        }

        fn url(&self) -> String {
            let path = self.upstream().to_string_lossy().replace('\\', "/");
            if path.starts_with('/') {
                format!("file://{path}")
            } else {
                format!("file:///{path}")
            }
        }

        fn isolated_git(&self) -> Git {
            Git {
                global_config: Some(self.temp.path().join("gitconfig")),
            }
        }

        fn check_drift<'a>(&self, manifest: &'a Manifest) -> Result<Vec<RepoReport<'a>>> {
            check_drift(manifest, &self.cache(), &self.isolated_git())
        }

        fn git(&self, args: &[&str]) -> String {
            let output = self
                .isolated_git()
                .command(&self.upstream())
                .env("GIT_AUTHOR_NAME", "Fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@example.org")
                .env("GIT_COMMITTER_NAME", "Fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@example.org")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        }

        fn commit_file(&self, path: &str, contents: &str, subject: &str) -> String {
            let file = self.upstream().join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, contents).unwrap();
            self.git(&["add", "--", path]);
            self.git(&["commit", "--quiet", "--no-gpg-sign", "-m", subject]);
            self.git(&["rev-parse", "HEAD"]).trim().to_owned()
        }

        fn manifest(&self, modules: &[(&str, &str, &str)]) -> Manifest {
            let text: String = modules
                .iter()
                .map(|(path, upstream_path, commit)| {
                    format!(
                        "[[module]]\npath = \"{path}\"\ntask = \"F-05\"\nupstream.repo = \"{}\"\nupstream.paths = [\"{upstream_path}\"]\nupstream.commit = \"{commit}\"\n",
                        self.url()
                    )
                })
                .collect();
            Manifest::parse(&text).unwrap()
        }
    }

    fn reported(reports: &[RepoReport<'_>], path: &str) -> Vec<String> {
        reports
            .iter()
            .flat_map(|report| &report.modules)
            .find(|drift| drift.module.path == path)
            .unwrap()
            .commits
            .iter()
            .map(|commit| commit.id.clone())
            .collect()
    }

    #[test]
    fn reports_changes_to_recorded_paths_only() {
        let fixture = Fixture::new();
        fixture.commit_file("core/src/ser.rs", "v1", "add ser");
        let recorded = fixture.commit_file("core/src/hash.rs", "v1", "add hash");
        let ser_change = fixture.commit_file("core/src/ser.rs", "v2", "change ser");
        fixture.commit_file("README.md", "elsewhere", "change elsewhere");

        let manifest = fixture.manifest(&[
            ("crates/a/src/ser", "core/src/ser.rs", &recorded),
            ("crates/a/src/hash", "core/src/hash.rs", &recorded),
        ]);
        let reports = fixture.check_drift(&manifest).unwrap();

        assert_eq!(reported(&reports, "crates/a/src/ser"), vec![ser_change]);
        assert!(reported(&reports, "crates/a/src/hash").is_empty());
        let report = reports.first().unwrap().to_string();
        assert!(report.contains("change ser"), "{report}");
        assert!(!report.contains("change elsewhere"), "{report}");
    }

    #[test]
    fn reports_directory_paths_and_refetches_into_existing_cache() {
        let fixture = Fixture::new();
        let recorded = fixture.commit_file("core/src/ser.rs", "v1", "add ser");
        let manifest = fixture.manifest(&[("crates/a/src/core", "core", &recorded)]);

        let first = fixture.check_drift(&manifest).unwrap();
        assert!(reported(&first, "crates/a/src/core").is_empty());

        let change = fixture.commit_file("core/src/new.rs", "v1", "add new");
        let second = fixture.check_drift(&manifest).unwrap();
        assert_eq!(reported(&second, "crates/a/src/core"), vec![change]);
    }

    #[test]
    fn fails_when_recorded_path_is_absent_at_recorded_commit() {
        let fixture = Fixture::new();
        let recorded = fixture.commit_file("core/src/ser.rs", "v1", "add ser");
        let manifest = fixture.manifest(&[("crates/a/src/ser", "core/src/missing.rs", &recorded)]);
        let error = fixture.check_drift(&manifest).unwrap_err();
        assert_eq!(
            error.downcast_ref::<MissingUpstreamPath>(),
            Some(&MissingUpstreamPath {
                path: "core/src/missing.rs".to_owned(),
                commit: CommitId(recorded),
            })
        );
    }

    #[test]
    fn fails_when_recorded_commit_is_off_the_default_branch() {
        let fixture = Fixture::new();
        fixture.commit_file("core/src/ser.rs", "v1", "add ser");
        fixture.git(&["checkout", "--quiet", "-b", "side"]);
        let side = fixture.commit_file("core/src/ser.rs", "side", "side change");
        fixture.git(&["checkout", "--quiet", "master"]);
        fixture.commit_file("core/src/ser.rs", "v2", "change ser");

        let manifest = fixture.manifest(&[("crates/a/src/ser", "core/src/ser.rs", &side)]);
        let error = fixture.check_drift(&manifest).unwrap_err();
        assert_eq!(
            error.downcast_ref::<RecordedCommitOffBranch>(),
            Some(&RecordedCommitOffBranch {
                commit: CommitId(side),
            })
        );
    }

    #[test]
    fn counts_drifted_modules_for_the_drift_exit_status() {
        let fixture = Fixture::new();
        fixture.commit_file("core/src/ser.rs", "v1", "add ser");
        let recorded = fixture.commit_file("docs/hash.md", "v1", "add hash doc");
        fixture.commit_file("core/src/ser.rs", "v2", "change ser");
        let manifest = fixture.manifest(&[
            ("crates/a/src/ser", "core/src/ser.rs", &recorded),
            ("crates/a/src/core", "core/src", &recorded),
            ("crates/a/src/hash", "docs/hash.md", &recorded),
        ]);
        let reports = fixture.check_drift(&manifest).unwrap();
        assert_eq!(
            DriftFound::count(&reports),
            DriftFound {
                drifted: 2,
                total: 3,
            }
        );
    }
}
