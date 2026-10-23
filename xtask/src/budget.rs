//! `cargo xtask budget`: measures the shipped library size per mobile target, restore and Epicbox
//! drain time and peak memory, and fails when a measurement exceeds its budget in
//! `docs/budgets.md`.
//!
//! Restore and drain are measured as the release build of one existing test each, so the measured
//! work is exactly what those tests prove correct: the restore replays every G-05 session through
//! `MockNode`, the drain empties a queue on the mock relay.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::{cargo, mobile};

const BUDGETS_DOC: &str = "docs/budgets.md";
const TABLE_HEADING: &str = "## Budgets";

const USAGE: &str = "usage: cargo xtask budget [--measurements <file.json>]";

/// Runs per probe. Time is the median of the runs and memory the largest peak, so one run slowed
/// by other work on the machine does not decide the result.
const RUNS: usize = 5;

/// How often a running probe's memory high-water mark is read.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(1);

const FFI_LIBRARY_STEM: &str = "lepic_ffi";

/// Probe output goes here, so a failing probe can be read after the fact.
const LOG_DIR: &str = "target/budget";

/// One existing test, run alone from its release test binary.
struct Probe {
    name: &'static str,
    package: &'static str,
    test_target: &'static str,
    test: &'static str,
}

const PROBES: &[Probe] = &[
    Probe {
        name: "restore",
        package: "lepic-wallet",
        test_target: "vectors",
        test: "restore_vectors_find_exactly_the_outputs_upstream_found",
    },
    Probe {
        name: "drain",
        package: "lepic-epicbox",
        test_target: "client",
        test: "drain_hands_out_oldest_first_and_returns_when_the_queue_is_empty",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    KiB,
    Ms,
}

impl Unit {
    fn parse(text: &str) -> Result<Self> {
        match text {
            "KiB" => Ok(Self::KiB),
            "ms" => Ok(Self::Ms),
            other => bail!("unknown unit `{other}`, expected `KiB` or `ms`"),
        }
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KiB => "KiB",
            Self::Ms => "ms",
        })
    }
}

/// What a budget key measures.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Metric {
    LibrarySize { target: String },
    Time { probe: &'static str },
    PeakMemory { probe: &'static str },
}

impl Metric {
    fn parse(key: &str) -> Result<Self> {
        if let Some(target) = key.strip_prefix("size.") {
            if target.is_empty() {
                bail!("`{key}` names no target");
            }
            return Ok(Self::LibrarySize {
                target: target.to_owned(),
            });
        }
        let (name, quantity) = key
            .split_once('.')
            .with_context(|| format!("`{key}` is not `<probe>.<quantity>`"))?;
        let probe = PROBES
            .iter()
            .find(|probe| probe.name == name)
            .with_context(|| format!("`{key}` names no known probe"))?
            .name;
        match quantity {
            "time" => Ok(Self::Time { probe }),
            "peak_memory" => Ok(Self::PeakMemory { probe }),
            other => bail!("`{key}` has unknown quantity `{other}`"),
        }
    }

    fn unit(&self) -> Unit {
        match self {
            Self::LibrarySize { .. } | Self::PeakMemory { .. } => Unit::KiB,
            Self::Time { .. } => Unit::Ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Budget {
    key: String,
    metric: Metric,
    limit: u64,
}

/// Reads the table after the budgets heading: `| `key` | limit | unit | ... |`, one row per
/// budget, after a header row and a separator row.
fn parse_budgets(doc: &str) -> Result<Vec<Budget>> {
    let mut lines = doc.lines().skip_while(|line| line.trim() != TABLE_HEADING);
    if lines.next().is_none() {
        bail!("heading `{TABLE_HEADING}` not found");
    }
    let rows: Vec<&str> = lines
        .map(str::trim)
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .collect();
    if rows.is_empty() {
        bail!("no budget rows after `{TABLE_HEADING}`");
    }
    let mut budgets: Vec<Budget> = Vec::new();
    for row in rows {
        let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
        let (Some(key), Some(limit), Some(unit)) = (cells.first(), cells.get(1), cells.get(2))
        else {
            bail!("row `{row}` needs a key, a limit and a unit");
        };
        let key = key.trim_matches('`');
        let metric = Metric::parse(key)?;
        let limit: u64 = limit
            .parse()
            .with_context(|| format!("`{key}` limit `{limit}` is not a whole number"))?;
        let unit = Unit::parse(unit)?;
        if unit != metric.unit() {
            bail!("`{key}` is measured in {}, not {unit}", metric.unit());
        }
        if budgets.iter().any(|budget| budget.key == key) {
            bail!("`{key}` is listed twice");
        }
        budgets.push(Budget {
            key: key.to_owned(),
            metric,
            limit,
        });
    }
    Ok(budgets)
}

/// A measurement in its budget's unit, or why the host cannot take it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum Measured {
    Value(u64),
    Skipped(String),
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Within,
    Over,
    NotMeasured(String),
}

struct Row<'a> {
    budget: &'a Budget,
    measured: Option<u64>,
    verdict: Verdict,
}

/// Compares every budget with its measurement. A measurement without a budget is an error, so a
/// renamed key cannot pass unchecked.
fn evaluate<'a>(
    budgets: &'a [Budget],
    measurements: &BTreeMap<String, Measured>,
) -> Result<Vec<Row<'a>>> {
    if let Some(unknown) = measurements
        .keys()
        .find(|key| !budgets.iter().any(|budget| &budget.key == *key))
    {
        bail!("measurement `{unknown}` has no budget in {BUDGETS_DOC}");
    }
    Ok(budgets
        .iter()
        .map(|budget| {
            let (measured, verdict) = match measurements.get(&budget.key) {
                Some(Measured::Value(value)) if *value <= budget.limit => {
                    (Some(*value), Verdict::Within)
                }
                Some(Measured::Value(value)) => (Some(*value), Verdict::Over),
                Some(Measured::Skipped(reason)) => (None, Verdict::NotMeasured(reason.clone())),
                None => (None, Verdict::NotMeasured("no measurement".to_owned())),
            };
            Row {
                budget,
                measured,
                verdict,
            }
        })
        .collect())
}

fn report(rows: &[Row<'_>]) -> Result<()> {
    let mut over = 0_usize;
    for row in rows {
        let unit = row.budget.metric.unit();
        let limit = row.budget.limit;
        let key = &row.budget.key;
        match (&row.verdict, row.measured) {
            (Verdict::Within, Some(value)) => {
                eprintln!("xtask budget: ok    {key}: {value} {unit} (budget {limit} {unit})");
            }
            (Verdict::Over, Some(value)) => {
                over = over.saturating_add(1);
                eprintln!("xtask budget: OVER  {key}: {value} {unit} (budget {limit} {unit})");
            }
            (Verdict::NotMeasured(reason), _) => {
                eprintln!("xtask budget: skip  {key}: {reason}");
            }
            (_, None) => eprintln!("xtask budget: skip  {key}: no measurement"),
        }
    }
    if over > 0 {
        bail!("{over} measurement(s) over budget, see {BUDGETS_DOC}");
    }
    eprintln!("xtask budget: every measurement is within its budget");
    Ok(())
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let fixture = match args {
        [] => None,
        [flag, file] if flag == "--measurements" => Some(PathBuf::from(file)),
        _ => bail!("{USAGE}"),
    };
    let doc_path = root.join(BUDGETS_DOC);
    let doc = fs::read_to_string(&doc_path)
        .with_context(|| format!("could not read {}", doc_path.display()))?;
    let budgets = parse_budgets(&doc).with_context(|| format!("bad budgets in {BUDGETS_DOC}"))?;
    let measurements = match fixture {
        Some(file) => read_measurements(&file)?,
        None => measure(root, &budgets)?,
    };
    report(&evaluate(&budgets, &measurements)?)
}

/// A JSON object from budget key to a whole number in the budget's unit, or to a string saying
/// why it was not measured.
fn read_measurements(file: &Path) -> Result<BTreeMap<String, Measured>> {
    let text = fs::read_to_string(file)
        .with_context(|| format!("could not read measurements {}", file.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("measurements {} are not a JSON object", file.display()))
}

fn measure(root: &Path, budgets: &[Budget]) -> Result<BTreeMap<String, Measured>> {
    let mut measurements = BTreeMap::new();
    let mut probes: BTreeMap<&str, ProbeResult> = BTreeMap::new();
    for budget in budgets {
        let measured = match &budget.metric {
            Metric::LibrarySize { target } => library_size(root, target)?,
            Metric::Time { probe } | Metric::PeakMemory { probe } => {
                let result = match probes.get(probe) {
                    Some(result) => result,
                    None => {
                        let result = run_probe(root, probe_named(probe)?)?;
                        probes.entry(probe).or_insert(result)
                    }
                };
                match budget.metric {
                    Metric::Time { .. } => Measured::Value(result.median_ms),
                    _ => memory_measurement(result.peak_kib, std::env::consts::OS)
                        .with_context(|| format!("probe `{probe}`"))?,
                }
            }
        };
        measurements.insert(budget.key.clone(), measured);
    }
    Ok(measurements)
}

/// Off Linux there is no `/proc` to read, so the budget is skipped. On Linux a missing sample
/// means every read failed, and passing the budget unchecked would hide that.
fn memory_measurement(peak_kib: Option<u64>, os: &str) -> Result<Measured> {
    match (peak_kib, os) {
        (Some(kib), _) => Ok(Measured::Value(kib)),
        (None, "linux") => bail!("no memory sample taken from /proc/<pid>/status"),
        (None, other) => Ok(Measured::Skipped(format!(
            "peak memory is read from /proc, not available on {other}"
        ))),
    }
}

fn probe_named(name: &str) -> Result<&'static Probe> {
    PROBES
        .iter()
        .find(|probe| probe.name == name)
        .with_context(|| format!("no probe named `{name}`"))
}

/// Why `host_os` (a `std::env::consts::OS` value) cannot build the library for `target`, or
/// `None` when it can. Apple targets need the Xcode SDK; the Linux library links against the
/// host's glibc, so `cargo xtask mobile` builds it only natively.
fn unbuildable_on_host(target: &str, host_os: &str) -> Option<String> {
    let (needed_os, name) = if target.contains("-apple-") {
        ("macos", "macOS")
    } else if target.ends_with("-linux-gnu") {
        ("linux", "Linux")
    } else {
        return None;
    };
    (host_os != needed_os).then(|| format!("`{target}` builds only on {name}"))
}

/// The stripped release `lepic-ffi` library as `cargo xtask mobile --package` ships it.
fn library_size(root: &Path, target: &str) -> Result<Measured> {
    if let Some(reason) = unbuildable_on_host(target, std::env::consts::OS) {
        return Ok(Measured::Skipped(reason));
    }
    let apple = target.contains("-apple-");
    eprintln!(
        "xtask budget: building the release lepic-ffi library for {target}, this takes minutes"
    );
    mobile::run(
        root,
        &[
            "--package".to_owned(),
            "--target".to_owned(),
            target.to_owned(),
        ],
    )?;
    let extension = if apple { "dylib" } else { "so" };
    let library = root
        .join(mobile::PACKAGE_NATIVE_DIR)
        .join(target)
        .join(format!("lib{FFI_LIBRARY_STEM}.{extension}"));
    let bytes = fs::metadata(&library)
        .with_context(|| format!("could not read the size of {}", library.display()))?
        .len();
    Ok(Measured::Value(bytes.div_ceil(1024)))
}

struct ProbeResult {
    median_ms: u64,
    peak_kib: Option<u64>,
}

fn run_probe(root: &Path, probe: &Probe) -> Result<ProbeResult> {
    let binary = build_test_binary(root, probe)?;
    check_test_exists(&binary, probe)?;
    let log_dir = root.join(LOG_DIR);
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("could not create {}", log_dir.display()))?;
    let mut times = Vec::with_capacity(RUNS);
    let mut peak_kib: Option<u64> = None;
    for attempt in 1..=RUNS {
        let log = log_dir.join(format!("{}-{attempt}.log", probe.name));
        let sample = run_sampled(root, &binary, probe, &log)?;
        eprintln!(
            "xtask budget: {} run {attempt}/{RUNS}: {} ms{}",
            probe.name,
            sample.elapsed_ms,
            sample
                .peak_kib
                .map(|kib| format!(", peak {kib} KiB"))
                .unwrap_or_default()
        );
        times.push(sample.elapsed_ms);
        peak_kib = peak_kib.max(sample.peak_kib);
    }
    Ok(ProbeResult {
        median_ms: median(&mut times).context("no probe runs")?,
        peak_kib,
    })
}

fn median(values: &mut [u64]) -> Option<u64> {
    values.sort_unstable();
    values.get(values.len().checked_div(2)?).copied()
}

fn build_test_binary(root: &Path, probe: &Probe) -> Result<PathBuf> {
    eprintln!(
        "xtask budget: building the release `{}` tests of {}",
        probe.test_target, probe.package
    );
    let output = cargo()
        .args(["test", "--release", "--locked", "--no-run"])
        .args(["--package", probe.package, "--test", probe.test_target])
        .args(["--message-format", "json"])
        .current_dir(root)
        .stderr(Stdio::inherit())
        .output()
        .context("could not start `cargo test --no-run`")?;
    if !output.status.success() {
        bail!(
            "building the `{}` tests of {} failed",
            probe.test_target,
            probe.package
        );
    }
    test_executable(&String::from_utf8_lossy(&output.stdout), probe.test_target)
}

#[derive(Deserialize)]
struct Artifact {
    reason: String,
    target: Option<ArtifactTarget>,
    executable: Option<PathBuf>,
}

#[derive(Deserialize)]
struct ArtifactTarget {
    name: String,
    kind: Vec<String>,
}

/// The test executable named `test_target` in cargo's JSON messages.
fn test_executable(messages: &str, test_target: &str) -> Result<PathBuf> {
    messages
        .lines()
        .filter_map(|line| serde_json::from_str::<Artifact>(line).ok())
        .filter(|artifact| artifact.reason == "compiler-artifact")
        .filter(|artifact| {
            artifact.target.as_ref().is_some_and(|target| {
                target.name == test_target && target.kind.iter().any(|kind| kind == "test")
            })
        })
        .find_map(|artifact| artifact.executable)
        .with_context(|| format!("cargo built no `{test_target}` test executable"))
}

/// A filter that matches nothing still exits 0, which would measure an empty run.
fn check_test_exists(binary: &Path, probe: &Probe) -> Result<()> {
    let output = Command::new(binary)
        .args(["--list", "--exact", probe.test])
        .output()
        .with_context(|| format!("could not start {}", binary.display()))?;
    let listed = String::from_utf8_lossy(&output.stdout);
    let entry = format!("{}: test", probe.test);
    if !output.status.success() || !listed.lines().any(|line| line.trim() == entry) {
        bail!(
            "{} has no test `{}`; update the probe in xtask/src/budget.rs",
            probe.package,
            probe.test
        );
    }
    Ok(())
}

struct Sample {
    elapsed_ms: u64,
    peak_kib: Option<u64>,
}

fn run_sampled(root: &Path, binary: &Path, probe: &Probe, log: &Path) -> Result<Sample> {
    let stdout =
        fs::File::create(log).with_context(|| format!("could not create {}", log.display()))?;
    let stderr = stdout
        .try_clone()
        .with_context(|| format!("could not share {}", log.display()))?;
    let started = Instant::now();
    let mut child = Command::new(binary)
        .args(["--exact", probe.test, "--test-threads=1"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .with_context(|| format!("could not start {}", binary.display()))?;
    let mut peak_kib: Option<u64> = None;
    let status = loop {
        peak_kib = peak_kib.max(memory_high_water_kib(child.id()));
        if let Some(status) = child.try_wait().context("could not wait for the probe")? {
            break status;
        }
        thread::sleep(SAMPLE_INTERVAL);
    };
    let elapsed = started.elapsed();
    if !status.success() {
        bail!(
            "probe `{}` failed ({status}), output in {}",
            probe.name,
            log.display()
        );
    }
    Ok(Sample {
        elapsed_ms: u64::try_from(elapsed.as_micros().div_ceil(1000))
            .context("probe ran for longer than u64 milliseconds")?,
        peak_kib,
    })
}

/// The process's resident set high-water mark. Only Linux exposes it without a system call
/// binding; elsewhere peak memory is reported as not measured.
fn memory_high_water_kib(pid: u32) -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_vm_hwm(&status)
}

fn parse_vm_hwm(status: &str) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .trim()
        .strip_suffix("kB")?
        .trim();
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "# Budgets

## Budgets

| Measurement | Budget | Unit | Measured |
|---|---|---|---|
| `size.aarch64-linux-android` | 4096 | KiB | 3000 |
| `restore.time` | 500 | ms | 100 |
| `restore.peak_memory` | 65536 | KiB | 20000 |

## Method
";

    fn measurements(json: &str) -> BTreeMap<String, Measured> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn parses_the_budget_table() {
        let budgets = parse_budgets(DOC).unwrap();
        assert_eq!(
            budgets,
            [
                Budget {
                    key: "size.aarch64-linux-android".to_owned(),
                    metric: Metric::LibrarySize {
                        target: "aarch64-linux-android".to_owned()
                    },
                    limit: 4096,
                },
                Budget {
                    key: "restore.time".to_owned(),
                    metric: Metric::Time { probe: "restore" },
                    limit: 500,
                },
                Budget {
                    key: "restore.peak_memory".to_owned(),
                    metric: Metric::PeakMemory { probe: "restore" },
                    limit: 65536,
                },
            ]
        );
    }

    #[test]
    fn rejects_malformed_budget_tables() {
        assert!(parse_budgets("# no heading\n").is_err());
        assert!(parse_budgets("## Budgets\n\nno table\n").is_err());
        let row = |row: &str| format!("## Budgets\n\n| a | b | c |\n|---|---|---|\n{row}\n");
        assert!(parse_budgets(&row("| `restore.time` | 5 | KiB |")).is_err());
        assert!(parse_budgets(&row("| `restore.time` | fast | ms |")).is_err());
        assert!(parse_budgets(&row("| `restore.speed` | 5 | ms |")).is_err());
        assert!(parse_budgets(&row("| `sync.time` | 5 | ms |")).is_err());
        assert!(parse_budgets(&row("| `size.` | 5 | KiB |")).is_err());
        assert!(parse_budgets(&row("| `restore.time` | 5 |")).is_err());
        let twice = row("| `restore.time` | 5 | ms |\n| `restore.time` | 6 | ms |");
        assert!(parse_budgets(&twice).is_err());
    }

    #[test]
    fn the_repository_budgets_parse_and_name_known_measurements() {
        let doc =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/budgets.md"))
                .unwrap();
        let budgets = parse_budgets(&doc).unwrap();
        for probe in PROBES {
            assert!(
                budgets
                    .iter()
                    .any(|budget| budget.metric == Metric::Time { probe: probe.name }),
                "no time budget for {}",
                probe.name
            );
        }
        assert!(
            budgets
                .iter()
                .any(|budget| matches!(budget.metric, Metric::LibrarySize { .. }))
        );
    }

    #[test]
    fn measurements_within_budget_pass() {
        let budgets = parse_budgets(DOC).unwrap();
        let rows = evaluate(
            &budgets,
            &measurements(
                r#"{"size.aarch64-linux-android": 4096, "restore.time": 1, "restore.peak_memory": "not on this host"}"#,
            ),
        )
        .unwrap();
        assert_eq!(rows[0].verdict, Verdict::Within);
        assert_eq!(rows[1].verdict, Verdict::Within);
        assert_eq!(
            rows[2].verdict,
            Verdict::NotMeasured("not on this host".to_owned())
        );
        assert!(report(&rows).is_ok());
    }

    #[test]
    fn a_measurement_over_its_budget_fails() {
        let budgets = parse_budgets(DOC).unwrap();
        let rows = evaluate(&budgets, &measurements(r#"{"restore.time": 501}"#)).unwrap();
        assert_eq!(rows[1].verdict, Verdict::Over);
        assert!(report(&rows).is_err());
    }

    #[test]
    fn a_measurement_without_a_budget_is_refused() {
        let budgets = parse_budgets(DOC).unwrap();
        assert!(evaluate(&budgets, &measurements(r#"{"drain.time": 1}"#)).is_err());
    }

    #[test]
    fn the_command_fails_on_a_measurement_fixture_over_budget() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("docs")).unwrap();
        fs::write(root.path().join(BUDGETS_DOC), DOC).unwrap();
        let fixture = root.path().join("measurements.json");
        let args = |file: &Path| ["--measurements".to_owned(), file.display().to_string()];

        fs::write(&fixture, r#"{"restore.time": 500}"#).unwrap();
        assert!(run(root.path(), &args(&fixture)).is_ok());

        fs::write(&fixture, r#"{"restore.peak_memory": 65537}"#).unwrap();
        assert!(run(root.path(), &args(&fixture)).is_err());
    }

    #[test]
    fn rejects_unknown_arguments() {
        let root = Path::new("/nonexistent");
        assert!(run(root, &["--measurements".to_owned()]).is_err());
        assert!(run(root, &["--fast".to_owned()]).is_err());
    }

    #[test]
    fn reads_the_high_water_mark_from_proc_status() {
        let status =
            "Name:\tvectors\nVmPeak:\t  900000 kB\nVmHWM:\t   23456 kB\nVmRSS:\t  20000 kB\n";
        assert_eq!(parse_vm_hwm(status), Some(23456));
        assert_eq!(parse_vm_hwm("Name:\tzombie\nState:\tZ (zombie)\n"), None);
    }

    #[test]
    fn a_missing_memory_sample_fails_on_linux_and_is_skipped_elsewhere() {
        assert_eq!(
            memory_measurement(Some(6000), "linux").unwrap(),
            Measured::Value(6000)
        );
        assert!(memory_measurement(None, "linux").is_err());
        assert!(matches!(
            memory_measurement(None, "windows").unwrap(),
            Measured::Skipped(_)
        ));
    }

    #[test]
    fn libraries_a_host_cannot_build_are_skipped_with_a_reason() {
        let linux = "x86_64-unknown-linux-gnu";
        assert_eq!(unbuildable_on_host(linux, "linux"), None);
        for os in ["macos", "windows"] {
            assert_eq!(
                unbuildable_on_host(linux, os),
                Some(format!("`{linux}` builds only on Linux"))
            );
        }
        assert_eq!(unbuildable_on_host("aarch64-apple-ios", "macos"), None);
        assert_eq!(
            unbuildable_on_host("aarch64-apple-ios", "linux"),
            Some("`aarch64-apple-ios` builds only on macOS".to_owned())
        );
        for os in ["linux", "macos", "windows"] {
            assert_eq!(unbuildable_on_host("aarch64-linux-android", os), None);
            assert_eq!(unbuildable_on_host("armv7-linux-androideabi", os), None);
        }
    }

    #[test]
    fn median_takes_the_middle_run() {
        assert_eq!(median(&mut [9, 1, 5, 7, 3]), Some(5));
        assert_eq!(median(&mut []), None);
    }

    #[test]
    fn finds_the_test_executable_in_cargo_messages() {
        let messages = r#"{"reason":"compiler-artifact","target":{"name":"lepic_wallet","kind":["lib"]},"executable":null}
not json
{"reason":"compiler-artifact","target":{"name":"vectors","kind":["test"]},"executable":"/t/release/deps/vectors-abc"}
{"reason":"build-finished","success":true}"#;
        assert_eq!(
            test_executable(messages, "vectors").unwrap(),
            PathBuf::from("/t/release/deps/vectors-abc")
        );
        assert!(test_executable(messages, "client").is_err());
    }
}
