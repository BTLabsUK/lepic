//! `cargo xtask fuzz`: seeds the corpora from the golden vectors and runs the cargo-fuzz targets
//! in `fuzz/` (task V-04).

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::Value;

const USAGE: &str = "usage: cargo xtask fuzz (--smoke | --full) [--target <name>]... [--jobs <n>]

  --smoke   run each target for 60 seconds
  --full    run each target for 10 minutes
  --target  run only this target; repeatable
  --jobs    targets to run at the same time, default 1";

const SMOKE_SECONDS: u64 = 60;
const FULL_SECONDS: u64 = 600;

/// Slack on top of the fuzzing time for the build check and the final corpus merge before a run
/// is killed as hung.
const WALL_CLOCK_SLACK: Duration = Duration::from_secs(300);

/// Per-input limits that keep a slow or memory-hungry input a reported failure, not a stall.
const LIBFUZZER_LIMITS: &[&str] = &["-timeout=25", "-rss_limit_mb=2560", "-print_final_stats=1"];

// Environment that rustup and the outer cargo set for this process. Each one would make the nested
// build use the product toolchain instead of the nightly `fuzz/rust-toolchain.toml` pins.
const TOOLCHAIN_ENV: &[&str] = &["RUSTUP_TOOLCHAIN", "CARGO", "RUSTC", "RUSTDOC"];

/// Every target in `fuzz/Cargo.toml`, in run order. A test keeps the two lists equal.
const TARGETS: &[&str] = &[
    "ser_read",
    "tx_decode",
    "slate_v2",
    "slate_v3",
    "slate_detect",
    "file_import",
    "epicbox_frame",
    "epicbox_address",
    "epicbox_message",
    "node_response",
    "vault_file",
    "wallet_seed",
];

#[derive(Debug, PartialEq, Eq)]
struct Options {
    seconds: u64,
    targets: Vec<&'static str>,
    jobs: usize,
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let options = parse_args(args)?;
    let fuzz_dir = root.join("fuzz");
    for target in &options.targets {
        let written = write_seeds(root, target, &fuzz_dir.join("corpus").join(target))?;
        eprintln!("xtask fuzz: {target}: {written} seeds");
    }
    build(&fuzz_dir)?;
    let failed = run_targets(&fuzz_dir, &options)?;
    if !failed.is_empty() {
        bail!(
            "fuzz targets failed: {}; crashing inputs are under fuzz/artifacts/<target>/",
            failed.join(", ")
        );
    }
    eprintln!(
        "xtask fuzz: {} targets ran {} s each without a failure",
        options.targets.len(),
        options.seconds
    );
    Ok(())
}

fn parse_args(args: &[String]) -> Result<Options> {
    let mut seconds = None;
    let mut targets = Vec::new();
    let mut jobs = 1;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--smoke" | "--full" if seconds.is_some() => {
                bail!("give one of --smoke and --full\n\n{USAGE}")
            }
            "--smoke" => seconds = Some(SMOKE_SECONDS),
            "--full" => seconds = Some(FULL_SECONDS),
            "--target" => {
                let name = args.next().context("--target needs a name")?;
                let Some(target) = TARGETS.iter().find(|target| *target == name) else {
                    bail!(
                        "unknown fuzz target `{name}`; targets: {}",
                        TARGETS.join(", ")
                    );
                };
                targets.push(*target);
            }
            "--jobs" => {
                jobs = args
                    .next()
                    .and_then(|jobs| jobs.parse().ok())
                    .filter(|jobs| *jobs > 0)
                    .context("--jobs needs a positive number")?;
            }
            other => bail!("unknown argument `{other}`\n\n{USAGE}"),
        }
    }
    let seconds = seconds.with_context(|| format!("give --smoke or --full\n\n{USAGE}"))?;
    if targets.is_empty() {
        targets = TARGETS.to_vec();
    }
    Ok(Options {
        seconds,
        targets,
        jobs,
    })
}

/// The rustup proxy, not `cargo()`, so the nightly in `fuzz/rust-toolchain.toml` takes effect.
fn nightly_cargo(fuzz_dir: &Path) -> Command {
    let mut command = Command::new("cargo");
    for name in TOOLCHAIN_ENV {
        command.env_remove(name);
    }
    command.current_dir(fuzz_dir);
    command
}

fn fuzz_command(fuzz_dir: &Path) -> Command {
    let mut command = nightly_cargo(fuzz_dir);
    command.arg("fuzz");
    command
}

fn build(fuzz_dir: &Path) -> Result<()> {
    // cargo-fuzz has no `--locked`; fetching with it fails when `fuzz/Cargo.lock` is stale.
    let status = nightly_cargo(fuzz_dir)
        .args(["fetch", "--locked", "--quiet"])
        .status()
        .context("could not start `cargo fetch` in fuzz/")?;
    if !status.success() {
        bail!("fuzz/Cargo.lock is not up to date; run `cargo fuzz build` in fuzz/ and commit it");
    }
    eprintln!("xtask fuzz: building the targets");
    let status = fuzz_command(fuzz_dir)
        .arg("build")
        .status()
        .context("could not start `cargo fuzz build`; is cargo-fuzz installed?")?;
    if !status.success() {
        bail!("`cargo fuzz build` failed");
    }
    Ok(())
}

fn run_command(fuzz_dir: &Path, target: &str, seconds: u64) -> Command {
    let mut command = fuzz_command(fuzz_dir);
    command
        .args(["run", target])
        .arg(Path::new("corpus").join(target))
        .arg("--")
        .arg(format!("-max_total_time={seconds}"))
        .args(LIBFUZZER_LIMITS);
    command
}

struct Running {
    target: &'static str,
    child: Child,
    log: PathBuf,
    started: Instant,
}

/// Runs the targets, at most `jobs` at a time, and returns the names of those that failed.
fn run_targets(fuzz_dir: &Path, options: &Options) -> Result<Vec<&'static str>> {
    let logs = fuzz_dir.join("target").join("fuzz-logs");
    fs::create_dir_all(&logs).with_context(|| format!("could not create {}", logs.display()))?;
    let deadline = Duration::from_secs(options.seconds).saturating_add(WALL_CLOCK_SLACK);
    let mut pending = options.targets.iter().copied();
    let mut running: Vec<Running> = Vec::new();
    let mut failed = Vec::new();
    loop {
        while running.len() < options.jobs {
            let Some(target) = pending.next() else {
                break;
            };
            running.push(start(fuzz_dir, &logs, target, options.seconds)?);
        }
        if running.is_empty() {
            return Ok(failed);
        }
        thread::sleep(Duration::from_secs(1));
        let mut still_running = Vec::with_capacity(running.len());
        for mut run in running {
            let outcome = match run.child.try_wait() {
                Ok(Some(status)) => Some(status.success()),
                Ok(None) if run.started.elapsed() > deadline => {
                    // Already exited or not killable; either way the run is reported failed.
                    let _ = run.child.kill();
                    let _ = run.child.wait();
                    eprintln!(
                        "xtask fuzz: {}: killed after {} s of wall clock",
                        run.target,
                        deadline.as_secs()
                    );
                    Some(false)
                }
                Ok(None) => None,
                Err(error) => {
                    eprintln!(
                        "xtask fuzz: {}: could not poll the run: {error}",
                        run.target
                    );
                    Some(false)
                }
            };
            match outcome {
                None => still_running.push(run),
                Some(true) => eprintln!(
                    "xtask fuzz: {}: passed in {} s",
                    run.target,
                    run.started.elapsed().as_secs()
                ),
                Some(false) => {
                    eprintln!(
                        "xtask fuzz: {}: FAILED, log {}",
                        run.target,
                        run.log.display()
                    );
                    print_tail(&run.log);
                    failed.push(run.target);
                }
            }
        }
        running = still_running;
    }
}

fn start(fuzz_dir: &Path, logs: &Path, target: &'static str, seconds: u64) -> Result<Running> {
    let log = logs.join(format!("{target}.log"));
    let file = File::create(&log).with_context(|| format!("could not create {}", log.display()))?;
    let child = run_command(fuzz_dir, target, seconds)
        .stdin(Stdio::null())
        .stdout(file.try_clone().context("could not share the log file")?)
        .stderr(file)
        .spawn()
        .with_context(|| format!("could not start `cargo fuzz run {target}`"))?;
    eprintln!(
        "xtask fuzz: {target}: running for {seconds} s, log {}",
        log.display()
    );
    Ok(Running {
        target,
        child,
        log,
        started: Instant::now(),
    })
}

fn print_tail(log: &Path) {
    const TAIL_LINES: usize = 40;
    let Ok(text) = fs::read_to_string(log) else {
        return;
    };
    let lines: Vec<&str> = text.lines().collect();
    let skip = lines.len().saturating_sub(TAIL_LINES);
    for line in lines.iter().skip(skip) {
        eprintln!("    {line}");
    }
}

/// Writes the seeds of `target` into `corpus` as `seed-<n>` files and returns how many. Inputs
/// libfuzzer added to the corpus are left alone.
fn write_seeds(root: &Path, target: &str, corpus: &Path) -> Result<usize> {
    let seeds = seeds(root, target)?;
    fs::create_dir_all(corpus).with_context(|| format!("could not create {}", corpus.display()))?;
    for (index, seed) in seeds.iter().enumerate() {
        let path = corpus.join(format!("seed-{index}"));
        fs::write(&path, seed).with_context(|| format!("could not write {}", path.display()))?;
    }
    Ok(seeds.len())
}

/// The seed inputs of one target, without duplicates, in a stable order.
fn seeds(root: &Path, target: &str) -> Result<BTreeSet<Vec<u8>>> {
    let vectors = root.join("testdata").join("vectors");
    let mut seeds = BTreeSet::new();
    match target {
        "ser_read" => {
            for rule in SER_READ_RULES {
                for vector in read_area(&vectors, "primitives", rule.file_prefix)? {
                    for bytes in hex_fields(&vector, rule.field) {
                        for version in rule.versions {
                            seeds.insert(prefixed(&[rule.type_index, *version], &bytes));
                        }
                    }
                }
            }
            // A transaction is a 32-byte offset followed by its body.
            for vector in read_area(&vectors, "primitives", "tx_")? {
                for (field, version) in [("serialized_v1", 1), ("serialized_v2", 2)] {
                    for bytes in hex_fields(&vector, field) {
                        if let Some(body) = bytes.get(32..) {
                            seeds.insert(prefixed(&[SER_TRANSACTION_BODY, version], body));
                        }
                    }
                }
            }
        }
        "tx_decode" => {
            for vector in read_area(&vectors, "primitives", "tx_")? {
                for (field, version) in [("serialized_v1", 1), ("serialized_v2", 2)] {
                    for bytes in hex_fields(&vector, field) {
                        seeds.insert(prefixed(&[version], &bytes));
                    }
                }
            }
        }
        "slate_v2" | "slate_v3" | "slate_detect" | "file_import" => {
            for vector in read_area(&vectors, "slates", "")? {
                seeds.extend(text_fields(&vector, "json"));
            }
            for vector in read_area(&vectors, "epicbox", "message_")? {
                seeds.extend(text_fields(&vector, "plaintext"));
            }
        }
        "epicbox_address" => {
            for vector in read_area(&vectors, "epicbox", "address_")? {
                seeds.extend(text_fields(
                    vector.get("inputs").unwrap_or(&Value::Null),
                    "text",
                ));
            }
        }
        "epicbox_message" => {
            for vector in read_area(&vectors, "epicbox", "message_")? {
                seeds.extend(text_fields(&vector, "str"));
            }
        }
        "epicbox_frame" => {
            seeds.extend(FIXED_FRAMES.iter().map(|frame| frame.as_bytes().to_vec()));
            for vector in read_area(&vectors, "epicbox", "message_")? {
                let field = |name: &str| vector.pointer(&format!("/expected/{name}")).cloned();
                let frame = serde_json::json!({
                    "type": "Slate",
                    "from": field("from"),
                    "str": field("str"),
                    "signature": field("signature"),
                    "challenge": "",
                });
                seeds.insert(frame.to_string().into_bytes());
            }
        }
        "node_response" => {
            let mut sources = read_area(&vectors, "engine", "")?;
            sources.extend(read_dir_json(&root.join("testdata").join("node"), "")?);
            for source in sources {
                for response in values_of(&source, "response") {
                    seeds.insert(response.to_string().into_bytes());
                }
            }
        }
        "vault_file" => seeds.extend(vault_seeds()),
        "wallet_seed" => {
            for vector in read_area(&vectors, "keys", "wallet_seed_")? {
                seeds.extend(text_fields(&vector, "file"));
            }
        }
        other => bail!("no seed rule for fuzz target `{other}`"),
    }
    if seeds.is_empty() {
        bail!("no seeds for fuzz target `{target}`; did the golden vectors move?");
    }
    Ok(seeds)
}

/// Seeds for `ser_read`: a hex field of the primitives vectors, read as one type.
struct SerReadRule {
    file_prefix: &'static str,
    field: &'static str,
    /// The index of the type in `TYPES` of `fuzz/fuzz_targets/ser_read.rs`.
    type_index: u8,
    versions: &'static [u8],
}

const SER_TRANSACTION_BODY: u8 = 1;

const SER_READ_RULES: &[SerReadRule] = &[
    rule("tx_", "serialized_v1", 0, &[1]),
    rule("tx_", "serialized_v2", 0, &[2]),
    rule("kernels", "serialized_v1", 2, &[1]),
    rule("kernels", "serialized_v2", 2, &[2]),
    rule("kernel_features.", "serialized_v1", 3, &[1]),
    rule("kernel_features.", "serialized_v2", 3, &[2]),
    rule("kernel_features_decode", "bytes", 3, &[1, 2]),
    rule("inputs", "serialized_v1", 4, &[1]),
    rule("inputs", "serialized_v2", 4, &[2]),
    rule("outputs", "serialized_v1", 5, &[1]),
    rule("outputs", "serialized_v2", 5, &[2]),
    rule("outputs", "identifier_serialized", 6, &[1, 2]),
    rule("output_features", "byte", 7, &[1, 2]),
    rule("crypto_types", "commitment_ser", 8, &[2]),
    rule("crypto_types", "public_key_ser", 9, &[2]),
    rule("crypto_types", "signature_ser", 10, &[2]),
    rule("crypto_types", "range_proof_ser", 11, &[2]),
    rule("crypto_types", "blinding_factor_ser", 12, &[2]),
    rule("hash_values", "hash", 13, &[2]),
];

const fn rule(
    file_prefix: &'static str,
    field: &'static str,
    type_index: u8,
    versions: &'static [u8],
) -> SerReadRule {
    SerReadRule {
        file_prefix,
        field,
        type_index,
        versions,
    }
}

/// Relay frames the message vectors do not cover, in the relay's wire form.
const FIXED_FRAMES: &[&str] = &[
    r#"{"type":"Challenge","str":"7WUDtkSaKyGRUnQ22rE3QUXChV8DmA6NnunDYP4vheTpc"}"#,
    r#"{"type":"Ok"}"#,
    r#"{"type":"Error","kind":"InvalidSignature","description":"Invalid signature."}"#,
    r#"{"type":"GetVersion","str":"3.0.0"}"#,
    r#"{"type":"GetVersion"}"#,
    r#"{"type":"Unsubscribe","address":"esYTimgooNuxKXdEEXJk3fbXoy2HWyyY2CaRXYU8Z8B7fSPyz6YL"}"#,
    "pong",
];

/// Minimal vault files in the layout of `crates/lepic-keychain/src/vault/format.rs`: an empty
/// sealed payload under the smallest and the default Argon2id parameters. They do not decrypt;
/// the target reads the framing only.
fn vault_seeds() -> Vec<Vec<u8>> {
    [(8u32, 1u32, 1u32), (64 * 1024, 3, 1)]
        .into_iter()
        .map(|(memory_kib, iterations, parallelism)| {
            let mut bytes = b"LEPICVLT".to_vec();
            bytes.extend_from_slice(&[1, 1]);
            for value in [memory_kib, iterations, parallelism] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            // Salt, nonce, then a two-byte payload and its tag.
            bytes.extend_from_slice(&[0; 16 + 24 + 2 + 16]);
            bytes
        })
        .collect()
}

fn prefixed(prefix: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut seed = prefix.to_vec();
    seed.extend_from_slice(bytes);
    seed
}

fn read_area(vectors: &Path, area: &str, file_prefix: &str) -> Result<Vec<Value>> {
    read_dir_json(&vectors.join(area), file_prefix)
}

/// The parsed JSON files in `dir` whose names start with `file_prefix`, sorted by name.
fn read_dir_json(dir: &Path, file_prefix: &str) -> Result<Vec<Value>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("could not list {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(file_prefix) && name.ends_with(".json"))
        })
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path)
                .with_context(|| format!("could not read {}", path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("could not parse {}", path.display()))
        })
        .collect()
}

/// Every value stored under `key`, at any depth.
fn values_of<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    let mut found = Vec::new();
    collect_values(value, key, &mut found);
    found
}

fn collect_values<'a>(value: &'a Value, key: &str, found: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            for (name, child) in map {
                if name == key {
                    found.push(child);
                }
                collect_values(child, key, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_values(item, key, found);
            }
        }
        _ => {}
    }
}

/// Every string under `key`, at any depth, as bytes.
fn text_fields(value: &Value, key: &str) -> Vec<Vec<u8>> {
    values_of(value, key)
        .into_iter()
        .filter_map(|value| value.as_str().map(|text| text.as_bytes().to_vec()))
        .collect()
}

/// Every hex string under `key`, at any depth, decoded.
fn hex_fields(value: &Value, key: &str) -> Vec<Vec<u8>> {
    text_fields(value, key)
        .iter()
        .filter_map(|text| decode_hex(text))
        .collect()
}

fn decode_hex(text: &[u8]) -> Option<Vec<u8>> {
    let (pairs, []) = text.as_chunks::<2>() else {
        return None;
    };
    pairs
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn root() -> PathBuf {
        crate::workspace_root().unwrap()
    }

    #[test]
    fn targets_match_the_bins_of_the_fuzz_manifest() {
        let manifest = fs::read_to_string(root().join("fuzz/Cargo.toml")).unwrap();
        let bins: Vec<&str> = manifest
            .split("[[bin]]")
            .skip(1)
            .filter_map(|section| {
                section
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("name = "))
                    .map(|name| name.trim_matches('"'))
            })
            .collect();
        assert_eq!(bins, TARGETS);
    }

    #[test]
    fn every_target_gets_seeds_from_the_repository() {
        for target in TARGETS {
            let seeds = seeds(&root(), target).unwrap();
            assert!(!seeds.is_empty(), "{target} has no seeds");
        }
    }

    #[test]
    fn every_ser_read_rule_finds_a_field() {
        let vectors = root().join("testdata/vectors");
        for rule in SER_READ_RULES {
            let found: usize = read_area(&vectors, "primitives", rule.file_prefix)
                .unwrap()
                .iter()
                .map(|vector| hex_fields(vector, rule.field).len())
                .sum();
            assert!(
                found > 0,
                "{} {} matches nothing",
                rule.file_prefix,
                rule.field
            );
        }
    }

    #[test]
    fn seeds_are_written_as_numbered_files() {
        let corpus = tempfile::tempdir().unwrap();
        let written = write_seeds(&root(), "wallet_seed", corpus.path()).unwrap();
        assert!(written > 0);
        assert!(corpus.path().join("seed-0").is_file());
    }

    #[test]
    fn parses_the_run_length_targets_and_jobs() {
        assert_eq!(
            parse_args(&args(&["--full", "--target", "tx_decode", "--jobs", "4"])).unwrap(),
            Options {
                seconds: FULL_SECONDS,
                targets: vec!["tx_decode"],
                jobs: 4
            }
        );
        let smoke = parse_args(&args(&["--smoke"])).unwrap();
        assert_eq!(smoke.seconds, SMOKE_SECONDS);
        assert_eq!(smoke.targets, TARGETS);
        assert_eq!(smoke.jobs, 1);
    }

    #[test]
    fn rejects_bad_arguments() {
        for bad in [
            &[][..],
            &["--target", "tx_decode"],
            &["--smoke", "--full"],
            &["--smoke", "--target", "nope"],
            &["--smoke", "--jobs", "0"],
            &["--smoke", "--jobs"],
            &["--smoke", "--verbose"],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn runs_in_the_fuzz_workspace_without_the_product_toolchain() {
        let command = run_command(Path::new("/repo/fuzz"), "tx_decode", 60);
        assert_eq!(command.get_program(), "cargo");
        assert_eq!(command.get_current_dir(), Some(Path::new("/repo/fuzz")));
        let removed: Vec<&OsStr> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name)
            .collect();
        for name in TOOLCHAIN_ENV {
            assert!(removed.contains(&OsStr::new(name)), "{name} is inherited");
        }
        let passed: Vec<&OsStr> = command.get_args().collect();
        assert!(passed.starts_with(&[
            OsStr::new("fuzz"),
            OsStr::new("run"),
            OsStr::new("tx_decode"),
        ]));
        assert!(passed.contains(&OsStr::new("-max_total_time=60")));
    }

    #[test]
    fn decodes_hex_and_refuses_anything_else() {
        assert_eq!(decode_hex(b"00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(decode_hex(b""), Some(vec![]));
        assert_eq!(decode_hex(b"abc"), None);
        assert_eq!(decode_hex(b"zz"), None);
    }
}
