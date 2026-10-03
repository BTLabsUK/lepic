//! `cargo xtask soak`: the randomized differential soak in `conformance/differential`. Each
//! iteration runs one seeded scenario against the reference wallet; iteration `i` uses seed
//! `seed + i`, so a failing seed replays on its own with `--iterations 1 --seed <seed>`.

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: cargo xtask soak --iterations <n> [--seed <s>] [--jobs <j>]";

// Environment that rustup and the outer cargo set for this process. Each one would make the nested
// build use the product toolchain instead of the one `conformance/rust-toolchain.toml` pins.
const TOOLCHAIN_ENV: &[&str] = &["RUSTUP_TOOLCHAIN", "CARGO", "RUSTC", "RUSTDOC"];

#[derive(Debug, PartialEq, Eq)]
struct Request {
    iterations: u64,
    seed: Option<u64>,
    jobs: Option<u64>,
}

fn parse(args: &[String]) -> Result<Request> {
    let mut iterations = None;
    let mut seed = None;
    let mut jobs = None;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let slot = match flag.as_str() {
            "--iterations" => &mut iterations,
            "--seed" => &mut seed,
            "--jobs" => &mut jobs,
            other => bail!("unknown argument `{other}`\n\n{USAGE}"),
        };
        let Some(value) = rest.next() else {
            bail!("{flag} needs a value\n\n{USAGE}");
        };
        let value = value
            .parse::<u64>()
            .with_context(|| format!("{flag} takes a whole number, not `{value}`"))?;
        if slot.replace(value).is_some() {
            bail!("{flag} given twice\n\n{USAGE}");
        }
    }
    let Some(iterations) = iterations.filter(|&n| n > 0) else {
        bail!("--iterations must be given and above zero\n\n{USAGE}");
    };
    if jobs == Some(0) {
        bail!("--jobs must be above zero\n\n{USAGE}");
    }
    Ok(Request {
        iterations,
        seed,
        jobs,
    })
}

/// A seed for a run that names none, printed so the run can be repeated.
fn fresh_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn soak_command(root: &Path, request: &Request, seed: u64) -> Command {
    // The rustup proxy, not `cargo()`, so the conformance toolchain file takes effect.
    let mut command = Command::new("cargo");
    for name in TOOLCHAIN_ENV {
        command.env_remove(name);
    }
    command
        .current_dir(root.join("conformance"))
        .env("LEPIC_SOAK_ITERATIONS", request.iterations.to_string())
        .env("LEPIC_SOAK_SEED", seed.to_string())
        .args([
            "test",
            "--release",
            "--locked",
            "--package",
            "differential",
            "--test",
            "soak",
            "--",
            "--ignored",
            "--exact",
            "soak",
            "--nocapture",
        ]);
    if let Some(jobs) = request.jobs {
        command.env("LEPIC_SOAK_JOBS", jobs.to_string());
    }
    command
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let request = parse(args)?;
    let seed = request.seed.unwrap_or_else(fresh_seed);
    eprintln!(
        "xtask soak: {} iterations from seed {seed}; building the conformance workspace in release",
        request.iterations
    );
    let status = soak_command(root, &request, seed)
        .status()
        .context("could not start the differential soak")?;
    if !status.success() {
        bail!(
            "soak failed; the failing seeds are listed above, replay one with \
             `cargo xtask soak --iterations 1 --seed <seed>`"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|&arg| arg.to_owned()).collect()
    }

    #[test]
    fn parses_iterations_seed_and_jobs() {
        assert_eq!(
            parse(&strings(&[
                "--iterations",
                "1000",
                "--seed",
                "7",
                "--jobs",
                "8"
            ]))
            .unwrap(),
            Request {
                iterations: 1000,
                seed: Some(7),
                jobs: Some(8),
            }
        );
        assert_eq!(
            parse(&strings(&["--iterations", "3"])).unwrap(),
            Request {
                iterations: 3,
                seed: None,
                jobs: None,
            }
        );
    }

    #[test]
    fn rejects_missing_zero_repeated_and_unknown_arguments() {
        for args in [
            &[][..],
            &["--seed", "1"][..],
            &["--iterations", "0"][..],
            &["--iterations"][..],
            &["--iterations", "ten"][..],
            &["--iterations", "1", "--iterations", "2"][..],
            &["--iterations", "1", "--jobs", "0"][..],
            &["--iterations", "1", "--fast"][..],
        ] {
            assert!(parse(&strings(args)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn runs_the_ignored_soak_test_in_conformance_without_the_product_toolchain() {
        let request = Request {
            iterations: 5,
            seed: None,
            jobs: Some(2),
        };
        let command = soak_command(Path::new("/repo"), &request, 42);
        assert_eq!(command.get_program(), "cargo");
        assert_eq!(
            command.get_current_dir(),
            Some(Path::new("/repo/conformance"))
        );
        let envs: Vec<(&OsStr, Option<&OsStr>)> = command.get_envs().collect();
        for name in TOOLCHAIN_ENV {
            assert!(
                envs.contains(&(OsStr::new(name), None)),
                "{name} is inherited"
            );
        }
        for (name, value) in [
            ("LEPIC_SOAK_ITERATIONS", "5"),
            ("LEPIC_SOAK_SEED", "42"),
            ("LEPIC_SOAK_JOBS", "2"),
        ] {
            assert!(
                envs.contains(&(OsStr::new(name), Some(OsStr::new(value)))),
                "{name}"
            );
        }
        let args: Vec<&OsStr> = command.get_args().collect();
        assert!(args.contains(&OsStr::new("--release")));
        assert!(args.ends_with(&[
            OsStr::new("--ignored"),
            OsStr::new("--exact"),
            OsStr::new("soak"),
            OsStr::new("--nocapture"),
        ]));
    }
}
