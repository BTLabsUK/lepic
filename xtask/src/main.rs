// SPDX-License-Identifier: Apache-2.0
//! Repository automation, run as `cargo xtask <command>`.

mod budget;
mod check;
mod ci_lint;
#[cfg(test)]
mod commit_hook_tests;
mod deps_check;
mod fuzz;
mod install;
mod lockfiles;
mod mobile;
mod repo_lint;
mod soak;
mod sources;
mod upstream;
mod vectors;

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: cargo xtask <command>

commands:
  budget      [--measurements <file.json>]: size, restore and drain against docs/budgets.md
  check       fmt, clippy, tests, cargo deny, deps-check, ci-lint, repo-lint, the conformance
              and fuzz lockfiles, and vectors verify
  ci-lint     workflow pins, read-only token permissions and checkout credentials
  deps-check  crate edges and banned crates against docs/architecture.md
  fuzz        (--smoke | --full) [--target <name>]... [--jobs <n>]: seed and run the fuzz targets
  install     [--dir <directory>]: build release lepic and install it, default ~/.local/bin
  mobile      --target <triple> [--release]: build the library crates for a mobile target
              --package [--mock] [--out <dir>] [--target <triple>]...: build release
              lepic-ffi into <dir>/<triple>/ with a SHA256SUMS, default dist/native; --mock adds
              the scripted node and relay, default dist/native-mock; --no-tor leaves the
              wallet's tor out (ADR 0026), default dist/native-no-tor
  repo-lint   workspace lints and unsafe code, pure crates, the vendored secp256k1-zkp, the bridge
              fingerprint in crates/lepic-ffi/bridge.sha256, interop images
  soak        --iterations <n> [--seed <s>] [--jobs <j>]: randomized differential soak
  upstream-drift
              upstream commits since the ones recorded in upstream.toml
  vectors     generate [--area <area>] golden vectors, or verify them";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error:#}");
            if error.is::<upstream::DriftFound>() {
                ExitCode::from(upstream::DRIFT_EXIT_CODE)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        bail!("no command given\n\n{USAGE}");
    };
    let root = workspace_root()?;
    match command.as_str() {
        "budget" => budget::run(&root, rest),
        "check" => check::run(&root),
        "ci-lint" => ci_lint::run(&root),
        "deps-check" => deps_check::run(&root),
        "fuzz" => fuzz::run(&root, rest),
        "install" => install::run(&root, rest),
        "mobile" => mobile::run(&root, rest),
        "repo-lint" => repo_lint::run(&root),
        "soak" => soak::run(&root, rest),
        "upstream-drift" => upstream::run(&root),
        "vectors" => vectors::run(&root, rest),
        other => bail!("unknown command `{other}`\n\n{USAGE}"),
    }
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("xtask manifest directory has no parent")
}

/// The cargo that runs xtask, so every step uses the pinned toolchain.
pub(crate) fn cargo() -> Command {
    Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}
