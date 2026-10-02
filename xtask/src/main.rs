//! Repository automation, run as `cargo xtask <command>`.

mod check;
mod deps_check;

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};

const USAGE: &str = "usage: cargo xtask <command>

commands:
  check       fmt, clippy, tests, cargo deny and deps-check
  deps-check  crate edges and banned crates against docs/architecture.md";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some((command, _rest)) = args.split_first() else {
        bail!("no command given\n\n{USAGE}");
    };
    let root = workspace_root()?;
    match command.as_str() {
        "check" => check::run(&root),
        "deps-check" => deps_check::run(&root),
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
