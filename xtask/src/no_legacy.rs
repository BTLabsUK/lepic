// SPDX-License-Identifier: Apache-2.0
//! The crates that build without the legacy formats (ADR 0052): each checks with
//! `--no-default-features`, one package per invocation so no other member's features are
//! unified into it, and its normal dependency tree then holds no legacy crate. The method
//! registry's unit tests run the same way.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::cargo;

/// Crates that build with no legacy crate in their tree. lepic-epicbox is the Epicbox protocol,
/// whose slates are V2/V3 JSON; lepic-wallet keeps its slates at rest as V3 JSON.
pub(crate) const NO_LEGACY_CRATES: &[&str] = &[
    "lepic-primitives",
    "lepic-crypto",
    "lepic-keychain",
    "lepic-slate",
    "lepic-contact",
    "lepic-node",
    "lepic-store",
    "lepic-telemetry",
    "lepic-transport",
    "lepic-peer",
    "lepic-methods",
];

/// The prefix every legacy crate's name starts with.
const LEGACY_PREFIX: &str = "lepic-legacy-";

pub(crate) fn run(root: &Path) -> Result<()> {
    for package in NO_LEGACY_CRATES {
        eprintln!("xtask no-legacy: {package}");
        run_cargo(
            root,
            &["check", "-p", package, "--no-default-features", "--locked"],
        )?;
        let tree = cargo()
            .args([
                "tree",
                "-p",
                package,
                "--no-default-features",
                "--edges",
                "normal",
                "--prefix",
                "none",
                "--locked",
            ])
            .current_dir(root)
            .output()
            .with_context(|| format!("could not start `cargo tree -p {package}`"))?;
        if !tree.status.success() {
            bail!(
                "`cargo tree -p {package}` failed: {}",
                String::from_utf8_lossy(&tree.stderr)
            );
        }
        let legacy = legacy_crates(&String::from_utf8_lossy(&tree.stdout));
        if !legacy.is_empty() {
            bail!(
                "{package} without default features still depends on {}",
                legacy.join(", ")
            );
        }
    }
    eprintln!("xtask no-legacy: lepic-methods unit tests");
    run_cargo(
        root,
        &[
            "test",
            "-p",
            "lepic-methods",
            "--no-default-features",
            "--lib",
            "--locked",
        ],
    )
}

fn run_cargo(root: &Path, args: &[&str]) -> Result<()> {
    let status = cargo()
        .args(args)
        .current_dir(root)
        .status()
        .with_context(|| format!("could not start `cargo {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`cargo {}` failed", args.join(" "));
    }
    Ok(())
}

/// The legacy crates `cargo tree --prefix none` lists, each once.
fn legacy_crates(tree: &str) -> Vec<String> {
    let mut found: Vec<String> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.starts_with(LEGACY_PREFIX))
        .map(str::to_owned)
        .collect();
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_without_legacy_crates_passes() {
        let tree = "lepic-transport v0.3.1 (/repo/crates/lepic-transport)\n\
                    lepic-slate v0.3.1 (/repo/crates/lepic-slate)\n\
                    serde v1.0.0\n";
        assert!(legacy_crates(tree).is_empty());
    }

    #[test]
    fn legacy_crates_are_named_once() {
        let tree = "lepic-methods v0.3.1 (/repo/crates/lepic-methods)\n\
                    lepic-legacy-slate v0.3.1 (/repo/crates/lepic-legacy-slate)\n\
                    lepic-legacy-rpc v0.3.1 (/repo/crates/lepic-legacy-rpc)\n\
                    lepic-legacy-slate v0.3.1 (/repo/crates/lepic-legacy-slate) (*)\n";
        assert_eq!(
            legacy_crates(tree),
            ["lepic-legacy-rpc", "lepic-legacy-slate"]
        );
    }
}
