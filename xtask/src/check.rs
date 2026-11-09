// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{cargo, ci_lint, deps_check, lockfiles, no_legacy, repo_lint, vectors};

const STEPS: &[(&str, &[&str])] = &[
    // Run from the workspace root, `cargo fmt` checks every member; `--all` would also check the
    // path dependencies outside the workspace, the vendored secp256k1-zkp among them.
    ("fmt", &["fmt", "--check"]),
    (
        "clippy",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    ),
    // The library without its default `tor` feature (ADR 0026), as `mobile --package --no-tor`
    // builds it, with its tests.
    (
        "clippy without tor",
        &[
            "clippy",
            "--package",
            "lepic-ffi",
            "--all-targets",
            "--no-default-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    ),
    ("test", &["test", "--workspace", "--locked"]),
    ("deny", &["deny", "check"]),
];

type Gate = fn(&Path) -> Result<()>;

pub(crate) fn run(root: &Path) -> Result<()> {
    for (name, args) in STEPS {
        eprintln!("xtask check: {name}");
        let status = cargo()
            .args(*args)
            .current_dir(root)
            .status()
            .with_context(|| format!("could not start `cargo {}`", args.join(" ")))?;
        if !status.success() {
            bail!("step `{name}` failed: `cargo {}`", args.join(" "));
        }
    }
    let gates: &[(&str, Gate)] = &[
        ("deps-check", deps_check::run),
        ("ci-lint", ci_lint::run),
        ("repo-lint", repo_lint::run),
        ("lockfiles", lockfiles::run),
        ("vectors verify", vectors::verify),
        ("no-legacy", no_legacy::run),
    ];
    for (name, gate) in gates {
        eprintln!("xtask check: {name}");
        gate(root).with_context(|| format!("step `{name}` failed"))?;
    }
    eprintln!("xtask check: all steps passed");
    Ok(())
}
