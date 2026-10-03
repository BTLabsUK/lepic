use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{cargo, ci_lint, deps_check, lockfiles, repo_lint, vectors};

const STEPS: &[(&str, &[&str])] = &[
    ("fmt", &["fmt", "--all", "--check"]),
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
    ];
    for (name, gate) in gates {
        eprintln!("xtask check: {name}");
        gate(root).with_context(|| format!("step `{name}` failed"))?;
    }
    eprintln!("xtask check: all steps passed");
    Ok(())
}
