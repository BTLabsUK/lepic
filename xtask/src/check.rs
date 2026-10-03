use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{cargo, ci_lint, deps_check};

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
    eprintln!("xtask check: deps-check");
    deps_check::run(root)?;
    eprintln!("xtask check: ci-lint");
    ci_lint::run(root)?;
    eprintln!("xtask check: all steps passed");
    Ok(())
}
