// SPDX-License-Identifier: Apache-2.0
//! `cargo xtask vectors`: golden vector generation and replay (ADR 0009).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::cargo;

const USAGE: &str =
    "usage: cargo xtask vectors generate [--area <area>] | cargo xtask vectors verify";

const VECTOR_TEST: &str = "vectors";

/// RFC 0002 has no upstream implementation; its vectors come from the independent Python kit
/// (RFC 0002 section 14), found through this variable or at `~/epic-pairing-kit`.
const PAIRING_AREA: &str = "pairing";
const PAIRING_KIT_ENV: &str = "EPIC_PAIRING_KIT";
const PAIRING_KIT_DEFAULT: &str = "epic-pairing-kit";
const SAS_TABLE: &str = "testdata/sas/emoji-v1.txt";

// Environment that rustup and the outer cargo set for this process. Each one would make the nested
// build use the product toolchain instead of the one `conformance/rust-toolchain.toml` pins.
const TOOLCHAIN_ENV: &[&str] = &["RUSTUP_TOOLCHAIN", "CARGO", "RUSTC", "RUSTDOC"];

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    match args.split_first() {
        Some((command, rest)) if command == "generate" => generate(root, rest),
        Some((command, rest)) if command == "verify" && rest.is_empty() => verify(root),
        _ => bail!("{USAGE}"),
    }
}

/// Runs the generator in the conformance workspace, which validates its own arguments, and the
/// pairing kit for the pairing area.
fn generate(root: &Path, args: &[String]) -> Result<()> {
    let area = args
        .iter()
        .position(|arg| arg == "--area")
        .and_then(|at| args.get(at.saturating_add(1)));
    if area.is_some_and(|area| area == PAIRING_AREA) {
        if args.len() != 2 {
            bail!("usage: cargo xtask vectors generate --area {PAIRING_AREA}");
        }
        return generate_pairing(root);
    }
    let status = generator_command(root, args)
        .status()
        .context("could not start the conformance vector generator")?;
    if !status.success() {
        bail!("vector generation failed");
    }
    if area.is_none() {
        generate_pairing(root)?;
    }
    Ok(())
}

/// Runs the kit's generator into a fresh directory, then replaces the JSON files of the area with
/// its output, so files the kit no longer writes disappear.
fn generate_pairing(root: &Path) -> Result<()> {
    let kit = pairing_kit_dir(std::env::var_os(PAIRING_KIT_ENV), std::env::var_os("HOME"))?;
    let staging =
        std::env::temp_dir().join(format!("lepic-pairing-vectors-{}", std::process::id()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .with_context(|| format!("could not clear {}", staging.display()))?;
    }
    let status = pairing_command(&kit, &staging, &root.join(SAS_TABLE))
        .status()
        .with_context(|| format!("could not start the pairing kit in {}", kit.display()))?;
    if !status.success() {
        bail!("pairing vector generation failed");
    }
    let target = root.join("testdata/vectors").join(PAIRING_AREA);
    std::fs::create_dir_all(&target)?;
    for entry in std::fs::read_dir(&target)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            std::fs::remove_file(&path)
                .with_context(|| format!("could not remove {}", path.display()))?;
        }
    }
    for entry in std::fs::read_dir(&staging)? {
        let path = entry?.path();
        if let Some(name) = path
            .file_name()
            .filter(|_| path.extension().is_some_and(|ext| ext == "json"))
        {
            std::fs::copy(&path, target.join(name))
                .with_context(|| format!("could not copy {}", path.display()))?;
        }
    }
    std::fs::remove_dir_all(&staging)
        .with_context(|| format!("could not remove {}", staging.display()))?;
    eprintln!("xtask vectors: wrote {}", target.display());
    Ok(())
}

fn pairing_kit_dir(configured: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    match (configured, home) {
        (Some(kit), _) => Ok(PathBuf::from(kit)),
        (None, Some(home)) => Ok(PathBuf::from(home).join(PAIRING_KIT_DEFAULT)),
        (None, None) => bail!("neither {PAIRING_KIT_ENV} nor HOME is set"),
    }
}

/// The kit's own virtual environment when it has one: Argon2id needs its pinned `cryptography`.
fn pairing_command(kit: &Path, out: &Path, sas_table: &Path) -> Command {
    let venv = kit.join(".venv/bin/python");
    let python = if venv.is_file() {
        venv.into_os_string()
    } else {
        OsString::from("python3")
    };
    let mut command = Command::new(python);
    command
        .current_dir(kit)
        .args(["-m", "epic_pairing.vectors"])
        .arg(out)
        .arg("--sas-table")
        .arg(sas_table);
    command
}

fn generator_command(root: &Path, args: &[String]) -> Command {
    // The rustup proxy, not `cargo()`, so the conformance toolchain file takes effect.
    let mut command = Command::new("cargo");
    for name in TOOLCHAIN_ENV {
        command.env_remove(name);
    }
    command
        .current_dir(root.join("conformance"))
        .args([
            "run",
            "--quiet",
            "--locked",
            "--package",
            "vectors",
            "--",
            "generate",
        ])
        .args(args);
    command
}

pub(crate) fn verify(root: &Path) -> Result<()> {
    let metadata = workspace_metadata(root)?;
    let packages = packages_to_verify(&metadata)?;
    eprintln!(
        "xtask vectors: replaying vectors of {}",
        packages.join(", ")
    );
    let status = cargo()
        .args(["test", "--workspace", "--locked", "--test", VECTOR_TEST])
        .current_dir(root)
        .status()
        .context("could not start `cargo test`")?;
    if !status.success() {
        bail!("vector tests failed");
    }
    Ok(())
}

#[derive(Deserialize)]
pub(crate) struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
}

impl Metadata {
    pub(crate) fn members(&self) -> impl Iterator<Item = &Package> {
        self.packages
            .iter()
            .filter(|package| self.workspace_members.contains(&package.id))
    }
}

#[derive(Deserialize)]
pub(crate) struct Package {
    id: String,
    pub(crate) name: String,
    pub(crate) manifest_path: String,
    targets: Vec<Target>,
}

#[derive(Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
}

pub(crate) fn workspace_metadata(root: &Path) -> Result<Metadata> {
    let output = cargo()
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(root)
        .output()
        .context("could not start `cargo metadata`")?;
    if !output.status.success() {
        bail!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("could not parse `cargo metadata` output")
}

/// A run that replays nothing would pass while proving nothing, so finding no target is an error.
fn packages_to_verify(metadata: &Metadata) -> Result<Vec<&str>> {
    let packages = packages_with_vector_tests(metadata);
    if packages.is_empty() {
        bail!(
            "no workspace crate has a `{VECTOR_TEST}` test target, so no vector would be replayed"
        );
    }
    Ok(packages)
}

fn packages_with_vector_tests(metadata: &Metadata) -> Vec<&str> {
    metadata
        .members()
        .filter(|package| {
            package.targets.iter().any(|target| {
                target.name == VECTOR_TEST && target.kind.iter().any(|kind| kind == "test")
            })
        })
        .map(|package| package.name.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    fn metadata(json: &str) -> Metadata {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn finds_only_workspace_members_with_a_vectors_test() {
        let metadata = metadata(
            r#"{
                "workspace_members": ["a", "b", "c"],
                "packages": [
                    {"id": "a", "name": "lepic-crypto", "manifest_path": "/a", "targets": [
                        {"name": "lepic_crypto", "kind": ["lib"]},
                        {"name": "vectors", "kind": ["test"]}
                    ]},
                    {"id": "b", "name": "lepic-node", "manifest_path": "/b", "targets": [
                        {"name": "vectors", "kind": ["bin"]}
                    ]},
                    {"id": "c", "name": "lepic-store", "manifest_path": "/c", "targets": [
                        {"name": "store", "kind": ["test"]}
                    ]},
                    {"id": "x", "name": "outside", "manifest_path": "/x", "targets": [
                        {"name": "vectors", "kind": ["test"]}
                    ]}
                ]
            }"#,
        );
        assert_eq!(packages_with_vector_tests(&metadata), ["lepic-crypto"]);
    }

    #[test]
    fn fails_when_no_workspace_member_has_a_vectors_test() {
        let metadata = metadata(
            r#"{
                "workspace_members": ["a"],
                "packages": [
                    {"id": "a", "name": "lepic-crypto", "manifest_path": "/a", "targets": [
                        {"name": "lepic_crypto", "kind": ["lib"]}
                    ]},
                    {"id": "x", "name": "outside", "manifest_path": "/x", "targets": [
                        {"name": "vectors", "kind": ["test"]}
                    ]}
                ]
            }"#,
        );
        assert!(packages_to_verify(&metadata).is_err());
    }

    #[test]
    fn generator_runs_in_conformance_without_the_product_toolchain() {
        let args = ["--area".to_owned(), "smoke".to_owned()];
        let command = generator_command(Path::new("/repo"), &args);

        assert_eq!(command.get_program(), "cargo");
        assert_eq!(
            command.get_current_dir(),
            Some(Path::new("/repo/conformance"))
        );
        let removed: Vec<&OsStr> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name)
            .collect();
        for name in TOOLCHAIN_ENV {
            assert!(removed.contains(&OsStr::new(name)), "{name} is inherited");
        }
        let passed: Vec<&OsStr> = command.get_args().collect();
        assert!(passed.ends_with(&[
            OsStr::new("generate"),
            OsStr::new("--area"),
            OsStr::new("smoke")
        ]));
    }

    #[test]
    fn pairing_kit_comes_from_the_variable_or_home() {
        assert_eq!(
            pairing_kit_dir(Some("/kit".into()), Some("/home/u".into())).unwrap(),
            PathBuf::from("/kit")
        );
        assert_eq!(
            pairing_kit_dir(None, Some("/home/u".into())).unwrap(),
            PathBuf::from("/home/u/epic-pairing-kit")
        );
        assert!(pairing_kit_dir(None, None).is_err());
    }

    #[test]
    fn pairing_generator_runs_the_kit_module_with_the_sas_table() {
        let command = pairing_command(
            Path::new("/no-kit"),
            Path::new("/out"),
            Path::new("/repo/testdata/sas/emoji-v1.txt"),
        );
        assert_eq!(command.get_program(), "python3");
        assert_eq!(command.get_current_dir(), Some(Path::new("/no-kit")));
        let passed: Vec<&OsStr> = command.get_args().collect();
        assert_eq!(
            passed,
            [
                "-m",
                "epic_pairing.vectors",
                "/out",
                "--sas-table",
                "/repo/testdata/sas/emoji-v1.txt"
            ]
        );
    }

    #[test]
    fn rejects_unknown_subcommands_and_extra_verify_arguments() {
        let root = Path::new("/nonexistent");
        assert!(run(root, &["regen".to_owned()]).is_err());
        assert!(run(root, &["verify".to_owned(), "--area".to_owned()]).is_err());
        assert!(run(root, &[]).is_err());
        assert!(
            run(
                root,
                &[
                    "generate".to_owned(),
                    "--area".to_owned(),
                    "pairing".to_owned(),
                    "--out".to_owned()
                ]
            )
            .is_err()
        );
    }
}
