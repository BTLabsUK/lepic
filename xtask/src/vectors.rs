//! `cargo xtask vectors`: golden vector generation and replay (ADR 0009).

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::cargo;

const USAGE: &str =
    "usage: cargo xtask vectors generate [--area <area>] | cargo xtask vectors verify";

const VECTOR_TEST: &str = "vectors";

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

/// Runs the generator in the conformance workspace; it validates its own arguments.
fn generate(root: &Path, args: &[String]) -> Result<()> {
    let status = generator_command(root, args)
        .status()
        .context("could not start the conformance vector generator")?;
    if !status.success() {
        bail!("vector generation failed");
    }
    Ok(())
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
    fn rejects_unknown_subcommands_and_extra_verify_arguments() {
        let root = Path::new("/nonexistent");
        assert!(run(root, &["regen".to_owned()]).is_err());
        assert!(run(root, &["verify".to_owned(), "--area".to_owned()]).is_err());
        assert!(run(root, &[]).is_err());
    }
}
