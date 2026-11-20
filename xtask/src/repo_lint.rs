// SPDX-License-Identifier: Apache-2.0
//! `cargo xtask repo-lint`: repository rules that neither the compiler nor cargo-deny can check.
//! Each gate returns its findings; this module only gathers the inputs and reports.

mod bridge;
mod home_paths;
mod interop;
mod lints;
mod pure;
mod secp;

use std::fmt::Display;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::sources::repository_files;
use crate::vectors::workspace_metadata;

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut findings: Vec<String> = Vec::new();
    let mut report = |gate: &str, items: Vec<Box<dyn Display>>| {
        findings.extend(items.into_iter().map(|item| format!("{gate}: {item}")));
    };

    let metadata = workspace_metadata(root)?;
    let root_manifest = read(&root.join("Cargo.toml"))?;
    let mut members = Vec::new();
    for package in metadata.members() {
        let manifest = read(Path::new(&package.manifest_path))?;
        members.push(lints::Member {
            name: package.name.clone(),
            manifest,
        });
    }
    let rust_sources = repository_files(root, &["crates/*.rs", "xtask/*.rs"])?;
    report(
        "lints",
        boxed(lints::check(&root_manifest, &members, &rust_sources)),
    );

    let pure_sources = repository_files(root, &pure::SOURCE_PATHSPECS)?;
    report("pure", boxed(pure::check_sources(&pure_sources)));

    let lockfile = read(&root.join("Cargo.lock"))?;
    report("secp", boxed(secp::check(&lockfile)));

    let bridge_api = repository_files(root, &[bridge::API_DIR])?;
    let bridge_generated = repository_files(root, &[bridge::GENERATED_FILE])?;
    let bridge_manifest_path = root.join(bridge::MANIFEST_FILE);
    let bridge_manifest = if bridge_manifest_path.is_file() {
        Some(read(&bridge_manifest_path)?)
    } else {
        None
    };
    report(
        "bridge",
        boxed(bridge::check(
            &bridge_api,
            bridge_generated.first(),
            bridge_manifest.as_deref(),
            &lockfile,
        )),
    );

    let text_files = repository_files(root, &home_paths::PATHSPECS)?;
    report("home-paths", boxed(home_paths::check(&text_files)));

    let interop_files = repository_files(root, &["interop"])?;
    report("interop", boxed(interop::check(&interop_files)));

    if findings.is_empty() {
        eprintln!("repo-lint: ok");
        return Ok(());
    }
    for finding in &findings {
        eprintln!("repo-lint: {finding}");
    }
    bail!("{} repository rule violation(s)", findings.len())
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn boxed<T: Display + 'static>(items: Vec<T>) -> Vec<Box<dyn Display>> {
    items
        .into_iter()
        .map(|item| Box::new(item) as Box<dyn Display>)
        .collect()
}
