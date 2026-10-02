//! lepic-ffi cannot inherit `[workspace.lints]` because it must permit the unsafe
//! glue flutter_rust_bridge generates, so it carries a copy. This keeps the copy exact.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const WORKSPACE_ONLY: &[&str] = &["unsafe_code"];

fn read(relative: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)).unwrap()
}

/// The `key = value` lines of one TOML table, with whitespace normalised.
fn table(manifest: &str, header: &str) -> BTreeSet<String> {
    manifest
        .lines()
        .skip_while(|line| line.trim() != header)
        .skip(1)
        .map(str::trim)
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_whitespace().collect::<String>())
        .collect()
}

fn lint_name(entry: &str) -> &str {
    entry.split('=').next().unwrap()
}

#[test]
fn ffi_clippy_lints_equal_workspace_clippy_lints() {
    let workspace = table(&read("../Cargo.toml"), "[workspace.lints.clippy]");
    let ffi = table(&read("../crates/lepic-ffi/Cargo.toml"), "[lints.clippy]");
    assert!(!workspace.is_empty());
    assert_eq!(ffi, workspace);
}

#[test]
fn ffi_rust_lints_equal_workspace_rust_lints_without_unsafe_code() {
    let workspace = table(&read("../Cargo.toml"), "[workspace.lints.rust]");
    assert!(
        workspace
            .iter()
            .any(|entry| lint_name(entry) == "unsafe_code")
    );
    let expected: BTreeSet<String> = workspace
        .into_iter()
        .filter(|entry| !WORKSPACE_ONLY.contains(&lint_name(entry)))
        .collect();
    let ffi = table(&read("../crates/lepic-ffi/Cargo.toml"), "[lints.rust]");
    assert_eq!(ffi, expected);
}
