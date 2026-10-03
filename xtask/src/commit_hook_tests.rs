//! Tests of `.githooks/commit-msg` and of how the commit-lint workflow runs it. The hook is a
//! bash script, so these run on Unix only.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const VALID: &str = "fix(xtask): keep the hook strict\n\nWhy it changed.\n\nSigned-off-by: A Tester <a@example.org>\n";
const FIXUP: &str = "fixup! fix(xtask): keep the hook strict\n";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Runs the hook outside any git repository, so no branch-derived `Refs:` rule applies.
fn hook_accepts(args: &[&str], message: &str) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("COMMIT_EDITMSG");
    fs::write(&file, message).unwrap();
    Command::new("bash")
        .arg(repository().join(".githooks/commit-msg"))
        .args(args)
        .arg(&file)
        .current_dir(dir.path())
        .output()
        .unwrap()
        .status
        .success()
}

#[test]
fn hook_accepts_autosquash_subjects_locally() {
    assert!(hook_accepts(&[], FIXUP));
    assert!(hook_accepts(&[], "squash! fix(xtask): a\n"));
}

#[test]
fn hook_refuses_autosquash_subjects_with_no_autosquash() {
    for subject in [FIXUP, "squash! fix(xtask): a\n", "amend! fix(xtask): a\n"] {
        assert!(!hook_accepts(&["--no-autosquash"], subject), "{subject}");
    }
    assert!(hook_accepts(&["--no-autosquash"], VALID));
}

#[test]
fn commit_lint_relints_edited_titles_with_the_base_branch_hook() {
    let workflow =
        fs::read_to_string(repository().join(".github/workflows/commit-lint.yml")).unwrap();
    let types = workflow
        .lines()
        .find(|line| line.trim_start().starts_with("types:"))
        .unwrap();
    assert!(types.contains("edited"), "{types}");
    assert!(workflow.contains("git show \"$BASE_SHA:.githooks/commit-msg\""));
    assert!(workflow.contains("\"$HOOK\" --subject \"$TITLE\""));
    assert!(workflow.contains("\"$HOOK\" --no-autosquash \"$message\""));
    // The head branch's copy of the hook must never run.
    assert!(!workflow.contains(".githooks/commit-msg \""));
    let ci = fs::read_to_string(repository().join(".github/workflows/ci.yml")).unwrap();
    assert!(!ci.contains(".githooks/commit-msg"));
}
