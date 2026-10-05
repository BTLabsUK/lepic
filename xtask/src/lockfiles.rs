//! The separate workspaces build the product crates too, so a product dependency change must
//! update their lockfiles in the same commit. Their scheduled jobs build with `--locked` and
//! would otherwise fail long after the change merged.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::cargo;

const WORKSPACES: &[&str] = &["conformance", "fuzz", "interop/probe"];

pub(crate) fn run(root: &Path) -> Result<()> {
    check(root, WORKSPACES)
}

fn check(root: &Path, workspaces: &[&str]) -> Result<()> {
    for workspace in workspaces {
        // The product cargo, called directly, so the workspace's own toolchain file (nightly for
        // fuzz/) need not be installed to read its lockfile.
        let output = cargo()
            .args(["fetch", "--locked", "--quiet", "--manifest-path"])
            .arg(root.join(workspace).join("Cargo.toml"))
            .current_dir(root)
            .output()
            .with_context(|| format!("could not start `cargo fetch` for {workspace}/"))?;
        if output.status.success() {
            continue;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if says_lockfile_is_stale(&stderr) {
            bail!(
                "{workspace}/Cargo.lock is not up to date; run \
                 `cargo fetch --manifest-path {workspace}/Cargo.toml` and commit the lockfile"
            );
        }
        // Anything else, such as no network for a dependency not fetched yet, says nothing
        // about the lockfile.
        bail!(
            "could not check {workspace}/Cargo.lock: cargo fetch failed: {}",
            stderr.trim()
        );
    }
    Ok(())
}

/// Whether cargo refused to run only because `--locked` forbids rewriting the lockfile. Cargo
/// has worded this both ways.
fn says_lockfile_is_stale(stderr: &str) -> bool {
    stderr.contains("needs to be updated but --locked was passed")
        || stderr.contains("cannot update the lock file")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// A workspace `ws` whose package depends on a path crate, with a lockfile written for it.
    fn workspace(root: &Path) {
        let ws = root.join("ws");
        fs::create_dir_all(ws.join("src")).unwrap();
        fs::create_dir_all(root.join("leaf/src")).unwrap();
        fs::write(
            root.join("leaf/Cargo.toml"),
            "[package]\nname = \"leaf\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("leaf/src/lib.rs"), "").unwrap();
        fs::write(
            ws.join("Cargo.toml"),
            "[package]\nname = \"ws\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
             [dependencies]\nleaf = { path = \"../leaf\" }\n\n[workspace]\n",
        )
        .unwrap();
        fs::write(ws.join("src/lib.rs"), "").unwrap();
        let status = cargo()
            .args([
                "generate-lockfile",
                "--offline",
                "--quiet",
                "--manifest-path",
            ])
            .arg(ws.join("Cargo.toml"))
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn accepts_a_current_lockfile() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path());
        check(root.path(), &["ws"]).unwrap();
    }

    #[test]
    fn rejects_a_lockfile_a_product_change_left_stale() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path());
        let before = fs::read_to_string(root.path().join("ws/Cargo.lock")).unwrap();
        fs::write(
            root.path().join("leaf/Cargo.toml"),
            "[package]\nname = \"leaf\"\nversion = \"0.2.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        let error = check(root.path(), &["ws"]).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("ws/Cargo.lock is not up to date"),
            "{error}"
        );
        let after = fs::read_to_string(root.path().join("ws/Cargo.lock")).unwrap();
        assert_eq!(before, after, "the check rewrote the lockfile");
    }

    #[test]
    fn a_fetch_that_fails_for_another_reason_is_not_called_stale() {
        let root = tempfile::tempdir().unwrap();
        workspace(root.path());
        fs::remove_dir_all(root.path().join("leaf")).unwrap();
        let error = check(root.path(), &["ws"]).unwrap_err().to_string();
        assert!(
            error.starts_with("could not check ws/Cargo.lock: cargo fetch failed"),
            "{error}"
        );
        assert!(error.contains("leaf"), "{error}");
    }

    #[test]
    fn recognises_both_wordings_of_a_stale_lockfile() {
        assert!(says_lockfile_is_stale(
            "error: the lock file /w/Cargo.lock needs to be updated but --locked was passed to \
             prevent this"
        ));
        assert!(says_lockfile_is_stale(
            "error: cannot update the lock file /w/Cargo.lock because --locked was passed"
        ));
        assert!(!says_lockfile_is_stale(
            "error: failed to load manifest for dependency `leaf`"
        ));
    }
}
