// SPDX-License-Identifier: Apache-2.0
//! Windows: keeps a file to the account that runs the wallet. `unsafe` is denied, so this asks
//! `whoami` and `icacls` from `System32`, which every Windows has, instead of calling the
//! security API, as the CLI asks `stty` for terminal echo.
//!
//! The file gets a protected access list of two entries, full control for the process's user
//! (by SID, never by name) and for `SYSTEM`; inherited entries, such as `Administrators` from the
//! profile folder, are dropped. The grant runs first, so a failure halfway leaves the user with
//! access. A file that already has no inherited entry is left as it is.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

/// `SYSTEM`: Windows itself, backup and the file indexer run as it.
const SYSTEM_SID: &str = "S-1-5-18";

pub(super) fn restrict(path: &Path) -> io::Result<()> {
    let listed = icacls([path.as_os_str()])?;
    if !inherits(&String::from_utf8_lossy(&listed.stdout)) {
        return Ok(());
    }
    let sid = user_sid()?;
    let grant_user = format!("*{sid}:F");
    let grant_system = format!("*{SYSTEM_SID}:F");
    icacls([
        path.as_os_str(),
        OsStr::new("/grant:r"),
        OsStr::new(&grant_user),
        OsStr::new(&grant_system),
        OsStr::new("/q"),
    ])?;
    icacls([
        path.as_os_str(),
        OsStr::new("/inheritance:r"),
        OsStr::new("/q"),
    ])?;
    Ok(())
}

/// Whether an `icacls` listing shows an inherited entry, marked `(I)` in every language.
fn inherits(listing: &str) -> bool {
    listing.contains("(I)")
}

/// The SID of the process's user, asked once.
fn user_sid() -> io::Result<String> {
    static SID: OnceLock<Option<String>> = OnceLock::new();
    SID.get_or_init(|| {
        let out = run("whoami.exe", ["/user", "/fo", "csv", "/nh"].map(OsStr::new)).ok()?;
        parse_sid(&String::from_utf8_lossy(&out.stdout))
    })
    .clone()
    .ok_or_else(|| io::Error::other("the user's SID is not known"))
}

/// The SID in `whoami /user /fo csv /nh` output: `"host\user","S-1-5-21-…"`.
fn parse_sid(csv: &str) -> Option<String> {
    let sid = csv.trim().rsplit(',').next()?.trim_matches('"');
    let parts = sid.strip_prefix("S-1-")?;
    let valid = sid.len() <= 184
        && parts
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    valid.then(|| sid.to_owned())
}

fn icacls<'a>(args: impl IntoIterator<Item = &'a OsStr>) -> io::Result<Output> {
    run("icacls.exe", args)
}

/// Runs `System32\<tool>` (never one found on the `PATH`) and fails on a non-zero exit.
fn run<'a>(tool: &str, args: impl IntoIterator<Item = &'a OsStr>) -> io::Result<Output> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let program: PathBuf = [root.as_os_str(), OsStr::new("System32"), OsStr::new(tool)]
        .iter()
        .collect();
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    if out.status.success() {
        Ok(out)
    } else {
        Err(io::Error::other(format!(
            "{tool} exited with {}",
            out.status
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_is_read_from_whoami_csv() {
        assert_eq!(
            parse_sid("\"desktop-1\\\\rig\",\"S-1-5-21-1004336348-1177238915-682003330-1001\"\r\n")
                .as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        assert_eq!(parse_sid(""), None);
        assert_eq!(parse_sid("\"a\",\"S-1-5-21-x\""), None);
        assert_eq!(parse_sid("\"a\",\"S-1-\""), None);
        assert_eq!(parse_sid("\"a\",\"S-1-5-18 /grant\""), None);
    }

    #[test]
    fn inherited_entries_are_seen() {
        assert!(inherits("C:\\w\\db NT AUTHORITY\\SYSTEM:(I)(F)\r\n"));
        assert!(!inherits(
            "C:\\w\\db NT AUTHORITY\\SYSTEM:(F)\r\n  host\\rig:(F)\r\n"
        ));
    }
}
