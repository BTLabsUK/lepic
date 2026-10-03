//! `cargo xtask install` builds the release `lepic` binary and copies it into a directory on the
//! user's `PATH`, `~/.local/bin` unless `--dir` names another.
//!
//! The copy goes to a temporary file in the destination directory first and is then renamed
//! over the old binary, so a `lepic` that is running while it is replaced keeps its file and a
//! failed copy never leaves a half-written binary where the shell finds it.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::cargo;

const USAGE: &str = "install [--dir <directory>]";

const BUILD_ARGS: &[&str] = &[
    "build",
    "--release",
    "--locked",
    "--package",
    "lepic-cli",
    "--bin",
    "lepic",
];

#[derive(Debug, PartialEq, Eq)]
struct Request {
    dir: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<Request> {
    let mut dir = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dir" => {
                let value = args.next().context("`--dir` needs a directory")?;
                if dir.replace(PathBuf::from(value)).is_some() {
                    bail!("`--dir` given twice, usage: cargo xtask {USAGE}");
                }
            }
            other => bail!("unknown argument `{other}`, usage: cargo xtask {USAGE}"),
        }
    }
    Ok(Request { dir })
}

/// `~/.local/bin`, from `HOME`, or from `USERPROFILE` where `HOME` is not set.
fn default_dir(home: Option<OsString>, user_profile: Option<OsString>) -> Result<PathBuf> {
    let home = home
        .filter(|value| !value.is_empty())
        .or_else(|| user_profile.filter(|value| !value.is_empty()))
        .context("neither HOME nor USERPROFILE is set; give `--dir`")?;
    Ok(PathBuf::from(home).join(".local").join("bin"))
}

fn binary_name() -> String {
    format!("lepic{}", std::env::consts::EXE_SUFFIX)
}

fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

/// Copies `built` to `dir/<name>` through a temporary file in `dir`, executable by everyone and
/// writable by the owner only, and returns the installed path.
fn install_binary(built: &Path, dir: &Path, name: &str) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("could not create `{}`", dir.display()))?;
    let destination = dir.join(name);
    let staging = dir.join(format!(".{name}.install-{}", std::process::id()));
    let copied = fs::copy(built, &staging)
        .with_context(|| {
            format!(
                "could not copy `{}` to `{}`",
                built.display(),
                staging.display()
            )
        })
        .and_then(|_| make_executable(&staging))
        .and_then(|()| {
            fs::rename(&staging, &destination).with_context(|| {
                format!(
                    "could not move the new binary to `{}`",
                    destination.display()
                )
            })
        });
    if copied.is_err() {
        let _ = fs::remove_file(&staging);
    }
    copied.map(|()| destination)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("could not make `{}` executable", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_: &Path) -> Result<()> {
    Ok(())
}

/// True when `dir` is one of the entries of a `PATH` value.
fn on_path(dir: &Path, path: Option<&OsString>) -> bool {
    path.is_some_and(|path| std::env::split_paths(path).any(|entry| entry == dir))
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let request = parse(args)?;
    let dir = match request.dir {
        Some(dir) => std::path::absolute(&dir)
            .with_context(|| format!("could not resolve `{}`", dir.display()))?,
        None => default_dir(std::env::var_os("HOME"), std::env::var_os("USERPROFILE"))?,
    };

    eprintln!("xtask install: cargo {}", BUILD_ARGS.join(" "));
    let status = cargo()
        .args(BUILD_ARGS)
        .current_dir(root)
        .status()
        .with_context(|| format!("could not start `cargo {}`", BUILD_ARGS.join(" ")))?;
    if !status.success() {
        bail!("release build failed: `cargo {}`", BUILD_ARGS.join(" "));
    }

    let name = binary_name();
    let built = target_dir(root).join("release").join(&name);
    let installed = install_binary(&built, &dir, &name)?;

    let version = Command::new(&installed)
        .arg("--version")
        .output()
        .with_context(|| format!("could not run `{} --version`", installed.display()))?;
    if !version.status.success() {
        bail!("`{} --version` failed", installed.display());
    }
    eprintln!(
        "xtask install: installed {} at {}",
        String::from_utf8_lossy(&version.stdout).trim(),
        installed.display()
    );
    if !on_path(&dir, std::env::var_os("PATH").as_ref()) {
        eprintln!(
            "xtask install: {} is not on PATH; add it to run `lepic` by name",
            dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn parses_an_optional_directory() {
        assert_eq!(parse(&[]).unwrap(), Request { dir: None });
        assert_eq!(
            parse(&strings(&["--dir", "/opt/bin"])).unwrap(),
            Request {
                dir: Some(PathBuf::from("/opt/bin"))
            }
        );
    }

    #[test]
    fn rejects_unknown_missing_and_repeated_arguments() {
        assert!(parse(&strings(&["--release"])).is_err());
        assert!(parse(&strings(&["--dir"])).is_err());
        assert!(parse(&strings(&["--dir", "a", "--dir", "b"])).is_err());
    }

    #[test]
    fn defaults_to_local_bin_under_home_then_user_profile() {
        let home = default_dir(Some("/home/u".into()), Some("C:\\Users\\u".into())).unwrap();
        assert_eq!(home, Path::new("/home/u").join(".local").join("bin"));
        let profile = default_dir(Some("".into()), Some("/profile".into())).unwrap();
        assert_eq!(profile, Path::new("/profile").join(".local").join("bin"));
        assert!(default_dir(None, None).is_err());
    }

    #[test]
    fn builds_only_the_release_lepic_binary_from_the_lockfile() {
        for expected in ["--release", "--locked", "lepic-cli", "lepic"] {
            assert!(BUILD_ARGS.contains(&expected), "{expected}");
        }
    }

    #[test]
    fn installs_into_a_new_directory_and_replaces_an_old_binary() {
        let dir = tempfile::tempdir().unwrap();
        let built = dir.path().join("built");
        let bin = dir.path().join("a/bin");

        fs::write(&built, b"old").unwrap();
        let installed = install_binary(&built, &bin, "lepic").unwrap();
        assert_eq!(installed, bin.join("lepic"));

        fs::write(&built, b"new").unwrap();
        install_binary(&built, &bin, "lepic").unwrap();
        assert_eq!(fs::read(&installed).unwrap(), b"new");
        let left: Vec<_> = fs::read_dir(&bin).unwrap().collect();
        assert_eq!(left.len(), 1, "staging file left behind");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&installed).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    #[test]
    fn a_missing_build_leaves_the_installed_binary_alone() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("lepic"), b"old").unwrap();
        let result = install_binary(&dir.path().join("missing"), dir.path(), "lepic");
        assert!(result.is_err());
        assert_eq!(fs::read(dir.path().join("lepic")).unwrap(), b"old");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn finds_the_directory_among_path_entries() {
        let path = std::env::join_paths(["/usr/bin", "/home/u/.local/bin"]).unwrap();
        assert!(on_path(Path::new("/home/u/.local/bin"), Some(&path)));
        assert!(!on_path(Path::new("/opt/bin"), Some(&path)));
        assert!(!on_path(Path::new("/usr/bin"), None));
    }
}
