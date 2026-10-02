//! Android builds go through `cargo ndk` so the NDK linker, sysroot and API level are set for every
//! C dependency.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::cargo;

/// The lowest Android API level the libraries link against. It must not exceed the host app's
/// `minSdk`.
const ANDROID_API_LEVEL: &str = "24";

/// Host-only packages: the build tool itself and the desktop CLI never ship in a mobile app.
const HOST_ONLY_PACKAGES: &[&str] = &["xtask", "lepic-cli"];

const ANDROID_TARGETS: &[&str] = &[
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
];
const APPLE_TARGETS: &[&str] = &["aarch64-apple-ios", "aarch64-apple-ios-sim"];

const USAGE: &str = "mobile --target <triple> [--release]";

#[derive(Debug, PartialEq, Eq)]
struct Request {
    target: String,
    release: bool,
}

fn parse(args: &[String]) -> Result<Request> {
    let mut target = None;
    let mut release = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                let value = args.next().context("`--target` needs a target triple")?;
                target = Some(value.clone());
            }
            "--release" => release = true,
            other => bail!("unknown argument `{other}`, usage: cargo xtask {USAGE}"),
        }
    }
    let target =
        target.with_context(|| format!("missing `--target`, usage: cargo xtask {USAGE}"))?;
    Ok(Request { target, release })
}

/// The cargo arguments for `request`, or an error when the target is not a supported mobile
/// target or cannot be built on `host_os` (a `std::env::consts::OS` value).
fn cargo_args(request: &Request, host_os: &str) -> Result<Vec<String>> {
    let target = request.target.as_str();
    let mut args: Vec<String> = if ANDROID_TARGETS.contains(&target) {
        ["ndk", "-t", target, "-P", ANDROID_API_LEVEL, "build"]
            .map(String::from)
            .to_vec()
    } else if APPLE_TARGETS.contains(&target) {
        if host_os != "macos" {
            bail!("`{target}` needs the Xcode SDK and builds only on macOS");
        }
        ["build", "--target", target].map(String::from).to_vec()
    } else {
        bail!(
            "`{target}` is not a mobile target, expected one of: {}",
            [ANDROID_TARGETS, APPLE_TARGETS].concat().join(", ")
        );
    };
    args.extend(["--workspace", "--locked"].map(String::from));
    for package in HOST_ONLY_PACKAGES {
        args.extend(["--exclude".to_owned(), (*package).to_owned()]);
    }
    if request.release {
        args.push("--release".to_owned());
    }
    Ok(args)
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let request = parse(args)?;
    let args = cargo_args(&request, std::env::consts::OS)?;
    if args.first().is_some_and(|a| a == "ndk") {
        let found = cargo()
            .args(["ndk", "--version"])
            .output()
            .is_ok_and(|out| out.status.success());
        if !found {
            bail!("`cargo ndk` is not installed; Android builds need cargo-ndk and an Android NDK");
        }
    }
    eprintln!("xtask mobile: cargo {}", args.join(" "));
    let status = cargo()
        .args(&args)
        .current_dir(root)
        .status()
        .with_context(|| format!("could not start `cargo {}`", args.join(" ")))?;
    if !status.success() {
        bail!("mobile build failed: `cargo {}`", args.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    fn request(target: &str, release: bool) -> Request {
        Request {
            target: target.to_owned(),
            release,
        }
    }

    #[test]
    fn parses_target_and_release() {
        let parsed = parse(&strings(&["--release", "--target", "x86_64-linux-android"])).unwrap();
        assert_eq!(parsed, request("x86_64-linux-android", true));
    }

    #[test]
    fn rejects_missing_target_and_unknown_flags() {
        assert!(parse(&[]).is_err());
        assert!(parse(&strings(&["--target"])).is_err());
        assert!(parse(&strings(&["--target", "x86_64-linux-android", "--jobs"])).is_err());
    }

    #[test]
    fn android_builds_through_cargo_ndk_without_host_only_packages() {
        let args = cargo_args(&request("aarch64-linux-android", false), "linux").unwrap();
        assert_eq!(
            args,
            strings(&[
                "ndk",
                "-t",
                "aarch64-linux-android",
                "-P",
                "24",
                "build",
                "--workspace",
                "--locked",
                "--exclude",
                "xtask",
                "--exclude",
                "lepic-cli",
            ])
        );
    }

    #[test]
    fn apple_targets_build_only_on_macos() {
        assert!(cargo_args(&request("aarch64-apple-ios", false), "linux").is_err());
        let args = cargo_args(&request("aarch64-apple-ios-sim", true), "macos").unwrap();
        assert_eq!(
            args.get(..3),
            Some(&strings(&["build", "--target", "aarch64-apple-ios-sim"])[..])
        );
        assert_eq!(args.last().map(String::as_str), Some("--release"));
    }

    #[test]
    fn rejects_non_mobile_targets() {
        assert!(cargo_args(&request("x86_64-unknown-linux-gnu", false), "linux").is_err());
    }
}
