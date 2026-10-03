//! Android builds go through `cargo ndk` so the NDK linker, sysroot and API level are set for every
//! C dependency.
//!
//! `--package` builds the `lepic-ffi` shared library in release mode and copies it to
//! `bindings/flutter/native/<triple>/`, where the Dart package's build hook picks it up.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::cargo;

/// The lowest Android API level the libraries link against. It must not exceed the host app's
/// `minSdk`; `bindings/flutter/hook/build.dart` checks the same value.
const ANDROID_API_LEVEL: &str = "24";

/// Host-only packages: the build tool itself and the desktop CLI never ship in a mobile app.
const HOST_ONLY_PACKAGES: &[&str] = &["xtask", "lepic-cli"];

/// The package the Flutter app loads, and the library file stem flutter_rust_bridge opens.
const FFI_PACKAGE: &str = "lepic-ffi";
const FFI_LIBRARY_STEM: &str = "lepic_ffi";

/// Where `--package` puts the libraries, relative to the workspace root.
const PACKAGE_NATIVE_DIR: &str = "bindings/flutter/native";

const ANDROID_TARGETS: &[&str] = &[
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
];
const APPLE_TARGETS: &[&str] = &["aarch64-apple-ios", "aarch64-apple-ios-sim"];

const USAGE: &str =
    "mobile --target <triple> [--release] | mobile --package [--target <triple>]...";

#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// Check that the library crates build for one target.
    Build { target: String, release: bool },
    /// Build the `lepic-ffi` release library for each target and copy it into the Dart package.
    /// An empty list means every target the host can build.
    Package { targets: Vec<String> },
}

fn parse(args: &[String]) -> Result<Request> {
    let mut targets = Vec::new();
    let mut release = false;
    let mut package = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                let value = args.next().context("`--target` needs a target triple")?;
                targets.push(value.clone());
            }
            "--release" => release = true,
            "--package" => package = true,
            other => bail!("unknown argument `{other}`, usage: cargo xtask {USAGE}"),
        }
    }
    if package {
        if release {
            bail!("`--package` always builds in release mode; drop `--release`");
        }
        return Ok(Request::Package { targets });
    }
    let mut targets = targets.into_iter();
    let (Some(target), None) = (targets.next(), targets.next()) else {
        bail!("give exactly one `--target`, usage: cargo xtask {USAGE}");
    };
    Ok(Request::Build { target, release })
}

/// The targets `--package` builds when none is named: Android everywhere, iOS on macOS too.
fn default_package_targets(host_os: &str) -> Vec<String> {
    let mut targets = ANDROID_TARGETS.to_vec();
    if host_os == "macos" {
        targets.extend(APPLE_TARGETS);
    }
    targets.into_iter().map(String::from).collect()
}

/// The start of the cargo command for `target`, up to and including `build`, or an error when the
/// target is not a supported mobile target or cannot be built on `host_os` (a
/// `std::env::consts::OS` value).
fn cargo_build_prefix(target: &str, host_os: &str) -> Result<Vec<String>> {
    if ANDROID_TARGETS.contains(&target) {
        return Ok(["ndk", "-t", target, "-P", ANDROID_API_LEVEL, "build"]
            .map(String::from)
            .to_vec());
    }
    if APPLE_TARGETS.contains(&target) {
        if host_os != "macos" {
            bail!("`{target}` needs the Xcode SDK and builds only on macOS");
        }
        return Ok(["build", "--target", target].map(String::from).to_vec());
    }
    bail!(
        "`{target}` is not a mobile target, expected one of: {}",
        [ANDROID_TARGETS, APPLE_TARGETS].concat().join(", ")
    )
}

/// The cargo arguments that check the library crates build for `target`.
fn build_args(target: &str, release: bool, host_os: &str) -> Result<Vec<String>> {
    let mut args = cargo_build_prefix(target, host_os)?;
    args.extend(["--workspace", "--locked"].map(String::from));
    for package in HOST_ONLY_PACKAGES {
        args.extend(["--exclude".to_owned(), (*package).to_owned()]);
    }
    if release {
        args.push("--release".to_owned());
    }
    Ok(args)
}

/// The cargo arguments that build the shipped `lepic-ffi` library for `target`.
fn package_args(target: &str, host_os: &str) -> Result<Vec<String>> {
    let mut args = cargo_build_prefix(target, host_os)?;
    args.extend(["--package", FFI_PACKAGE, "--lib", "--locked", "--release"].map(String::from));
    Ok(args)
}

/// The file name of the shared library flutter_rust_bridge loads on `target`.
fn shared_library_name(target: &str) -> String {
    if APPLE_TARGETS.contains(&target) {
        format!("lib{FFI_LIBRARY_STEM}.dylib")
    } else {
        format!("lib{FFI_LIBRARY_STEM}.so")
    }
}

fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

fn run_cargo(root: &Path, args: &[String]) -> Result<()> {
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
        .args(args)
        .current_dir(root)
        .status()
        .with_context(|| format!("could not start `cargo {}`", args.join(" ")))?;
    if !status.success() {
        bail!("mobile build failed: `cargo {}`", args.join(" "));
    }
    Ok(())
}

/// Copies the built library for `target` into `native_dir/<target>/` and returns its new path.
fn copy_into_package(target_dir: &Path, native_dir: &Path, target: &str) -> Result<PathBuf> {
    let name = shared_library_name(target);
    let built = target_dir.join(target).join("release").join(&name);
    let destination_dir = native_dir.join(target);
    fs::create_dir_all(&destination_dir)
        .with_context(|| format!("could not create `{}`", destination_dir.display()))?;
    let destination = destination_dir.join(&name);
    fs::copy(&built, &destination).with_context(|| {
        format!(
            "could not copy `{}` to `{}`",
            built.display(),
            destination.display()
        )
    })?;
    Ok(destination)
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let host_os = std::env::consts::OS;
    match parse(args)? {
        Request::Build { target, release } => {
            run_cargo(root, &build_args(&target, release, host_os)?)
        }
        Request::Package { targets } => {
            let targets = if targets.is_empty() {
                default_package_targets(host_os)
            } else {
                targets
            };
            // Reject every unbuildable target before spending minutes on the first build.
            let commands = targets
                .iter()
                .map(|target| package_args(target, host_os))
                .collect::<Result<Vec<_>>>()?;
            let target_dir = target_dir(root);
            let native_dir = root.join(PACKAGE_NATIVE_DIR);
            for (target, args) in targets.iter().zip(commands) {
                run_cargo(root, &args)?;
                let packaged = copy_into_package(&target_dir, &native_dir, target)?;
                eprintln!("xtask mobile: packaged {}", packaged.display());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn parses_target_and_release() {
        let parsed = parse(&strings(&["--release", "--target", "x86_64-linux-android"])).unwrap();
        assert_eq!(
            parsed,
            Request::Build {
                target: "x86_64-linux-android".to_owned(),
                release: true
            }
        );
    }

    #[test]
    fn rejects_missing_target_and_unknown_flags() {
        assert!(parse(&[]).is_err());
        assert!(parse(&strings(&["--target"])).is_err());
        assert!(parse(&strings(&["--target", "x86_64-linux-android", "--jobs"])).is_err());
    }

    #[test]
    fn plain_build_takes_exactly_one_target() {
        let two = strings(&[
            "--target",
            "x86_64-linux-android",
            "--target",
            "aarch64-linux-android",
        ]);
        assert!(parse(&two).is_err());
    }

    #[test]
    fn package_takes_any_number_of_targets_and_no_release_flag() {
        assert_eq!(
            parse(&strings(&["--package"])).unwrap(),
            Request::Package { targets: vec![] }
        );
        let two = strings(&[
            "--package",
            "--target",
            "aarch64-apple-ios",
            "--target",
            "aarch64-apple-ios-sim",
        ]);
        assert_eq!(
            parse(&two).unwrap(),
            Request::Package {
                targets: strings(&["aarch64-apple-ios", "aarch64-apple-ios-sim"])
            }
        );
        assert!(parse(&strings(&["--package", "--release"])).is_err());
    }

    #[test]
    fn package_defaults_to_android_off_macos_and_adds_ios_on_macos() {
        assert_eq!(default_package_targets("linux"), strings(ANDROID_TARGETS));
        assert_eq!(
            default_package_targets("macos"),
            strings(&[ANDROID_TARGETS, APPLE_TARGETS].concat())
        );
    }

    #[test]
    fn android_builds_through_cargo_ndk_without_host_only_packages() {
        let args = build_args("aarch64-linux-android", false, "linux").unwrap();
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
    fn package_builds_only_the_ffi_library_in_release() {
        let args = package_args("x86_64-linux-android", "linux").unwrap();
        assert_eq!(
            args,
            strings(&[
                "ndk",
                "-t",
                "x86_64-linux-android",
                "-P",
                "24",
                "build",
                "--package",
                "lepic-ffi",
                "--lib",
                "--locked",
                "--release",
            ])
        );
    }

    #[test]
    fn apple_targets_build_only_on_macos() {
        assert!(build_args("aarch64-apple-ios", false, "linux").is_err());
        assert!(package_args("aarch64-apple-ios", "linux").is_err());
        let args = build_args("aarch64-apple-ios-sim", true, "macos").unwrap();
        assert_eq!(
            args.get(..3),
            Some(&strings(&["build", "--target", "aarch64-apple-ios-sim"])[..])
        );
        assert_eq!(args.last().map(String::as_str), Some("--release"));
    }

    #[test]
    fn rejects_non_mobile_targets() {
        assert!(build_args("x86_64-unknown-linux-gnu", false, "linux").is_err());
        assert!(package_args("x86_64-unknown-linux-gnu", "linux").is_err());
    }

    #[test]
    fn library_names_match_the_flutter_rust_bridge_stem() {
        assert_eq!(
            shared_library_name("aarch64-linux-android"),
            "liblepic_ffi.so"
        );
        assert_eq!(
            shared_library_name("aarch64-apple-ios"),
            "liblepic_ffi.dylib"
        );
    }

    #[test]
    fn copies_the_release_library_into_the_target_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("target");
        let built = target_dir.join("x86_64-linux-android/release");
        fs::create_dir_all(&built).unwrap();
        fs::write(built.join("liblepic_ffi.so"), b"elf").unwrap();
        let native_dir = dir.path().join("native");

        let packaged = copy_into_package(&target_dir, &native_dir, "x86_64-linux-android").unwrap();

        assert_eq!(
            packaged,
            native_dir.join("x86_64-linux-android/liblepic_ffi.so")
        );
        assert_eq!(fs::read(packaged).unwrap(), b"elf");
    }

    #[test]
    fn copy_fails_when_the_library_was_not_built() {
        let dir = tempfile::tempdir().unwrap();
        let result = copy_into_package(dir.path(), &dir.path().join("native"), "aarch64-apple-ios");
        assert!(result.is_err());
    }
}
