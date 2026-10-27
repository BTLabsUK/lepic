//! Android builds go through `cargo ndk` so the NDK linker, sysroot and API level are set for every
//! C dependency.
//!
//! `--package` builds the `lepic-ffi` shared library in release mode and copies it, with a
//! `SHA256SUMS` manifest, to `<out>/<triple>/`, by default `dist/native/` in the workspace. The
//! Flutter binding, which lives in its own repository, runs it with its own `--out` and its build
//! hook checks the manifest before bundling the library. Besides the mobile targets it builds the
//! Linux desktop library, on a Linux host only, which links against that host's glibc, and the
//! Windows desktop library, on a Windows host only, with the MSVC toolchain.
//!
//! `--package --mock` builds the same library with the in-process scripted node and Epicbox relay
//! (the `mock` feature) for the binding's own tests, by default into `dist/native-mock/` so it
//! never mixes with the libraries an app ships.
//!
//! `--package --no-tor` builds the library without its default `tor` feature (ADR 0026): no
//! `lepic-tor` in it, by default into `dist/native-no-tor/` (`dist/native-mock-no-tor/` with
//! `--mock`). Next to every library a `FEATURES` file lists the `lepic-ffi` features it was
//! built with, one per line, so the binding's build hook can tell the two builds apart.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::cargo;

/// The lowest Android API level the libraries link against. It must not exceed the host app's
/// `minSdk`; the binding's build hook checks the same value.
const ANDROID_API_LEVEL: &str = "24";

/// Host-only packages: the build tool itself and the desktop CLI never ship in a mobile app.
const HOST_ONLY_PACKAGES: &[&str] = &["xtask", "lepic-cli"];

/// The package the app loads, and the library file stem flutter_rust_bridge opens.
const FFI_PACKAGE: &str = "lepic-ffi";
const FFI_LIBRARY_STEM: &str = "lepic_ffi";

/// Where `--package` puts the libraries without `--out`, relative to the workspace root: the
/// shipped ones, and the `--mock` ones apart from them.
pub(crate) const PACKAGE_NATIVE_DIR: &str = "dist/native";
const MOCK_NATIVE_DIR: &str = "dist/native-mock";
/// What a build without Tor adds to the name of its default directory.
const NO_TOR_SUFFIX: &str = "-no-tor";

/// The checksum file `--package` writes next to each library. The binding's build hook reads it
/// under the same name.
const MANIFEST_FILE: &str = "SHA256SUMS";

/// The file `--package` writes next to each library with the `lepic-ffi` features it has, one
/// per line. The binding's build hook reads it under the same name.
const FEATURES_FILE: &str = "FEATURES";

/// The `lepic-ffi` feature with the in-process scripted node and relay the binding's tests drive.
const MOCK_FEATURE: &str = "mock";

/// The default `lepic-ffi` feature with the wallet's tor; `--no-tor` builds without it.
const TOR_FEATURE: &str = "tor";

const ANDROID_TARGETS: &[&str] = &[
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
];
const APPLE_TARGETS: &[&str] = &["aarch64-apple-ios", "aarch64-apple-ios-sim"];
const LINUX_TARGETS: &[&str] = &["x86_64-unknown-linux-gnu"];
const WINDOWS_TARGETS: &[&str] = &["x86_64-pc-windows-msvc"];

const USAGE: &str = "mobile --target <triple> [--release] \
                     | mobile --package [--mock] [--no-tor] [--out <dir>] [--target <triple>]...";

#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// Check that the library crates build for one target.
    Build { target: String, release: bool },
    /// Build the `lepic-ffi` release library for each target and copy it into `out`, or the
    /// default directory when that is `None`. An empty list means every target the host can
    /// build. `mock` adds the scripted node and relay; `tor` false leaves the wallet's tor out.
    Package {
        targets: Vec<String>,
        out: Option<PathBuf>,
        mock: bool,
        tor: bool,
    },
}

fn parse(args: &[String]) -> Result<Request> {
    let mut targets = Vec::new();
    let mut release = false;
    let mut package = false;
    let mut mock = false;
    let mut tor = true;
    let mut out = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                let value = args.next().context("`--target` needs a target triple")?;
                targets.push(value.clone());
            }
            "--release" => release = true,
            "--package" => package = true,
            "--mock" => mock = true,
            "--no-tor" => tor = false,
            "--out" => {
                let value = args.next().context("`--out` needs a directory")?;
                if out.replace(PathBuf::from(value)).is_some() {
                    bail!("give `--out` once");
                }
            }
            other => bail!("unknown argument `{other}`, usage: cargo xtask {USAGE}"),
        }
    }
    if package {
        if release {
            bail!("`--package` always builds in release mode; drop `--release`");
        }
        return Ok(Request::Package {
            targets,
            out,
            mock,
            tor,
        });
    }
    if mock || !tor || out.is_some() {
        bail!("`--mock`, `--no-tor` and `--out` go with `--package`, usage: cargo xtask {USAGE}");
    }
    let mut targets = targets.into_iter();
    let (Some(target), None) = (targets.next(), targets.next()) else {
        bail!("give exactly one `--target`, usage: cargo xtask {USAGE}");
    };
    Ok(Request::Build { target, release })
}

/// The targets `--package` builds when none is named: Android everywhere, iOS on macOS, Linux on
/// Linux.
fn default_package_targets(host_os: &str) -> Vec<String> {
    let mut targets = ANDROID_TARGETS.to_vec();
    match host_os {
        "macos" => targets.extend(APPLE_TARGETS),
        "linux" => targets.extend(LINUX_TARGETS),
        "windows" => targets.extend(WINDOWS_TARGETS),
        _ => {}
    }
    targets.into_iter().map(String::from).collect()
}

/// The start of the cargo command for `target`, up to and including `build`, or an error when the
/// target is not a supported target or cannot be built on `host_os` (a `std::env::consts::OS`
/// value).
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
    if LINUX_TARGETS.contains(&target) {
        // The library links against the host's glibc, so it is built natively, not cross-built.
        if host_os != "linux" {
            bail!("`{target}` builds only on Linux");
        }
        return Ok(["build", "--target", target].map(String::from).to_vec());
    }
    if WINDOWS_TARGETS.contains(&target) {
        // The library needs the MSVC linker and C compiler for its C dependencies.
        if host_os != "windows" {
            bail!("`{target}` builds only on Windows");
        }
        return Ok(["build", "--target", target].map(String::from).to_vec());
    }
    bail!(
        "`{target}` is not a supported target, expected one of: {}",
        [
            ANDROID_TARGETS,
            APPLE_TARGETS,
            LINUX_TARGETS,
            WINDOWS_TARGETS
        ]
        .concat()
        .join(", ")
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

/// The `lepic-ffi` features a packaged library has: `tor` unless it is left out, and `mock`
/// when it is set.
fn package_features(mock: bool, tor: bool) -> Vec<&'static str> {
    [(tor, TOR_FEATURE), (mock, MOCK_FEATURE)]
        .into_iter()
        .filter_map(|(on, feature)| on.then_some(feature))
        .collect()
}

/// The cargo arguments that build the `lepic-ffi` release library for `target`, with the
/// scripted node and relay when `mock` is set and without the wallet's tor when `tor` is not.
fn package_args(target: &str, mock: bool, tor: bool, host_os: &str) -> Result<Vec<String>> {
    let mut args = cargo_build_prefix(target, host_os)?;
    args.extend(["--package", FFI_PACKAGE, "--lib", "--locked", "--release"].map(String::from));
    if !tor {
        args.push("--no-default-features".to_owned());
    }
    if mock {
        args.extend(["--features".to_owned(), MOCK_FEATURE.to_owned()]);
    }
    Ok(args)
}

/// Where `--package` puts the libraries without `--out`, relative to the workspace root.
fn default_native_dir(mock: bool, tor: bool) -> String {
    let base = if mock {
        MOCK_NATIVE_DIR
    } else {
        PACKAGE_NATIVE_DIR
    };
    if tor {
        base.to_owned()
    } else {
        format!("{base}{NO_TOR_SUFFIX}")
    }
}

/// The file name of the shared library flutter_rust_bridge loads on `target`.
fn shared_library_name(target: &str) -> String {
    if APPLE_TARGETS.contains(&target) {
        format!("lib{FFI_LIBRARY_STEM}.dylib")
    } else if WINDOWS_TARGETS.contains(&target) {
        format!("{FFI_LIBRARY_STEM}.dll")
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

/// Where cargo puts the release library it builds for `target` with `--target`.
fn release_library(target_dir: &Path, target: &str) -> PathBuf {
    target_dir
        .join(target)
        .join("release")
        .join(shared_library_name(target))
}

/// Copies the `built` library for `target` into `native_dir/<target>/` and returns its new path.
fn copy_into_package(built: &Path, native_dir: &Path, target: &str) -> Result<PathBuf> {
    let name = shared_library_name(target);
    let destination_dir = native_dir.join(target);
    fs::create_dir_all(&destination_dir)
        .with_context(|| format!("could not create `{}`", destination_dir.display()))?;
    let destination = destination_dir.join(&name);
    fs::copy(built, &destination).with_context(|| {
        format!(
            "could not copy `{}` to `{}`",
            built.display(),
            destination.display()
        )
    })?;
    Ok(destination)
}

/// Writes the `FEATURES_FILE` next to `library`: the `features` it was built with, one per line.
fn write_features(library: &Path, features: &[&str]) -> Result<PathBuf> {
    let file = library.with_file_name(FEATURES_FILE);
    let text: String = features
        .iter()
        .map(|feature| format!("{feature}\n"))
        .collect();
    fs::write(&file, text).with_context(|| format!("could not write `{}`", file.display()))?;
    Ok(file)
}

/// Writes the `MANIFEST_FILE` next to `library`: its SHA-256 and file name in `sha256sum`
/// format, which the binding's build hook checks before it bundles the library.
fn write_manifest(library: &Path) -> Result<PathBuf> {
    let bytes =
        fs::read(library).with_context(|| format!("could not read `{}`", library.display()))?;
    let name = library
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("`{}` has no file name", library.display()))?;
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let manifest = library.with_file_name(MANIFEST_FILE);
    fs::write(&manifest, format!("{digest}  {name}\n"))
        .with_context(|| format!("could not write `{}`", manifest.display()))?;
    Ok(manifest)
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<()> {
    let host_os = std::env::consts::OS;
    match parse(args)? {
        Request::Build { target, release } => {
            run_cargo(root, &build_args(&target, release, host_os)?)
        }
        Request::Package {
            targets,
            out,
            mock,
            tor,
        } => {
            let targets = if targets.is_empty() {
                default_package_targets(host_os)
            } else {
                targets
            };
            // Reject every unbuildable target before spending minutes on the first build.
            let commands = targets
                .iter()
                .map(|target| package_args(target, mock, tor, host_os))
                .collect::<Result<Vec<_>>>()?;
            let target_dir = target_dir(root);
            // A relative `--out` is relative to where xtask was started, as any path argument.
            let native_dir = match out {
                Some(out) => std::env::current_dir()
                    .context("could not read the current directory")?
                    .join(out),
                None => root.join(default_native_dir(mock, tor)),
            };
            for (target, args) in targets.iter().zip(commands) {
                run_cargo(root, &args)?;
                let packaged =
                    copy_into_package(&release_library(&target_dir, target), &native_dir, target)?;
                write_manifest(&packaged)?;
                write_features(&packaged, &package_features(mock, tor))?;
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
            Request::Package {
                targets: vec![],
                out: None,
                mock: false,
                tor: true
            }
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
                targets: strings(&["aarch64-apple-ios", "aarch64-apple-ios-sim"]),
                out: None,
                mock: false,
                tor: true
            }
        );
        assert!(parse(&strings(&["--package", "--release"])).is_err());
    }

    #[test]
    fn package_takes_one_out_directory_and_the_mock_flag() {
        assert_eq!(
            parse(&strings(&["--package", "--mock", "--out", "test_native"])).unwrap(),
            Request::Package {
                targets: vec![],
                out: Some(PathBuf::from("test_native")),
                mock: true,
                tor: true
            }
        );
        assert!(parse(&strings(&["--package", "--out"])).is_err());
        assert!(parse(&strings(&["--package", "--out", "a", "--out", "b"])).is_err());
    }

    #[test]
    fn package_takes_the_no_tor_flag() {
        assert_eq!(
            parse(&strings(&[
                "--package",
                "--no-tor",
                "--target",
                "x86_64-linux-android"
            ]))
            .unwrap(),
            Request::Package {
                targets: strings(&["x86_64-linux-android"]),
                out: None,
                mock: false,
                tor: false
            }
        );
    }

    #[test]
    fn package_without_tor_drops_the_default_features_into_a_directory_of_its_own() {
        let with_tor = package_args("x86_64-linux-android", false, true, "linux").unwrap();
        let without = package_args("x86_64-linux-android", false, false, "linux").unwrap();
        assert_eq!(
            without.get(with_tor.len()..),
            Some(&strings(&["--no-default-features"])[..])
        );
        let mock_without = package_args("x86_64-linux-android", true, false, "linux").unwrap();
        assert_eq!(
            mock_without.get(with_tor.len()..),
            Some(&strings(&["--no-default-features", "--features", "mock"])[..])
        );
        let dirs = [
            default_native_dir(false, true),
            default_native_dir(false, false),
            default_native_dir(true, true),
            default_native_dir(true, false),
        ];
        assert_eq!(dirs[0], PACKAGE_NATIVE_DIR);
        assert_eq!(dirs[2], MOCK_NATIVE_DIR);
        for (i, dir) in dirs.iter().enumerate() {
            for other in dirs.get(i + 1..).unwrap() {
                assert_ne!(dir, other);
                assert!(!other.starts_with(&format!("{dir}/")));
            }
        }
    }

    #[test]
    fn features_name_tor_unless_it_is_left_out() {
        assert_eq!(package_features(false, true), ["tor"]);
        assert_eq!(package_features(true, true), ["tor", "mock"]);
        assert_eq!(package_features(false, false), Vec::<&str>::new());
        assert_eq!(package_features(true, false), ["mock"]);
    }

    #[test]
    fn mock_and_out_go_with_package_only() {
        for flags in [&["--mock"][..], &["--no-tor"], &["--out", "native"]] {
            let mut args = strings(&["--target", "x86_64-linux-android"]);
            args.extend(strings(flags));
            assert!(
                parse(&args).is_err(),
                "accepted {flags:?} without --package"
            );
        }
    }

    #[test]
    fn mock_libraries_default_apart_from_the_shipped_ones() {
        assert_ne!(MOCK_NATIVE_DIR, PACKAGE_NATIVE_DIR);
        assert!(!MOCK_NATIVE_DIR.starts_with(&format!("{PACKAGE_NATIVE_DIR}/")));
    }

    #[test]
    fn package_defaults_to_android_plus_the_host_desktop_or_ios() {
        assert_eq!(
            default_package_targets("linux"),
            strings(&[ANDROID_TARGETS, LINUX_TARGETS].concat())
        );
        assert_eq!(
            default_package_targets("macos"),
            strings(&[ANDROID_TARGETS, APPLE_TARGETS].concat())
        );
        assert_eq!(
            default_package_targets("windows"),
            strings(&[ANDROID_TARGETS, WINDOWS_TARGETS].concat())
        );
    }

    #[test]
    fn package_builds_the_linux_library_natively_on_linux_only() {
        let args = package_args("x86_64-unknown-linux-gnu", false, true, "linux").unwrap();
        assert_eq!(
            args,
            strings(&[
                "build",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--package",
                "lepic-ffi",
                "--lib",
                "--locked",
                "--release",
            ])
        );
        assert!(package_args("x86_64-unknown-linux-gnu", false, true, "macos").is_err());
        assert!(build_args("x86_64-unknown-linux-gnu", false, "windows").is_err());
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
        let args = package_args("x86_64-linux-android", false, true, "linux").unwrap();
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
        let mock = package_args("x86_64-linux-android", true, true, "linux").unwrap();
        assert_eq!(
            mock.get(args.len()..),
            Some(&strings(&["--features", "mock"])[..])
        );
    }

    #[test]
    fn apple_targets_build_only_on_macos() {
        assert!(build_args("aarch64-apple-ios", false, "linux").is_err());
        assert!(package_args("aarch64-apple-ios", false, true, "linux").is_err());
        let args = build_args("aarch64-apple-ios-sim", true, "macos").unwrap();
        assert_eq!(
            args.get(..3),
            Some(&strings(&["build", "--target", "aarch64-apple-ios-sim"])[..])
        );
        assert_eq!(args.last().map(String::as_str), Some("--release"));
    }

    #[test]
    fn rejects_unsupported_targets() {
        assert!(package_args("aarch64-unknown-linux-gnu", false, true, "linux").is_err());
        assert!(package_args("aarch64-pc-windows-msvc", false, true, "windows").is_err());
    }

    #[test]
    fn package_builds_the_windows_library_natively_on_windows_only() {
        let args = package_args("x86_64-pc-windows-msvc", false, true, "windows").unwrap();
        assert_eq!(
            args.get(..3),
            Some(&strings(&["build", "--target", "x86_64-pc-windows-msvc"])[..])
        );
        assert!(package_args("x86_64-pc-windows-msvc", false, true, "linux").is_err());
        assert!(build_args("x86_64-pc-windows-msvc", false, "macos").is_err());
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
        assert_eq!(
            shared_library_name("x86_64-unknown-linux-gnu"),
            "liblepic_ffi.so"
        );
        assert_eq!(
            shared_library_name("x86_64-pc-windows-msvc"),
            "lepic_ffi.dll"
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

        let packaged = copy_into_package(
            &release_library(&target_dir, "x86_64-linux-android"),
            &native_dir,
            "x86_64-linux-android",
        )
        .unwrap();

        assert_eq!(
            packaged,
            native_dir.join("x86_64-linux-android/liblepic_ffi.so")
        );
        assert_eq!(fs::read(packaged).unwrap(), b"elf");
    }

    #[test]
    fn copy_fails_when_the_library_was_not_built() {
        let dir = tempfile::tempdir().unwrap();
        let result = copy_into_package(
            &release_library(dir.path(), "aarch64-apple-ios"),
            &dir.path().join("native"),
            "aarch64-apple-ios",
        );
        assert!(result.is_err());
    }

    #[test]
    fn writes_the_sha256_manifest_next_to_the_library() {
        let dir = tempfile::tempdir().unwrap();
        let library = dir.path().join("liblepic_ffi.so");
        fs::write(&library, b"abc").unwrap();

        let manifest = write_manifest(&library).unwrap();

        assert_eq!(manifest, dir.path().join("SHA256SUMS"));
        assert_eq!(
            fs::read_to_string(manifest).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  liblepic_ffi.so\n"
        );
    }
}
