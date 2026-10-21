//! Android builds go through `cargo ndk` so the NDK linker, sysroot and API level are set for every
//! C dependency.
//!
//! `--package` builds the `lepic-ffi` shared library in release mode and copies it, with a
//! `SHA256SUMS` manifest, to `bindings/flutter/native/<triple>/`, where the Dart package's build
//! hook checks it and picks it up. Besides the mobile targets it builds the Linux desktop library,
//! on a Linux host only, which links against that host's glibc, and the Windows desktop library,
//! on a Windows host only, with the MSVC toolchain.
//!
//! `--emulator-test` builds the library with the scripted node (`mock`) for the attached Android
//! device's ABI, puts it in the integration test app `bindings/flutter/emulator_test/native/`, and
//! runs `flutter test integration_test` there on that device. Start the emulator first.
//!
//! `--host-test` builds the library with the scripted node for the Linux host, puts it in
//! `bindings/flutter/test_native/`, which the package's own `pubspec.yaml` names as `native_dir`,
//! and runs `flutter test` in `bindings/flutter`, whose build hook bundles it from there.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

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

/// The checksum file `--package` writes next to each library. Must match `manifestFileName`
/// in `bindings/flutter/hook/build.dart`.
const MANIFEST_FILE: &str = "SHA256SUMS";

/// The Flutter app that runs `package:lepic` on a device, relative to the workspace root, and the
/// directory under it its `pubspec.yaml` names as `native_dir`.
const EMULATOR_TEST_APP: &str = "bindings/flutter/emulator_test";
const EMULATOR_TEST_NATIVE_DIR: &str = "native";

/// The Dart package, and the directory its own `pubspec.yaml` names as `native_dir` for its
/// `flutter test` run, both relative to the workspace root.
const FLUTTER_PACKAGE: &str = "bindings/flutter";
const HOST_TEST_NATIVE_DIR: &str = "bindings/flutter/test_native";

/// The `lepic-ffi` feature with the in-process scripted node the integration test drives.
const MOCK_FEATURE: &str = "mock";

const ANDROID_TARGETS: &[&str] = &[
    "aarch64-linux-android",
    "armv7-linux-androideabi",
    "x86_64-linux-android",
];
const APPLE_TARGETS: &[&str] = &["aarch64-apple-ios", "aarch64-apple-ios-sim"];
const LINUX_TARGETS: &[&str] = &["x86_64-unknown-linux-gnu"];
const WINDOWS_TARGETS: &[&str] = &["x86_64-pc-windows-msvc"];

/// The only host `--host-test` runs on: `flutter test` runs the build hook for the host, and the
/// hook bundles a library for this Linux target only.
const HOST_TEST_TARGET: &str = "x86_64-unknown-linux-gnu";

const USAGE: &str = "mobile --target <triple> [--release] | mobile --package [--target <triple>]... \
                     | mobile --emulator-test [--device <serial>] | mobile --host-test";

#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// Check that the library crates build for one target.
    Build { target: String, release: bool },
    /// Build the `lepic-ffi` release library for each target and copy it into the Dart package.
    /// An empty list means every target the host can build.
    Package { targets: Vec<String> },
    /// Run the Flutter integration test on an attached Android device, the only one attached
    /// when no serial is given.
    EmulatorTest { device: Option<String> },
    /// Run the Dart package's `flutter test` against the scripted-node library for the host.
    HostTest,
}

fn parse(args: &[String]) -> Result<Request> {
    let mut targets = Vec::new();
    let mut release = false;
    let mut package = false;
    let mut emulator_test = false;
    let mut host_test = false;
    let mut device = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                let value = args.next().context("`--target` needs a target triple")?;
                targets.push(value.clone());
            }
            "--release" => release = true,
            "--package" => package = true,
            "--emulator-test" => emulator_test = true,
            "--host-test" => host_test = true,
            "--device" => {
                let value = args.next().context("`--device` needs an adb serial")?;
                device = Some(value.clone());
            }
            other => bail!("unknown argument `{other}`, usage: cargo xtask {USAGE}"),
        }
    }
    if host_test {
        if package || release || emulator_test || device.is_some() || !targets.is_empty() {
            bail!("`--host-test` takes no other argument; it builds for the host");
        }
        return Ok(Request::HostTest);
    }
    if emulator_test {
        if package || release || !targets.is_empty() {
            bail!("`--emulator-test` takes only `--device`; the target follows the device's ABI");
        }
        return Ok(Request::EmulatorTest { device });
    }
    if device.is_some() {
        bail!("`--device` goes with `--emulator-test`, usage: cargo xtask {USAGE}");
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

/// The cargo arguments that build the shipped `lepic-ffi` library for `target`.
fn package_args(target: &str, host_os: &str) -> Result<Vec<String>> {
    let mut args = cargo_build_prefix(target, host_os)?;
    args.extend(["--package", FFI_PACKAGE, "--lib", "--locked", "--release"].map(String::from));
    Ok(args)
}

/// The cargo arguments that build `lepic-ffi` with the scripted node for `target`. Release, so
/// the wallet's key stretching runs at app speed on the device.
fn emulator_test_args(target: &str, host_os: &str) -> Result<Vec<String>> {
    let mut args = package_args(target, host_os)?;
    args.extend(["--features".to_owned(), MOCK_FEATURE.to_owned()]);
    Ok(args)
}

/// The cargo arguments that build `lepic-ffi` with the scripted node for the host, or an error
/// when the host (`std::env::consts` `OS` and `ARCH` values) is not `HOST_TEST_TARGET`. A debug
/// build for the host, without `--target`, so it shares the artifacts of a plain
/// `cargo build -p lepic-ffi --features mock`.
fn host_test_args(host_os: &str, host_arch: &str) -> Result<Vec<String>> {
    if (host_os, host_arch) != ("linux", "x86_64") {
        bail!("`--host-test` runs only on an x86_64 Linux host ({HOST_TEST_TARGET})");
    }
    Ok([
        "build",
        "--package",
        FFI_PACKAGE,
        "--lib",
        "--locked",
        "--features",
        MOCK_FEATURE,
    ]
    .map(String::from)
    .to_vec())
}

/// The serials of the devices `adb devices` lists as ready.
fn ready_devices(adb_devices_output: &str) -> Vec<String> {
    adb_devices_output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some(serial), Some("device")) => Some(serial.to_owned()),
                _ => None,
            }
        })
        .collect()
}

/// The device to test on: `requested` when it is ready, otherwise the only ready device.
fn choose_device(requested: Option<&str>, ready: &[String]) -> Result<String> {
    match (requested, ready) {
        (Some(serial), _) if ready.iter().any(|d| d == serial) => Ok(serial.to_owned()),
        (Some(serial), _) => bail!("device `{serial}` is not attached and ready (`adb devices`)"),
        (None, [only]) => Ok(only.clone()),
        (None, []) => bail!("no Android device is attached; start an emulator first"),
        (None, _) => bail!(
            "several devices are attached ({}); pick one with `--device`",
            ready.join(", ")
        ),
    }
}

/// The Rust target for a device's primary ABI (`ro.product.cpu.abi`).
fn android_target_for_abi(abi: &str) -> Result<&'static str> {
    match abi.trim() {
        "arm64-v8a" => Ok("aarch64-linux-android"),
        "armeabi-v7a" => Ok("armv7-linux-androideabi"),
        "x86_64" => Ok("x86_64-linux-android"),
        other => bail!("LEPIC has no Android build for the device ABI `{other}`"),
    }
}

/// `name` from `<$root_var>/<dir>/` when that variable is set, so the documented SDK wins over
/// whatever is first on `PATH`.
fn sdk_tool(root_var: &str, dir: &str, name: &str) -> PathBuf {
    std::env::var_os(root_var)
        .map(|root| PathBuf::from(root).join(dir).join(name))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

fn adb_output(adb: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(adb).args(args).output().with_context(|| {
        format!(
            "could not start `{}`; is the Android SDK installed?",
            adb.display()
        )
    })?;
    if !output.status.success() {
        bail!("`adb {}` failed", args.join(" "));
    }
    String::from_utf8(output.stdout).context("adb printed non-UTF-8 output")
}

fn run_emulator_test(root: &Path, device: Option<&str>, host_os: &str) -> Result<()> {
    let adb = sdk_tool("ANDROID_HOME", "platform-tools", "adb");
    let device = choose_device(device, &ready_devices(&adb_output(&adb, &["devices"])?))?;
    let abi = adb_output(
        &adb,
        &["-s", &device, "shell", "getprop", "ro.product.cpu.abi"],
    )?;
    let target = android_target_for_abi(&abi)?;

    run_cargo(root, &emulator_test_args(target, host_os)?)?;
    let app = root.join(EMULATOR_TEST_APP);
    let packaged = copy_into_package(
        &release_library(&target_dir(root), target),
        &app.join(EMULATOR_TEST_NATIVE_DIR),
        target,
    )?;
    write_manifest(&packaged)?;

    if !run_flutter(&app, &["test", "integration_test", "-d", device.as_str()])? {
        bail!("the integration test failed on `{device}`");
    }
    Ok(())
}

fn run_host_test(root: &Path, host_os: &str, host_arch: &str) -> Result<()> {
    run_cargo(root, &host_test_args(host_os, host_arch)?)?;
    let built = target_dir(root)
        .join("debug")
        .join(shared_library_name(HOST_TEST_TARGET));
    let packaged = copy_into_package(&built, &root.join(HOST_TEST_NATIVE_DIR), HOST_TEST_TARGET)?;
    write_manifest(&packaged)?;

    if !run_flutter(&root.join(FLUTTER_PACKAGE), &["test"])? {
        bail!("`flutter test` failed in `{FLUTTER_PACKAGE}`");
    }
    Ok(())
}

/// Runs `flutter` with `args` in `dir` and returns whether it succeeded.
fn run_flutter(dir: &Path, args: &[&str]) -> Result<bool> {
    let flutter = sdk_tool("FLUTTER_ROOT", "bin", "flutter");
    eprintln!("xtask mobile: {} {}", flutter.display(), args.join(" "));
    let status = Command::new(&flutter)
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| {
            format!(
                "could not start `{}`; is Flutter installed?",
                flutter.display()
            )
        })?;
    Ok(status.success())
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

/// Writes the `MANIFEST_FILE` next to `library`: its SHA-256 and file name in `sha256sum`
/// format, which the Dart build hook checks before it bundles the library.
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
                let packaged =
                    copy_into_package(&release_library(&target_dir, target), &native_dir, target)?;
                write_manifest(&packaged)?;
                eprintln!("xtask mobile: packaged {}", packaged.display());
            }
            Ok(())
        }
        Request::EmulatorTest { device } => run_emulator_test(root, device.as_deref(), host_os),
        Request::HostTest => run_host_test(root, host_os, std::env::consts::ARCH),
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
        let args = package_args("x86_64-unknown-linux-gnu", "linux").unwrap();
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
        assert!(package_args("x86_64-unknown-linux-gnu", "macos").is_err());
        assert!(build_args("x86_64-unknown-linux-gnu", false, "windows").is_err());
    }

    #[test]
    fn host_test_takes_no_other_argument() {
        assert_eq!(
            parse(&strings(&["--host-test"])).unwrap(),
            Request::HostTest
        );
        for other in [
            &["--package"][..],
            &["--release"],
            &["--emulator-test"],
            &["--device", "emulator-5554"],
            &["--target", "x86_64-unknown-linux-gnu"],
        ] {
            let mut args = strings(&["--host-test"]);
            args.extend(strings(other));
            assert!(parse(&args).is_err(), "accepted --host-test {other:?}");
        }
    }

    #[test]
    fn host_test_builds_the_mock_debug_library_on_x86_64_linux_only() {
        assert_eq!(
            host_test_args("linux", "x86_64").unwrap(),
            strings(&[
                "build",
                "--package",
                "lepic-ffi",
                "--lib",
                "--locked",
                "--features",
                "mock",
            ])
        );
        assert!(host_test_args("linux", "aarch64").is_err());
        assert!(host_test_args("macos", "x86_64").is_err());
        assert!(LINUX_TARGETS.contains(&HOST_TEST_TARGET));
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
    fn emulator_test_takes_only_a_device() {
        assert_eq!(
            parse(&strings(&["--emulator-test"])).unwrap(),
            Request::EmulatorTest { device: None }
        );
        assert_eq!(
            parse(&strings(&["--emulator-test", "--device", "emulator-5554"])).unwrap(),
            Request::EmulatorTest {
                device: Some("emulator-5554".to_owned())
            }
        );
        assert!(parse(&strings(&["--emulator-test", "--device"])).is_err());
        assert!(parse(&strings(&["--emulator-test", "--package"])).is_err());
        assert!(parse(&strings(&["--emulator-test", "--release"])).is_err());
        assert!(
            parse(&strings(&[
                "--emulator-test",
                "--target",
                "x86_64-linux-android"
            ]))
            .is_err()
        );
        assert!(parse(&strings(&["--package", "--device", "emulator-5554"])).is_err());
    }

    #[test]
    fn emulator_test_builds_the_mock_ffi_library_in_release() {
        let args = emulator_test_args("x86_64-linux-android", "linux").unwrap();
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
                "--features",
                "mock",
            ])
        );
    }

    #[test]
    fn lists_only_ready_devices() {
        let output = "List of devices attached\n\
                      emulator-5554\tdevice\n\
                      emulator-5556\toffline\n\
                      R58M\tunauthorized\n\
                      0a1b2c\tdevice product:x model:y\n\n";
        assert_eq!(ready_devices(output), strings(&["emulator-5554", "0a1b2c"]));
        assert!(ready_devices("List of devices attached\n\n").is_empty());
    }

    #[test]
    fn chooses_the_requested_or_the_only_device() {
        let one = strings(&["emulator-5554"]);
        let two = strings(&["emulator-5554", "emulator-5556"]);
        assert_eq!(choose_device(None, &one).unwrap(), "emulator-5554");
        assert_eq!(
            choose_device(Some("emulator-5556"), &two).unwrap(),
            "emulator-5556"
        );
        assert!(choose_device(None, &[]).is_err());
        assert!(choose_device(None, &two).is_err());
        assert!(choose_device(Some("emulator-5558"), &two).is_err());
    }

    #[test]
    fn maps_device_abis_to_android_targets() {
        assert_eq!(
            android_target_for_abi("x86_64\n").unwrap(),
            "x86_64-linux-android"
        );
        assert_eq!(
            android_target_for_abi("arm64-v8a").unwrap(),
            "aarch64-linux-android"
        );
        assert_eq!(
            android_target_for_abi("armeabi-v7a").unwrap(),
            "armv7-linux-androideabi"
        );
        assert!(android_target_for_abi("x86").is_err());
        for abi in ["x86_64", "arm64-v8a", "armeabi-v7a"] {
            assert!(ANDROID_TARGETS.contains(&android_target_for_abi(abi).unwrap()));
        }
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
    fn rejects_unsupported_targets() {
        assert!(package_args("aarch64-unknown-linux-gnu", "linux").is_err());
        assert!(package_args("aarch64-pc-windows-msvc", "windows").is_err());
    }

    #[test]
    fn package_builds_the_windows_library_natively_on_windows_only() {
        let args = package_args("x86_64-pc-windows-msvc", "windows").unwrap();
        assert_eq!(
            args.get(..3),
            Some(&strings(&["build", "--target", "x86_64-pc-windows-msvc"])[..])
        );
        assert!(package_args("x86_64-pc-windows-msvc", "linux").is_err());
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
