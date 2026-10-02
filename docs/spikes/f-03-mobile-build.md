# Spike F-03: mobile build and TLS stack

## TL;DR

The native pieces LEPIC needs (the pinned secp256k1-zkp wrapper, bundled SQLite, rustls with ring)
cross-build for Android with Rust, the NDK and `cargo-ndk`, and nothing else. Both candidate TLS
stacks from ADR 0006 build and work on the Linux host. On an Android 16 emulator, the hyper stack
completed an HTTPS request and a WSS echo. The reqwest stack panicked on its first TLS handshake,
because `rustls-platform-verifier` needs the host app to initialise it from the JVM. Decision: hyper
with hyper-rustls and webpki-roots. iOS was not built, because this machine has no Xcode SDK. CI on
macOS builds it.

Date: 2026-10-02. The spike code lived in `spikes/f-03/` and was removed before merge. Commit
`6e8b3f868d345b2388fe592e4fc6f6367943276a` holds it: `git show 6e8b3f8 --stat`, or
`git archive 6e8b3f8 spikes/f-03 | tar x` to rebuild it.

## What was built

A library (`staticlib` and `cdylib`) with one exported C function. The function:

1. creates a Pedersen commitment and a Bulletproof with `grin_secp256k1zkp` from
   `EpicCash/rust-secp256k1-zkp` at `42fcb29d` (`bullet-proof-sizing`) and verifies the proof,
2. opens a bundled SQLite database in WAL mode, writes a row and reads it back,
3. makes one HTTPS GET and one WSS round trip (send a text frame, receive the echo).

The same library was built as three variants:

| Variant | HTTPS | WSS | Certificate verification |
|---|---|---|---|
| core | none | none | none |
| reqwest | reqwest 0.13.5, `rustls-no-provider` | tokio-tungstenite 0.30 over tokio-rustls | rustls-platform-verifier 0.7.1 |
| hyper | hyper 1.11.1, hyper-util 0.1.21, hyper-rustls 0.27.10 | tokio-tungstenite 0.30 over tokio-rustls | webpki-roots 1.0.9 |

Both network variants use rustls 0.23.45 with the ring provider, `default-features = false`, and HTTP/1.1
only. `cargo tree` for `aarch64-linux-android` shows no aws-lc, OpenSSL, native-tls, CMake or bindgen
crate in any variant. libsqlite3-sys uses its pregenerated bindings.

The release profile is the one from ADR 0010: `lto = "fat"`, `codegen-units = 1`, `strip = true`,
`overflow-checks = true`, `opt-level = "s"`, unwinding panics.

## Tools

| Tool | Version |
|---|---|
| rustc and cargo | 1.99.0 |
| Android NDK | 28.2.13676358 (clang 19.0.1) |
| cargo-ndk | 4.1.2 |
| Android emulator | 37.1.11.0, system image android-36 google_apis x86_64 |

No other tools were needed: no CMake, Perl, Go, NASM, libclang or Gradle.

## Android results

Command, run from `spikes/f-03` with a clean target directory each time, 4 jobs, no sccache:

```
ANDROID_NDK_HOME=~/Android/Sdk/ndk/28.2.13676358 CARGO_BUILD_JOBS=4 \
  cargo ndk -t <target> -P 24 build --release --lib [--features stack-reqwest|stack-hyper]
```

`spikes/f-03/measure.sh` runs all six builds and writes `spikes/f-03/results/<target>-<variant>.txt`.

| Target | Variant | Build (s) | `.so` stripped (bytes) | `.a` (bytes) | `.a` after `--strip-debug` (bytes) | Crates |
|---|---|---|---|---|---|---|
| aarch64-linux-android | core | 23 | 1,622,192 | 31,483,562 | 19,591,058 | 36 |
| aarch64-linux-android | reqwest | 72 | 4,128,472 | 71,837,466 | 59,404,290 | 134 |
| aarch64-linux-android | hyper | 45 | 3,430,592 | 57,645,776 | 45,214,568 | 88 |
| x86_64-linux-android | core | 28 | 1,639,224 | 30,749,296 | 19,399,688 | 36 |
| x86_64-linux-android | reqwest | 44 | 4,428,480 | 70,965,010 | 59,060,306 | 134 |
| x86_64-linux-android | hyper | 35 | 3,664,248 | 56,834,448 | 44,931,712 | 88 |

Crates is the number of distinct packages in `cargo tree -e normal,build` for the target. Other builds
were compiling on the same machine, so build times only rank the variants. Each time is one sample.

The stripped `.so` is the number that ships in an APK. A static archive contains every object of the
standard library and the dependencies before the final link, so it overstates shipped size. On arm64
the network stack adds 2.51 MB with reqwest and 1.81 MB with hyper, so hyper is 0.70 MB (17%) smaller
than reqwest.

### Running on the emulator

The `f03-probe` binary runs the same checks and prints one line per check. It was built for
`x86_64-linux-android` and run through `adb shell` from `/data/local/tmp` on the running Android 16
(API 36) emulator. The HTTPS host was `example.com` and the WSS host `echo.websocket.org`.

```
cargo ndk -t x86_64-linux-android -P 24 build --release --bin f03-probe [--features ...]
adb push <target-dir>/x86_64-linux-android/release/f03-probe /data/local/tmp/
adb shell "cd /data/local/tmp && F03_DB_DIR=/data/local/tmp ./f03-probe"
```

| Variant | commitment and Bulletproof | SQLite | HTTPS | WSS |
|---|---|---|---|---|
| core | pass | pass (3.53.2, WAL) | | |
| reqwest | pass | pass | panic | panic |
| hyper | pass | pass | pass (200) | pass (101, echo) |

The reqwest variant panicked with `Expect rustls-platform-verifier to be initialized` inside the
verifier. The probe caught the panic with `catch_unwind`. On the Linux host, all checks passed for both
network variants.

`aarch64-linux-android` was built but not run, because the only emulator image here is x86_64 and no
arm64 device was attached.

### Host-app changes for the platform verifier

On Android, `rustls-platform-verifier` calls the platform `X509TrustManager` through JNI. To use it, the
host app must:

- add the crate's Kotlin component to the Gradle build, from a Maven repository inside the Cargo
  registry that `cargo metadata` locates;
- obtain a `JNIEnv` and an Android `Context`, and call `rustls_platform_verifier::android::init_with_env`
  before the first TLS handshake. With flutter_rust_bridge, this needs a Flutter plugin or extra JNI
  glue, because the bridge does not pass a `Context` to Rust;
- accept that the verifier stores the JVM handle in a process-global `OnceCell`, and that a handshake
  before initialisation panics instead of returning an error.

The hyper variant needs no host-app changes on either platform.

## iOS

Not built. `cargo build --release --lib --target aarch64-apple-ios` stops in the libsqlite3-sys build
script with `failed to find tool "xcrun"`. The build stopped at that first failure. secp256k1-zkp and
ring compile C through the same `cc` crate and need the SDK as well. The iOS SDK ships only with
Xcode, and its licence permits use only on Apple hardware. The iOS targets `aarch64-apple-ios` and
`aarch64-apple-ios-sim` are left for the macOS CI job (task U-03). The chosen stack has no
Android-specific dependency. Whether it builds for iOS has not been checked.

## Certificates

- webpki-roots bundles the Mozilla root program. Roots change only when the crate is updated, which
  Dependabot does weekly (ADR 0010).
- Apps targeting API 24 or higher do not trust user-installed CAs unless their network security
  config allows them. So on Android the platform verifier mostly adds OS-updated roots and revocation
  checks, not user CAs. On iOS it would also honour CAs the user installed and trusted.
- A node or relay with a self-signed certificate or a private CA fails with both variants unless LEPIC
  accepts extra trust anchors. That is a settings question for N-01 and E-02, not a stack choice.

## Decision

hyper 1.x with hyper-util and hyper-rustls for HTTP, tokio-tungstenite over tokio-rustls for WSS, one
rustls `ClientConfig` with the ring provider and webpki-roots shared by both. Recorded in ADR 0006.
