# Mobile build and TLS stack

LEPIC's native pieces cross-build for Android with Rust, the Android NDK and `cargo-ndk`, and
nothing else. TLS is rustls with the ring provider, certificates are checked against the roots in
`webpki-roots`, and HTTP is hyper. The host app does no TLS setup. This note records how the
libraries are built and why that stack was chosen over reqwest with the platform verifier
([ADR 0006](../adr/0006-tls-and-http.md)).

## Building

`cargo xtask mobile` builds for one target or packages the `lepic-ffi` library
(`xtask/src/mobile.rs`).

```text
cargo xtask mobile --target <triple> [--release]
cargo xtask mobile --package [--mock] [--no-tor] [--out <dir>] [--target <triple>]...
```

- `--target` builds every workspace package except `xtask` and `lepic-cli` for one target. Use it
  to check that the library crates compile.
- `--package` builds the `lepic-ffi` library in release mode for each `--target`. Without a
  `--target` it builds every target the host can build. It copies each library to
  `<out>/<triple>/`, which is `dist/native/` in the workspace root by default, with three files
  beside it: `SHA256SUMS`, `FEATURES` and `SOURCE`.
- `--mock` adds the scripted node and Epicbox relay of the `mock` feature, for the binding's tests.
  It writes to `dist/native-mock/` by default.
- `--no-tor` leaves out the `tor` feature (ADR 0026). The default directory gets the suffix
  `-no-tor`.

The targets, by host:

| Host | Targets |
|---|---|
| Any | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` |
| macOS | `aarch64-apple-ios`, `aarch64-apple-ios-sim` |
| Linux | `x86_64-unknown-linux-gnu` |
| Windows | `x86_64-pc-windows-msvc` |

Android builds run through `cargo ndk -t <target> -P 24 build`, so the NDK linker, sysroot and API
level 24 apply to every C dependency. The build stops with an error if `cargo ndk` is missing.
`.github/workflows/mobile.yml` builds with NDK `28.2.13676358` and cargo-ndk `4.1.2`, and builds
the iOS targets on a macOS runner. iOS builds need the Xcode SDK.

No CMake, Perl, Go, NASM, libclang or Gradle is needed. The pinned `grin_secp256k1zkp` wrapper,
the bundled SQLite and ring compile through the NDK's clang.

The release profile (`Cargo.toml`) is `opt-level = "s"`, fat LTO, `codegen-units = 1`,
`strip = true` and `overflow-checks = true`.

## TLS stack

| Part | Choice |
|---|---|
| TLS | rustls 0.23 with the ring provider, `default-features = false` |
| Roots | Mozilla roots from `webpki-roots` |
| HTTP | hyper 1.x, hyper-util and hyper-rustls, HTTP/1.1 only |
| Websockets | tokio-tungstenite over tokio-rustls |

One rustls `ClientConfig` is built per wallet and handed to both clients
(`webpki_tls_config` in `crates/lepic-node/src/http.rs`). `deny.toml` bans `openssl`,
`openssl-sys`, `openssl-src`, `native-tls` and `tokio-native-tls`. No `aws-lc` crate enters the
product graph.

### Why not reqwest

reqwest with `rustls-no-provider` also builds for Android. It verifies certificates with
`rustls-platform-verifier`, which calls the platform `X509TrustManager` through JNI. To use it the
host app must:

- add the crate's Kotlin component to the Gradle build;
- obtain a `JNIEnv` and an Android `Context` and call
  `rustls_platform_verifier::android::init_with_env` before the first TLS handshake;
- accept that a handshake before initialisation panics instead of returning an error.

flutter_rust_bridge does not pass a `Context` to Rust, so this needs a Flutter plugin or extra JNI
glue. The hyper stack needs none of it.

### Comparison

Measured on a spike library with the same three checks in each variant (a commitment and
Bulletproof, a SQLite WAL write, one HTTPS request and one websocket echo), built for
`aarch64-linux-android` with the release profile.

| | reqwest and platform verifier | hyper and webpki-roots |
|---|---|---|
| Extra build tools | none | none |
| Stripped `.so` | 4,128,472 bytes | 3,430,592 bytes |
| Crates in the target graph | 134 | 88 |
| HTTPS and WSS on an Android 16 emulator | panics until the app initialises the verifier | pass |
| Host-app work on Android | Gradle component and JNI init | none |

A library without any network stack is 1,622,192 bytes stripped. The spike code is not in the
tree; commit `6e8b3f8` holds it under `spikes/f-03/`.

## Certificates

- `webpki-roots` bundles the Mozilla root program. The roots change only when the crate is
  updated.
- A node or relay with a self-signed certificate or a private CA fails the check. User-installed
  and enterprise CAs are not trusted, which matches the default of apps that target Android API 24
  or higher.
- Plain `http` to a node is accepted only for a loopback host, or for an onion address when the
  caller enables it (`crates/lepic-node/src/http.rs`).
