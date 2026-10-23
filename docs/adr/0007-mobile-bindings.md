# 0007 Mobile bindings with flutter_rust_bridge for the existing Flutter frontend

Status: accepted, delivery bullet superseded by 0023
Date: 2026-10-02

## Context

A Flutter frontend already exists. LEPIC is its backend: the Rust library and the binding layer the
app calls. Findings, 2026-10-02:

- flutter_rust_bridge 2.13 is the established choice for Flutter, with async Rust, streams to Dart,
  and Android, iOS and desktop support. (https://cjycode.com/flutter_rust_bridge/)
- UniFFI 0.32 targets Kotlin and Swift; its Dart support is an experimental community project.
  (https://mozilla.github.io/uniffi-rs/latest/, https://github.com/Uniffi-Dart/uniffi-dart)
- The existing Flutter integration of `epic-wallet` uses a hand-written C interface with string
  arguments and JSON results. A generated, typed binding removes that whole class of glue code.

## Decision

- `lepic-ffi` uses flutter_rust_bridge v2 at its latest stable release. It exposes a small,
  binding-friendly API over `lepic-wallet`; `lepic-wallet` itself knows nothing about Dart.
- Requirements:
  - Opaque object handles. No raw pointers or secrets cross the boundary.
  - One error enum with stable numeric codes, so the app maps errors to messages without parsing
    text.
  - Async functions, plus Dart streams for wallet events and log records.
  - Panics are converted to errors at the boundary. The workspace never sets `panic = "abort"`.
  - The app implements `SecretStore` (for example with `flutter_secure_storage`, which uses Android
    Keystore and the iOS Keychain) and passes it in.
- Delivery is a Dart package containing the generated bindings and the native libraries for Android
  and iOS, which the existing app depends on. No sample or smoke app is built here.

## Consequences

- Host-side tests run with `flutter test` against the generated bindings on the Linux build machine.
- The flutter_rust_bridge code generator version is pinned together with the Rust crate version.

## Alternatives considered

- UniFFI with a community Dart backend: experimental and one release behind UniFFI.
- A hand-written C interface: the approach the existing integration uses, and the one LEPIC replaces.
