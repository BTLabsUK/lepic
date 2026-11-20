# ADR 0007: Mobile bindings with flutter_rust_bridge for the Flutter frontend

Status: accepted. The secrets line: see ADR 0014. Delivery: see ADR 0023.

## Context

The frontend is a Flutter app. LEPIC is its backend: the Rust library and the binding layer the app
calls. flutter_rust_bridge is the established choice for Flutter, with async Rust, streams to Dart,
and Android, iOS and desktop support. UniFFI targets Kotlin and Swift, and its Dart support is a
community project. The existing Flutter integration of `epic-wallet` is a hand-written C interface
with string arguments and JSON results; a generated, typed binding removes that class of glue code.

## Decision

- `lepic-ffi` uses flutter_rust_bridge, pinned exactly (`=2.13.0` in the root `Cargo.toml`). It
  exposes a binding-friendly API over `lepic-wallet`, in `crates/lepic-ffi/src/api`.
  `lepic-wallet` knows nothing about Dart.
- The API has these properties:
  - Opaque object handles. No raw pointers cross the boundary.
  - One error enum, `WalletErrorKind`, with stable numeric codes (`code()`), so the app maps errors
    to messages without parsing text.
  - Async functions, plus Dart streams for wallet events and log records.
  - Every call runs as a task on the runtime and a panic in it becomes a `Panic` error instead of
    unwinding into Dart (`boundary.rs`). The task keeps running if the Dart future is dropped, so
    a store write is never cut in half.
  - The app passes in a secret store it implements, for example over Android Keystore or the iOS
    Keychain (`AppSecretStore`). Secrets that may cross the boundary: see ADR 0014.
- Delivery of the binding: see ADR 0023.

## Consequences

- The generator version is pinned together with the Rust crate version.
- Changing `api` changes the generated halves of the binding (ADR 0023).

## Related

- ADR 0014: secrets across the boundary.
- ADR 0023: the binding repository.
- ADR 0008: errors and logging.
