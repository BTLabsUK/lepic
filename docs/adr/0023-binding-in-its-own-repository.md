# ADR 0023: The Flutter binding lives in its own repository

Status: accepted

## Context

LEPIC holds no Flutter or Dart. It is a Rust library with a Rust FFI API in `lepic-ffi`, and the
binding to Flutter is a separate project that pins a LEPIC commit.

flutter_rust_bridge generates two halves from one parse of the API: `frb_generated.rs`, compiled
into `lepic-ffi`, and the Dart files. Both embed a hash of the API they were generated from, and
the Dart side refuses to start against a library whose hash differs. The code generator needs a
Dart toolchain even to write the Rust half. The API imports `StreamSink` from `frb_generated`
(for example in `crates/lepic-ffi/src/api/http.rs`), so the Rust half cannot leave the crate
without changing the API.

## Decision

- The binding is the Dart package `lepic` in its own repository, `lepic-flutter`
  (github.com/BTLabsUK/lepic-flutter). It pins a LEPIC commit in `lepic.rev` and holds the
  codegen configuration, the generated Dart, the build hook, the tests, the device test app and
  `tool/lepic.sh`, which builds the native libraries from the pinned LEPIC per platform. Apps
  depend on that package.
- `frb_generated.rs` stays in `crates/lepic-ffi`. It is written only by the binding's
  `tool/lepic.sh generate`, in the same run as the Dart half, against a LEPIC checkout, and
  committed to LEPIC.
- That run also writes `crates/lepic-ffi/bridge.sha256`: the SHA-256 of every file under
  `src/api` and of `src/frb_generated.rs`, in `sha256sum` format. `cargo xtask repo-lint` (part
  of `cargo xtask check`) fails when any of them differs from the record, when the record is
  missing or malformed, and when `frb_generated.rs` comes from another flutter_rust_bridge
  version than `Cargo.lock` resolves. So LEPIC cannot change the API, or the Rust half, without
  both halves being generated again.
- The binding's `tool/lepic.sh check` generates both halves again at its pin and fails unless
  the results equal what is committed. So the binding cannot pin a LEPIC whose Rust half does
  not match its Dart half.
- `cargo xtask mobile --package` writes the release libraries and a `SHA256SUMS` manifest to
  `<out>/<triple>/`, by default under `dist/native/`. `--mock` builds them with the scripted
  node and relay for the binding's tests, by default into `dist/native-mock/`. `--no-tor`
  builds without Tor (ADR 0026). xtask runs no Flutter or Dart.

## Consequences

- Changing the API is a two-repository change: edit `src/api` in LEPIC, run the binding's
  `tool/lepic.sh generate` against that checkout, commit `frb_generated.rs` and `bridge.sha256`
  in LEPIC and the Dart in the binding, then move the binding's pin.
- LEPIC's checks need no Dart toolchain. The binding's checks need Flutter and a Rust toolchain.
- The Dart host and device tests run from the binding repository, against the library built from
  its pinned LEPIC.
- This supersedes the delivery part of ADR 0007. The rest of ADR 0007 stands.

## Related

- ADR 0007, ADR 0026
