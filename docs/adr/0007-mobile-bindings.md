# 0007 Binding generator: UniFFI or flutter_rust_bridge

Status: proposed, needs an operator decision
Date: 2026-10-02

## Context

The mobile app's UI stack decides the binding generator. Findings, 2026-10-02:

- UniFFI 0.32 generates Kotlin and Swift (and Python for tests), supports async functions as Kotlin
  `suspend` and Swift `async`, and is used in production by Firefox mobile. Dart support exists only
  as an experimental community project.
  (https://mozilla.github.io/uniffi-rs/latest/, https://github.com/Uniffi-Dart/uniffi-dart)
- flutter_rust_bridge 2.13 is the established choice for Flutter, with async Rust support on Android,
  iOS and desktop. (https://cjycode.com/flutter_rust_bridge/)
- The existing Flutter integration of `epic-wallet` uses a hand-written C interface with string
  arguments and JSON results. A generated, typed binding removes that whole class of glue code.

## Options

1. Native apps (Kotlin and Swift): UniFFI in `lepic-ffi`.
2. Flutter: flutter_rust_bridge in `lepic-ffi`.
3. Both: one binding-agnostic API in `lepic-wallet`, two thin binding crates.

## Requirements for any option

- Opaque object handles; no raw pointers or secrets cross the boundary.
- Typed error enum with stable codes.
- Async functions, and an event stream or callback for wallet events and log records.
- Panics are converted to errors at the boundary. The workspace never sets `panic = "abort"`, so
  unwinding reaches the boundary.

## Decision

Pending. Tasks U-02 and U-03 wait for it; nothing earlier depends on it.
