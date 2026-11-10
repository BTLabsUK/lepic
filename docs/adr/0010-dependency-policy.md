# ADR 0010: Dependency and toolchain policy

Status: accepted

## Context

`epic-wallet` and the node carry deprecated and very old dependencies, so every upgrade there is
a project. LEPIC keeps its dependencies current and its dependency graph small.

## Decision

- Toolchain. `rust-toolchain.toml` pins a stable Rust release (1.99.0) with the Android and iOS
  targets. The workspace uses edition 2024 and `rust-version = "1.99"`. `fuzz/` pins a dated
  nightly in its own `rust-toolchain.toml`, because `cargo-fuzz` needs one.
- Versions. Each external crate is set once in `[workspace.dependencies]` of `Cargo.toml` with
  default features off. Member crates enable the features they use. Dependabot proposes weekly
  updates for Cargo (root, `conformance/`, `fuzz/`) and GitHub Actions.
- Libraries by area: tokio and tokio-tungstenite (async, websocket); rustls with the `ring`
  provider, hyper, hyper-rustls and webpki-roots (TLS and HTTP, ADR 0006); rusqlite with the
  bundled, encrypted SQLite (ADR 0032); argon2, pbkdf2, chacha20poly1305, blake2, sha2, sha3,
  hmac, hkdf and ripemd (KDFs, AEAD, hashes); zeroize and secrecy (secrets); bip39, bs58,
  base64; ed25519-dalek, x25519-dalek and hpke (payment proofs, sealed envelopes); ur and
  minicbor (animated QR, ADR 0025); serde, serde_json, toml; thiserror, anyhow; tracing,
  tracing-subscriber, tracing-appender; clap; uuid, jiff; rand, rand_core, getrandom;
  flutter_rust_bridge, pinned to `=2.13.0` (ADR 0007). Exact versions are in the root
  `Cargo.toml` and `Cargo.lock`.
- Curve library. `grin_secp256k1zkp` is a vendored copy of `EpicCash/rust-secp256k1-zkp` at
  `42fcb29d` with upstream backports and build fixes, in `third_party/grin_secp256k1zkp`
  (`PATCHES.md`; `docs/compat/secp256k1-zkp-fork.md`). A vendored `libsqlite3-sys` in
  `third_party/libsqlite3-sys` links SQLite3 Multiple Ciphers through `[patch.crates-io]`.
  `third_party` is excluded from the workspace.
- `cargo deny check` runs in CI and in `cargo xtask check`, with `all-features = true`:
  - Advisories: yanked crates are denied.
  - Licences allowed: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib,
    CC0-1.0, MPL-2.0, CDLA-Permissive-2.0 (the Mozilla root certificates in `webpki-roots`),
    BlueOak-1.0.0 (`minicbor`). `sqlite3mc-src` has an exception for Unlicense (ADR 0032).
  - Sources: only crates.io. Git sources are denied.
  - Bans: a second version of a crate fails unless `deny.toml` lists it in `skip` with the
    dependency that holds it back. Wildcard versions are denied.
- Banned crates (`[bans].deny`): RandomX, ProgPoW, CRoaring, every LMDB binding, OpenSSL,
  native-tls and hyper-tls, aws-lc, and the C++ bridge and build tools (`cmake`, `bindgen`,
  `cxx`, `autocxx`, `cpp_build` and their helpers). A build needs Rust and a C compiler only.
  `cargo xtask deps-check` keeps its own copy of the list equal to `deny.toml`.
- `failure`, `log4rs`, `lazy_static`, `once_cell`, `chrono` and `log` may appear deeper in the
  graph but are not direct dependencies of a workspace crate. `deps-check` enforces this.
- The `fuzz/` workspace never ships. It sets the NCSA-licensed `libfuzzer-sys` directly in its
  own `Cargo.toml`.
- Release profile: `opt-level = "s"`, `lto = "fat"`, `codegen-units = 1`, `strip = true`,
  `overflow-checks = true`.

## Consequences

- Upgrades are small and frequent.
- The vendored secp256k1-zkp wrapper uses older `rand` and `getrandom` versions. These are
  listed in `skip` in `deny.toml` until the wrapper moves.
- A crate that needs OpenSSL, CMake or a C++ toolchain cannot enter the graph.
- Builds for the mobile targets need no tool besides Rust and a C compiler.

## Related

- ADR 0006, ADR 0007, ADR 0032
