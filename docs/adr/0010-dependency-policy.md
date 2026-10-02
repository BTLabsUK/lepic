# 0010 Latest stable crates and toolchain, banned list, update bots

Status: accepted
Date: 2026-10-02

## Context

`epic-wallet` and the node carry deprecated and very old dependencies, which makes every upgrade a
project. LEPIC starts fresh and must stay current.

## Decision

- Toolchain: the latest stable Rust, pinned in `rust-toolchain.toml` with the mobile targets. Stable
  was 1.99.0 on 2026-10-01 (https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/). The pin moves within
  two weeks of each stable release. Edition 2024.
- Versions: the latest stable release of each crate at the time it is added, set once in
  `[workspace.dependencies]`. Dependabot (or Renovate) proposes weekly updates for Cargo and GitHub
  Actions.
- `cargo deny` checks advisories, licenses, sources and bans in CI. Allowed licenses: Apache-2.0, MIT,
  BSD-2/3-Clause, ISC, Unicode-3.0, Zlib, CC0-1.0, MPL-2.0 (file-level). Allowed git source: the pinned
  secp256k1-zkp wrapper.
- The `fuzz/` workspace is test tooling that never ships, so it may also use NCSA-licensed fuzzing
  crates such as `libfuzzer-sys`, set directly in `fuzz/Cargo.toml`.
- Banned in the graph: RandomX, ProgPoW, CRoaring, LMDB, OpenSSL, native-tls, and crates that need
  CMake or bindgen at build time. Not used by LEPIC crates directly: `failure`, `log4rs`,
  `lazy_static`, `once_cell`, `chrono`, `log`.
- Release profile: `lto = "fat"`, `codegen-units = 1`, `strip = true`, `overflow-checks = true`,
  `opt-level = "s"` until measurements say otherwise.

Starting versions, read from crates.io on 2026-10-02. Task F-01 rechecks them before writing the
workspace table:

| Area | Crate | Version |
|---|---|---|
| Async | tokio | 1.53 |
| Websocket | tokio-tungstenite | 0.30 |
| TLS | rustls | 0.23 (ring provider) |
| HTTP | hyper 1.11 with hyper-util 0.1, hyper-rustls 0.27, http-body-util 0.1, webpki-roots 1.0 | ADR 0006 |
| Serialization | serde 1.0, serde_json 1.0 | |
| Errors | thiserror 2.0, anyhow 1.0 | |
| Logging | tracing 0.1, tracing-subscriber 0.3, tracing-appender 0.2 | |
| CLI | clap 4.6 | |
| Storage | rusqlite 0.40 (bundled) | |
| KDF and AEAD | argon2 0.6, pbkdf2 0.13, chacha20poly1305 0.11 | |
| Hashes and MACs | blake2 0.11, sha2 0.11, hmac 0.13, ripemd 0.2 | |
| Secrets | zeroize 1.9, secrecy 0.10 | |
| Encoding | bs58 0.5, base64 0.23 | |
| Mnemonic | bip39 3.0 | |
| Ids and time | uuid 1.26, jiff 0.2 | |
| Randomness | rand 0.10, rand_core 0.10, getrandom 0.4 | |
| Curve | grin_secp256k1zkp from `EpicCash/rust-secp256k1-zkp` at `42fcb29d` | |
| Bindings | flutter_rust_bridge 2.13 | ADR 0007 |
| Tests | proptest 1.11, insta 1.48, tempfile 3.27, libfuzzer-sys 0.4 | |

## Consequences

- Upgrades are small and frequent instead of rare and large.
- The secp256k1-zkp wrapper may pull older crates; `cargo deny` reports duplicate versions as warnings.

## Alternatives considered

- Pin the versions `epic-wallet` uses. Inherits the problem this project exists to avoid.
