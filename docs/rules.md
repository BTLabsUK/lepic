# Project rules

The rules every change to LEPIC follows: goals, hard rules, Rust code, compatibility, testing,
security and versioning. A rule marked with a tool name is checked by that tool; the rest are
checked in review. [`CONTRIBUTING.md`](../CONTRIBUTING.md) covers branches, commit messages and the
sign-off, [`logging.md`](logging.md) covers logging, and the [ADRs](adr/README.md) record the
decisions these rules point to. A hard rule changes only with the maintainer's approval and a note in
the change that changes it.

## Goals, in priority order

1. Correct. LEPIC produces and accepts what `epic-wallet` and the Epic node produce and accept on the
   methods it supports. Behaviour that handles money is shown by golden vectors and differential
   tests against the reference code.
2. Mobile-first. Builds for Android and iOS with Rust and a C compiler only. Works when the OS
   suspends the app: connect, drain, disconnect.
3. Light. No proof-of-work, chain storage, LMDB, OpenSSL, C++ or Epic node crates in the product
   dependency graph.
4. Extensible. A new transaction method or slate format is one new module plus one registration,
   with no edits to existing methods or formats.
5. Current and readable. Latest stable crates, code that explains itself, structured logs, typed
   errors.

## Scope

LEPIC does not mine, does not run a node, has no Keybase transport, no emoji method and no
transaction with more than two parties. Direct transactions are in scope: HTTP send, the HTTP
listener's foreign API and Tor (ADR 0017). So is reading an `epic-wallet` wallet's transaction
history, read-only and reconciled with the scan (ADR 0019); funds come from the seed and the scan.
Building the coinbase a mining node asks for, over the HTTP listener when the host turns it on, is
in scope (ADR 0046); mining is not.

LEPIC is minimal and unopinionated. It holds no app policy and no process-wide state; features
live in the app. LEPIC adds only what a higher layer cannot do, such as a per-session flag the
engine reads (ADR 0031).

## Hard rules

- Reject, do not panic. Anything from the network, a file, a peer, a node or the host app becomes a
  typed error. Outside tests, `unwrap`, `expect`, `panic!`, unchecked indexing and unchecked
  arithmetic are defects (workspace clippy lints).
- Untrusted input may cause bounded work. Only validated data becomes stored state.
- No process-global mutable state. Network, paths and settings are explicit parameters, so two
  wallets on different networks run in one process (ADR 0011).
- Port only from public sources: the Epic node and `epic-wallet` releases that ADR 0020 and ADR 0038
  name, and the libraries they pin, as [ADR 0009](adr/0009-conformance.md) and
  [`upstream.toml`](../upstream.toml) record them. Never copy from private repositories.
- Describe correct behaviour. Code, docs, commits and branch names carry no exploit detail, no
  failure modes an attacker could trigger, no private finding ids and no private repository names.
- Secrets never reach logs. Across the Flutter boundary only what ADR 0014 lists may pass.
- Tracked files are fit for publication: no home-directory path of a developer's machine, no secrets,
  no build output. `cargo xtask repo-lint` refuses `/home/<name>/`, `/Users/<name>/` and
  `C:\Users\<name>\` paths in tracked `.md`, `.rs`, `.toml`, `.sh`, `.yml`, `.yaml`, `.txt`,
  `.dart` and `.ps1` files, except the placeholder names `a`, `alice`, `bob`, `dev`, `example`,
  `me`, `runner`, `test`, `u`, `user` and `you`, and except the audit reports under `docs/audit/`.

## When facts disagree

For facts about formats and behaviour, golden vectors and running code outrank ADRs, and ADRs
outrank [`compat/`](compat/). The change that finds a disagreement fixes the lower source, or says in
its commit body which source is wrong.

## Rust code

### Code that explains itself

- Names carry the meaning. A reader understands a function from its name, its argument types and
  its return type.
- Model the domain in types: `Amount`, `Fee`, `Height`, `SlateId`, `Stage`, `Network` instead of
  bare integers, strings and booleans. Use an enum where a boolean would need a comment.
- Parse, do not validate. Constructors and decoders check invariants once; the type guarantees them
  afterwards. Invalid states are unrepresentable.
- Small functions with one job. Modules follow domain concepts, not technical layers.
- Default to `pub(crate)`. Every `pub` item is a promise.

### Comments

Comments are rare and long-lived. Write one when the code cannot say it: why a non-obvious choice
was made, an invariant or ordering the types cannot express, or a compatibility constraint that must
survive refactors. A comment does not restate the code, narrate steps or record history, dates or
one-off use cases; commits, tests and ADRs hold those. Doc comments are required on the public API
of `lepic-ffi` and `lepic-wallet` and say what the signature cannot: errors, side effects, ordering.
A task id appears in code only as `TODO(<task-id>)`.

### Errors and panics

- Each library crate defines its errors with `thiserror`. Variants carry typed context, not
  formatted strings, and keep the cause with `#[source]` or `#[from]`.
- `Display` text is lowercase, has no trailing period and states what failed, not what to do.
- `anyhow` is used in `lepic-cli`, `xtask` and test helpers only.
- Outside tests the workspace lints deny `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!`,
  `unimplemented!`, indexing and slicing that can go out of bounds, and arithmetic that can
  overflow. Use `get`, `checked_*` and `try_from` and return an error. `clippy.toml` lifts the
  `unwrap`, `expect`, `panic` and indexing lints inside tests.
- Amounts, fees and heights use checked arithmetic through their newtypes. The release profile sets
  `overflow-checks = true`.

### Boundaries

- `unsafe_code` is denied workspace-wide. `cargo xtask repo-lint` fails when a member does not
  inherit `[workspace.lints]` (`[lints] workspace = true`), declares its own `[lints.*]` table, or
  relaxes `unsafe_code` anywhere except the module `flutter_rust_bridge` generates in
  `lepic-ffi` and one `#[expect(unsafe_code)]` around the SQLite3 Multiple Ciphers key call in
  [`lepic-store/src/sqlite/cipher.rs`](../crates/lepic-store/src/sqlite/cipher.rs) (ADR 0032).
  Crypto goes through the safe API of the vendored secp256k1-zkp wrapper, and `lepic-crypto` checks
  every length, count and key before the call.
- The pure crates are `lepic-crypto`, `lepic-primitives`, `lepic-keychain`, `lepic-slate`,
  `lepic-legacy-slate`, `lepic-native-slate`, `lepic-seal` and `lepic-contact`. They do no I/O, read
  no clock and create no randomness of their own; callers pass an RNG and the time in. That keeps
  them deterministic and fuzzable. `cargo xtask deps-check` keeps Tokio, the network and TLS stack,
  `rusqlite`, `tempfile`, `getrandom`, `tracing-appender`, `tracing-subscriber`, `clap` and
  `flutter_rust_bridge` out of their manifests, and refuses the `rand` features `default`,
  `sys_rng` and `thread_rng` and the `jiff` features `default` and `std` there. `cargo xtask
  repo-lint` scans the library sources of `lepic-crypto`, `lepic-primitives`, `lepic-keychain`,
  `lepic-slate`, `lepic-legacy-slate` and `lepic-contact` for `std::fs`, `std::net`, `std::env`,
  `std::process`, `std::thread`, clocks (`SystemTime`, `Instant`, `UNIX_EPOCH`, `::now`), `tokio`,
  `getrandom` and operating-system random sources.
- Async code lives in the I/O crates only, on Tokio.
- No mutable statics and no lazily initialised global configuration. Immutable tables and the
  secp256k1 context are the only statics.
- [`architecture.md`](architecture.md) lists the allowed dependency edges between crates, and
  `cargo xtask deps-check` fails on any other edge.

### Dependencies

- A dependency is added or bumped only in `[workspace.dependencies]` of the root `Cargo.toml`. Crates
  reference it with `name.workspace = true`.
- Use the latest stable release, with `default-features = false` and only the features the code
  uses.
- The commit that adds a crate says why it is needed, that it is maintained, and what else was
  considered (ADR 0010).
- `cargo deny check` (`deny.toml`) fails on: yanked crates, licences outside the allow list, a
  second version of a crate that `skip` does not list with a reason, wildcard version requirements,
  registries other than crates.io and git sources, and these crates anywhere in the graph:
  `randomx`, `progpow`, `croaring`, the LMDB crates, `openssl` and `native-tls` with their
  companions, `aws-lc-rs`, `cmake`, `bindgen`, and the `cxx` and `autocxx` family. The rustls
  provider is `ring`.
- `cargo xtask deps-check` also fails when a workspace crate depends directly on `failure`,
  `log4rs`, `lazy_static`, `once_cell`, `chrono` or `log`. Use `std::sync::LazyLock` and `OnceLock`
  in place of `lazy_static` and `once_cell`, `jiff` in place of `chrono`, and `tracing` in place of
  `log`.
- The secp256k1-zkp wrapper is the vendored copy in `third_party/grin_secp256k1zkp`. `cargo xtask
  repo-lint` fails when `Cargo.lock` resolves it from anywhere else, and when any package of the
  product workspace comes from a git source.

### Formatting and lints

`cargo fmt` runs with the repository [`rustfmt.toml`](../rustfmt.toml) (style edition 2024, Unix
newlines, field-init and `?` shorthand). Clippy runs with `-D warnings` over the workspace lint
table in the root `Cargo.toml`: the deny set above, and warnings for lossy numeric casts,
`manual_let_else`, `too_many_lines`, `wildcard_imports`, `needless_pass_by_value` and the other
lints that table lists. An `#[allow(...)]` carries a comment saying why the lint is wrong in that
place. The `pedantic` and `nursery` groups are not enabled. The toolchain is pinned in
[`rust-toolchain.toml`](../rust-toolchain.toml), with the Android and iOS targets.

## Compatibility with epic-wallet and the Epic node

LEPIC interoperates with the reference `epic-wallet` and Epic node (ADR 0020, ADR 0038) on the
methods it supports. The bar is agreement at the byte level.

- Must match exactly: key derivation from a mnemonic, account and output paths, switch commitments;
  range proof creation and rewind with both proof builders; transaction, kernel and output
  serialization, hashes, kernel signature messages, fee and weight; legacy slate JSON (V2 and V3)
  with the quirks in [`compat/legacy-slates.md`](compat/legacy-slates.md); Epicbox addresses,
  message encryption, signatures and the relay protocol; the node JSON-RPC calls and their response
  shapes. The facts are in [`compat/`](compat/); each page names the upstream files it describes.
- Golden vectors live in `testdata/vectors/<area>/<name>.json`, each with its generator, upstream
  repository and commit, inputs and expected output. Only `conformance/` generates them, by running
  the reference code (`cargo xtask vectors generate`); a vector is never written or edited by hand.
  Where upstream draws randomness internally, LEPIC is checked by consistency: it decrypts, rewinds
  or verifies upstream output, and upstream accepts LEPIC output in the differential suite. A port
  without vectors is not done.
- The codecs in `lepic-legacy-slate` follow `epic-wallet`. They change to fix a mismatch a vector
  shows; improvements go into a new codec (ADR 0002).
- `upstream.toml` maps each ported module to its upstream paths and commit, and
  `cargo xtask upstream-drift` reports upstream commits that touched those paths since. A drift
  report is reviewed and either ported, with vectors, or recorded as not applying.
- Compatibility breaks on purpose only: through a new codec, transport capability or storage format,
  with an ADR that states who is affected and how they migrate, and a commit marked `!` with a
  `BREAKING CHANGE:` footer.

## Testing

A change is finished when a test shows it works and would have shown it broken.

| Change | Required test |
|---|---|
| Bug fix | A test that fails before the fix and passes after. |
| Ported algorithm or format | Golden vectors from `conformance/`. |
| Decoder of untrusted input | Unit tests for each rejection, a property test for round trips, and a fuzz target in `fuzz/`. |
| Encoder | Round-trip property test, and an `insta` snapshot for human-readable output. |
| Engine flow | Integration test in `crates/lepic-wallet/tests/` with in-memory ports, the mock node and the loopback transport. |
| Cross-wallet behaviour | A differential test in `conformance/` or a scenario in `interop/`. |
| CLI | The command tree and output shape, not the engine again. |

- Unit and integration tests use no network, wall clock, global state or shared directories. They
  inject the clock and the RNG, use `tempfile` for paths, and use the mock relay and mock node.
- Tests are deterministic: seed any randomness and print the seed on failure.
- Test names state the behaviour; tests assert on typed errors, not on error strings.
- A crate's vector tests are an integration test named `vectors` (`crates/<crate>/tests/vectors.rs`),
  so `cargo xtask vectors verify` runs exactly them.
- A fuzz crash becomes a regression test before it is fixed. The pull-request workflow builds every
  fuzz target (`cargo xtask fuzz --build`); the weekly scheduled workflow runs each target in a
  smoke run (`cargo xtask fuzz --smoke`). See [`fuzzing.md`](fuzzing.md).
- Automated tests, CI and fuzzing do not touch public nodes or relays. The opt-in live tests
  (`LEPIC_LIVE_TESTS=1`) make a few ordinary wallet calls against public floonet services within
  their rate limits and never use mainnet.

`cargo xtask check` is the gate: `cargo fmt --check`, clippy over the workspace and over `lepic-ffi`
without default features, `cargo test --workspace --locked`, `cargo deny check`, then `deps-check`,
`ci-lint`, `repo-lint`, the lockfile check of `conformance/`, `fuzz/` and `interop/probe/`,
`vectors verify` and `no-legacy`.

## Security

LEPIC holds the keys to people's money. Every external byte is treated as hostile and every secret
as one log line from leaking.

- Untrusted input: node responses, relay frames, slates from peers, files, QR codes and everything
  the host app passes in. Sizes and counts are bounded before allocating, every length and curve
  point is checked before it reaches crypto, and every failure becomes a typed error. A malicious
  node or relay may lie, delay, replay or reorder; it must not crash the wallet, corrupt stored
  state or move funds.
- Secrets (seeds, mnemonics, passwords, private keys, blinding factors, nonces) live in types that
  zeroize on drop and redact in `Debug` and `Display`, cross the FFI boundary only as ADR 0014
  allows, and are encrypted at rest (ADR 0005, ADR 0032). No secret appears in a log, an error
  message, a panic message, a test snapshot or a commit.
- Crypto: the vendored secp256k1-zkp wrapper for everything Epic consensus needs, reached through
  `lepic-crypto` only; RustCrypto crates for symmetric crypto and key derivation. No code
  implements a primitive.
- Supply chain: `cargo deny check` runs in the `check` job of CI (`cargo xtask check`) and
  `cargo deny check advisories` runs weekly. `cargo xtask ci-lint` fails when a GitHub Actions
  workflow uses an action that is not pinned to a full commit SHA, lacks a top-level `permissions`
  block, holds a write scope that `xtask/src/ci_lint.rs` does not list, or has a checkout without
  `persist-credentials: false`.
- Reporting: [`SECURITY.md`](../SECURITY.md).

## Versioning

Semantic Versioning. While the version is `0.y.z`, a minor bump marks a breaking change. All
workspace crates share the version in `[workspace.package]`. Versions are set at release time and
not in an ordinary change. [`CHANGELOG.md`](../CHANGELOG.md) follows Keep a Changelog.
