# Project rules

The rules every change to LEPIC follows. `CONTRIBUTING.md`
covers branches, commit messages and the sign-off; `docs/logging.md` covers logging; the ADRs in
`docs/adr/` record the decisions these rules point to. A hard rule changes only with the
maintainer's approval and a note in the change that makes it.

## Goals, in priority order

1. Correct. LEPIC produces and accepts exactly what `epic-wallet` and the Epic node produce and
   accept on the methods it supports. Money-handling behaviour is proven by golden vectors and
   differential tests against the reference code, never by reasoning alone.
2. Mobile-first. Builds for Android and iOS with Rust and a C compiler only. Works when the OS
   suspends the app: connect, drain, disconnect.
3. Light. No proof-of-work, chain storage, LMDB, OpenSSL, C++ or Epic node crates in the product
   dependency graph.
4. Extensible. A new transaction method or slate format is one new module plus one registration,
   with no edits to existing methods or formats.
5. Current and readable. Latest stable crates, code that explains itself, structured logs, typed
   errors.

## Non-goals for 1.0

Mining, running a node, Keybase, the emoji method, transactions with more than two parties. Direct
transactions (HTTP send, the HTTP listener's foreign API, Tor) are in scope (ADR 0017), and so is
importing an `epic-wallet` wallet's transaction history, read-only and reconciled with the scan
(ADR 0019); funds still come from the seed and the scan.

## Minimal and unopinionated

LEPIC is minimal and unopinionated: no app policy, no process-wide state, features live in the
app. LEPIC adds only what a higher layer cannot do, such as a per-session flag the engine reads
(ADR 0031), never a mode the app would otherwise decide.

## Hard rules

- Reject, do not panic. Anything from the network, a file, a peer, a node or the host app becomes a
  typed error. `unwrap`, `expect`, `panic!`, unchecked indexing and unchecked arithmetic are defects
  outside tests.
- Untrusted input may cause bounded work. Only validated data becomes stored state.
- No process-global mutable state. Network, paths and settings are explicit parameters, so two
  wallets on different networks can run in one process (ADR 0011).
- Port only from public sources: the Epic node and `epic-wallet` releases ADR 0020 names, and the
  libraries they pin, as `docs/adr/0009-conformance.md` and `upstream.toml` record them. Never copy
  from private repositories.
- Describe correct behaviour, never weaknesses of Epic Cash software or services. No exploit
  detail, failure modes an attacker could trigger, private finding ids or private repository names
  in code, docs, commits or branch names.
- Secrets never reach logs. Across the Flutter boundary only what ADR 0014 lists may pass.
- Tracked files are fit for publication: no absolute paths of a developer's machine, no secrets, no
  build output. `cargo xtask repo-lint` refuses home-directory paths in tracked text.

## When facts disagree

For facts about formats and behaviour, golden vectors and running code beat ADRs, and ADRs beat
`docs/compat/`. Fix the lower source in the same change, or say in the commit body which source is
now wrong.

## Rust code

### Code that explains itself

- Names carry the meaning. A reader should understand a function from its name, its argument types
  and its return type.
- Model the domain in types: `Amount`, `Fee`, `Height`, `SlateId`, `Stage`, `Network` instead of
  bare integers, strings and booleans. Use an enum where a boolean would need a comment.
- Parse, don't validate. Constructors and decoders check invariants once; after that the type
  guarantees them. Make invalid states unrepresentable.
- Small functions with one job. Modules follow domain concepts, not technical layers.
- Default to `pub(crate)`. Every `pub` item is a promise.

### Comments

Comments are rare and long-lived. Write one only when the code cannot say it: why a non-obvious
choice was made, an invariant or ordering requirement the types cannot express, or a compatibility
constraint that must survive refactors. Never restate the code, narrate steps, or record history,
dates or one-off use cases; those belong in commits, tests or ADRs. Doc comments are required on the
public API of `lepic-ffi` and `lepic-wallet`, and say what the signature cannot: errors, side
effects, ordering. The one place a task id belongs in code is `TODO(<task-id>)`.

### Errors and panics

- Each library crate defines its errors with `thiserror`. Variants carry typed context, not
  formatted strings, and keep the cause with `#[source]` or `#[from]`.
- `Display` text is lowercase with no trailing period and states what failed, not what to do.
- `anyhow` only in `lepic-cli`, `xtask` and test helpers.
- Outside tests: no `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`, slice
  indexing that can go out of bounds, or arithmetic that can overflow. The workspace lints deny
  them; use `get`, `checked_*` and `try_from` and return an error.
- Amounts, fees and heights use checked arithmetic through their newtypes. Release builds keep
  `overflow-checks = true`.

### Boundaries

- `unsafe` is denied workspace-wide and no LEPIC code writes it. Crypto goes through the safe API of
  the pinned secp256k1-zkp wrapper, and `lepic-crypto` checks every length, count and key before
  the call. `lepic-ffi` alone permits the unsafe code its binding generator emits; hand-written code
  there follows the same rule. The one exception is the store's SQLite3MC key call, a single
  `#[expect(unsafe_code)]` block in `lepic-store/src/sqlite/cipher.rs` (ADR 0032).
- The pure crates (`lepic-crypto`, `lepic-primitives`, `lepic-keychain`, `lepic-slate`) do no I/O,
  read no clock and never create their own randomness; callers pass an RNG and the time in. That
  keeps them deterministic and fuzzable.
- Async lives in the I/O crates only, on Tokio.
- No mutable statics and no lazily initialised global config. Immutable tables and the secp context
  are the only statics.
- `docs/architecture.md` lists the allowed dependency edges between crates;
  `cargo xtask deps-check` enforces them.

### Dependencies

- Add or bump a dependency only through `[workspace.dependencies]` in the root `Cargo.toml`. Crates
  reference it with `name.workspace = true`.
- Use the latest stable release, with `default-features = false` and only the features used.
- The commit that adds a crate says why it is needed, that it is maintained, and what else was
  considered (ADR 0010).
- Banned anywhere in the graph, as `deny.toml` enforces: RandomX, ProgPoW, CRoaring, LMDB, OpenSSL,
  native-tls, and crates that need CMake or bindgen at build time.
- Not used directly: `failure`, `log4rs`, `lazy_static`, `once_cell` (use `std::sync::LazyLock` and
  `OnceLock`), `chrono` (use `jiff`), `log` (use `tracing`).

### Formatting and lints

`cargo fmt` with the repository `rustfmt.toml`. Clippy runs with `-D warnings` and the workspace
lint table. An `#[allow(...)]` needs a comment explaining why the lint is wrong in that place. The
`pedantic` and `nursery` groups are not enabled: an advisory pass over them found style findings
only (`use_self`, `redundant_pub_crate`, long first doc paragraphs and the like), none of them a
defect.

## Compatibility with epic-wallet and the Epic node

LEPIC interoperates with the reference `epic-wallet` and Epic node (ADR 0020) on the methods it
supports. Byte-level agreement is the bar.

- What must match exactly: key derivation from a mnemonic, account and output paths, switch
  commitments; range proof creation and rewind with both proof builders; transaction, kernel and
  output serialization, hashes, kernel signature messages, fee and weight; legacy slate JSON (V2
  and V3) with the quirks in `docs/compat/legacy-slates.md`; Epicbox addresses, message encryption,
  signatures and the relay protocol; the node JSON-RPC calls and their response shapes. The facts
  are in `docs/compat/`, and each page names the upstream files it was derived from.
- Golden vectors live in `testdata/vectors/<area>/<name>.json`, each with its generator, upstream
  repository and commit, inputs and expected output. Only `conformance/` generates them, by running
  the reference code; never write or edit a vector by hand. Where upstream draws randomness
  internally, LEPIC is checked by consistency (it decrypts, rewinds or verifies upstream output, and
  upstream accepts LEPIC output in the differential suite). A port with no vectors is not done.
- The legacy codecs under `lepic-slate`'s `codec::legacy` are frozen: they change only to fix a
  mismatch a vector demonstrates. Improvements go into a new codec (ADR 0002).
- `upstream.toml` maps each ported module to its upstream path and commit, and
  `cargo xtask upstream-drift` reports upstream changes since then. A drift report is reviewed and
  either ported, with vectors, or recorded as not applying.
- Compatibility breaks only on purpose: through a new codec, transport capability or storage format,
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

- No network, wall clock, global state or shared directories in unit and integration tests. Inject
  the clock and the RNG, use `tempfile` for paths, and use the mock relay and mock node.
- Deterministic: seed any randomness and print the seed on failure.
- Test names state the behaviour; tests assert on typed errors, not on error strings.
- Vector tests are integration tests named `vectors` in each crate, so `cargo xtask vectors verify`
  runs exactly them.
- A fuzz crash becomes a regression test before it is fixed. The pull-request CI builds every fuzz
  target (`cargo xtask fuzz --build`); the scheduled CI runs each for a minute
  (`cargo xtask fuzz --smoke`). Without CI, a nightly local run does it
  (`docs/fuzzing.md`).
- Automated tests, CI and fuzzing never touch public nodes or relays. Opt-in live tests
  (`LEPIC_LIVE_TESTS=1`) may make a few ordinary wallet calls against public floonet services,
  within their rate limits, never mainnet.

## Security

LEPIC holds the keys to people's money. Treat every external byte as hostile and every secret as one
log line away from leaking.

- Untrusted input: node responses, relay frames, slates from peers, files, QR codes and everything
  the host app passes in. Bound sizes and counts before allocating, check every length and curve
  point before it reaches crypto, and turn every failure into a typed error. A malicious node or
  relay may lie, delay, replay or reorder; it must not crash the wallet, corrupt stored state or
  move funds.
- Secrets (seeds, mnemonics, passwords, private keys, blinding factors, nonces) live in types that
  zeroize on drop and redact in `Debug` and `Display`, cross the FFI boundary only as ADR 0014
  allows, and are encrypted at rest (ADR 0005). No secret in a log, an error message, a panic
  message, a test snapshot or a commit.
- Crypto: the pinned secp256k1-zkp wrapper for everything Epic consensus needs, through
  `lepic-crypto` only; RustCrypto crates for symmetric crypto and KDFs. Never implement a
  primitive.
- Supply chain: `cargo deny check` runs in CI (advisories, licences, banned crates, allowed
  sources). GitHub Actions are pinned to full commit SHAs and run with read-only tokens.
- Disclosure: follow `SECURITY.md`.

## Versioning

Semantic Versioning; while the version is `0.y.z` a minor bump marks a breaking change, and all
workspace crates share one version. Versions are set only at release time, never in an ordinary
change. `CHANGELOG.md` follows Keep a Changelog.
