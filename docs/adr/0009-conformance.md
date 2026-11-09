# ADR 0009: Conformance workspace and golden vectors

Status: accepted; version table superseded in part by ADR 0020

## Context

LEPIC matches the reference node and `epic-wallet` byte for byte on keys, proofs, slates,
Epicbox messages and wallet files. It does so without the reference crates in its own dependency
graph (ADR 0001).

## Decision

- `conformance/` is a separate Cargo workspace with its own `Cargo.lock`. It has two members,
  `vectors` and `differential`. The root workspace excludes it.
- The workspace depends on public upstream code only, pinned in `conformance/Cargo.lock`:
  `EpicCash/epic` and `EpicCash/epic-wallet` by tag and commit, and
  `EpicCash/rust-secp256k1-zkp` at the commit the reference lockfile records. Version table:
  see ADR 0020. The `vectors` crate tests that the lockfile resolves to the commits it expects.
- The `vectors` binary runs the pinned reference code and writes golden vectors to
  `testdata/vectors/<area>/<name>.json`. Each file records the generator, the upstream commit,
  the inputs and the expected outputs. Vectors are committed. Areas: `smoke`, `primitives`,
  `aggsig`, `keys`, `epicbox`, `slates`, `slates_native`, `engine`, `app_data`, `store`,
  `store_key`, and `pairing` (written by a separate script kit, no upstream implementation).
  `testdata/vectors/README.md` describes the format and the commands.
- `cargo xtask vectors generate [--area <area>]` runs the generator. `cargo xtask vectors
  verify` runs the vector tests of every product crate.
- Product crates test against the committed vectors and never against upstream code, so
  ordinary builds stay light.
- `conformance/differential` links the reference crates and the LEPIC crates in one test binary
  and runs both on the same inputs: key derivation, proofs, serialization, slates at each stage,
  Epicbox crypto, output selection, file-method exchanges, restore over an in-process test chain.
- `interop/` runs the real `epic-wallet` and node binaries against LEPIC over files and a local
  Epicbox relay container built from the public relay repository. `interop/pins.env` holds the
  upstream commits it builds from.
- Generation is deterministic. It uses the reference code's test RNG mode where one exists, and
  fixed keys, salts and nonces elsewhere.

## Consequences

- The conformance workspace builds RandomX and LMDB. It runs on Linux only.
- The workspace uses the product toolchain (`conformance/rust-toolchain.toml`), because the
  differential tests link LEPIC crates.
- A deterministic area shows no diff in `testdata/vectors` unless a generator case or a pin
  changed.
- Changing a pin is a deliberate act: regenerate, review the vector diff, and port any behaviour
  change. `cargo xtask upstream-drift` reports the ported modules whose upstream files changed
  (`upstream.toml`).

## Related

- ADR 0001, ADR 0020, ADR 0038
