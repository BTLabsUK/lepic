# 0009 Separate conformance workspace on public pins, golden vectors

Status: accepted; superseded in part by 0020 (the version table)
Date: 2026-10-02

## Context

LEPIC must match the reference wallet and node byte for byte, without putting their crates in its
own dependency graph (ADR 0001).

## Decision

- `conformance/` is a separate Cargo workspace with its own `Cargo.lock`, excluded from the root
  workspace. It depends on public upstream code only, pinned by commit:

  | Upstream | Tag | Commit |
  |---|---|---|
  | `EpicCash/epic` | `v4.0.4` | `9d022b1d521d3f705532e12ab77e0a429f6fde1f` |
  | `EpicCash/epic-wallet` | `v4.0.2` | `465d499f01aad7e570b6cc220d52c6bfcf6a9a44` |
  | `EpicCash/rust-secp256k1-zkp` | `master` | `42fcb29d4b635ea771d1984be0d11b0e64b15a93` |

- A generator binary writes golden vectors to `testdata/vectors/<area>/<name>.json`, each with
  generator name, upstream commit, inputs and expected outputs. Vectors are committed.
- Product crates test against the committed vectors with no access to upstream code, so ordinary
  builds and CI stay light.
- Differential tests in `conformance/` run reference and LEPIC code side by side on the same inputs:
  key derivation, proofs, serialization, slates at every stage, Epicbox crypto, output selection,
  restore over an in-process test chain.
- `interop/` runs real `epic-wallet` binaries against LEPIC over files and a local Epicbox relay
  container built from the public relay repository.
- Deterministic generation uses the reference code's test RNG mode where it exists, and fixed keys,
  salts and nonces otherwise.

## Consequences

- The conformance workspace builds RandomX and LMDB; it runs on Linux CI and developer machines only.
- Bumping a pin is a deliberate change: regenerate, review the vector diff, and port any behaviour
  change.

## Alternatives considered

- Hand-written expected values. Unverifiable.
- Dev-dependencies on the reference crates inside product crates. Puts them in `Cargo.lock` and in
  every test build.
