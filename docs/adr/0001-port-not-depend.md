# 0001 Port the node and wallet logic; no Epic crates in the product graph

Status: accepted
Date: 2026-10-02

## Context

`epic-wallet` depends on the node crates `epic_core`, `epic_keychain`, `epic_util`, `epic_api`,
`epic_chain` and `epic_store`. `epic_core` lists RandomX and ProgPoW as unconditional dependencies,
and its `global` module imports the proof-of-work module, so taking the transaction code compiles the
mining code. The wallet's `impls` crate builds its test framework into release builds, which pulls in
`epic_chain` and `epic_store` and with them LMDB and CRoaring. Its node client imports response types
from `epic_api`, which depends on chain, p2p, pool and store. A mobile build of `epic-wallet` therefore
compiles most of the node.

The node code cannot be changed for LEPIC's sake.

The code the wallet actually needs changes rarely. In the public history up to `v4.0.4`, commits
touching the node's transaction, serialization, signing and keychain code number 1 in 2022, 2 in 2023,
0 in 2024 and 12 in 2025, most of them dependency bumps.

## Decision

LEPIC ports the needed behaviour into its own crates and depends on no Epic crate:

- From the node: serialization, hashing, transaction types, kernel sums, weights and fees, aggregate
  signature helpers, proof builders, the keychain. About 5.5k lines in the node, including tests.
- From the wallet: slate handling, output selection, transaction building, scan and refresh logic, the
  Epicbox client protocol and crypto, the file method, the seed file format.
- Written fresh: the node client and its response types, storage, transports, engine API, CLI,
  bindings, logging.

Ported code is modernised, not copied: current crates, typed errors, no globals, no panics, clearer
names. Behaviour stays identical, and golden vectors from the reference code prove it (ADR 0009).

The only C dependency from the Epic ecosystem is the secp256k1-zkp wrapper the node uses, pinned to the
same commit.

## Consequences

- Mobile builds need Rust and a C compiler only.
- LEPIC must notice upstream fixes itself. `upstream.toml` records the origin of every ported module,
  and `cargo xtask upstream-drift` reports upstream changes (task F-05).
- Ports are reviewed against vectors, not against the upstream diff, because the code differs.

## Alternatives considered

- Depend on `epic_core` and accept RandomX. Works (another mobile wallet does it) but keeps the C++
  build, the cross-compile patches and the deprecated dependency tree.
- Ask upstream to feature-gate proof-of-work. Right long term, not available now.
- Copy files verbatim and trim. Simplest drift tracking, but freezes old crates and old error
  handling, which this project exists to leave behind.
