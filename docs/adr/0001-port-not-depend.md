# ADR 0001: Port the node and wallet logic; no Epic crates in the product graph

Status: accepted

## Context

`epic-wallet` depends on the node crates `epic_core`, `epic_keychain`, `epic_util`, `epic_api`,
`epic_chain` and `epic_store`. `epic_core` lists RandomX and ProgPoW as unconditional dependencies,
and its `global` module imports the proof-of-work module, so taking the transaction code compiles
the mining code. The wallet's `impls` crate builds its test framework into release builds, which
pulls in `epic_chain` and `epic_store` and with them LMDB and CRoaring. Its node client imports
response types from `epic_api`, which depends on chain, p2p, pool and store. A mobile build of
`epic-wallet` therefore compiles most of the node.

The node code cannot be changed for LEPIC's sake. The code the wallet needs changes rarely.

## Decision

LEPIC ports the behaviour it needs into its own crates and depends on no Epic crate. `Cargo.lock`
holds no `epic_*` package.

- From the node: serialization, hashing, transaction types, kernel sums, weights and fees,
  aggregate signature helpers, proof builders and the keychain
  (`lepic-primitives`, `lepic-crypto`, `lepic-keychain`).
- From the wallet: slate handling, output selection, transaction building, scan and refresh logic,
  the Epicbox client protocol and crypto, the file method and the seed file format.
- Written fresh: the node client and its response types, storage, transports, the engine API, the
  CLI, the bindings and logging.

Ported code is modernised, not copied: current crates, typed errors, no global state, no panics,
clearer names. Behaviour stays identical, and golden vectors from the reference code prove it
(ADR 0009).

The one C dependency from the Epic ecosystem is the secp256k1-zkp wrapper the node uses. LEPIC
builds it from a vendored copy in `third_party/grin_secp256k1zkp`, which records its origin and
patches in `PATCHES.md` (ADR 0010).

`upstream.toml` lists every ported module with the upstream repository, paths and commit it was
derived from. `cargo xtask upstream-drift` reports upstream commits that touched those paths after
the recorded commit.

## Consequences

- Mobile builds need Rust and a C compiler only.
- LEPIC has to notice upstream fixes itself. A drift report is reviewed and either ported, with
  vectors, or recorded as not applying.
- Ports are reviewed against vectors, not against the upstream diff, because the code differs.

## Related

- [ADR 0009](0009-conformance.md): how ported behaviour is proven.
- [ADR 0010](0010-dependency-policy.md): banned crates and the vendored wrapper.
- [ADR 0020](0020-reference-epic-wallet-4-1.md): the upstream releases LEPIC follows.
