# 0038 Reference node moves to epic v4.1.2

Status: accepted
Date: 2026-11-04

## Context

ADR 0020 pinned the Epic node `v4.1.0` (`82fa7e81`) for the reference code, the golden vectors
and the interop images. Upstream released `v4.1.1` and `v4.1.2` (`bd3a8c8c`). The live nodes
LEPIC users connect to run `v4.1.2`, and its header validation refuses a block whose bottles
differ from the expected ones, so a `v4.1.0` node and a `v4.1.2` node can disagree on a block.
`epic-wallet` has no release after `v4.1.0`.

## Decision

- The interop stacks (`interop/pins.env`, `interop/miner`, `interop/live/miner`) run and link
  `epic` `v4.1.2` at `bd3a8c8c`. The node and the miners build with the node's own toolchain,
  Rust `1.99.1` (`NODE_RUST`); `epic-wallet` keeps `1.89.0`.
- `upstream.toml` records `bd3a8c8c` for every node module, after the review in
  `docs/compat/upstream-4.1.2-review.md` found no change to any ported path.
- The conformance workspace and the golden vectors stay on `epic` `v4.1.0`, which `epic-wallet`
  `v4.1.0` links. This supersedes the node row of ADR 0020's table for the interop images and
  `upstream.toml` only.

## Consequences

- The interop suite tests LEPIC against the node users run.
- Contributors rebuild the interop builder image and the node once.
- A later node release that changes a ported path moves the conformance pin as well, with
  regenerated vectors, as ADR 0020 did.

## Alternatives considered

- Keep `v4.1.0` in the interop stack. Tests against a node no live network runs.
- Move the conformance workspace too. It would build two copies of the node crates, one under
  `epic-wallet` `v4.1.0`, for files that are identical.
