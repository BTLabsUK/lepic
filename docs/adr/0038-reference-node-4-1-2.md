# ADR 0038: Interop node at epic v4.1.2

Status: accepted

## Context

ADR 0020 pins the Epic node `v4.1.0` for the reference code, the golden vectors and the interop
images. The nodes that LEPIC users connect to run `v4.1.2` (`bd3a8c8c`). Its header validation
refuses a block whose bottles differ from the expected ones, so a `v4.1.0` node and a `v4.1.2`
node can disagree on a block. `epic-wallet` has no release after `v4.1.0`.

## Decision

- The interop stacks (`interop/pins.env`, `interop/miner`, `interop/live/miner`) run and link
  `epic` `v4.1.2` at `bd3a8c8c5e957e57574364326dfb17051d0096ae`. The node and the miners build
  with the node's own toolchain, Rust 1.99.1 (`NODE_RUST`); `epic-wallet` builds with 1.89.0.
- `upstream.toml` records `bd3a8c8c` for the node modules, after the review in
  `docs/compat/upstream-4.1.2-review.md` found no change to any ported path.
- The conformance workspace and the golden vectors stay on `epic` `v4.1.0`, which `epic-wallet`
  `v4.1.0` links.

The node row of ADR 0020's table: see this record for the interop images and `upstream.toml`.

## Consequences

- The interop suite tests LEPIC against the node users run.
- The interop builder image and the node are built from the new pin.
- A node release that changes a ported path moves the conformance pin as well, with regenerated
  vectors.

## Alternatives considered

- Keep `v4.1.0` in the interop stack: the tests would run against a node no live network runs.
- Move the conformance workspace too: it would build two copies of the node crates, one under
  `epic-wallet` `v4.1.0`, for files that are identical.

## Related

- ADR 0020: reference wallet and node.
