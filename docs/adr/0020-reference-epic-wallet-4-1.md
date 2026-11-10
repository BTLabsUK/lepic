# ADR 0020: Reference wallet and node at epic-wallet v4.1.0

Status: accepted; the node pin of the interop images and `upstream.toml` is superseded by ADR 0038

## Context

LEPIC's compatibility target is `epic-wallet` `v4.1.0`, the current public release, and the
Epic node release that wallet links. The reference code, the golden vectors and the interop
images need one set of pins. The conformance workspace builds the reference crates from them
(ADR 0009).

## Decision

The reference code and the golden vectors use these public pins:

| Upstream | Tag | Commit |
|---|---|---|
| `EpicCash/epic-wallet` | `v4.1.0` | `845b3fcf4df12ed0139929c62157015447a9d063` |
| `EpicCash/epic` | `v4.1.0` | `82fa7e813dc3b9bf137b9dd523d847f4210f5ba4` |
| `EpicCash/rust-secp256k1-zkp` | `master` | `1131a20920576413cd949e012a160561080324c1` |

- The node and secp256k1-zkp commits are the ones `epic-wallet` `v4.1.0` records in its
  `Cargo.lock`. `1131a209` descends from `42fcb29d`, the commit of the vendored wrapper
  (ADR 0010), and computes the same results on valid input. The product workspace keeps its
  own secp256k1-zkp pin, so the conformance workspace builds both copies, one under the
  reference crates and one under the LEPIC crates its differential tests link. Its pin test
  holds each copy to its own manifest.
- The interop images take `epic-wallet` `v4.1.0` (`interop/pins.env`). The node of the interop
  images and `upstream.toml`: see ADR 0038.
- `epic-wallet` is built with Rust `1.89.0`, as its `rust-toolchain.toml` pins. The conformance
  workspace and the interop builds use the toolchains of `conformance/rust-toolchain.toml` and
  `interop/pins.env`. The Epicbox relay (`EPICBOX_COMMIT`) is pinned separately.

What `v4.1.0` does that matters to LEPIC:

- Slate parsing (`libwallet/src/slate_versions/ser.rs`) takes hex fields of fixed, checked
  length: public keys, signatures, the offset, commitments and range proofs. A malformed slate
  is refused before it reaches the hex decoder. On the file path a duplicate participant id and
  a zero participant count are refused as well; the Epicbox path still reads those two. LEPIC
  refuses all of them.
- Output selection and change (`libwallet/src/internal/selection.rs`) sums with checked
  arithmetic, requires between one and a block-weight-bounded number of change outputs, and
  splits change into equal parts with the remainder in the last output.
- The HTTP send adapter parses the version and slate answers as typed errors. It posts
  `receive_tx` with four parameters: slate, destination account, message, `addr_from`
  (ADR 0017).
- The node client asks the node's foreign API `ready_for_txs` for `is_node_ready`, and falls
  back to the owner status call only when the method is not found.
- The Epicbox adapter refuses a slate that arrives before the relay challenge.
- The `version_info.version` of a legacy slate follows its shape: 2 on every V2-shaped slate and
  3 on every V3-shaped one, with `orig_version` and `block_header_version` carried through.
  Epicbox payloads therefore carry the header `2/3/<b>`, and the V3-shaped file of an invoice
  payer says 3, so its TTL is read. LEPIC writes the same. Both header forms decode, so slates
  from `epic-wallet` `v4.0.2`, which copied the whole header on conversion, still read.
- The wallet database layout and the field layout of the legacy slate V2 and V3 formats are
  unchanged from `v4.0.2`.

## Consequences

- Vectors are regenerated from the pins with `cargo xtask vectors generate`. The `wallet.seed`
  vectors are written afresh, because upstream draws their salt and nonce. The `epicbox/message_*`
  vectors carry the header `2/3/6` in the plaintext.
- `upstream.toml` records the commit each ported module was reviewed at. A module whose upstream
  files changed after its recorded commit keeps that commit, so `cargo xtask upstream-drift`
  keeps listing the change until it is reviewed and ported with vectors or recorded as not
  applying (`docs/compat/upstream-4.1.0-review.md`).
- `docs/compat/` pages describe behaviour that holds at `v4.1.0`.
- Contributors rebuild the conformance workspace and the interop images when a pin moves.

## Related

- ADR 0002, ADR 0009, ADR 0010, ADR 0017, ADR 0038
