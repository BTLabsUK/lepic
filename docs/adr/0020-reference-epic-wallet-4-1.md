# 0020 Reference wallet and node move to epic-wallet v4.1.0

Status: accepted; superseded in part by 0038 (the node pin of the interop images and `upstream.toml`)
Date: 2026-10-22

Supersedes the version table of [0009](0009-conformance.md). The rest of 0009 stands.
Also supersedes the statement in [0002](0002-slate-domain-and-codecs.md) that an Epicbox payload
has the V2 shape while its header says version 3: that holds for `v4.0.2`; at `v4.1.0` the header
follows the shape.

## Context

The owner decided (feature-gap assessment §10, D7, 2026-10-21) that LEPIC's compatibility target
moves from `epic-wallet` `v4.0.2` and the Epic node `v4.0.4` to `epic-wallet` `v4.1.0`, the
current public release. ADR 0017 already names `v4.1.0` as the reference for the foreign API.
`conformance/`, the golden vectors and `interop/` were still pinned to the older pair.

## Decision

The reference code, the golden vectors and the interop images use these public pins:

| Upstream | Tag | Commit |
|---|---|---|
| `EpicCash/epic-wallet` | `v4.1.0` | `845b3fcf4df12ed0139929c62157015447a9d063` |
| `EpicCash/epic` | `v4.1.0` | `82fa7e813dc3b9bf137b9dd523d847f4210f5ba4` |
| `EpicCash/rust-secp256k1-zkp` | `master` | `1131a20920576413cd949e012a160561080324c1` |

The node and secp256k1-zkp commits are the ones `epic-wallet` `v4.1.0` records in its
`Cargo.lock` (0009 had `42fcb29d` for secp256k1-zkp). `1131a209` descends from `42fcb29d` and
computes the same results on valid input. The product
workspace keeps its own secp256k1-zkp pin, so the conformance workspace builds both copies, one
under the reference crates and one under the LEPIC crates its differential tests link; its pin
test holds each copy to its own manifest. The reference code pins Rust `1.89.0` in its `rust-toolchain.toml`, as before; the
conformance workspace and interop builds keep the toolchains of `conformance/rust-toolchain.toml`
and `interop/pins.env`. The Epicbox relay checker (`EPICBOX_COMMIT`) is not part of this change.

What differs between `v4.0.2` and `v4.1.0` and matters to LEPIC:

- Slate parsing (`libwallet/src/slate_versions/ser.rs`) takes hex fields of fixed, checked length:
  public keys, signatures, the offset, commitments and range proofs. Well-formed slates read as
  before; malformed ones are refused instead of reaching the hex decoder.
- Output selection and change (`libwallet/src/internal/selection.rs`) sums with checked
  arithmetic, requires between one and a block-weight-bounded number of change outputs, and
  splits change into equal parts with the remainder in the last output. For every change value
  the old code split correctly, the amounts are the same.
- The HTTP send adapter parses the version and slate answers as typed errors. It posts
  `receive_tx` with the four parameters `v4.0.2` already sent: slate, destination account,
  message, `addr_from` (ADR 0017).
- The node client asks the node's foreign API `ready_for_txs` for `is_node_ready`, and falls back
  to the owner status call only when the method is not found.
- The Epicbox adapter refuses a slate that arrives before the relay challenge.
- The `version_info.version` of a legacy slate follows its shape: upstream writes 2 on every
  V2-shaped slate and 3 on every V3-shaped one, and carries `orig_version` and
  `block_header_version` through (`v4.0.2` copied the whole header when it converted). Epicbox
  payloads therefore carry header `2/3/<b>` instead of `3/3/<b>`, and the invoice payer's
  V3-shaped file says 3, so its TTL is read. LEPIC writes the same; both header forms decode.
- Slate parsing refuses an offset of the wrong length, and on the file path also a duplicate
  participant id and a zero participant count (the Epicbox path still reads those two). LEPIC
  already refused all three.
- The regenerated `epicbox/message_*` vectors change in the plaintext's slate header (`3/3/6` to
  `2/3/6`) as well as in key, salt, nonce, ciphertext and signature; the header change is the
  rule above.
- Wallet database layout and the field layout of the legacy slate V2 and V3 formats are
  unchanged.

## Consequences

- Vectors are regenerated from the new pins. The provenance fields change; data changes only
  where upstream behaviour changed, and each such change is reviewed and, if needed, ported.
  The `wallet.seed` vectors are written afresh, because upstream draws their salt and nonce.
- `upstream.toml` records `v4.1.0` for each ported module whose upstream files are identical at
  both pins. A module whose upstream files changed keeps its old commit, so the drift check
  keeps listing that change until someone reviews it and ports it with vectors or records why it
  does not apply.
- Users of `epic-wallet` `v4.0.2` keep working with LEPIC: LEPIC still reads the headers
  `v4.0.2` writes, and `v4.0.2` reads a slate whose header version follows its shape, since its
  Epicbox path ignores the header and its file path dispatches on it. The interop suite runs
  against both versions. The wallet and node versions the reference documents are now the `v4.1.0` pair.
- Contributors rebuild the conformance workspace and the interop images; the first build is slow.
- `docs/compat/` pages that name `v4.0.2` or `v4.0.4` describe behaviour that holds at `v4.1.0`
  unless a page says otherwise. 

## Alternatives considered

- Stay on `v4.0.2`. Leaves the foreign API of ADR 0017 without a matching reference.
- Track the unreleased `master` of `epic-wallet`. Not a stable target.
