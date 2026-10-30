# The secp256k1-zkp fork

LEPIC's curve library is `grin_secp256k1zkp` from `EpicCash/rust-secp256k1-zkp` at
`42fcb29d4b635ea771d1984be0d11b0e64b15a93` (the workspace `Cargo.toml`, ADR 0010). It is a
fork of `mimblewimble/rust-secp256k1-zkp` and is not vendored. This page records how the fork
differs from upstream, so a review or a move to upstream starts from facts. It was compared on
2026-10-30 against upstream `main` at `915edc3` (v0.8.0).

## Where it forks

- Merge base with upstream: `6242b05` (2024-05-13, "Version increment to 0.7.14").
- The C library is upstream's: `depend/secp256k1-zkp` is the same submodule commit as at the
  merge base, `b247e1ec8ed62b9abf123dc83189d253e17d488d`. The fork changes only the Rust
  wrapper.

## What the fork adds (5 commits, Rust only)

| Commit | Date | Change |
|---|---|---|
| `18f836b` | 2025-03-21 | rand 0.5 to 0.9 (`rng()` for `thread_rng()`), edition 2021; `blank()` of the FFI types zero-initialized instead of uninitialized; FFI declarations reformatted and documented |
| `e5ee752` | 2025-09-07 | Version 0.8.0, repository URL to EpicCash |
| `a9c92ee` | 2026-03-06 | "Extra safety guards": `commit_parse` returns an error on a bad commitment instead of an `unwrap` in `verify_commit_sum`, `commit_sum`, range proof creation and verification; commitment `blank()` zeroed. The same change as upstream `ca4c010` |
| `78fbbb0` | 2026-03-06 | Compile fix for the above; the same as upstream `680910c` |
| `bf79821` | 2026-03-17 | Version 0.8.1 |

`git diff --stat 6242b05 42fcb29`: 11 files, 387 insertions, 629 deletions, all in `src/`,
`Cargo.toml` and the fuzz harness.

## What upstream has that the fork lacks

Upstream after the merge base, besides the two guards the fork took:

- `6877373` zero-initialized arrays instead of `MaybeUninit::uninit().assume_init()` everywhere,
  and the `blank()` methods gone (the fork zeroes some of them).
- `00e2381` FFI signatures matched to the C headers (pointer mutability, `c_int`/`size_t`),
  and `Clone` dropped from opaque C types.
- `d514444` a data race and unchecked return codes fixed.
- `af84dd4` hardened deserialization with regression tests.
- `5859195`, `49622b0`, `3f388db` return codes of pedersen, aggsig and range proof calls checked
  the same way.
- `b4dd5ba` bulletproof, commitment and aggsig tests.
- `ed7ffec` (PR #91) a scratch-space leak fixed.
- `d5b4968` the C library moved to `0eefcedc1fec37d54e53bac4e535afa47d6774fa`.

## What it means for LEPIC

- Only `lepic-crypto` depends on the library; every other crate goes through its types. The
  fuzz targets and the vector tests exercise the library through that crate.
- Moving to upstream v0.8.0, or asking EpicCash to take the commits above, closes the gap. Either
  is a dependency change under ADR 0010: re-run the vectors (`cargo xtask vectors verify`) and the
  fuzz targets, since the consensus results must not change.

To redo the comparison: clone upstream, fetch the pinned commit from the fork, and run
`git merge-base`, `git log --no-merges <base>..<rev>` and `git diff --stat <base> <rev>`.
