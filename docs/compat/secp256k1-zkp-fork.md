# The secp256k1-zkp fork

LEPIC's curve library is `grin_secp256k1zkp` from `EpicCash/rust-secp256k1-zkp` at
`42fcb29d4b635ea771d1984be0d11b0e64b15a93`, vendored in `third_party/grin_secp256k1zkp` with the
upstream fixes its `PATCHES.md` lists (ADR 0010, "The vendored copy" below). It is a fork of
`mimblewimble/rust-secp256k1-zkp`. This page records how the fork differs from upstream, so a
review or a move to upstream starts from facts. It was compared on 2026-10-30 against upstream
`main` at `915edc3` (v0.8.0), and on 2026-11-04 against the EpicCash fork's `main` and the
C library's upstreams (mimblewimble, ElementsProject and bitcoin-core).

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

After 42fcb29 the fork has two more commits (as of 2026-11-04): `11b505f` moves the C submodule
to `EpicCash/secp256k1-zkp` at `69adeea`, which is mimblewimble `b247e1e` plus the scratch-leak
fix (the same two lines as `0eefced`; the tree is byte-identical to the vendored one), and
`3028f01` bounds the `RangeProof` deserializer (the same change as upstream `af84dd4`). Both are
in the vendored copy.

## What upstream has that the fork lacks

Upstream after the merge base, besides the two guards the fork took. "Vendored" means the
vendored copy carries the change as a patch (`PATCHES.md`):

- `6877373` zero-initialized arrays instead of `MaybeUninit::uninit().assume_init()` everywhere,
  and the `blank()` methods gone. The fork's `18f836b` zeroes the FFI buffers and the
  deserializers; the remaining `Clone` hunk is vendored.
- `00e2381` FFI signatures matched to the C headers (pointer mutability, `c_int`/`size_t`),
  and `Clone` dropped from opaque C types. Vendored.
- `d514444` a data race on the shared bulletproof generators and unchecked return codes of the
  pedersen commit calls fixed. Vendored.
- `af84dd4` hardened deserialization with regression tests. The `RangeProof` bound is vendored
  (through the fork's `3028f01`); the rest of the commit touches tests and docs.
- `5859195`, `49622b0`, `3f388db` return codes of pedersen, aggsig and range proof calls checked
  by changing the functions' return types. Not taken: an API change; `lepic-crypto` re-verifies
  every proof it creates and checks every aggsig verdict itself.
- `b4dd5ba` bulletproof, commitment and aggsig tests. Not taken: tests only.
- `ed7ffec` (PR #91), `d5b4968`: the C library moved to
  `0eefcedc1fec37d54e53bac4e535afa47d6774fa`, "fix scratch leak":
  `secp256k1_bulletproof_rangeproof_verify_multi` freed no scratch frame when a proof failed.
  Vendored.
- `1caad22` (PR #89) drops the unconditional `-g` from `build.rs`. Vendored.

## What it means for LEPIC

- The scratch leak reached LEPIC: every transaction whose range proof failed
  `Transaction::validate` leaked 416 bytes, and a peer could send such slates to a listener as
  often as its rate limits allow. The `slate_flow` fuzz target found it within minutes. The
  vendored copy below closes it.
- Only `lepic-crypto` depends on the library; every other crate goes through its types. The
  fuzz targets and the vector tests exercise the library through that crate.
- The wrapper gap is closed except for the return-type changes and the tests. A move to
  upstream v0.8.0, or to a later EpicCash commit, is a dependency change under ADR 0010: re-run
  the vectors (`cargo xtask vectors verify`) and the fuzz targets, since the consensus results
  must not change.

## The vendored copy

`third_party/grin_secp256k1zkp` is the fork at 42fcb29 with its C library at b247e1ec, plus the
patches `PATCHES.md` there lists, each a backport of one named upstream commit:

- C library: the `0eefced` scratch-leak fix, and bitcoin-core/secp256k1 fixes from after the
  2018 fork point that the compiled modules reach: the constant-time masks and table lookups
  written as upstream writes them now, secret buffers wiped through `secp256k1_memclear`,
  integer-width and undefined-behaviour fixes (scratch sizes, batch counts, DER lengths, the
  SHA256 byte counter, RFC6979 lengths and counter), fields set on points at infinity, and
  upstream's `secp256k1_memcmp_var` in place of `memcmp`. Not taken: anything that changes an
  accepted or rejected input or an output byte (the secret-key range checks in the tweak
  functions, the RFC6979 change for messages above the group order), performance rewrites, API
  additions, and VERIFY-only or test-only changes.
- Rust wrapper: the mimblewimble and EpicCash commits marked "Vendored" above, and LEPIC's own
  removal of two unused or deprecated imports in `src/pedersen.rs` (no rustc warnings).
- `build.rs`: `SECP256K1_BUILD` and an empty `SECP256K1_API` are defined, as upstream's
  `Makefile.am` and rust-secp256k1-sys do, so the library's own argument checks are compiled
  as in upstream's build; `-Wno-unused-function` as upstream's `configure.ac`; no forced `-g`.

The workspace takes it as a path dependency; `third_party` is excluded from the workspace, and
`cargo xtask repo-lint` rejects any git source in the product lockfile.

Why patches and not upstream v0.8.0 or the fork's `main`: each patch is one upstream commit
with a stated reason, and none changes an output byte or a verdict, which was proven by building
the crate before and after and comparing fixed vectors (keys, ECDSA, commitments, sums,
bulletproofs single and batched, aggsig, rewinds) and Epic mainnet blocks (outputs with proofs,
kernel signatures) in both directions: every proof and signature from the old build verifies on
the new and the other way round. v0.8.0 also changes return types, which `lepic-crypto` would
have to follow. Pushing a patched fork elsewhere would put the dependency outside this repository.

To re-check: clone the fork at 42fcb29 with its submodule and diff each vendored file against
it, as `PATCHES.md` shows; every difference is one of its items.

The next release candidate runs the full check on the vendored copy: `cargo xtask vectors
verify`, the fuzz targets (`slate_flow` with leak detection on), the full test suite, and the
Android, iOS and Windows builds.

To redo the comparison: clone upstream, fetch the pinned commit from the fork, and run
`git merge-base`, `git log --no-merges <base>..<rev>` and `git diff --stat <base> <rev>`.
