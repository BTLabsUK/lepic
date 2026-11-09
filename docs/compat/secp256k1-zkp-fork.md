# The secp256k1-zkp fork

LEPIC's curve library is `grin_secp256k1zkp` 0.8.1 from `EpicCash/rust-secp256k1-zkp` at
`42fcb29d4b635ea771d1984be0d11b0e64b15a93`. It is vendored in `third_party/grin_secp256k1zkp`
with the upstream fixes that `PATCHES.md` there lists (ADR 0010). This page says how the fork
differs from `mimblewimble/rust-secp256k1-zkp` and which later upstream commits the vendored copy
carries.

## Where it forks

- The merge base with upstream is `6242b05`, "Version increment to 0.7.14".
- The C library is upstream's. `depend/secp256k1-zkp` is the submodule commit of the merge base,
  `b247e1ec8ed62b9abf123dc83189d253e17d488d` of `mimblewimble/secp256k1-zkp`. The fork changes
  only the Rust wrapper.

## What the fork adds

Five commits, in `src/`, `Cargo.toml` and the fuzz harness:

| Commit | Change |
|---|---|
| `18f836b` | `rand` 0.5 to 0.9 (`rng()` for `thread_rng()`), edition 2021; `blank()` of the FFI types zero-initialized instead of uninitialized; FFI declarations reformatted and documented |
| `e5ee752` | Version 0.8.0, repository URL to EpicCash |
| `a9c92ee` | "Extra safety guards": `commit_parse` returns an error on a bad commitment instead of an `unwrap` in `verify_commit_sum`, `commit_sum`, range proof creation and verification; commitment `blank()` zeroed. The same change as upstream `ca4c010` |
| `78fbbb0` | Compile fix for the above; the same as upstream `680910c` |
| `bf79821` | Version 0.8.1 |

## Upstream commits after the fork point

Upstream commits after the merge base, other than the two guards the fork has. "Vendored" means
the vendored copy carries the change as a patch.

- `6877373`: zero-initialized arrays instead of `MaybeUninit::uninit().assume_init()`, and the
  `blank()` methods gone. The fork's `18f836b` zeroes the FFI buffers and the deserializers; the
  remaining `Clone` hunk is vendored.
- `00e2381`: FFI signatures matched to the C headers (pointer mutability, `c_int` and `size_t`),
  and `Clone` dropped from opaque C types. Vendored.
- `d514444`: synchronized access to the shared bulletproof generators and checked return codes of
  the Pedersen commit calls. Vendored.
- `af84dd4`: hardened deserialization with regression tests. The `RangeProof` bound is vendored
  (it is the fork's own later commit `3028f01`); the rest of the commit touches tests and docs.
- `5859195`, `49622b0`, `3f388db`: return codes of Pedersen, aggsig and range proof calls
  checked by changing the functions' return types. Not taken, because it changes the API.
  `lepic-crypto` re-verifies every proof it creates and checks every aggsig verdict itself.
- `b4dd5ba`: bulletproof, commitment and aggsig tests. Not taken.
- `ed7ffec`, `d5b4968`: the C library moved to `0eefcedc1fec37d54e53bac4e535afa47d6774fa`, where
  `secp256k1_bulletproof_rangeproof_verify_multi` frees its scratch frame when a proof fails.
  Vendored.
- `1caad22`: the unconditional `-g` dropped from `build.rs`. Vendored.

## The vendored copy

`third_party/grin_secp256k1zkp` is the fork at `42fcb29` with its C library at `b247e1ec`, plus
the patches in `PATCHES.md`. Each patch is a backport of one named upstream commit:

- C library: the `0eefced` scratch frame change, and bitcoin-core/secp256k1 fixes made after the
  library's fork point that reach the compiled modules. They cover constant-time masks and table
  lookups, secret buffers wiped through `secp256k1_memclear`, integer-width and
  undefined-behaviour fixes (scratch sizes, batch counts, DER lengths, the SHA256 byte counter,
  RFC6979 lengths and counter), fields set on points at infinity, and `secp256k1_memcmp_var` in
  place of `memcmp`. Not taken: anything that changes an accepted or rejected input or an output
  byte (the secret-key range checks in the tweak functions, the RFC6979 change for messages
  above the group order), performance rewrites, API additions, and changes that only affect
  `VERIFY` builds or tests.
- Rust wrapper: the commits marked "Vendored" above, and the removal of two unused or deprecated
  imports in `src/pedersen.rs`.
- `build.rs`: `SECP256K1_BUILD` is defined and `SECP256K1_API` is empty, as in upstream's
  `Makefile.am` and in `rust-secp256k1-sys`, so the library's own argument checks are compiled.
  `-Wno-unused-function` is passed as in upstream's `configure.ac`. No `-g` is forced.

`PATCHES.md` lists 18 C library patches, 3 build changes and 7 wrapper patches. None changes an
output byte or an accept or reject verdict.

The workspace takes the copy as a path dependency. `third_party` is excluded from the
workspace. `cargo xtask repo-lint` fails when `Cargo.lock` resolves the wrapper from anywhere
else or holds any git source, and a test in `xtask/src/repo_lint/secp.rs` requires `PATCHES.md`
and ADR 0009 to name the commit `42fcb29d`.

To check the copy, clone the fork at `42fcb29` with its submodule and diff each vendored file
against it. Every difference is one item of `PATCHES.md`.

## What it means for LEPIC

- Only `lepic-crypto` depends on the library. Every other crate goes through its types.
- The fuzz targets and the vector tests exercise the library through that crate. The range
  proof verifier runs under `Transaction::validate`, so a target such as `slate_flow` exercises it
  with leak detection on ([fuzzing](../fuzzing.md)).
- A move to upstream or to a later EpicCash commit is a dependency change under ADR 0010. The
  consensus results must not change, so run `cargo xtask vectors verify` and the fuzz targets.
