# Vendored grin_secp256k1zkp

LEPIC builds its secp256k1-zkp wrapper from this copy, not from git.

## Origin

- Rust wrapper: <https://github.com/EpicCash/rust-secp256k1-zkp> at
  `42fcb29d4b635ea771d1984be0d11b0e64b15a93`, crate `grin_secp256k1zkp` 0.8.1.
- C library (`depend/secp256k1-zkp`): <https://github.com/mimblewimble/secp256k1-zkp> at
  `b247e1ec8ed62b9abf123dc83189d253e17d488d`, the submodule commit of 42fcb29.

Only what `build.rs` compiles and includes is kept, with the licence and fork notes. Left out:
`.git`, CI files, `fuzz/`, the C tests and benchmarks, `src/java`, `src/asm`, `sage/`, `obj/`,
`build-aux/` and the autotools files.

## Patches

One, taken from upstream mimblewimble/secp256k1-zkp commit
`0eefcedc1fec37d54e53bac4e535afa47d6774fa` ("fix scratch leak"):

- `depend/secp256k1-zkp/src/modules/bulletproofs/rangeproof_impl.h`: two added lines, a
  `secp256k1_scratch_deallocate_frame(scratch);` before each early `return 0;` that follows a
  failed `secp256k1_bulletproof_deserialize_point` in
  `secp256k1_bulletproof_rangeproof_verify_impl`. The file is byte-identical to upstream's at
  0eefced. A proof with an invalid point is still rejected with the same return value; only the
  verifier's scratch frame is now released.

The upstream commit's new C test (`tests_impl.h`) is not applied: the C tests are not built here.

## Build changes (`build.rs`)

Each one is a change to how the C library is compiled, not to its source.

1. `SECP256K1_BUILD` defined, `SECP256K1_API` defined empty. Upstream's own build passes
   `-DSECP256K1_BUILD` for the library (mimblewimble/secp256k1-zkp `Makefile.am`,
   `libsecp256k1_la_CPPFLAGS`), and bitcoin-core/secp256k1 later put the define into
   `secp256k1.c` itself (commit `ae9e648`, "Define SECP256K1_BUILD in secp256k1.c directly",
   <https://github.com/bitcoin-core/secp256k1/pull/929>). The fork's `build.rs` never defined it,
   so `include/secp256k1.h` marked the API arguments `__nonnull__` and GCC was free to delete
   the library's own `ARG_CHECK` null checks, which it reported as 163 `-Wnonnull-compare`
   warnings. `SECP256K1_API` is emptied as rust-bitcoin/rust-secp256k1's `secp256k1-sys`
   `build.rs` does, so the static library carries no `dllexport` or visibility attribute into
   the Rust cdylib. Byte-identical outputs before and after, and proofs and signatures from
   each build verify on the other (the harness is described in the review that made this
   change).

2. `-Wno-unused-function` (when the compiler accepts it). Upstream's `configure.ac` sets it in
   `warn_CFLAGS` (mimblewimble/secp256k1-zkp `configure.ac`, line 68), and
   rust-bitcoin/rust-secp256k1's `secp256k1-sys/build.rs` passes the same flag for the same
   reason: `secp256k1.c` is a unity build and defines five static helpers
   (`secp256k1_ecmult_strauss_batch_single`, `secp256k1_ecmult_pippenger_batch_single`,
   `secp256k1_gej_is_valid_var`, `secp256k1_ge_set_infinity`, `secp256k1_fe_inv_all_var`)
   that no enabled module calls. Diagnostics only; no code changes.

3. The unconditional `-g` flag removed, as upstream mimblewimble/rust-secp256k1-zkp did in
   commit `1caad22` ("drop -g debug flag", part of
   <https://github.com/mimblewimble/rust-secp256k1-zkp/pull/89>). The `cc` crate already adds
   debug information when Cargo's profile asks for it, so the flag only forced DWARF data into
   release builds, and MSVC's `cl.exe` does not know the option. No compiled code changes.

## Rust wrapper patches (`src/`)

Each is a backport of one upstream commit, applied hunk for hunk to the vendored files. None
changes a public signature LEPIC calls, and none changes the bytes any operation produces or
accepts; that was checked with fixed-vector and mainnet-data comparisons of the old and new
builds.
1. `src/ffi.rs`, `src/key.rs`: the `extern "C"` declarations match `include/*.h`, from
   mimblewimble/rust-secp256k1-zkp commit `00e2381` ("fix ffi signatures to match c headers").
   `secp256k1_ec_pubkey_combine` takes `n: size_t` (the C side reads a 64-bit count; the wrapper
   passed a 32-bit one), six output buffers are `*mut` instead of `*const` and `serialize_vec`
   hands over `as_mut_ptr()`, the nonce-function type has the C argument order and `int` return
   (`include/secp256k1.h`, lines 100-107), `is_partial` is `c_int`
   (`include/secp256k1_aggsig.h`), `context_clone` and `scratch_space_create` take a
   `*const Context`, `rangeproof_verify` takes `*mut u64`, and the four opaque C handle types no
   longer derive `Clone`. Byte-neutral.
2. `src/pedersen.rs`: the shared bulletproof generators are created once through
   `std::sync::Once` and published through an `AtomicPtr`, instead of a `static mut` that two
   threads could read and write at the same time. From mimblewimble/rust-secp256k1-zkp commit
   `d514444` ("fix data race and return checks"), the `shared_generators` hunk. The generators
   are the same bytes (they depend only on `GENERATOR_G` and `MAX_GENERATORS`).
3. `src/pedersen.rs`: `commit`, `commit_blind` and `commit_value` check the return of
   `secp256k1_pedersen_commit` / `secp256k1_pedersen_blind_commit` and return
   `Error::InvalidCommit` when the C library reports failure (a zero value with a zero blind, or
   an overflowing blind), instead of serialising an all-zero internal commitment. From
   mimblewimble/rust-secp256k1-zkp commit `d514444`, the return-check hunks. Every successful
   commitment is byte-identical; only the failure path changes from `Ok(zeroes)` to `Err`.
4. `src/pedersen.rs`: the `RangeProof` serde visitor rejects a sequence longer than
   `MAX_PROOF_SIZE` with `invalid_length` instead of indexing past the buffer, with the
   upstream regression test. From EpicCash/rust-secp256k1-zkp commit `3028f01` ("harden
   deser/tests"), the same bound as mimblewimble/rust-secp256k1-zkp `af84dd4`. Every proof that
   deserialised before still does, to the same bytes.
5. `src/macros.rs`: `Clone` for the array newtypes (`SecretKey`, `PublicKey`, `Signature`,
   `Message` and the rest) copies the inner array instead of writing through a `&mut` into
   `MaybeUninit` memory. From mimblewimble/rust-secp256k1-zkp commit `6877373` ("zero-init
   instead of uninit"), the `macros.rs` `Clone` hunk; the rest of that commit is already covered
   by the fork's own `18f836b`. Same bytes.

Nothing else differs from 42fcb29 and the changes listed here. This file is the only addition.

## Re-checking

```
git clone https://github.com/EpicCash/rust-secp256k1-zkp fork
git -C fork checkout 42fcb29d4b635ea771d1984be0d11b0e64b15a93
git -C fork submodule update --init
cd third_party/grin_secp256k1zkp
find . -type f ! -name PATCHES.md | while read f; do diff -u "../../fork/$f" "$f"; done
```

The only output is the two lines above.
