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
