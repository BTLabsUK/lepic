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

Nothing else differs from 42fcb29. This file is the only addition.

## Re-checking

```
git clone https://github.com/EpicCash/rust-secp256k1-zkp fork
git -C fork checkout 42fcb29d4b635ea771d1984be0d11b0e64b15a93
git -C fork submodule update --init
cd third_party/grin_secp256k1zkp
find . -type f ! -name PATCHES.md | while read f; do diff -u "../../fork/$f" "$f"; done
```

The only output is the two lines above.
