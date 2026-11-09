# Argon2id parameters for the seed vault

New vaults derive their key with Argon2id version 0x13 at 64 MiB of memory, 3 passes and 1 lane
(`KdfParams::DEFAULT` in `crates/lepic-keychain/src/vault/kdf.rs`). The vault parameters sit in
each vault's header, so a vault keeps the parameters it was written with.

## Parameters in code

| Constant | Value | Meaning |
|---|---|---|
| `KdfParams::DEFAULT` | 64 MiB, 3 passes, 1 lane | What `lepic-ffi` (`api/runtime.rs`) and `lepic-cli` (`host.rs`) pass for a new vault. |
| `MIN_WRITE_MEMORY_KIB` | 19 MiB | Least memory a new vault or a rekey may use. |
| `MIN_WRITE_COST_KIB` | 38 MiB | Least memory times passes. 19 MiB with two passes and 46 MiB with one both meet it. |
| `MAX_MEMORY_KIB` | 128 MiB | Largest memory a header may ask for. |
| `MAX_ITERATIONS` | 4 | Most passes. |
| `MAX_PARALLELISM` | 8 | Most lanes. |

- The write floor is the smallest Argon2id setting OWASP recommends. `Vault::create` and
  `Vault::rekey` refuse parameters below it. A file written with weaker parameters still opens.
- The upper bounds are the largest settings LEPIC itself writes: the default and the candidates in
  the benchmark. They stop a crafted vault file or sealed text from demanding more memory or time
  than LEPIC spends.
- `KdfParams::new` accepts any setting inside the bounds that Argon2 allows (8 KiB per lane at
  least). `KdfParams::for_tests` needs the `test-kdf` feature, which app builds never enable. It
  lets tests of higher layers use weak, fast parameters.
- The cost is 1 lane because the `argon2` crate is built without its `parallel` feature
  (`Cargo.toml` sets `default-features = false`). Lanes run one after another, so more lanes cost
  the same time and add no strength against an attacker.
- `Vault::rekey` writes new parameters, so the default can change without breaking existing vaults.

## Why 64 MiB and 3 passes

- Time grows linearly in memory times passes.
- 64 MiB with 3 passes matches the second recommended setting of RFC 9106 in memory and exceeds the
  OWASP minimum.
- 128 MiB with 3 passes leaves little room on a slower phone and asks a low-end phone for 128 MiB
  while the app runs.
- The aim is an unlock under 500 ms. On mobile the host app keeps the seed in the platform
  keystore (ADR 0005), so the vault key derivation is on the unlock path mainly on desktop.

## Measurements

The spike timed `Vault::open` on a vault holding one 32-byte seed: one Argon2id run plus decrypting
the file. Each figure is the median of 5 runs after one warm-up run.

| Target | Hardware | 64 MiB, 3 passes |
|---|---|---|
| Linux host | AMD Ryzen 7 4800H, 16 threads, Argon2 on the AVX2 path | 187 ms |
| Android 16 emulator | x86_64 image, 4 vCPUs on the same CPU, no AVX2 in the guest | 174 ms |

Both are under the 500 ms aim. The emulator shares the host CPU, so neither figure represents a
phone. No arm64 device and no iOS device was measured. Measure on one before lowering the aim.
Lower the pass count first if an unlock passes 500 ms.

## Running the benchmark

```text
cargo bench -p lepic-keychain --locked --bench argon2
```

The benchmark (`crates/lepic-keychain/benches/argon2.rs`) prints the median and slowest run for
memory of 19, 32, 46, 64 and 128 MiB with 1 to 4 passes, then the default. `LEPIC_BENCH_SAMPLES`
sets the runs per set; the default is 5.

For Android, build the benchmark with `cargo ndk -t <target> -P 24 build --release --benches`, push
the binary from `target/<target>/release/deps/` to the device and run it there. The build needs the
tools in [f-03-mobile-build.md](f-03-mobile-build.md).
