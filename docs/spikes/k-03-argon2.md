# Spike K-03: Argon2id parameters for the seed vault

## TL;DR

New vaults use Argon2id v0x13 with m = 64 MiB, t = 3, p = 1 (`KdfParams::DEFAULT` in
`crates/lepic-keychain/src/vault/kdf.rs`). An unlock took a median 187 ms on the Linux host and
174 ms on the Android emulator, well under the 500 ms budget on both. The emulator runs on the
same x86_64 CPU as the host, so neither number is phone-class. The default keeps about 2.6 times
headroom for slower phones. No arm64 device was measured.

Date: 2026-10-02.

## Command

Host, from the repository root:

```
cargo bench -p lepic-keychain --locked --bench argon2
```

Android emulator, with the release profile the app ships (`opt-level = "s"`, fat LTO):

```
ANDROID_NDK_HOME=~/Android/Sdk/ndk/28.2.13676358 \
  cargo ndk -t x86_64-linux-android -P 24 build --release --locked -p lepic-keychain --bench argon2
adb push target/x86_64-linux-android/release/deps/argon2-<hash> /data/local/tmp/lepic-argon2-bench
adb shell "cd /data/local/tmp && ./lepic-argon2-bench"
```

Each row times `Vault::open` on a vault holding one 32-byte seed: one Argon2id run plus
decrypting the file. One unmeasured warm-up, then 5 samples (`LEPIC_BENCH_SAMPLES` changes the
count). The two runs were made one after the other, never together, because the emulator shares
the host CPU. Other builds were compiling on the machine (load average about 2 on 16 threads).

## Targets

| Target | CPU | Argon2 code path | Toolchain |
|---|---|---|---|
| Host | AMD Ryzen 7 4800H, 16 threads, Linux | AVX2 (detected at run time) | Rust 1.99.0, bench profile |
| Emulator | Android 16 (API 36) x86_64 image, 4 vCPUs on the same host, 2.5 GB RAM | portable, the guest reports no AVX2 | Rust 1.99.0, NDK 28.2.13676358, release profile |

## Results

Median and slowest of 5 runs, in milliseconds.

| m (MiB) | t | host median | host max | emulator median | emulator max |
|---|---|---|---|---|---|
| 19 | 1 | 14 | 15 | 19 | 19 |
| 19 | 2 | 30 | 32 | 33 | 36 |
| 19 | 3 | 45 | 49 | 48 | 50 |
| 19 | 4 | 60 | 60 | 62 | 63 |
| 32 | 1 | 42 | 43 | 33 | 33 |
| 32 | 2 | 71 | 72 | 58 | 59 |
| 32 | 3 | 98 | 100 | 84 | 85 |
| 32 | 4 | 123 | 125 | 110 | 113 |
| 46 | 1 | 64 | 65 | 49 | 51 |
| 46 | 2 | 103 | 106 | 87 | 89 |
| 46 | 3 | 145 | 147 | 123 | 126 |
| 46 | 4 | 183 | 191 | 162 | 173 |
| 64 | 1 | 81 | 85 | 68 | 70 |
| 64 | 2 | 139 | 142 | 122 | 122 |
| 64 | 3 | 187 | 189 | 174 | 182 |
| 64 | 4 | 238 | 269 | 227 | 230 |
| 128 | 1 | 165 | 167 | 145 | 146 |
| 128 | 2 | 270 | 272 | 256 | 259 |
| 128 | 3 | 378 | 379 | 360 | 375 |
| 128 | 4 | 490 | 491 | 463 | 468 |

The final `default` line of both runs (a separate measurement of 64 MiB, t = 3) gave a median of
184 ms and a maximum of 196 ms on the host, and 172 ms and 173 ms on the emulator.

Raw output, host:

```
argon2id v0x13, p=1, 32-byte key, 5 samples per set
 m (MiB)   t   median ms      max ms
      19   1          14          15
      19   2          30          32
      19   3          45          49
      19   4          60          60
      32   1          42          43
      32   2          71          72
      32   3          98         100
      32   4         123         125
      46   1          64          65
      46   2         103         106
      46   3         145         147
      46   4         183         191
      64   1          81          85
      64   2         139         142
      64   3         187         189
      64   4         238         269
     128   1         165         167
     128   2         270         272
     128   3         378         379
     128   4         490         491
default m=64 MiB t=3 p=1: median 184 ms, max 196 ms
```

Raw output, emulator:

```
argon2id v0x13, p=1, 32-byte key, 5 samples per set
 m (MiB)   t   median ms      max ms
      19   1          19          19
      19   2          33          36
      19   3          48          50
      19   4          62          63
      32   1          33          33
      32   2          58          59
      32   3          84          85
      32   4         110         113
      46   1          49          51
      46   2          87          89
      46   3         123         126
      46   4         162         173
      64   1          68          70
      64   2         122         122
      64   3         174         182
      64   4         227         230
     128   1         145         146
     128   2         256         259
     128   3         360         375
     128   4         463         468
default m=64 MiB t=3 p=1: median 172 ms, max 173 ms
```

## Choice

- Time grows linearly in m × t on both targets, about 1 ms per MiB-pass on the host.
- 128 MiB with t = 3 also fits 500 ms on both measured targets, but leaves no room for a phone
  that is only 1.4 times slower, and asks a low-end phone for 128 MiB while the app runs.
- 64 MiB with t = 3 costs under 200 ms on both targets. It matches the second recommended
  setting of RFC 9106 in memory and passes, and is above the OWASP minimum (19 MiB, t = 2).
- p = 1 because the `argon2` crate is built without its `parallel` feature, so lanes run one after
  another. More lanes would cost the same time and add no strength against an attacker.
- The parameters are stored in every vault header and `Vault::rekey` changes them, so a later
  measurement on real phones can raise or lower the default without breaking existing vaults.
  Headers are bounded at 1 GiB, 16 passes and 8 lanes so a crafted file cannot demand more.

## Not measured

- An arm64 phone or emulator. The only system image here is x86_64 and no device was attached.
  Typical low-end arm64 cores are several times slower than this host, so measure on one before
  1.0 and lower t first if an unlock passes 500 ms.
- iOS, for the reason given in `docs/spikes/f-03-mobile-build.md`.
- On mobile the host app is expected to keep the seed in the platform keystore (ADR 0005), so the
  vault KDF is on the unlock path mainly on desktop.
