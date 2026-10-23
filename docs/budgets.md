# Size and performance budgets

## TL;DR

`cargo xtask budget` measures what a phone pays for LEPIC and fails when a measurement exceeds its
budget below: the size of the shipped library per mobile and Linux target, the time and peak
memory of a restore over the recorded G-05 node sessions, and the time and peak memory of an
Epicbox drain.
The table is the single source of the limits; `xtask/src/budget.rs` reads it.

## Budgets

| Measurement | Budget | Unit | Measured |
|---|---|---|---|
| `size.aarch64-linux-android` | 9216 | KiB | 7133 |
| `size.armv7-linux-androideabi` | 6144 | KiB | 4841 |
| `size.x86_64-linux-android` | 9728 | KiB | 7711 |
| `size.x86_64-unknown-linux-gnu` | 9728 | KiB | 7630 |
| `restore.time` | 800 | ms | 44 to 191 |
| `restore.peak_memory` | 12288 | KiB | 6084 |
| `drain.time` | 500 | ms | 48 to 139 |
| `drain.peak_memory` | 10240 | KiB | 5224 |

Measured on Linux x86_64 with the 1.99.0 toolchain while other builds shared the machine. Times are
the lowest and highest median seen across runs on that machine; load alone moved them by a factor of
four. Sizes get about 25% headroom, times about four times the highest median, memory about twice
the peak, so the check catches a regression of that order and not load or run-to-run noise. Most of
`drain.time` is the fixed cost of the test process and its setup, not the drain itself.

## What is measured

- `size.<target>`: the file size of `liblepic_ffi.so` that `cargo xtask mobile --package --target
  <target>` builds and copies into `dist/native/<target>/`. The release profile strips
  symbols, so this is the size the app bundles before its own compression.
- `restore.*`: the release build of the `lepic-wallet` test
  `restore_vectors_find_exactly_the_outputs_upstream_found`, run alone. It restores a wallet from
  the subject's phrase for every `testdata/vectors/engine/restore_*.json` session and scans the
  chain through `MockNode` replaying the recorded node responses.
- `drain.*`: the release build of the `lepic-epicbox` test
  `drain_hands_out_oldest_first_and_returns_when_the_queue_is_empty`, run alone. A client
  connects to the mock relay, receives and acknowledges three queued messages and disconnects.

Each probe runs five times. Time is the median wall time of the test process, so it includes
process start and the test's own setup and assertions. Peak memory is the largest resident set
high-water mark (`VmHWM` in `/proc/<pid>/status`) over the runs, read every millisecond.

## Limits

- Peak memory is measured on Linux only; elsewhere the rows are reported as not measured.
- The Linux library builds only on a Linux host, like the iOS ones only on macOS.
- The iOS targets build only on macOS and have no rows yet. Add `size.aarch64-apple-ios` and
  `size.aarch64-apple-ios-sim` after the first run on a macOS host.
- The recorded restore sessions are small chains, so `restore.*` catches regressions in the fixed
  cost of a restore and in per-output work, not in behaviour that only shows on a long chain.
- Probe output goes to `target/budget/`, and the size check leaves the built libraries in
  `dist/native/`, which is ignored by git (`/dist/`).

## Changing a budget

Raise a limit only with the reason in the commit body, and update the measured column from a run
of `cargo xtask budget` in the same commit. To check the failure path without building, pass a
JSON object from measurement key to a whole number in the row's unit, or to a string saying why it
was not measured:

```
cargo xtask budget --measurements over.json
```
