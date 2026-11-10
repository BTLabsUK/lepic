# Size and performance budgets

`cargo xtask budget` measures what a phone pays for LEPIC and fails when a measurement exceeds its
limit. It measures the size of the shipped library per target, the time and peak memory of a
restore, a store workload and an Epicbox drain. The table below is the only place the limits are
written; `xtask/src/budget.rs` reads it. The command is not part of `cargo xtask check` or the CI
workflows; run it by hand.

```sh
cargo xtask budget
```

The command prints one line per budget, `ok`, `OVER` or `skip`, and exits non-zero when any
measurement is over its limit.

## Budgets

| Measurement | Budget | Unit |
|---|---|---|
| `size.aarch64-linux-android` | 9216 | KiB |
| `size.armv7-linux-androideabi` | 6144 | KiB |
| `size.x86_64-linux-android` | 9728 | KiB |
| `size.x86_64-unknown-linux-gnu` | 9728 | KiB |
| `restore.time` | 800 | ms |
| `restore.peak_memory` | 12288 | KiB |
| `restore_sqlite.time` | 400 | ms |
| `restore_encrypted.time` | 400 | ms |
| `store_plain.time` | 700 | ms |
| `store_encrypted.time` | 700 | ms |
| `drain.time` | 500 | ms |
| `drain.peak_memory` | 10240 | KiB |

The parser reads the first three columns of each row under the `## Budgets` heading. A key must
name a size target or a probe with `time` or `peak_memory`, and the unit must match the key.

## What is measured

- `size.<target>`: the size of `liblepic_ffi.so` that `cargo xtask mobile --package --target
  <target>` builds and copies into `dist/native/<target>/`, rounded up to whole KiB. The release
  profile strips symbols (`strip = true`), so this is the size the app bundles before its own
  compression.
- `restore.*`: the release build of the `lepic-wallet` test
  `restore_vectors_find_exactly_the_outputs_upstream_found` (`tests/vectors.rs`), run alone. For
  each `testdata/vectors/engine/restore_*.json` it restores a wallet from the recorded phrase and
  scans the chain through `MockNode`, which replays the recorded node responses. It runs on the
  in-memory store.
- `restore_sqlite.*`, `restore_encrypted.*`: the same restore on the plain SQLite store and on the
  SQLite store encrypted at rest, the `lepic-wallet` tests `restore_vectors_on_the_plain_sqlite_store`
  and `restore_vectors_on_the_encrypted_sqlite_store`.
- `store_plain.*`, `store_encrypted.*`: the `lepic-store` tests
  `plain_store_workload_of_2000_transactions` and `encrypted_store_workload_of_2000_transactions`
  (`tests/at_rest_probe.rs`). Each creates a database, writes 2,000 transactions in commits of 100,
  refreshes them (reads all, sets each one's confirmed height, in commits of 100) and opens the
  database again.
- `drain.*`: the release build of the `lepic-epicbox` test
  `drain_hands_out_oldest_first_and_returns_when_the_queue_is_empty` (`tests/client.rs`), run
  alone. A client connects to the mock relay, receives and acknowledges three queued messages and
  disconnects.

Each probe runs five times. Time is the median wall time of the test process, so it includes
process start and the test's own setup and assertions. Peak memory is the largest resident set
high-water mark (`VmHWM` in `/proc/<pid>/status`) over the runs, read every millisecond. Probe
output goes to `target/budget/<probe>-<run>.log`.

Before it measures a probe, the command lists the test binary and stops if the named test does not
exist, so a renamed test cannot pass as an empty run.

## Not measured

A row is reported as `skip` when the host cannot take it:

- Peak memory is read from `/proc`, so it is measured on Linux only.
- `size.x86_64-unknown-linux-gnu` builds on a Linux host only. It links against the host's glibc.
- The iOS targets (`aarch64-apple-ios`, `aarch64-apple-ios-sim`) build on macOS only. The table has
  no rows for them.

The recorded restore sessions are small chains, so `restore.*` shows a change in the fixed cost of a
restore and in per-output work, not in behaviour that appears only on a long chain.

`cargo xtask mobile --package` leaves the built libraries in `dist/native/`, which git ignores.

## Encryption at rest

The test `compare_plain_and_encrypted_store` in `crates/lepic-store/tests/at_rest_probe.rs` is
ignored by default. It runs the store workload plain and encrypted seven times each, alternating,
and prints the median of each phase (`create`, `write`, `refresh`, `reopen`) and the ratio of
encrypted to plain. To run it on an arm64 Android device, build the test binary and run it with
adb:

```sh
cargo ndk -t arm64-v8a --platform 24 test -p lepic-store --release --test at_rest_probe --no-run
adb push target/aarch64-linux-android/release/deps/at_rest_probe-<hash> /data/local/tmp/at_rest_probe
adb shell 'cd /data/local/tmp && TMPDIR=/data/local/tmp ./at_rest_probe --ignored --nocapture'
```

`<hash>` is the suffix of the file `cargo ndk` built.

## Changing a budget

Change a limit in the table, with the reason in the commit body, and run `cargo xtask budget`.
To check the failure path without building, pass a JSON object from key to a whole number in the
key's unit, or to a string that says why the key was not measured:

```sh
cargo xtask budget --measurements over.json
```

```json
{ "size.aarch64-linux-android": 99999, "restore.peak_memory": "not measured here" }
```

A key in the file that has no row in the table is an error. A row without a measurement is
reported as `skip`.
