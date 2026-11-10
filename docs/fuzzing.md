# Fuzzing

The `fuzz/` workspace holds 34 libFuzzer targets that feed arbitrary bytes to the readers of
untrusted input: slate codecs, Epicbox frames, node responses, files, links and QR texts. `cargo
xtask fuzz` seeds the corpora, builds the targets and runs them for a fixed time. A target that
crashes fails the run and its input is kept.

## Commands

```sh
cargo xtask fuzz --build                       # build every target, run nothing
cargo xtask fuzz --smoke                       # run every target for 60 seconds
cargo xtask fuzz --full                        # run every target for 600 seconds
cargo xtask fuzz --full --target slate_flow    # one target; --target repeats
cargo xtask fuzz --smoke --jobs 4              # four targets at a time
```

Exactly one of `--build`, `--smoke` and `--full` is required. `--jobs` defaults to 1.

Each run:

1. Runs `cargo fetch --locked` in `fuzz/` and stops if `fuzz/Cargo.lock` is out of date. Run
   `cargo fuzz build` in `fuzz/` and commit the lockfile.
2. Writes the seeds into the corpora (below).
3. Builds the targets with `cargo fuzz build` on the nightly that `fuzz/rust-toolchain.toml`
   pins (`nightly-2026-10-02`, minimal profile, with rustfmt and clippy). `cargo-fuzz` 0.13.2 is
   the version CI installs.
4. Runs each target with `-timeout=25 -rss_limit_mb=2560 -print_final_stats=1` and
   `-max_total_time` set to the run length. A target is killed and reported as failed if it is
   still running 300 seconds after its fuzz time.

A target may use up to 2.5 GB of memory, so keep `--jobs` within the machine's memory.

| Path | Holds |
|---|---|
| `fuzz/corpus/<target>/` | Seeds and the inputs libFuzzer adds |
| `fuzz/artifacts/<target>/` | Crashing, slow and out-of-memory inputs |
| `fuzz/target/fuzz-logs/<target>.log` | The target's output; the last 40 lines are printed when it fails |

Git ignores all three. To rerun one crash input, run `cargo fuzz run <target>
artifacts/<target>/<file>` in `fuzz/`.

## Seeds

The command writes seeds as `fuzz/corpus/<target>/seed-<n>`, taken from the golden vectors in
`testdata/vectors` (primitives, slates, slates_native, engine, epicbox `message_*`, keys
`epic1_*` and `wallet_seed_*`, app_data `wfeh_*`) and from `testdata/node`. A few targets get
built-in seeds: `notice_classify`, `vault_file`, `slate_flow` and `ur_slate_decode`. Inputs
that libFuzzer added are left alone between runs.

## Targets

`fuzz/Cargo.toml` and `TARGETS` in `xtask/src/fuzz.rs` list the same names; a unit test keeps
them equal.

| Target | Reads |
|---|---|
| `app_data_open` | The `WFEH` app data file: header, key check and AEAD body |
| `armor_sealed` | Armored sealed text of either marker pair |
| `contact_backup_import` | The contact list of a `.wfeh` history payload |
| `contact_card` | Contact card bytes and the `epiccash://contact/1/` link |
| `envelope_inner` | The inner TLV fields of an opened envelope |
| `epic1_link` | Text through the `epic1` link and address readers, with a round trip |
| `epicbox_address` | Epicbox address text on both networks |
| `epicbox_frame` | Epicbox frames in both directions and the pushed `Slate` frame |
| `epicbox_message` | The encrypted Epicbox message, without the signature check |
| `ffi_inspect_slate` | `inspect_slate` on both chains |
| `file_import` | Slate file bytes through the file method's format policy |
| `foreign_rpc` | The foreign API JSON-RPC decoders; the first byte picks the decoder |
| `legacy_rows` | Rows of an `epic-wallet` database that the history import reads |
| `node_response` | Node JSON-RPC response bodies through the `lepic_node::decode` decoders |
| `notice_classify` | Decrypted Epicbox payload classification and the invoice message |
| `onion_parse` | Onion addresses and the head of a SOCKS reply |
| `pair_answers` | Bodies of the pairing answer messages |
| `pair_invite` | Pairing invites, the `epiccash://pair/1/` link, reply and confirm bodies |
| `pair_words` | Typed pairing words and the rendezvous mailbox text |
| `payment_file` | The payment file classifier and its armor |
| `relay_discovery` | A relay's onion discovery answer |
| `seal_open` | Decoding and opening sealed envelopes |
| `ser_read` | Binary reads of every transaction part at both protocol versions; the first byte is the type, the second the version |
| `slate_detect` | Codec detection over both legacy codecs |
| `slate_flow` | A stateful run of the slate builders (below) |
| `slate_marker` | The LEPIC marker probes |
| `slate_native` | The `lepic.v1` codec |
| `slate_v2`, `slate_v3` | The legacy V2 and V3 JSON codecs |
| `tor_control_reply` | Lines of the Tor control port |
| `tx_decode` | `Transaction::decode` with its consensus checks; the first byte is the version |
| `ur_slate_decode` | Scanned `ur:epic-slate` QR texts |
| `vault_file` | The vault file header and framing |
| `wallet_seed` | The `wallet.seed` file |

### slate_flow

`slate_flow` builds one honest send and one honest invoice, then hands a changed slate to the next
builder. The first byte of an input picks the step:

| First byte | Step |
|---|---|
| 0 | A changed S1 goes to `build_s2`, and its S2 to `build_s3` |
| 1 | A changed S2 goes to `build_s3` |
| 2 | A changed I1 goes to `build_i2`, and its I2 to `build_i3` |
| 3 | A changed I2 goes to `build_i3` |

The remaining bytes are edits that `mutate_slate` applies to the slate. A builder that accepts the
slate must not have let the peer change the agreed amount, fee or id. The inputs are edit
scripts, not slates, so the corpus means nothing without the target.

`slate_flow` builds and verifies range proofs, so it reaches the curve library's allocation
paths. xtask passes no `-detect_leaks` option, so libFuzzer's leak detection stays on. The
vendored library releases the verifier's scratch frame on a failed proof
([the secp256k1-zkp fork](compat/secp256k1-zkp-fork.md)).

## In CI

| Workflow | Job | Runs |
|---|---|---|
| `ci.yml` | `fuzz-build` | `cargo xtask fuzz --build` on every pull request and push to `main` |
| `scheduled.yml` | `fuzz-smoke` | `cargo xtask fuzz --smoke --jobs 4` each Monday; it uploads `fuzz/artifacts/` and `fuzz/target/fuzz-logs/` |

## A scheduled run without CI

A machine that builds LEPIC can run the full set from a clean checkout of `main`. A crontab line:

```cron
# m h dom mon dow
30 2 * * *  cd "$HOME/lepic-fuzz" && git pull -q --ff-only && cargo xtask fuzz --full --jobs 2 > fuzz.log 2>&1 || echo "fuzz failed: $HOME/lepic-fuzz/fuzz.log"
```

A systemd user timer with `OnCalendar=*-*-* 02:30` running the same command does the same and
keeps the log in the journal. A full run takes 600 seconds per target, divided by `--jobs`.

## A crash

A crash input becomes a regression test in the crate that owns the reader, before the fix
([rules](rules.md)).
