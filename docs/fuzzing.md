# Fuzzing on a schedule, locally

The fuzz targets in `fuzz/` run for a fixed time with `cargo xtask fuzz`, which seeds each corpus,
builds the targets on the nightly that `fuzz/rust-toolchain.toml` pins, and fails when a target
crashes (the input is kept under `fuzz/artifacts/<target>/`):

```sh
cargo xtask fuzz --smoke                       # every target for 60 seconds
cargo xtask fuzz --full                        # every target for 10 minutes
cargo xtask fuzz --full --target slate_flow    # one target; --target repeats
```

`slate_flow` is the stateful target: it builds an honest send and an honest invoice once, then
hands the receiver, the sender, the payer and the issuer a changed slate (`build_s2`, `build_s3`,
`build_i2`, `build_i3`) and checks that what a builder accepts still has the agreed amount, fee and
id. Its inputs are edit scripts, not slates, so its corpus says nothing on its own.

Until the curve library takes upstream's scratch-leak fix (`docs/compat/secp256k1-zkp-fork.md`),
`slate_flow` stops on that leak within minutes. To look past it, run the target directly in `fuzz/`:
`ASAN_OPTIONS=detect_leaks=0 cargo fuzz run slate_flow -- -detect_leaks=0 -max_total_time=600`.

## A scheduled run without CI

Run the full set once a night on a machine that builds LEPIC, from a clean checkout of `main`. A
crontab line:

```cron
# m h dom mon dow
30 2 * * *  cd "$HOME/lepic-fuzz" && git pull -q --ff-only && cargo xtask fuzz --full --jobs 2 > fuzz.log 2>&1 || echo "fuzz failed: $HOME/lepic-fuzz/fuzz.log"
```

A systemd user timer with `OnCalendar=*-*-* 02:30` running the same command does the same and
keeps the log in the journal.

- A full run takes ten minutes per target divided by `--jobs`; keep `--jobs` within the machine's
  memory, as each target may use up to 2.5 GB (`-rss_limit_mb=2560`).
- The corpora under `fuzz/corpus/` grow between runs and are not committed.
- A crash becomes a regression test in the owning crate before it is fixed (docs/rules.md).
