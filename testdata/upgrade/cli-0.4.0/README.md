# cli-0.4.0

A wallet made by the released LEPIC CLI 0.4.0, as `lepic init` and the `lepic serve` users have
it. Size: 388 KB.

| | |
|---|---|
| Made by | LEPIC `31609bd81a57610ce7af08495722d17216200d1e` (0.4.0; `git describe`: `v0.3.1-460-g31609bd8`) |
| Store schema | 16 (`SCHEMA_VERSION` of that commit; the file is encrypted, so the number is not readable from outside) |
| Network | floonet, a scripted node and a mock Epicbox relay, all in process |
| Phrase | the CLI test harness's `SENDER_MNEMONIC`: `abandon` 23 times, then `art` |
| Password | `upgrade fixture password` |
| Cargo features | none selected; the test build of `lepic-cli` has `lepic-keychain/test-kdf`, `lepic-node/mock` and `lepic-epicbox/mock-relay` from its dev-dependencies. The wallet's key derivation is therefore the cheap test one: it opens only in a build with `test-kdf`, which the tests of `lepic-cli` have |

## Files

- `wallet/`: the CLI data directory (`wallet.enc.sqlite3`, `wallet.enc.sqlite3.check`,
  `wallet.vault`, `.lepic.lock`). Git keeps no file modes; the test sets 0700 and 0600 on its copy
  because the CLI refuses a data directory other users can reach.
- `chain.json`: the scripted node's chain when the generator stopped (tip 31, outputs, kernels,
  the transactions pushed and not mined). `RecordedChain` in `lepic-node` (`mock`) loads it.
- `expected.json`: what the 0.4.0 build printed with `--json`: `wallet info`, `wallet address`,
  `wallet outputs`, `tx list`, `tx show` for every transaction, `contact list`, `epic1 address`,
  and `ids` (the ids of the transactions and the contact below).

## History

1. Two funding outputs of 10 EPIC (heights 1 and 2) found by `wallet restore` from the
   phrase: transactions 1 and 2, received, confirmed.
2. A contact: the wallet invited, a second wallet (not in the fixture) accepted, both collected
   until paired. Contact `ids.contact`.
3. Send A, 1.5 EPIC, message "mined payment": by file, received and finalized by the second
   wallet, mined at tip 31, shown confirmed (transaction 3, `ids.mined`).
4. Send C, 1 EPIC, "cancelled payment": made and cancelled (transaction 4, `ids.cancelled`).
5. Send B, 2 EPIC, "pending payment": finalized and pushed, not mined when the generator stopped
   (transaction 5, `ids.pending`, state `posted`). The test mines it.
6. `epic1 address` printed the wallet's `tepic1` address (exit 0).

## Generator

`generator/upgrade_fixture.rs` is an ignored test of `lepic-cli`. To make the fixture again:

```sh
git -C ~/lepic worktree add --detach ~/lepic-worktrees/gen-040 31609bd8
cp testdata/upgrade/cli-0.4.0/generator/upgrade_fixture.rs \
   ~/lepic-worktrees/gen-040/crates/lepic-cli/tests/
cd ~/lepic-worktrees/gen-040
mkdir -p "$SCRATCH/cli-0.4.0"   # an empty directory
LEPIC_UPGRADE_OUT="$SCRATCH/cli-0.4.0" CARGO_INCREMENTAL=0 \
  cargo test -p lepic-cli --test upgrade_fixture -- --ignored
```

It uses the commit's own `tests/support` harness and needs no change to the old tree. Generated
ids, the second wallet's keys, kernel excesses and the `created_at` of the sends (wall clock of the
run) differ on every run, so a regenerated fixture replaces `expected.json` and `chain.json` with
it; do not mix files from two runs. The funding transactions carry the node's fixed dates
(2019-03-01).

## Left out

- The second wallet: only the wallet under test is kept.
- Anything the harness cannot make offline: Tor, a real node, mainnet, coinbase outputs,
  invoices, a contact in another state than paired.
- The CLI's config file and other state outside the data directory (the harness passes the
  password and node by flags and environment).

## Meaning changes since 0.4.0

None found by the test: every value of `expected.json` is listed again unchanged.
