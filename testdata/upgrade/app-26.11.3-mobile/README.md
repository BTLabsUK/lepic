# app-26.11.3-mobile

A wallet made through the FFI (`lepic-ffi`, the library of the app), the way the mobile app of release 26.11.3 creates a wallet. Size: 382 KB.

| | |
|---|---|
| Made by | LEPIC `b6f5003fdc0d5404cc549131c790cac280c9d9aa` (the pin of the app release 26.11.3, wallet-for-epic tag `v26.11.3`) |
| Store schema | 13 (`SCHEMA_VERSION` of that commit; the file is encrypted, so the number is not readable from outside) |
| Network | floonet, a scripted node and a mock Epicbox relay (`relay.example.org:443`), all in process |
| Made with | `EpicWallet.createWithPin` with the PIN `471100` |
| Opened with | `EpicWallet.openWithPin(pin, sealed_password)` |
| Password | none the user types: the library made a random password and sealed it. `secrets.json` holds `sealed_password`; the PIN is `471100` |
| Phrase | in `mnemonic.txt` (a random throwaway phrase the library made) |
| Cargo features | `lepic-ffi` test build with `mock`, which the crate's dev-dependency turns on: `lepic-node/mock`, `lepic-epicbox/mock-relay`, `lepic-keychain/test-kdf`. The key derivation is the cheap test one, so the wallet opens only in a build with `test-kdf`, which the tests of `lepic-ffi` have |

## Files

- `wallet/`: the wallet directory the library kept (`wallet.enc.sqlite3`,
  `wallet.enc.sqlite3.check`, `.lepic.lock`). The library keeps the vault in the app's secret
  store, not here.
- `secrets.json`: `pin`, `sealed_password` and `store`, the entries (`lepic.pin-key`, `lepic.vault`) the library
  had written to the app's secret store, by their raw key names. The test serves them back
  through `AppSecretStore::in_memory()`.
- `chain.json`: the scripted node's chain when the generator stopped (tip 30, outputs, kernels,
  the transactions pushed and not mined). `RecordedChain` in `lepic-node` (`mock`) loads it.
- `expected.json`: what the build listed through its own calls: `summary(false)`, `outputs`,
  `transactions` and `contacts`, plus `store_at_rest` (the `Debug` text of the value) and `ids`
  (the ids of the transactions and the contact below). Enums are kept as their `Debug` text.
- `mnemonic.txt`: the phrase. The test uses it to open the database as another program would,
  to see that the tables of schema 17 exist.

## History

1. Two funding outputs of 10 EPIC (heights 1 and 2), found by `scan_to_tip` at height 20:
   transactions 1 and 2, received, confirmed.
2. A contact: the wallet invited ("Fixture friend"), a second wallet (not in the fixture)
   accepted as "Fixture owner", both collected until paired. Contact `ids.contact`.
3. Send A, 1.5 EPIC, "mined payment": received and finalized by the second wallet, posted,
   mined, tip 30, refreshed to confirmed (transaction 3, `ids.mined`).
4. Send C, 1 EPIC, "cancelled payment": made and cancelled (transaction 4, `ids.cancelled`).
5. Send B, 2 EPIC, "pending payment": finalized and posted, not mined when the generator
   stopped (transaction 5, `ids.pending`, status `Posted`). The test mines it.

## Generator

`generator/upgrade_fixture.rs` is an ignored test in `lepic-ffi`. `generator/helpers.patch` adds
the module line to `src/tests.rs` and `MockBackend::snapshot` to `src/mock.rs` of the old tree.
To make the fixture again (`$FIXTURE` is this directory):

```sh
git -C ~/lepic worktree add --detach ~/lepic-worktrees/gen b6f5003fdc0d5404cc549131c790cac280c9d9aa
cd ~/lepic-worktrees/gen
git apply "$FIXTURE/generator/helpers.patch"
cp "$FIXTURE/generator/upgrade_fixture.rs" crates/lepic-ffi/src/tests/
mkdir -p "$SCRATCH/out"   # an empty directory
LEPIC_UPGRADE_OUT="$SCRATCH/out" LEPIC_UPGRADE_KIND=mobile CARGO_INCREMENTAL=0 \
  cargo test -p lepic-ffi write_the_ffi_fixture -- --ignored
```

The generator calls the library as the app does. Ids, keys, kernel excesses and the
`created_at_ms` of the sends and the contact (wall clock of the run) differ on every run; a
regenerated fixture replaces all its files, and files of two runs must not be mixed.

## Left out

- The second wallet: only the wallet under test is kept.
- What the app adds around the library, which a library test cannot make: the app prefixes
  every secret-store key (`lepic:<chain>:<dataDir>:`), keeps the wallet in `<dataDir>/lepic` and
  writes `wfe_meta.json`. The fixture holds the raw keys the library wrote and the library files
  only.
- A real keystore (the store is in memory), Tor, a real node, mainnet, coinbase outputs,
  invoices, contacts in another state than paired.

## Meaning changes since the build

None found: every value of `expected.json` is listed again unchanged by the current code.
