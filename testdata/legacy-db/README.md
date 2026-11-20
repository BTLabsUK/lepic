# Legacy wallet databases

This directory holds `epic-wallet` SQLite databases (`wallet_data/db/sqlite/epic.db`) as fixtures
for the legacy history reader in `crates/lepic-store/src/legacy/`. The format is in
[docs/compat/epic-wallet-db.md](../../docs/compat/epic-wallet-db.md).

The test `reads_every_fixture_without_skipping` in `crates/lepic-store/tests/store/legacy.rs` reads every
`*.db` file here, with its `*.db-wal` file if present, from a temporary copy. It requires at least
one account and no skipped row. It fails when `epic-wallet-4.0.2.db` is not here.

Only databases of throwaway wallets on a local or test chain belong here, because a database also
holds private transaction contexts. Record for each file which `epic-wallet` version wrote it and
what history it holds.

## Files

### `epic-wallet-4.0.2.db` (44 KiB), `epic-wallet-4.0.2.txs.json` (8 KiB)

Written by `epic-wallet 4.0.2 (git 465d499)`, the build in `interop/.work/bin/epic-wallet-legacy`, on a
throwaway `--usernet` wallet (password `fixturepass`, no funds, the seed is not in the database).
It was made in two stages.

Stage 1, the base: `init`, then `account --create savings`, then `import_tx` of six
transactions into the default account (ids 0 to 5): a sent and a received transaction, a
cancelled send with a cancel height, a cancelled receive, a confirmed coinbase and a confirmed
send with a kernel excess. That wallet never saw a node and held no outputs. The base lacks the
`i` row (next transaction id) that a wallet writes itself, so stage 2 starts from a copy with one
`i` row of `6` added, or the new transactions would overwrite ids 0 to 2.

Stage 2, outputs: the same 4.0.2 binary ran against a scripted node, a small local HTTP server
that answered `get_status`, `get_outputs`, `push_transaction`, the pool listing and an empty
UTXO scan from a state file it re-read per request (tip height 1000). The wallet itself did the
work:

1. `listen` and three `build_coinbase` calls through the foreign API, for heights 980, 984 and
   988 (usernet maturity is 3). The scripted node reported all three on chain; `outputs` made
   them `Unspent` with three `ConfirmedCoinbase` log entries (ids 6, 7, 8).
2. `send -m file 10` and `send -m file 5` (message `fixture send one` / `fixture send two`).
   Each locked one coinbase and created an unconfirmed change output.
3. A second 4.0.2 wallet ran `receive` on the first slate and the first wallet ran `finalize`;
   the node accepted the push, so the send reached `TxSentMempool`. Then the node state was
   changed to report the first send's change on chain and its input gone, and a refresh made the
   send `TxSent` (confirmed), its input `Spent` and its change `Unspent`. The second send was
   left unfinished.

The scripted node reports no PMMR index, so every `mmr_index` is `null`. The `public_addr` of
the two sends held a path on the build machine; it was replaced with `s1.json` and `s2.json` in
both files. The scripted node and the build are not kept in the repository.

Outputs (all on the default account): a coinbase at height 980, `Spent` by tx 9; a coinbase at 984,
`Locked` by tx 10; a coinbase at 988, `Unspent`; the change of tx 9, `Unspent`; the change of
tx 10, `Unconfirmed`. Transactions: the six base ones, three `ConfirmedCoinbase`, a confirmed
`TxSent` (id 9) and a `TxSentCreated` (id 10).

The file `epic-wallet-4.0.2.txs.json` is what that wallet printed for `export_tx --all` (the first
six entries are the base ones, byte for byte). The test
`the_epic_wallet_402_fixture_reads_back_as_the_wallet_exported_it` compares every transaction
with it and asserts the five outputs. The 4.0.2 writer stores heights as strings
(`"ttl_cutoff_height":"1440"`).
