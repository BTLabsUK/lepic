# ADR 0019: Import the transaction history of an epic-wallet wallet

Status: accepted

## Context

Restoring from the seed recovers the funds of an `epic-wallet` wallet, and a restore alone shows
only the outputs a scan found, all dated at the time of the scan: no sends, fees, cancelled
transactions, messages or slate ids. Users moving from the Electron GUI would lose their history
that way. The desktop import brings the history across.

`epic-wallet` from 3.3 on keeps its data in SQLite at `wallet_data/db/sqlite/epic.db`: one
key-value table whose rows are serde JSON of the `TxLogEntry`, `OutputData` and `AcctPathMapping`
records (`docs/compat/epic-wallet-db.md`). Wallets older than 3.3 used LMDB, which LEPIC does
not read.

## Decision

- LEPIC reads the old database read-only and imports its history. Keys come from the seed,
  never from the database.
- The source is never opened in place. `epic.db` and its `-wal` file are copied with plain file
  reads into a directory inside the new wallet's folder (`ImportWorkDir`). The copy is accepted
  only if the source did not change while it was read. It is opened from there and removed
  afterwards. The `p` rows (private transaction context) are never read.
- Each log entry becomes an ordinary log entry plus an `imported_transactions` record. The
  record keeps what only the old wallet knew: its log id, its type, the kernel excess, the TTL
  cutoff, the input and output counts, and the messages whose signatures verify
  (`imported_messages`). The entry keeps the original dates, amounts, fee, slate id and
  counterparty.
- Outputs are not imported as outputs. Their commitments go into `imported_outputs`, linked to
  the entry that created them, and only if the seed reproduces the commitment. A history in
  which no checked output matches the seed is refused as another wallet's.
- The scan stays the only source of spendable funds and balances. A scan that finds an output
  the old wallet recorded links it to that entry, which becomes confirmed (`on-chain`). One
  the old wallet had cancelled is marked `cancelled-but-on-chain`. After a scan from genesis, an
  entry whose output the old wallet held unspent but no scan found is marked
  `unspent-not-on-chain`. Open entries stay open, since their private keys stay in the old
  wallet. The node's kernel lookup may still confirm them, for at most 200 open imported
  entries per import.
- A scan-found output with no record gets an entry dated by its block header (`get_header`),
  not by the scan time. This applies to every restore, imported or not. A header that cannot be
  fetched leaves the date undone.
- Account labels are taken over unless this wallet's user chose one. Each account's key counter
  moves past every key the old wallet used, spent ones included.
- The history imported is identified by the SHA-256 of the copied database. The same source
  again is `AlreadyImported` and brings links and dates up to date; another history is
  `OtherHistory`.
- What cannot be imported is returned as a status, not an error: `NoHistory`, `OldFormat` (before
  3.3), `Unreadable` (damaged, encrypted or foreign), `SourceBusy`, `TooLarge`, `OtherWallet`
  and `OtherHistory`. The wallet then keeps scan-only history.
- Where an entry came from is `TxOrigin`: `Wallet`, `Imported`, `FoundByScan` or `OtherWallet`.

## Consequences

- The tables arrive with schema 5. Migrations are forward-only: a build older than a database's
  schema refuses it (`SchemaTooNew`).
- The import adds node calls: one header per distinct height of a scan-found output, and the
  kernel lookups. A node failure leaves dates and confirmations undone, never the import.
- Imported open entries cannot be finalized here. Cancelling one only marks it locally.
- Not imported: payment proofs, the saved finalized transactions in `saved_txs/` (their kernel is
  in the log), private contexts, and LMDB-era history. Data of the host app (contacts, node,
  Epicbox server, language) is the host's to carry.
- Output states of the old wallet may be stale if it kept running after the copy, which is why
  outputs come from the scan alone.

## Related

- ADR 0001, ADR 0005, ADR 0028
