# 0019 Import the transaction history of an epic-wallet wallet

Status: accepted
Date: 2026-10-22

## Context

ADR 0005 ruled out importing the `epic-wallet` database: restoring from the seed recovers the
funds, and history was not carried over. Users moving from the Electron GUI (6.1.6) lose their
whole history that way. The GUI keeps it, because it keeps opening the old `wallet_data` in place.
A desktop import into wallet-for-epic showed only scan-found receipts, all dated at the time of
the import: no sends, fees, cancelled transactions, messages or slate ids. On 2026-10-22 the owner
decided that the desktop import must bring the history across, at parity with the GUI.

`epic-wallet` from 3.3 on (every 4.x release) keeps its data in SQLite at
`wallet_data/db/sqlite/epic.db`: one key-value table whose rows are serde JSON of the
`TxLogEntry`, `OutputData` and `AcctPathMapping` records (`docs/compat/epic-wallet-db.md`).
Wallets older than 3.3 used LMDB, which no `epic-wallet` 4.x migrates either.

## Decision

- LEPIC reads the old database read-only and imports its history. This supersedes the
  "no import of the epic-wallet database" bullet of ADR 0005. Keys still come from the seed,
  never from the database.
- The source is never opened in place. `epic.db` and its `-wal` file are copied with plain file
  reads into a directory inside the new wallet's folder. The copy is accepted only if the source
  did not change while it was read. It is opened from there and removed afterwards. The `p`
  rows (private transaction context) are never read.
- Each log entry becomes an ordinary log entry plus an `imported_transactions` record (schema
  version 5). The record keeps what only the old wallet knew: its log id, its type, the kernel
  excess, the TTL, the counts, and the messages whose signatures verify. The entry keeps the
  original dates, amounts, fee, slate id and counterparty.
- Outputs are not imported as outputs. Their commitments go into `imported_outputs`, linked to the
  entry that created them, and only if the seed reproduces the commitment. A history in which no
  checked output matches the seed is refused as another wallet's.
- The scan stays the only source of spendable funds and balances. A scan that finds an output
  the old wallet recorded links it to that entry, which becomes confirmed. One the old wallet had
  cancelled is marked `cancelled-but-on-chain`. After a scan from genesis, an entry whose output
  the old wallet held unspent but no scan found is marked `unspent-not-on-chain`. Open entries
  stay open, since their private keys stay in the old wallet. The node's kernel lookup may still
  confirm them.
- A scan-found output with no record gets an entry dated by its block header (new node call
  `get_header`), not by the scan time. This applies to every restore, imported or not.
- Account labels are taken over unless this wallet's user chose one. Each account's key counter
  moves past every key the old wallet used, spent ones included.
- What cannot be imported is reported as a status, not an error: no database, the pre-3.3 LMDB
  format, an unreadable (damaged, encrypted, foreign) database, a source that keeps changing,
  too large, another seed, another history already imported. The wallet then keeps scan-only
  history.

## Consequences

- Schema 5 is forward-only, like every LEPIC migration. A build before it refuses a migrated
  database (`SchemaTooNew`).
- The import adds node calls: one header per distinct height of a scan-found output, and kernel
  lookups for at most 200 open imported entries. A node failure leaves dates and confirmations
  undone, never the import.
- Imported open entries cannot be finalized here. Cancelling one only marks it locally.
- Not imported: payment proofs (the GUI stopped asking for them in 6.1.3), the saved finalized
  transactions in `saved_txs/` (their kernel is in the log), private contexts, and LMDB-era
  history. The GUI-side data (contacts, node, Epicbox server, language, labels) is the host
  app's to carry.

## Alternatives considered

- Copy the whole `wallet_data` and keep using it, as the GUI does. That means running
  `epic-wallet`'s storage, which LEPIC does not have (ADR 0001, ADR 0005).
- Import the outputs too. The old wallet may have kept running after the copy, so its output
  states can be stale. Trusting them could show funds that are gone. The scan is the only
  source that cannot be stale.
- Keep imported history in the host app's archive only. The app could not reconcile it with the
  scan, and each host would have to redo the work.
