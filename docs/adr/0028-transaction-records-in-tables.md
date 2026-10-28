# 0028 Per-transaction state lives in tables that cascade with the transaction

Status: accepted
Date: 2026-10-28

## Context

ADR 0005 promised a real schema. Over the invoice, cancel and pairing changes of October 2026 the wallet nevertheless kept a growing set
of per-transaction facts in the `settings` table, under keys built from a prefix and the
transaction id (`send.local_cutoff.<id>`, `release.released.<id>`, `tx.other_wallet.<id>`,
`scan.found.<id>` and others), with hand-rolled encodings: space- and colon-separated text, JSON,
or decimal strings. A reader turned a value that did not decode into "absent", nothing tied the
keys to the transaction they described, and every refresh walked all transactions of all
accounts to look each prefix up. An outside reviewer could not see the data model from the
schema. The 2026-10-27 security audit asked for these records to move into tables.

## Decision

- Schema version 8 adds one table per kind of record, each keyed by the transaction id and
  declared `REFERENCES transactions (id) ON DELETE CASCADE`:
  - `tx_marks`: the heights and flags of a transaction's limits (local cutoff, finalized at,
    kernel absent at, receive first seen at, receive inputs seen unspent, inputs spent
    elsewhere).
  - `tx_watch` and its `tx_watch_outputs`: what recognises a transaction that ended unconfirmed
    if the chain mines it after all (kernel excess, minimum height, the tip it ended at, the
    phase it is looked for in, and the outputs it would have created).
  - `other_wallet_spends` and its `other_wallet_outputs`: the spend or receive another wallet
    on the same phrase made, with the outputs it spent and those taken for its change, and
    whether a scan may still credit change to it (this replaces the `tx.other_wallet.open`
    list).
  - `scan_found`: which scan stored an entry for an output it found with no record, how it is
    dated, and the output's commitment.
- `lepic-store` exposes them through `TxRecordRepository`, typed records (`TxMarks`, `TxWatch`,
  `OtherWalletSpend`, `ScanFoundRecord`) and stored enums (`WatchPhase`, `FoundDuring`). Writing a
  record for an unknown transaction fails with `UnknownTransaction`; a stored value that does not
  decode is `StoreError::Corrupt`, never "absent". The in-memory store behaves the same, deletion
  included.
- Deleting a transaction deletes its records. The wallet's own "forget" steps for these records
  are gone.
- The migration to version 8 moves every stored record of these kinds into the new tables,
  decoding the version-7 text with decoders frozen in `sqlite/v8.rs`, and deletes the moved
  settings. A record whose transaction no longer exists, or whose value did not decode, is
  dropped with a warning: version 7 read such a value as absent too.
- Schema version 9 does the same for which contact a slate or transaction was exchanged with
  (`contact_slates`, `contact_transactions`), and version 10 for the last two transaction facts
  kept by slate id (a sender's posted report and an answered withdrawal, now `tx_marks`
  columns), dropping the parked invoices' origin addresses that nothing writes any more.
- Schema version 11 adds two `tx_marks` columns for the `cancelled` notice (ADR 0016): when the
  sender of a received payment reported it cancelled it, and that the receiver of a cancelled
  send was told. Nothing moves.
- `settings` keeps true singletons only: network, fingerprint, chain reference, scan progress,
  minimum confirmations and the like.

## Consequences

- The schema shows every per-transaction fact the engine relies on, with foreign keys a reviewer
  can check, and a damaged record surfaces as an error instead of silently stopping a watch.
- A refresh reads the watched transactions with one query instead of a lookup per transaction.
- Code outside `lepic-store` that read these settings by key (tests, tools) reads the repository
  instead. There are no users to migrate beyond the developers' own wallets, which the migration
  carries over.

## Alternatives considered

- One generic `tx_state(tx_id, kind, value)` table: gains the cascade but keeps the hand-rolled
  encodings and hides the data model.
- Columns on `transactions`: most transactions have none of these records, and the watch and the
  other wallet's spend own lists of outputs.
- Dropping the old settings instead of moving them: simpler, but a developer wallet with a
  released send would stop watching it until a scan.
