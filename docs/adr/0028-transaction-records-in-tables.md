# ADR 0028: Per-transaction state lives in tables that cascade with the transaction

Status: accepted

## Context

The wallet keeps facts about a transaction that are not part of the transaction itself: the
limits that end a send, the data that recognises a transaction that ended unconfirmed if the
chain mines it after all, the spend another wallet on the same phrase made, and how a scan
stored an entry. Stored in the `settings` table under keys built from the transaction id, such
facts need hand-rolled encodings, nothing ties them to the transaction they describe, a value
that does not decode reads as absent, and a refresh looks each key up transaction by transaction.
A reviewer cannot see the data model from the schema.

## Decision

- One table per kind of record, each keyed by the transaction id and declared
  `REFERENCES transactions (id) ON DELETE CASCADE`
  (`crates/lepic-store/src/sqlite/schema.rs`):
  - `tx_marks`: the heights and flags of a transaction's limits and notices (local cutoff,
    finalized at, kernel absent at, receive first seen at, receive inputs seen unspent, inputs
    spent elsewhere, when the sender reported a post or a cancel, whether the payer was told of a
    withdrawal or the receiver of a cancel, and whether the latest answer carried the LEPIC
    marker).
  - `tx_watch` and `tx_watch_outputs`: what recognises a transaction that ended unconfirmed (the
    kernel excess, the minimum height, the tip it ended at, the phase it is looked for in, and
    the outputs it would have created).
  - `other_wallet_spends` and `other_wallet_outputs`: the spend or receive another wallet on the
    same phrase made, with the outputs it spent and those taken for its change, and whether a
    scan may still credit change to it.
  - `scan_found`: which scan stored an entry for an output it found with no record, how the
    entry is dated, and the output's commitment.
  - `contact_transactions`: which contact a transaction was exchanged with. `contact_slates`
    records the same by slate id and has no foreign key: a contact never takes over a slate id
    this wallet used with someone else.
- `lepic-store` exposes them through `TxRecordRepository`, typed records (`TxMarks`, `TxWatch`,
  `OtherWalletSpend`, `ScanFoundRecord`) and stored enums (`WatchPhase`, `FoundDuring`). Writing
  a record for an unknown transaction fails with `StoreError::UnknownTransaction`. A stored value
  that does not decode is `StoreError::Corrupt`, never "absent". The in-memory store behaves the
  same, deletion included.
- Deleting a transaction deletes its records.
- `settings` keeps singletons: the network, the fingerprint, the chain reference, the scan
  progress, the minimum confirmations and similar values of the wallet as a whole.

## Consequences

- The schema shows every per-transaction fact the engine relies on, with foreign keys a reviewer
  can check, and a damaged record surfaces as an error instead of silently stopping a watch.
- A refresh reads the watched transactions with one query (`tx_watches`).
- Code outside `lepic-store` reads these records through the repository, not by settings key.

## Related

- ADR 0005, ADR 0016
