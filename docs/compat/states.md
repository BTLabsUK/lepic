# Transaction and output states

Derived from `epic-wallet` `v4.0.2`: `libwallet/src/types.rs` (`TxLogEntryType`, `OutputStatus`,
`OutputData::mark_*`), `libwallet/src/internal/{selection,tx,updater,scan}.rs` and
`libwallet/src/api_impl/{owner,foreign}.rs`. The engine vectors in `testdata/vectors/engine/` record
upstream wallet states with these names; tasks W-07 and V-01 compare LEPIC's end states with them
through the tables below.

## How upstream records a transaction

An upstream transaction log entry has a `tx_type` and a separate `confirmed` flag. Finalizing and
posting do not change `tx_type`: finalizing stores the transaction and its kernel excess on the entry,
and posting changes nothing until a mempool check (`TxSentMempool`, `TxReceivedMempool`) or a refresh
that sees one of its outputs on chain (`confirmed = true`). LEPIC records each of these steps as its
own state (`lepic-wallet`'s `state` module).

## Transaction states

| LEPIC direction and state | Upstream `tx_type` | Upstream `confirmed` | Reached by |
|---|---|---|---|
| outgoing `sent` | `TxSentCreated` | false | creating S1, or paying an invoice (I2) |
| outgoing `finalized` | `TxSentCreated`, with the transaction stored | false | finalizing S3 |
| outgoing `posted` | `TxSentCreated`, or `TxSentMempool` once seen in the mempool | false | posting to the node |
| outgoing `confirmed` | `TxSent` | true | a refresh finding one of its outputs on chain |
| outgoing `cancelled` | `TxSentCancelled` | false | the owner's cancel |
| outgoing `expired` | `TxSentCancelled` | false | a refresh at or past the TTL cutoff height |
| incoming `received` | `TxReceived` | false | receiving S1 (S2 returned), or issuing an invoice (I1) |
| incoming `finalized` | `TxReceived`, with the transaction stored | false | the invoice issuer finalizing I3 |
| incoming `posted` | `TxReceived`, or `TxReceivedMempool` once seen in the mempool | false | the invoice issuer posting |
| incoming `confirmed` | `TxReceived` | true | a refresh finding one of its outputs on chain |
| incoming `confirmed` | `ConfirmedCoinbase` | true | a refresh confirming a coinbase output; no slate |
| incoming `confirmed` | `TxReceived`, no slate id | true | a restore finding an output with no entry |
| incoming `cancelled` | `TxReceivedCancelled` | false | the owner's cancel |
| incoming `expired` | `TxReceivedCancelled` | false | a refresh at or past the TTL cutoff height |

Upstream marks an expired transaction cancelled; LEPIC keeps `expired` apart so the user can tell the
two causes apart. Both map to the same upstream type.

## Transitions

Every state may be set again without effect; a repeated delivery, finalize or post succeeds and
changes nothing. Any other transition not listed is rejected with a typed error.

| From | To |
|---|---|
| `sent`, `received` | `finalized`, `confirmed`, `cancelled`, `expired` |
| `finalized` | `posted`, `confirmed`, `cancelled`, `expired` |
| `posted` | `confirmed`, `cancelled` |
| `confirmed`, `cancelled`, `expired` | none |

`confirmed` is reachable from every open state because the chain is the authority: a peer may post
the transaction before this wallet records finalizing or posting it.

Upstream cancels and expires any entry whose `tx_type` is still `TxSentCreated` or `TxReceived`,
which includes a transaction it posted but has not yet seen in the mempool. LEPIC does not expire a
posted transaction, because it may still be mined after the TTL cutoff; only the owner's explicit
cancel ends it before confirmation. Upstream refuses to cancel an entry with `confirmed = true`, and
so does LEPIC: `confirmed` is final.

## Output states

| LEPIC `OutputStatus` | Upstream `OutputStatus` | Meaning |
|---|---|---|
| `unconfirmed` | `Unconfirmed` | created by this wallet's transaction, not yet seen on chain |
| `unspent` | `Unspent` | on chain and not locked |
| `locked` | `Locked` | selected as an input of an open outgoing transaction |
| `spent` | `Spent` | no longer in the node's UTXO set |
| no record | `Deleted`, or the record removed | upstream deletes the unconfirmed outputs of a cancelled transaction and never stores `Deleted` |

Upstream's output transitions, which W-03, W-06 and W-07 follow:

- Cancel: `Locked` inputs become `Unspent`; the transaction's `Unconfirmed` outputs are deleted.
- Refresh, output found on chain: `Unconfirmed` becomes `Unspent`; other statuses are unchanged.
- Refresh, output missing from the UTXO set: `Unspent` and `Locked` become `Spent`.
- Scan: every output found is stored `Unspent`. A stored `Spent` or `Locked` output found unspent
  becomes `Unspent`, and in a scan run with `delete_unconfirmed` a stored `Unconfirmed` output not
  found is deleted; in both cases the
  transaction log entry the output belongs to is cancelled (`TxSentCreated` to `TxSentCancelled`,
  `TxReceived` to `TxReceivedCancelled`; other types are left alone).
