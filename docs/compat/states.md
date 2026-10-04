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
| outgoing `confirmed` | `TxSent` | true | a refresh finding one of its outputs on chain, or the kernel of a released send |
| outgoing `cancelled` | `TxSentCancelled` | false | the owner's cancel, or the owner's release of a finalized or posted send the network never took |
| outgoing `expired` | `TxSentCancelled` | false | a refresh at or past the TTL cutoff height |
| incoming `received` | `TxReceived` | false | receiving S1 (S2 returned), or issuing an invoice (I1) |
| incoming `finalized` | `TxReceived`, with the transaction stored | false | the invoice issuer finalizing I3 |
| incoming `posted` | `TxReceived`, or `TxReceivedMempool` once seen in the mempool | false | the invoice issuer posting |
| incoming `confirmed` | `TxReceived` | true | a refresh finding one of its outputs on chain |
| incoming `confirmed` | `TxReceivedMempool` | true | the same, for an invoice issuer whose posted transaction was seen in the mempool; the refresh rewrites only outgoing types |
| incoming `confirmed` | `ConfirmedCoinbase` | true | a refresh confirming a coinbase output, or a restore finding one; no slate |
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
| `finalized` | `posted`, `confirmed`, `cancelled` |
| `posted` | `confirmed`, `cancelled` |
| `cancelled`, for a released send only | `confirmed`, by a refresh that finds its kernel |
| `confirmed`, `cancelled`, `expired` | none otherwise |

`confirmed` is reachable from every open state because the chain is the authority: a peer may post
the transaction before this wallet records finalizing or posting it.

Upstream cancels and expires any entry whose `tx_type` is still `TxSentCreated` or `TxReceived`,
which includes a transaction it finalized or posted but has not yet seen in the mempool. LEPIC
expires neither a finalized nor a posted transaction, because either may still be mined after the
TTL cutoff. The owner may still cancel a finalized one, unless the node's chain or its transaction
pool holds its kernel; a posted one ends only by confirmation. Upstream refuses to cancel an entry with `confirmed = true`, and so does LEPIC: `confirmed` is final.

Upstream also refuses to cancel an entry whose type is neither `TxSentCreated` nor `TxReceived`, so
a transaction the mempool has seen (`TxSentMempool`, `TxReceivedMempool`) cannot be cancelled there.
LEPIC's state machine allows `posted` to `cancelled` for the scan's repair and for a release, but
the owner's cancel refuses a `posted` transaction.

A release (`Wallet::release`) ends an outgoing `finalized` or `posted` send the network never took,
as the Flutter app's `release_stuck_send` does. A refresh at or above 1,440 blocks after the
height the send was finalized at (for a send finalized before that height was stored, after the
height its slate was created at) looks up its kernel up to the tip, counting the highest confirmed
tip and not a tip held as pending. A kernel found confirms the send; a missing one makes it
releasable. The release then asks the node once more and refuses while its chain or its
transaction pool holds the kernel. It moves the send to `cancelled` as the owner's cancel does,
which upstream records as `TxSentCancelled`. If another node still holds the transaction and it is
mined later, its inputs are spent after all: a refresh marks them spent, and a newer send that
spent them fails. The release keeps the kernel excess, the height the lookup starts from and the
key and amount of each change output it deletes. Each refresh up to 10,080 blocks, about a week,
after the height the release was decided at looks the kernel up, to the highest confirmed tip and
not past that window. A kernel found moves the send from `cancelled` to `confirmed` at the
kernel's height and stores its change `unspent` from that height, so the balance equals what a
scan would find. This is the one transition out of `cancelled`, and only a released send takes
it. A kernel mined after the window is not looked for: the send stays `cancelled`, and a scan
stores its change `unspent` again.

The app releases only a send whose post the node refused with a JSON-RPC error. LEPIC also
releases a posted send the node dropped and a finalized one whose post got no answer: a kernel
still missing a day of blocks later, and in neither the node's chain nor its pool at the release,
means the same in each case.

The state machine does not know the direction of a transaction. Which side may take a step, for
example that only an invoice issuer finalizes an incoming transaction, is enforced by the stages
that take it (W-03 to W-05, W-08).

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
- Scan: every output found and not stored is stored `Unspent`. A stored `Spent` output found unspent
  becomes `Unspent`. In a scan run with `delete_unconfirmed`, a stored `Locked` output found unspent
  becomes `Unspent` and every stored `Unconfirmed` output is deleted. In each case the
  transaction log entry the output belongs to is cancelled (`TxSentCreated` to `TxSentCancelled`,
  `TxReceived` to `TxReceivedCancelled`; other types are left alone).
