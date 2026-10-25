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
| outgoing `confirmed` | `TxSent` | true | a refresh finding one of its outputs on chain, or the kernel of a watched transaction (below) |
| outgoing `cancelled` | `TxSentCancelled` | false | the owner's cancel, or the owner's release of a finalized or posted send the network never took |
| outgoing `expired` | `TxSentCancelled` | false | a refresh at or past the TTL cutoff height, or the send's wallet-local cutoff when that is earlier, or 10 blocks past the cutoff for an invoice payment, once the node holds no kernel the peer could have completed |
| incoming `received` | `TxReceived` | false | receiving S1 (S2 returned), or issuing an invoice (I1) |
| incoming `finalized` | `TxReceived`, with the transaction stored | false | the invoice issuer finalizing I3 |
| incoming `posted` | `TxReceived`, or `TxReceivedMempool` once seen in the mempool | false | the invoice issuer posting |
| incoming `confirmed` | `TxReceived` | true | a refresh finding one of its outputs on chain, or the kernel of a watched transaction (below) |
| incoming `confirmed` | `TxReceivedMempool` | true | the same, for an invoice issuer whose posted transaction was seen in the mempool; the refresh rewrites only outgoing types |
| incoming `confirmed` | `ConfirmedCoinbase` | true | a refresh confirming a coinbase output, or a restore finding one; no slate |
| incoming `confirmed` | `TxReceived`, no slate id | true | a restore finding an output with no entry |
| incoming `cancelled` | `TxReceivedCancelled` | false | the owner's cancel, or, for a payment received over Epicbox and answered with S2, the inbox making room at its cap of open receipts, which cancels as the owner's cancel does |
| incoming `expired` | `TxReceivedCancelled` | false | a refresh at or past the TTL cutoff height, or, for a received payment with no TTL, 10,080 blocks after a refresh first saw it; in both cases once the node holds no kernel the sender could have completed |

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
| `cancelled`, `expired`, for a watched transaction only | `confirmed`, by a refresh that finds its kernel |
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

A send may also carry a wallet-local cutoff (`SendRequest::local_ttl_blocks`), a height this
wallet stores next to the transaction and never puts in the slate, so it works on every method,
also those whose V2 slate cannot carry a TTL. LEPIC's app sends carry one 1,440 blocks above the
tip they were created at, and a file send carries the same height as its slate TTL, which the
receiver enforces too. Once the tip reaches the earlier of the slate TTL and the local cutoff,
this wallet neither finalizes the send nor posts it, also not again after a failed or earlier
post, and a refresh expires it if it is still `sent`, as at a TTL cutoff. A finalized or posted
send is still not expired. Upstream's `post_tx` checks no TTL.

A release (`Wallet::release`) ends an outgoing `finalized` or `posted` send the network never took,
as the Epic Cash app's `release_stuck_send` does. A refresh at or above 1,440 blocks after the
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
scan would find. If a scan already restored the change, under an incoming entry with no slate of
its own, the send takes the output over and that entry is dropped, so the history counts the
change once. This is the one transition out of `cancelled` or `expired`, and only a watched
transaction takes it. After the window a refresh asks the node for the change outputs instead,
with no end, as for a cancel below; a send with no change mined later stays `cancelled`.

The app releases only a send whose post the node refused with a JSON-RPC error. LEPIC also
releases a posted send the node dropped and a finalized one whose post got no answer: a kernel
still missing a day of blocks later, and in neither the node's chain nor its pool at the release,
means the same in each case.

### Transactions the peer can still complete

Once the peer holds this wallet's signature it can complete the transaction without this wallet:
a send this wallet finalized, whose post may have reached the node even when it failed; an
invoice payment once the payer has its I2; and a received payment once the receiver has
answered with S2. LEPIC knows the kernel of each: from the stored S3 or I3, or computed from the
I2 or S2, which hold every input, output and the final offset.

- The owner's cancel of one first asks the node's pool, then its chain up to a plausible tip,
  for that kernel, and refuses while either holds it. Upstream's `cancel_tx` checks neither.
  As upstream does, the receiver may cancel an unconfirmed incoming payment. The Epicbox inbox
  cancels one the same way when it holds as many open receipts as it keeps and a new payment
  arrives: it refreshes first, at most once a minute, so payments already mined are confirmed
  instead; it then cancels a receipt of the sender with the most open receipts, oldest first,
  and keeps any whose kernel the node's pool or chain holds. When none can be cancelled, the
  new payment is not received.
- A refresh that would expire one, at its TTL cutoff or by the no-TTL window, asks the same
  first, and leaves it open while either holds the kernel.
- A cancel or expiry that goes ahead keeps the transaction watched exactly as a release does:
  its kernel, the height below which it cannot be, and the key and amount of each unconfirmed
  output it deletes (the payer's change, the receiver's output). A refresh up to 1,440 blocks,
  a day, after the tip a received payment's cancel or expiry was decided at, 10,080 for a send,
  that finds the kernel moves it to `confirmed` and stores those outputs `unspent` from the
  kernel's height. After that window a refresh asks the node for those outputs instead, all
  watched transactions in one request, with no end: one found unspent at or below the highest
  confirmed tip, or already stored by a scan, confirms the transaction the same way at the
  output's height. Nothing in the chain's rules stops a peer from posting a transaction it
  holds signed later, and a slate's TTL binds only wallets that honour it (an Epicbox or HTTP
  S1 has none), so a received payment is never given up for good. A transaction whose record
  an older build already dropped, after its 10,080 blocks, is found again only by a scan.
- Every such lookup starts 10 blocks below the slate's height, and never above the tip or below
  height 1: the slate's height may be the peer's, and the node answers a lookup from a height it
  has no block for with an error, not with "not found". A lookup the node refuses for one
  transaction leaves that transaction as it is until a later refresh; the rest of the refresh
  goes on.
- Receiving an S1 or paying an I1 whose height is more than 10 blocks above the node's tip is
  refused, and nothing is stored. Upstream does not check the height.
- Paying an I1 whose TTL cutoff lies more than 2,880 blocks, two days, above the node's tip is
  refused, and nothing is stored: no issuer sets one that far ahead (the binding gives an
  invoice 1,440 blocks), so the request comes from another network, whose chain is longer, or
  from a wrong height. The second day allows for an issuer's node ahead of the payer's.
  Upstream does not check it.
- Paying an I1 whose TTL cutoff lies more than 525,600 blocks, a year, below the node's tip is
  refused as made for another network, not as expired, and nothing is stored: a floonet request
  read on mainnet has its cutoff millions of blocks below the tip, while nobody pays a real
  request a year after it expired. One that expired more recently is refused as expired.

A received payment with no TTL, which every V2 slate is, would otherwise stay `received` for
ever. A refresh records the tip at which it first sees one, not the slate's height, which the
sender chose, and expires it 10,080 blocks later under the rules above. An issued invoice
(`received` with no S2) is not ended this way; one issued with a TTL expires at its cutoff like
any slate with a TTL. A payer's I2 keeps the issuer's cutoff, or its own when that is earlier.

Issuer and payer read their tips from different nodes, which may stand a few blocks apart. So
that a payer never releases the inputs of a payment its issuer posted in time, the two keep a
margin of 10 blocks, as many as a peer's slate height may lead the tip, on each side of the
cutoff, the earlier of the I2's and the one the issuer issued:

- A LEPIC payer refuses to pay an I1 from 10 blocks before its cutoff on, and nothing is
  stored, so it never signs a payment the issuer would refuse and never locks inputs for one;
  the refusal names that height as the cutoff reached.
- The issuer refuses to finalize a payment from 10 blocks before the cutoff on, also when the
  I2 drops the TTL or moves it later; the refusal names that height as the cutoff reached.
- The issuer refuses to post a finalized payment again, after a failed post, from the cutoff
  itself on, by finalizing again or by `post`. That leaves the margin after the cutoff to an
  issuer's node behind the payer's, and a post retried this late is not worth the risk.
- The payer's refresh expires a payment, for example the second payment of one request, which
  the issuer never finalizes, 10 blocks after the cutoff, under the rules above. The Epicbox
  sweep lists one as cancellable from the same height.

An invoice without a TTL has no margin and no limit on posting.

The state machine does not know the direction of a transaction. Which side may take a step, for
example that only an invoice issuer finalizes an incoming transaction, is enforced by the stages
that take it (W-03 to W-05, W-08).

## Invoices over Epicbox

LEPIC's own rules; upstream has no invoice flow over Epicbox. They use the states above and add
none to transactions.

- A received I1 is parked, not stored as a transaction. A parked invoice is `parked`, then `paid`
  when the user pays it, in the same store transaction that stores the payment (outgoing `sent`), or
  `declined`. No other change is allowed, so a settled invoice never counts against the parking caps.
- Expiry, 24 hours by default and 48 at most, runs only when a host or a listener sweeps. A
  parked or declined invoice older than the window is deleted. An invoice the wallet issued over
  Epicbox whose incoming transaction is still `received` after the window is cancelled, as the
  owner's cancel does: its output and private context are dropped, so a late I2 is refused.
- A payment over Epicbox carries a TTL, 1440 blocks unless the payer sets one. A refresh does not
  expire it at its cutoff, unlike other open transactions, because the issuer may have posted it.
  Once a confirmed height is 10 blocks past the cutoff with the kernel neither in the node's pool
  nor on its chain, the sweep lists it as cancellable, and the user decides.

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
