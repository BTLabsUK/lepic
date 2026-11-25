# Transaction and output states

This page maps LEPIC's transaction and output states to the types and flags `epic-wallet` v4.1.0
stores, and lists the rules that move a transaction between them. The upstream side is read from
`libwallet/src/types.rs` (`TxLogEntryType`, `OutputStatus`, `OutputData::mark_*`),
`libwallet/src/internal/{selection,tx,updater,scan}.rs` and `libwallet/src/api_impl/{owner,foreign}.rs`.
The engine vectors in `testdata/vectors/engine/` record upstream wallet states under these names.
The LEPIC side is the `state`, `cancel`, `release`, `recover`, `refresh` and `invoice` modules of
`lepic-wallet`.

## How upstream records a transaction

An upstream transaction log entry has a `tx_type` and a separate `confirmed` flag. Finalizing and
posting do not change `tx_type`. Finalizing stores the transaction and its kernel excess on the
entry. Posting changes nothing until a mempool check (`TxSentMempool`, `TxReceivedMempool`) or a
refresh that sees one of its outputs on chain (`confirmed = true`).

LEPIC records each of these steps as its own state.

## Transaction states

| LEPIC direction and state | Upstream `tx_type` | Upstream `confirmed` | Reached by |
|---|---|---|---|
| outgoing `sent` | `TxSentCreated` | false | creating S1, or paying an invoice (I2) |
| outgoing `finalized` | `TxSentCreated`, with the transaction stored | false | finalizing S3 |
| outgoing `posted` | `TxSentCreated`, or `TxSentMempool` once seen in the mempool | false | posting to the node |
| outgoing `confirmed` | `TxSent` | true | a refresh finding one of its outputs on chain, or the kernel of a watched transaction (below) |
| outgoing `cancelled` | `TxSentCancelled` | false | the owner's cancel; a recovery once it is done; a post or refresh that finds an input of a finalized or posted send gone from the chain while neither the node's pool nor its chain holds its kernel |
| outgoing `expired` | `TxSentCancelled` | false | a refresh at or past the TTL cutoff height, or the send's wallet-local cutoff when that is earlier, or 10 blocks past the cutoff for an invoice payment, once the node holds no kernel the peer could have completed |
| incoming `received` | `TxReceived` | false | receiving S1 (S2 returned), or issuing an invoice (I1) |
| incoming `finalized` | `TxReceived`, with the transaction stored | false | the invoice issuer finalizing I3 |
| incoming `posted` | `TxReceived`, or `TxReceivedMempool` once seen in the mempool | false | the invoice issuer posting |
| incoming `confirmed` | `TxReceived` | true | a refresh finding one of its outputs on chain, or the kernel of a watched transaction (below) |
| incoming `confirmed` | `TxReceivedMempool` | true | the same, for an invoice issuer whose posted transaction was seen in the mempool; the refresh rewrites only outgoing types |
| incoming `confirmed` | `ConfirmedCoinbase` | true | a refresh confirming a coinbase output, or a restore finding one; no slate |
| incoming `expired`, block reward | none: upstream has no state for a reward a reorganisation took | none | a refresh or scan that finds its block replaced (ADR 0070); its output is unconfirmed again |
| incoming `confirmed` | `TxReceived`, no slate id | true | a restore finding an output with no entry |
| incoming `cancelled` | `TxReceivedCancelled` | false | the owner's cancel; for an invoice this wallet finalized, a post or refresh that finds an input of the payer gone from the chain while neither the node's pool nor its chain holds its kernel |
| incoming `expired` | `TxReceivedCancelled` | false | a refresh at or past the TTL cutoff height; for a received payment with no TTL, 10,080 blocks after a refresh first saw it; in both cases once the node holds no kernel the sender could have completed. For an invoice this wallet finalized or posted: a refresh at or past the earlier of its I3's and its I1's TTL cutoff, once the node holds no kernel of it |

Upstream marks an expired transaction cancelled. LEPIC keeps `expired` apart so the two causes can
be told apart, and both map to the same upstream type.

## Transitions

A repeated delivery, finalize or post succeeds and changes nothing. Any transition not listed is
refused with a typed error (`InvalidTransition`).

| From | To |
|---|---|
| `sent`, `received` | `finalized`, `confirmed`, `cancelled`, `expired` |
| `finalized` | `posted`, `confirmed`, `cancelled`, `expired` |
| `posted` | `confirmed`, `cancelled`, `expired` |
| `cancelled`, `expired`, for a watched transaction only | `confirmed`, by a refresh that finds its kernel |
| `confirmed`, within 1,440 blocks of its confirmation, when a refresh finds neither its outputs nor its kernel on chain (a reorganisation) | `posted` when this wallet holds the final transaction, otherwise `received` (a payment received) or `sent` (an invoice paid) |
| `confirmed` block reward (no slate), when a refresh within 1,440 blocks finds neither its output nor its kernel, or a scan finds no kernel for one whose output is stored spent (ADR 0070) | `expired`, reason `Orphaned` |
| `expired` block reward with reason `Orphaned` | `confirmed`, by a refresh within 1,440 blocks of its height or a scan that finds its output |
| `confirmed`, `cancelled`, `expired` | none otherwise |

`confirmed` is reachable from every open state because the chain decides: a peer may post the
transaction before this wallet records finalizing or posting it.

The table ignores direction. The stage that takes a step checks which side may take it, for
example that only an invoice issuer finalizes an incoming transaction.

### Cancel and expire

Upstream cancels and expires any entry whose `tx_type` is still `TxSentCreated` or `TxReceived`,
which includes a transaction it finalized or posted but has not yet seen in the mempool. It
refuses to cancel an entry with `confirmed = true`, or one whose type is neither of the two, so a
transaction the mempool has seen cannot be cancelled there. Upstream's `post_tx` checks no TTL.

LEPIC differs as follows:

- `confirmed` is final once it is 1,440 blocks deep (`CONFIRMATION_RECHECK_BLOCKS`). Until then each
  refresh checks that the chain still holds the transaction: one of the outputs it made, or else its
  kernel. A kernel found at another height moves the confirmation height. If neither is on chain
  any more, a reorganisation took the block that confirmed it, and the transaction leaves
  `confirmed` for `posted` when this wallet holds the final transaction (a refresh then pushes it
  again), else for `received` or `sent`. Its outputs become `unconfirmed`, the inputs it spent are
  `locked` again, the confirmation height is cleared, a state change is raised and the warning
  `confirmed transaction no longer on chain` is logged. A transaction whose kernel the wallet does
  not know (a coinbase, a scan's find, another wallet's spend) and the entries of an open recovery
  are not checked. Older confirmations cost no lookup.
- A finalized or posted send never expires, because either may still be mined after the TTL
  cutoff, with two exceptions, each at the cutoff from which the wallet no longer posts it: an
  invoice this wallet issued and finalized, and a finalized send whose every push the node's pool
  refused, with none the node took or that found it unreachable. Their kernel stays watched.
- The owner may cancel a finalized transaction unless the node's chain or pool holds its kernel.
  The owner's cancel refuses a `posted` transaction.
- A posted send ends by confirmation, by a recovery, or, like a finalized one, when an
  input it spends is gone from the chain and neither the node's pool nor its chain holds its
  kernel. It can never be mined then, and its kernel stays watched.
- A finalized or posted send whose missing inputs a reorganisation took stays as it is (ADR
  0071): each was made by a transaction of this wallet that a refresh reopened, or whose kernel
  the node no longer finds. Its coins stay `locked`, a refresh pushes it again, and it goes
  through once that transaction is mined again. A post refused for it returns `InputsReorged`.
  A send of a block reward whose kernel is gone waits the same way: the reward comes back if the
  chain returns to its block. A send still waiting 60 blocks (`REORG_WAIT_BLOCKS`) after the
  wallet first saw it waiting ends `expired` with reason `InputsReorged`, and its coins go back
  to the transactions that made them, `unconfirmed` (a reward's coin to the reward). The post
  cutoff still ends it earlier; the reason is `InputsReorged` then too.
- The two entries of a send to the wallet itself end together. The cancel of either refuses while
  the other is posted (`PartnerPosted`).

### Wallet-local cutoff

A send may carry a wallet-local cutoff (`SendRequest::local_ttl_blocks`): a height this wallet
stores next to the transaction and never puts in the slate. It works on every method, including
those whose V2 slate cannot carry a TTL. A file send can carry the same height as its slate TTL,
which the receiver enforces too. A `SendRequest::ttl_blocks` on a send whose slate goes out in the
V2 shape becomes the local cutoff (the earlier of the two when both are given) and is left out of
the slate.

Once the tip reaches the earlier of the slate TTL and the local cutoff, this wallet neither
finalizes the send nor posts it, also not again after a failed post. A refresh expires the send if
it is still `sent`. A finalized or posted send is not expired.

### Sends an earlier version released

Earlier versions let the owner release a `finalized` or `posted` send whose kernel a refresh had
not found 1,440 blocks after it was finalized: the send moved to `cancelled` and its inputs were
unlocked. This version has no release; a send the node took ends by a recovery
(`Wallet::recover`), which spends its inputs back to this wallet. A send an earlier version
released loads as it was stored and stays watched.

If another node still held such a send and it is mined later, its inputs are spent after all.
A refresh then marks them spent, and a newer send that spent them fails.

The release kept the kernel excess, the height the lookup starts from and the key and amount of
each change output it deleted. Each refresh up to `RELEASED_WATCH_BLOCKS` (10,080, about a week)
after the height the release was decided at looks the kernel up, to the highest confirmed tip. A
kernel found moves the send from `cancelled` to `confirmed` at the kernel's height and stores its
change `unspent` from that height, so the balance equals what a scan finds. If a scan already
restored the change under an incoming entry with no slate of its own, the send takes the output
over and that entry is dropped, so the history counts the change once.

Apart from an orphaned block reward confirmed again (ADR 0070), this is the one transition out
of `cancelled` or `expired`, and only a watched transaction takes it. After the window a refresh
asks the node for the change outputs instead, with no end. A send
with no change mined later stays `cancelled`.

### Transactions the peer can still complete

Once the peer holds this wallet's signature it can complete the transaction without this wallet:

- a send this wallet finalized, whose post may have reached the node even when it failed;
- an invoice payment once the payer has its I2;
- a received payment once the receiver has answered with S2.

LEPIC knows the kernel of each: from the stored S3 or I3, or computed from the I2 or S2, which
hold every input, output and the final offset.

- The owner's cancel of one asks the node's pool, then its chain up to a plausible tip, for that
  kernel, and refuses while either holds it. Upstream's `cancel_tx` checks neither. As upstream
  does, the receiver may cancel an unconfirmed incoming payment.
- No receipt is cancelled to make room for a new payment. When the wallet holds as many open
  receipts as it keeps, 10 from one sender key or 100 in all by default (`max_open_receipts_per_sender`
  and `max_open_receipts`), it refreshes first, at most once a minute, so payments already mined
  are confirmed. If the count is still at the cap, the new payment is refused: it is not signed or
  stored, a log line and a `slate.refused` event with reason `receipts_full` say so, and an HTTP
  or Tor sender gets `too many open receipts, retry later`. Over stock Epicbox no refusal can
  reach the sender; its send is marked unanswered after a day
  ([Unanswered sends](#unanswered-sends)).
- A refresh that would expire one, at its TTL cutoff or by the no-TTL window, asks the same
  first, and leaves it open while either holds the kernel.
- A cancel or expiry that goes ahead keeps the transaction watched, as a release did: its
  kernel, the height below which it cannot be, and the key and amount of each unconfirmed output
  it deletes (the payer's change, the receiver's output).
  - A refresh up to `ENDED_RECEIVE_WATCH_BLOCKS` (1,440, a day) after the tip a received payment's
    cancel or expiry was decided at, or 10,080 blocks for a send, looks the kernel up. A kernel
    found moves the transaction to `confirmed` and stores those outputs `unspent` from the
    kernel's height.
  - After that window a refresh asks the node for those outputs instead, all watched
    transactions in one request, with no end. An output found unspent at or below the highest
    confirmed tip, or already stored by a scan, confirms the transaction the same way at the
    output's height.
  - Nothing in the chain's rules stops a peer from posting a transaction it holds signed later,
    and a slate's TTL binds only wallets that honour it, so a received payment is not given up.
    The exception is a received payment whose sender's TTL passed with no kernel in the node's
    pool or chain, nothing pushed by this wallet and no I3 (not an invoice this wallet finalized):
    after it expires or is cancelled it is not watched at all, since the sender's wallet stops at
    the same TTL and a sender could otherwise grow the watched set without end. A later mining of
    it is found only by a scan (`lepic wallet scan`).
- Every such lookup starts 10 blocks (`SLATE_LEAD_BLOCKS`) below the slate's height, and never
  above the tip or below height 1. The slate's height may be the peer's, and a node answers a
  lookup from a height it has no block for with an error, not with "not found". A lookup the node
  refuses for one transaction leaves it as it is until a later refresh. The rest of the refresh
  goes on.

### Height checks on incoming slates

- Receiving an S1 or paying an I1 whose height is more than 10 blocks above the node's tip is
  refused, and nothing is stored.
- Paying an I1 whose TTL cutoff lies more than `MAX_INVOICE_TTL_LEAD_BLOCKS` (2,880, two days)
  above the node's tip is refused, and nothing is stored. Hosts issue invoices with
  `INVOICE_TTL_BLOCKS` (1,440), so a cutoff that far ahead comes from another network, whose chain
  is longer, or from a wrong height. The second day allows for an issuer's node ahead of the
  payer's. A host may set another lead with `PayRequest::max_ttl_lead_blocks`, up to
  `MAX_INVOICE_TTL_LEAD_CEILING_BLOCKS` (525,600).
- Paying an I1 whose TTL cutoff lies more than `MAX_INVOICE_TTL_LAG_BLOCKS` (525,600, a year)
  below the node's tip is refused as made for another network, not as expired, and nothing is
  stored. A floonet request read on mainnet has its cutoff millions of blocks below the tip. One
  that expired more recently is refused as expired.

### Notices

The sender of an ordinary payment through a paired contact, or to an epic1 address, tells a
LEPIC receiver that answered it when it cancels the send, with the `cancelled` notice of
ADR 0016 ([epicbox.md](epicbox.md)). The receiver records when and raises `PaymentCancelled`.
Nothing else changes: the payment stays `received` until the host cancels it, or a refresh
confirms or expires it.

### Unanswered sends

A receiver over stock Epicbox cannot tell the sender that it refused a payment, as one at its
open receipt caps does. A refresh marks a send that went to a stock Epicbox address, with no
contact or epic1 outbox behind it, once its S2 has not come a day (`UNANSWERED_AFTER`, as long
as the contact outbox waits before it marks a payment stuck) after it was made. The time is kept
under the settings key `send.unanswered.<slate id>`, the refresh raises `DeliveryChanged` as
`uncertain` once, and `lepic serve` shows the payment's delivery `uncertain` and `stuck` with an
error saying what the owner can do. Nothing else changes: the send stays `sent`, an S2 that comes
later finalizes it, and its funds unlock at its cutoff or when the owner cancels it. The first
refresh after the send leaves `sent` deletes the key.

### Reorganisation marks

Two settings keys hold what a refresh learned of a reorganisation (ADR 0071); the store schema
stays. `send.inputs_reorged.<slate id>` holds the tip at which the wallet first saw a send
waiting for inputs a reorganisation took. A push the node accepts deletes it; it stays with a
send that ended `expired`, as the record of the reason `InputsReorged`. `tx.reopened.<slate id>`
holds the tip at which a refresh reopened a confirmed transaction whose block was replaced. A
refresh deletes either key once its transaction is gone or ended any way the key does not
explain. `TransactionDetails::chain_replaced` reads them: `InputsReplaced`, `Reopened`, or
`Recent` for an incoming transaction while the session saw a block replaced in the last 60
blocks.

### Received payments with no TTL

A V2 slate has no TTL, so a received payment would otherwise stay `received` for ever. A refresh
records the tip at which it first sees one, not the slate's height, which the sender chose, and
expires it `UNFINALIZED_RECEIVE_BLOCKS` (10,080) blocks later under the rules above. An issued
invoice (`received` with no S2) is not ended this way. One issued with a TTL expires at its
cutoff like any slate with a TTL. A payer's I2 keeps the issuer's cutoff, or its own when that is
earlier.

### Invoice cutoff margin

Issuer and payer read their tips from different nodes, which may stand a few blocks apart. So that
a payer never releases the inputs of a payment its issuer posted in time, both keep a margin of
`INVOICE_TTL_MARGIN_BLOCKS` (10, as many as a peer's slate height may lead the tip) on each side
of the cutoff, the earlier of the I2's and the one the issuer issued:

- A LEPIC payer refuses to pay an I1 from 10 blocks before its cutoff on, and nothing is stored.
  It never signs a payment the issuer would refuse and never locks inputs for one. The refusal
  names that height as the cutoff reached.
- The issuer refuses to finalize a payment from 10 blocks before the cutoff on, also when the I2
  drops the TTL or moves it later. The refusal names that height as the cutoff reached.
- The issuer refuses to post a finalized payment again after a failed post from the cutoff itself
  on, whether by finalizing again or by `post`. That leaves the margin after the cutoff to an
  issuer's node behind the payer's.
- The payer's refresh expires a payment the issuer never finalizes, for example the second payment
  of one request, 10 blocks after the cutoff, under the rules above. The Epicbox sweep lists one
  as cancellable from the same height.

An invoice without a TTL has no margin and no limit on posting.

## Invoices over Epicbox

Upstream has no invoice flow over Epicbox, and LEPIC sends none: an invoice goes to a classic
address only as a file. A store may still hold invoices an older wallet parked or issued over
Epicbox. These rules cover them and add no state to transactions.

- A parked invoice cannot be paid or declined. It stays `parked` until the sweep deletes it.
- Expiry runs only when a host or a listener sweeps (`Wallet::sweep_invoices`). The window is an
  `InvoiceExpiry` of the host's choice, 24 hours by default. A parked or declined invoice older
  than the window is deleted. An invoice the wallet issued over Epicbox whose incoming transaction
  is still `received` after the window is cancelled, as the owner's cancel does: its output and
  private context are dropped. An I2 that arrives over Epicbox is acknowledged and dropped.
- A payment made to an Epicbox invoice is not expired by a refresh at its cutoff, unlike other
  open transactions, because the issuer may have posted it. Once a confirmed height is 10 blocks
  past the cutoff with the kernel neither in the node's pool nor on its chain, the sweep lists it
  as cancellable, and the user decides.

## Output states

| LEPIC `OutputStatus` | Upstream `OutputStatus` | Meaning |
|---|---|---|
| `unconfirmed` | `Unconfirmed` | created by this wallet's transaction, not yet seen on chain |
| `unspent` | `Unspent` | on chain and not locked |
| `locked` | `Locked` | selected as an input of an open outgoing transaction |
| `spent` | `Spent` | no longer in the node's UTXO set |
| no record | `Deleted`, or the record removed | upstream deletes the unconfirmed outputs of a cancelled transaction and never stores `Deleted` |

Upstream's output transitions, which LEPIC follows:

- Cancel: `Locked` inputs become `Unspent`. The transaction's `Unconfirmed` outputs are deleted.
- Refresh, output found on chain: `Unconfirmed` becomes `Unspent`. Other statuses are unchanged.
- Refresh, output missing from the UTXO set: `Unspent` and `Locked` become `Spent`.
- Scan: every output found and not stored is stored `Unspent`. A stored `Spent` output found
  unspent becomes `Unspent`. In a scan run with `delete_unconfirmed`, a stored `Locked` output
  found unspent becomes `Unspent` and every stored `Unconfirmed` output is deleted. In each case
  the transaction log entry the output belongs to is cancelled (`TxSentCreated` to
  `TxSentCancelled`, `TxReceived` to `TxReceivedCancelled`; other types are left alone).
