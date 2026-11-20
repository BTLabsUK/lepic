# Delivery

The delivery layer carries a LEPIC wallet's native mail: payments to an epic1 address and their
answers, the epic1 notices, messages to a paired contact, pairing mail and in-person answers. It
decides where each message goes, keeps the outbox of what is owed, watches the slots the
wallet expects mail in and reads them by mailbox push. The address decides the protocol: a classic
Epicbox address gets stock V2 and V3 JSON from the [Epicbox](epicbox.md) method and never passes
through this layer. The reasons are in [ADR 0062](../adr/0062-the-address-decides-the-protocol.md)
and [ADR 0063](../adr/0063-the-epic1-address-carries-its-own-mailbox.md).

| Crate | Holds |
|---|---|
| `lepic-wallet-contacts` (`delivery`) | Routes, the outbox, the watch set, the router, link posts |
| `lepic-epicbox` | The mailbox client and the push sessions ([mux/1](epicbox-mux.md)) |
| `lepic-store` | Outbox rows and watch rows |

## The mailbox list

Words: a mailbox is a server that runs Epicmail, the mail protocol; a slot is the box of one key
on a mailbox. Code and older records say relay for mailbox and mailbox for slot, and the code
names below keep those words.

A wallet has one mailbox list for all native mail: the mailboxes shipped with the host's release,
plus the mailboxes the user added, minus the shipped mailboxes the user removed. The host stores
only what was added and removed, so a release that changes the shipped part reaches every
install. The list holds at most 16 mailboxes and never fewer than 1; a wallet that should reach
no mailbox runs `Offline`. Two entries are the same mailbox when their domains match in any case
and their ports are equal.

There is no own mailbox, no meeting mailboxes and no list of pairing mailboxes: no native mail
depends on a mailbox's position in the list. The legacy Epicbox address keeps its own host, which
is a setting of that lane and decides nothing for native mail.

The core adds, removes and switches no mailbox by itself. It offers the user the tools: read the
list with each mailbox's origin (shipped or added) and health, probe a host (TLS, greeting, push
offered), and set what was added and removed. A change applies to the running sessions. The CLI
has `lepic mailbox list`, `add`, `remove` and `probe`; `lepic serve` has `GET /mailboxes`,
`POST /mailboxes` and `DELETE /mailboxes/{host}`, applied while it runs. Every FFI call and CLI
command takes the mailbox mode from the host; none passes `Online` by itself.

**Health.** The session service keeps one record per mailbox: whether it offers `mux/1`, the time
of the last success, the count of failures since and the last error. "No mux/1" is asked again
after 1 minute, doubling to 1 hour, because a mailbox at its connection limit answers the same way
as one without it. A mailbox that fails stays in the list: its posts are tried again, its session
reconnects with back-off, and the other mailboxes carry the mail meanwhile. Health is shown, never
used to drop a mailbox. The status the host reads carries the record; one event is raised when no
mailbox of the list can be reached, and one when a mailbox comes back. The first reconnect after a
lost session is spread over 1 to 10 seconds. A mailbox counts as usable unless it is known to
lack `mux/1` and its next ask is not due.

`lepic mailbox list` shows each mailbox of the list with its origin and health, without
connecting. `delivery_state` (FFI) shows the same and the state of the delivery loop's push
session on each mailbox, without connecting.

## Where mail goes

One rule for every native message ([ADR 0065](../adr/0065-mail-goes-where-the-receiver-reads.md)
§3). It is posted to its receiver's slot key on at most 3 mailboxes, never on every mailbox of the
list:

- a payment or other new message: the 3 healthiest mailboxes of the sender's list. Between
  mailboxes of equal health the shipped ones come first, in the list's order;
- mail to a paired contact: the mailbox of the contact's card, plus the 2 healthiest others of
  the list;
- an answer, a refusal or a notice about a message received: the mailbox that message was read
  on, plus the 2 healthiest others of the list.

Health only orders the pick and drops no mailbox from the list. A mailbox known to lack mux/1 is
not picked. A retry of the whole message picks again.

The same sealed bytes go to each. The outbox stores the result per mailbox. The entry is posted
when one mailbox took it, and the mailboxes that did not are tried again on the outbox's schedule
until the message is answered or ends. A route of the form `key@host`, which posts to one mailbox
only, is not written for native mail.

| Mail | Goes to |
|---|---|
| A payment to a bare epic1 address, or to a link with no entries | The address's delivery slot on the 3 healthiest mailboxes of the list |
| A payment to a link with entries | The link's `http` and `tor` entries, one at a time in link order |
| The payee's answer or refusal | The payer's reply slot on the mailbox the payment was read on, plus the 2 healthiest others of the list |
| `posted` and `cancelled` notices | The delivery slot of the address paid, on the 3 healthiest mailboxes of the list |
| A message to a paired contact (card update, mailbox move, contact check, invoice and its payment) | The contact's slot on the mailbox of its card, plus the 2 healthiest others of the list |
| Pairing replies and confirmations | The pairing slot on the mailbox the invite names, plus the 2 healthiest others of the list |
| Pairing status and unpaired notices | The contact's slot on the mailbox its card names, plus the 2 healthiest others of the list |

A link with entries is never paid through the delivery slot. An `http` entry whose host is on
this device is left out, and one on the local network is left out unless it is in the mailbox
list.

No link and no sealed payment names a mailbox. An address and a link carry none, and the reply
route of a payment holds the reply key alone: the payer watches its reply slot on every mailbox it
posted to. No code path connects to a mailbox read from a link or a sealed message. A link's `http`
and `tor` entries are hosts read from a link, and the payer posts to them (see above). A wallet connects
to a mailbox outside its list in one case only: the mailbox of a paired contact's card, or of an
invite the user accepted (the host applies a contact's move, ADR 0039). That connection uses TLS
to a public name, and goes through Tor when Tor is on.

**No shared mailbox.** When the payer's list holds no shipped mailbox and the pay call names none,
the payer cannot know that the payee reads any mailbox of its list. `epic1_pay` then fails at once
with `NoSharedMailbox` before storing anything, listing the shipped mailboxes. Nothing else is
checked: a payer on the shipped list who pays a payee that reads only a private mailbox gets no
error, and the payment ends at its deadline.

Pairing mail and notices carry no mailbox transaction id, so their copies are never cancelled.
The reader deletes the copy it takes and applies a message read twice once; the other copies stay
on their mailboxes until the mailbox's retention ends. The copies of a payment carry a transaction
id: once its answer or refusal is taken from one mailbox, the payer cancels the copies on the
mailboxes stored as having taken one (`txcancel/1`), and tries again on the outbox's schedule
while the payment is open.

[epic1](epic1.md) describes the payment, its answer and the notices; [Pairing](pairing.md)
describes contact and pairing mail.

## The watch set

The watch set is the list of slots the wallet reads, one row per slot and mailbox. Each
collect makes it equal to the records it comes from:

- a pairing in progress: its pairing slot on the mailboxes its mail goes to, until its deadline
  and one hour after;
- a paired contact: its current slot and a slot of an old box salt, on every mailbox of the list
  and the mailbox its card names, and its previous mailbox while that mailbox is drained after a move;
- each account's epic1 address: its delivery slot on every mailbox of the list;
- each epic1 payment that waits for an answer: its reply slot, on each mailbox the payment went
  to and on the mailboxes of the list, until the payment is confirmed, cancelled or expired;
- each in-person code that waits for an answer.

A row that no record backs, or that has expired, leaves the set. A slot has one reader at a time
on a mailbox: the newest attach takes it, and mail not acknowledged goes again to the new reader.
A slot that another socket took over (a second install on the same phrase, which is unsupported
without a link) stays in the set and
is counted replaced. The session attaches it again when its hold-off of 10 minutes ends; an open
collect (start, unlock, restore) takes it back at once, and a pull only retries the reconnect.
No mark is stored, so a restart takes the slot too. A
row is also skipped when its mailbox cannot be reached as written, when the wallet holds no key
for it, or when it repeats another row.

A socket carries at most 256 slots, or fewer when the mailbox says so. A session opens
another socket past that; a slot that finds no socket is left out and reported.

## Reading

The wallet reads by mailbox push only, through [mux/1](epicbox-mux.md) sessions
([Epicbox](epicbox.md#mux1) has the sessions and their groups). The router hands each pushed
message to its handler in the order the mailbox pushed it, one at a time, and acknowledges it only
after its handler stored what it did.

## The outbox

Every post the wallet owes is a row of the outbox, stored in the same write that makes the post
owed, so a crash leaves it queued. Each route a post tries has its own row: a link entry, or a
slot on the mailboxes picked for it, at once. A row of the last kind is posted once any mailbox
takes it. The row stores each mailbox that took a copy; until the message is answered or ends, the
mailboxes that did not take it are tried again on the waits below, and a mailbox that took a copy
gets none again.

A payment row stores one copy per mailbox: `taken`, `owed` (refused, not sent or not answered)
or `cancel` (answered elsewhere while this mailbox still holds a copy). A refusal that says the
transaction was cancelled drops an owed copy. The mailbox the answer was read on gets no cancel,
nor does a mailbox that refused or was never reached. The copies go with their row.

A notice, an app payload included, is a row marked as a notice
([ADR 0067](../adr/0067-one-notice-path.md)). It has no slate stage and no delivery state. It
raises no delivery event and no outbox report counts it. It is posted and retried like any row.

A row is `queued`, `posted`, `uncertain` or `failed`. The outcome of a post decides the next
step:

| Outcome | Row | Next |
|---|---|---|
| The mailbox or host took it | `posted` | The other copies of the same post end |
| Not sent, or refused with a time to come back | `failed` | The next route at once; on the last route, the same row again after the wait |
| Refused, an address or envelope not taken, too long, no carrier | `failed` | The next route at once |
| Sent and not answered | `uncertain` | The same bytes on the same route after the wait |

The waits are 30 seconds, 2 minutes, 10 minutes and 30 minutes, the last repeating; a mailbox's
own wait counts when it is longer. A payment's row with a cutoff height is tried until the
cutoff and is only marked stuck a day after the payment's newest row was stored; the mark changes
nothing. A payment's row without a cutoff ends `failed` after 7 days, the time a mailbox keeps a
message. Any other mail still not posted a day after it was stored ends `failed` as stuck. A row
of a payment ends `failed` once the chain reaches the payment's cutoff height; a post that waits for a later try reads the wallet's confirmed tip first and waits while
the wallet has none.

An `uncertain` post may have arrived, so the wallet never moves on from it by itself. The host
asks for the next route: `lepic epic1 post-next <SLATE_ID>` or
`POST /payments/{id}/deliver` in `lepic serve`. Only a link with entries has a next route. A
payment to a slot has none: asking again answers that no route is left, until the payment is
marked stuck. From then on the same route is posted again as a new row.

A payer's row that still waits ends `posted` once its payment is finalized, posted or
confirmed, and `failed` once the payment is cancelled or expired. A payee's row ends `posted`
once the payment confirms. The prune deletes posted rows after LEPIC's keep time for them
(`DELIVERED_KEPT`, 7 days), failed rows with no payment, and the rows of a payment that ended,
keeping a `cancelled` notice that is still owed.

## What the host does

Each host runs the collect, which reads, reconciles the watch set and posts what is due:

| Host | Who runs the collect | When |
|---|---|---|
| FFI | The session's delivery loop, started by `set_delivery(Online)` | A tick at start, then every `epicbox.collect_every_s` seconds (default 30) after the last tick ended |
| CLI | `lepic contact collect` | One collect |
| `lepic serve` | its own loop | A tick at start, then every 30 seconds after the last tick ended |

In both loops mail a mailbox pushes runs a tick at once, but no sooner than one second after the
last tick ended, and so does a tick that completed a pairing. Two ticks never run at once.
`delivery_wake` (FFI) runs one tick now, after any tick under way. A boost of `Relays` (`boost`
in the FFI, `POST /sync/boost` in `lepic serve`) runs the ticks more often for a while. A lock
ends the FFI loop until the next `set_delivery`.

| Trigger | Passed by | Does |
|---|---|---|
| `Open` | The first tick of a loop | Reconnects at once and tries the whole outbox |
| `Foreground` | The other timed ticks, and `POST /sync` | Asks the mailboxes what waits, keeps the reconnect and retry waits |
| `Pull` | `delivery_wake` and `lepic contact collect` | As `Open` |
| `Push` | A tick after a push or a completed pairing, and in the FFI after a mailbox switch | Reads what the sessions queued and asks the mailboxes nothing |

## What the user sees

`lepic serve` shows each epic1 payment's `delivery.state`: `by_hand`, `queued`, `sent`,
`uncertain` or `failed`. It raises `payment.delivery_changed` when a post turns `uncertain`,
when it fails with no route left, and with `sent` when the payment goes out after an earlier
post was `uncertain` or `failed`. A payment that goes out on its first post raises none. The
[wallet API](../api/README.md) has the fields.

A message to a contact is `Queued`, `Delivered` or `Stuck`; the FFI raises `OutboxDelivered`
and `OutboxStuck` for it. A payment to a contact delivered two hours ago or more, whose
transaction the contact has not posted, is marked `not_posted_yet` so the app can offer to send
it again.
