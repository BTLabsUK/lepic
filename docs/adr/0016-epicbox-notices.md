# ADR 0016: LEPIC notices over Epicbox

Status: accepted

## Context

A slate cannot say that a payment was pushed, that an invoice was withdrawn or declined, or that
a sender cancelled. Each side of an Epicbox exchange would otherwise wait on the other until a
timeout or a chain scan. A stock `epic-wallet` listener processes only V2 and V3 slates and
never acknowledges anything else, and the relay drops an address's whole queue after a few
unacknowledged rounds (`docs/compat/epicbox.md`). A payload that is not a slate therefore goes
only to a peer that is proven to run LEPIC.

## Decision

### Format

A notice is a JSON object, not a slate:

```json
{"lepic":1,"type":"declined","slate_id":"<uuid>"}
{"lepic":1,"type":"withdrawn","slate_id":"<uuid>"}
{"lepic":1,"type":"posted","slate_id":"<uuid>","excess":"<66 hex>"}
{"lepic":1,"type":"cancelled","slate_id":"<uuid>"}
```

- `lepic` is the format version, a number. A slate written by LEPIC carries an object under
  `lepic` (the marker) and a stock slate carries nothing there, so a number tells a notice
  from a slate before any slate decoding.
- A reader accepts at most `MAX_NOTICE_LEN`, 8,192 bytes. A longer notice-shaped payload is
  acknowledged and dropped. A notice of another version or an unknown type is acknowledged and
  ignored, and unknown keys are ignored. A known type with a missing or invalid field is
  acknowledged and dropped.
- A writer adds a last `pad` key of zeros so that the notice has the length of a first slate
  with one, two or three inputs, drawn at random: 2,452, 2,551 or 2,650 bytes over Epicbox, 76
  more when the wallet claims native slates. The length tells neither one kind from another nor
  a notice from a payment.
- Further types, sealed and signed in a contact mailbox or sent as a pairing request, are
  `pair` (with `invite`, an `epiccash://pair/1/` link), `pair-finished`, `pair-match`,
  `pair-mismatch` and `unpaired` (ADR 0034). A build that does not know a type
  classifies it as unknown and ignores it.

### Who sends what

- `declined`: from the payer of an invoice to its issuer. Also from a receiver that refuses
  payments nobody asked for to the sender of such an S1 (ADR 0045).
- `withdrawn`: from the issuer to the payer when the issuer cancels the invoice or it expires.
- `posted`: from the issuer of a paid invoice to its payer, and from the sender of an ordinary
  payment to its receiver, once the sender has pushed the transaction. It carries the kernel
  excess.
- `cancelled`: from the sender of an ordinary payment to its receiver, when the sender cancels
  or releases a send whose answer it finalized, and in reply to a marked S2 that arrives for a
  send already cancelled. Sent once per send.
- A payment sent through a paired contact's mailbox gets the same notices, sealed and signed to
  the contact's mailbox and queued in its outbox.
- Sending is best effort. A notice that cannot be delivered is logged and not retried. A failure
  to send never fails the cancel, release or push it follows.

### Which peers receive one

The store keeps per Epicbox key, and nothing else about the peer:

- the time of the last marked message (a marked S1, an S2 from the send's target, a parked
  I1, an I2, or an accepted notice);
- the time of the last unmarked slate (an S1, S2, I2, or an I1 sent back unchanged);
- the feature bits the last marked message claimed, the bits that worked, and when bits were
  last claimed;
- the key a marked message sealed native slates to, when it claimed them.

File, paste, QR and HTTP slates are tied to no key and are recorded for none. Every unmarked
slate is recorded before the wallet decides on any notice for its exchange.

From these the wallet derives, and never stores, the kind of a key: LEPIC while its last marked
message is newer than its last unmarked one, Epic otherwise (all other wallets as one group),
Unknown when nothing is recorded.

- A plain notice to a payments address needs the key to be LEPIC with a marked message in the
  last 30 days, and the incoming slate of the exchange the notice is about to have been marked:
  the S2 or I2 just finalized for `posted`, the send's latest S2 for `cancelled`, the parked I1
  for `declined`. For `withdrawn` the exchange is the I1 this wallet issued, which carries the
  marker. An I2 that answers it unmarked is recorded first and turns the key to Epic. Without
  proof nothing is sent.
- Two installs on one recovery phrase can flip a key as either one answers. Each flip is right
  for the moment it describes.
- Each row is sealed with XChaCha20-Poly1305 under the private context key and found by a
  keyed BLAKE2b hash of the key, with its own seed-derived subkey. The hash is part of the
  associated data, so a row moved under another hash does not open. The table `peer_compat`
  names no peer. The sealed record is versioned (vector `testdata/vectors/store/peer_compat.json`).
- `forget_peers(older_than)` deletes rows whose newest date is older than the host's limit.
  A forgotten key is unknown and gets no notice. The rows are in no backup or export and are
  learned again.

### Receiving

- A notice is accepted only from the recorded counterparty of its slate: for `posted` of an
  invoice, the issuer of an invoice this wallet paid; for `withdrawn`, the sender of a parked
  invoice or the issuer of a paid one; for `declined`, the address an issued invoice went to;
  for `posted` and `cancelled` of an ordinary payment, the key (or paired contact) the payment
  was exchanged with. Anything else is acknowledged and dropped.
- `posted` must carry the kernel excess that the stored S2 implies.
- A notice is advisory. It moves no funds and asks the node nothing. It deletes an unpaid
  parked invoice, which holds nothing, and raises an event. For a paid invoice the host offers
  the user a cancel. A `declined` for a send the receiver never answered cancels that send,
  which frees only this wallet's own inputs (ADR 0045).
- Events: `InvoicePosted`, `InvoiceDeclined`, `InvoiceWithdrawn`, `PaymentPosted`,
  `PaymentCancelled`. For a payment that still waits, the first accepted `posted` or
  `cancelled` stores the arrival time and raises the event; a repeat, and a notice for a
  payment that is confirmed or ended, is noted with no event. `TransactionDetails` reports the
  stored times as `sender_reported_posted_at` (for one hour, `POSTED_REPORT_WINDOW`, while the
  payment waits) and `sender_reported_cancelled_at` (while the payment is not confirmed).
- The cancel a host makes after `cancelled` is the owner's cancel with its usual checks of the
  node's pool and chain. The kernel stays watched, so a sender that posts after all still
  confirms the payment.
- A notice about a slate the wallet does not hold raises `NoticeUnmatched` with the notice and
  the sender the relay reported. The host may pass it to another install of the same wallet,
  which applies it with `notice_apply_forwarded` under the rules of a notice it received itself.
  When the host sets both early-notice caps, a `declined`, `withdrawn` or `cancelled` for an
  unknown slate is kept in a bounded buffer and applied once the slate arrives (ADR 0049).

### Answers for a slate the store does not know

Two installs on one recovery phrase share the payments address, and the relay hands each message
to whichever of their sockets subscribes. An S2 or I2 that decrypted and decoded but names no
known slate is therefore not refused at once:

- It is held unacknowledged for `TWIN_HOLD` (90 s, more than one relay challenge round), and
  the store is checked again on every try. The relay hands it to the other install meanwhile.
- At the bound the message is requeued: posted back to the own address with the same `from`,
  `str` and `signature` as the sender made them, and acknowledged only after the relay accepts
  the copy.
- The answer is refused for good and acknowledged when it was first seen `TWIN_REQUEUE_WINDOW`
  (24 hours) ago, when `MAX_TWIN_ANSWERS` (4) other answers are cycling (one not seen for an
  hour no longer counts), when the node no longer holds one of its inputs unspent, or when the
  requeue post still fails three minutes after the message arrived.
- Each such answer raises `UnknownSlate` once, with the slate id, stage and sender address.
- A refresh ends the other install's receive, raising `ReceiveSuperseded`, once an input of its
  slate is no longer unspent while neither its kernel nor its output is on chain, and only for a
  receive whose inputs an earlier refresh found all unspent and only once the tip is above the
  height the slate was made at. The kernel stays watched. Otherwise a receive ends at its TTL
  or after `UNFINALIZED_RECEIVE_BLOCKS`.

### Proof of LEPIC on the wire

- A new S1 over Epicbox goes out in the V2 shape with the marker as its last top-level key. A
  receiver that finds the marker records the sender key as LEPIC and answers with a marked S2;
  an unmarked S1 gets the unmarked S2. The sender records the receiver as LEPIC when a marked
  S2 comes from the key the send went to.
- Stock `epic-wallet` reads the marked S1 and drops the extra key in its answer, so a stock
  sender never sees the marker in a reply and a stock receiver is never sent a notice.
- The marker is covered by the Epicbox signature and by no slate signature. It proves a
  capability of the sending key and nothing about the slate. Feature bits never relax a check
  on a notice.

## Consequences

- No relay or wire change. Stock wallets never see a notice. An older LEPIC build treats a type
  it does not know as unknown and acknowledges it.
- A payer that rotated its invoice address after an invoice arrived declines from the new
  address, and the issuer drops that notice. The invoice still expires.
- Peer rows expire by the host's limit, so a key proven long ago gets no notice until a marked
  exchange in the last 30 days.
- A host that forwards unmatched notices between installs lets a second install apply a
  notice it did not receive, under the same counterparty rule.

## Related

- ADR 0033, ADR 0034, ADR 0045, ADR 0049
