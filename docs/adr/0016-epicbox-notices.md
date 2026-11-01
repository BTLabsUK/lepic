# 0016 LEPIC notices over Epicbox, sent only to proven peers

Status: accepted
Date: 2026-10-05

## Context

Invoices over Epicbox (ADR 0003 and ADR 0004 amendments, `docs/compat/epicbox.md`) leave each side
guessing about the other: the payer does not learn that its payment was pushed or that the issuer
withdrew the invoice, and the issuer does not learn that the payer declined. A slate cannot say
any of this, and no slate stage exists for it.

A stock `epic-wallet` `v4.0.2` listener processes only V2 and V3 slates (fact 3 in
`docs/compat/epicbox.md`), so LEPIC sends a payload that is not a slate only to a peer proven to
run LEPIC.

## Decision

A notice is a JSON object, not a slate:

```
{"lepic":1,"type":"declined","slate_id":"<uuid>"}
{"lepic":1,"type":"withdrawn","slate_id":"<uuid>"}
{"lepic":1,"type":"posted","slate_id":"<uuid>","excess":"<66 hex>"}
{"lepic":1,"type":"cancelled","slate_id":"<uuid>"}
```

- `lepic` is the format version, a number. A slate written by LEPIC carries an object under
  `lepic` (the marker), and a stock slate carries nothing there, so a number tells a notice from a
  slate before any slate decoding.
- At most 8 KiB. A longer notice-shaped payload is acknowledged and dropped. Writers pad every
  notice to the length of a first slate with one, two or three inputs, drawn at random
  (amended with schema version 13: before, 256 bytes and a 512-byte bound).
- A notice of another version or an unknown type is acknowledged and ignored. Unknown keys are
  ignored. A known type with a missing or invalid field is acknowledged and dropped.
- `declined` goes from the payer to the issuer, from the invoice address the payer holds now, to
  the address the user allowed. `withdrawn` goes from the issuer to the payer when the issuer
  cancels the invoice or it expires. `posted` goes from the issuer to the payer once the paid
  invoice was pushed, with the kernel excess. Both go to the address the invoice was issued to.

Capability proof, kept per peer key in the store:

- A peer is proven to run LEPIC once an I1 it sent with the marker was parked, an I2 with the
  marker answering an invoice this wallet issued was finalized, or it sent a notice that was
  accepted. A marked I2 proves both the key it came from and the key the invoice went to, since
  only a wallet reading that address could answer it and a stock wallet does not pay invoices
  over Epicbox.
- A peer that sent an issued I1 back unchanged is recorded as not supporting invoices.
- A notice goes only to a peer proven to run LEPIC. Without proof, nothing is sent.

Receiving:

- A notice is accepted only from the recorded counterparty of its slate: for `posted` the
  issuer of an invoice this wallet paid, with the excess this wallet's payment implies; for
  `withdrawn` the sender of a parked invoice or the issuer of a paid one; for `declined` the
  address an issued invoice went to. Anything else is acknowledged and dropped.
- A notice is advisory. It never moves funds, cancels or unlocks anything. `withdrawn` deletes an
  unpaid parked invoice, which holds nothing; for a paid invoice it raises an event, and the host
  offers the user a cancel. `posted` and `declined` raise events only.
- On the invoice address, the prefilter admits the senders of invoices the wallet holds as well
  as the allowlist, so their notices arrive after a sender was removed from the allowlist.

Sending is best effort: a notice that cannot be delivered is logged and not retried. Nothing
depends on it arriving.

## Consequences

- No relay or wire change. Stock wallets never see a notice, and an older LEPIC build drops one
  as an undecodable slate and acknowledges it.
- A payer that rotated its invoice address after an invoice arrived declines from the new
  address, and the issuer drops that notice. The invoice still expires as ADR 0003's amendment
  describes.
- The marker is covered by the Epicbox signature over `str` and by no slate signature, so it
  proves a capability of the sending key and nothing about the slate.
- New notice types are added under version 1 as new `type` values; peers that do not know them
  ignore them.
- Amendment, W-26: an S2 or I2 for a slate the store does not know is still refused
  for good and acknowledged, and now also raises `Event::UnknownSlate` with the slate id, its
  stage and the sender's address. Two installs on one recovery phrase share the payments
  address, so the install that did not make the send or issue the invoice may read the answer
  first; the event lets its host say so. No notice is sent and nothing on the wire changes.
- Amendment, 26.10.8 (android-12), replacing the refusal above: an install must not acknowledge
  or delete a message it cannot use, or one for a slate the other install started. The relay
  hands the oldest unacknowledged message to whichever socket of the address subscribes, and
  `Made` from either install deletes it for both. So an S2 or I2 for a slate the store does not
  know, that decrypted and decoded, is held unacknowledged until its message has waited
  `TWIN_HOLD` (90 s), more than one challenge round of a minute, so the other install is handed
  it too; the store is checked again on every try. At that bound the message is requeued: posted
  back to the own address with the same `from`, `str` and sender's `signature`, which is all the
  relay's `PostSlate` checks, and acknowledged only after the relay accepts the copy, which then
  waits at the back of the queue. A copy of an answer the other install already settled reaches
  it as repeated and is acknowledged there. The answer is refused for good and acknowledged, as
  before, when it was first seen `TWIN_REQUEUE_WINDOW` (24 h) ago, when `MAX_TWIN_ANSWERS` (4)
  other answers are cycling (one not seen for an hour no longer counts), when the node no longer
  holds one of its inputs unspent (two answers agree), or when the requeue post still fails
  three minutes after the message arrived. `Event::UnknownSlate` is raised once per answer.
  Both installs may also answer one S1, as the relay passes it live to one socket and hands it
  to the other on its subscribe; the sender finalizes one answer. A refresh ends the other
  install's receive once an input of its slate is no longer unspent while neither its kernel
  nor its output is on chain, as a cancel ends it, keeps watching the kernel, and raises
  `Event::ReceiveSuperseded`. It does so only for a receive whose inputs an earlier refresh
  found all unspent, and only once the tip is above the height the slate was made at, so a node
  that is behind, or an S1 whose inputs were never on chain, ends nothing; such a receive still
  ends at its TTL or after `UNFINALIZED_RECEIVE_BLOCKS`. Nothing new goes on the wire; the
  requeued copy is a message the sender already signed.

- Amendment, W-31: `posted` for ordinary sends. The receiver of an ordinary payment over
  Epicbox otherwise learns that the sender finished it only when a scan finds the kernel. The
  sender now tells it, with the `posted` notice and format above, once it pushed the
  transaction.
  - Proof. A new S1 over Epicbox goes out in the V2 shape with the marker as its last
    top-level key; no other transport changes. A receiver that finds the marker on an S1
    records the key it came from as running LEPIC and answers with an S2 in the same shape
    with the marker; an S1 without it gets the unmarked S2 as before. The sender records the
    receiver as running LEPIC when a marked S2 comes from the key the send went to; an S2 from
    any other key proves nothing. Stock `epic-wallet` `v4.0.2` and `v4.1.0` read the marked
    V2 S1 and drop the key when they answer, so a stock sender never sees it in a reply and a
    stock receiver is never sent a notice.
  - Sending. After the push that finalizing an S2 in a listen or drain makes, to a counterparty
    proven to run LEPIC, from the payments address, best effort and not retried. An S2 that
    arrives again for a posted transaction pushes nothing and sends nothing. A host's later
    post of the transaction sends nothing, so no notice reaches the relay outside a listen or
    drain the host started, and a host that turned its Epicbox method off is obeyed.
  - Accepting, after the invoice rule for the same slate id finds no payment: an incoming
    transaction over Epicbox under the slate id, with its S2 stored, whose counterparty key is
    the notice's `from`, and an `excess` equal to the kernel excess that S2 implies; anything
    else is acknowledged and dropped. For a payment still waiting for its sender, the first
    such notice stores the time it arrived (the setting `notice.posted_reported.<slate_id>`)
    and raises `Event::PaymentPosted`; a repeat, and a notice for a payment that is confirmed
    or ended, is noted with no event. So a replay or a stream of copies costs one event per
    payment.
  - Effect. Advisory: the notice changes no state and moves nothing. The wallet asks the node
    nothing on it; the host refreshes, which is the chain check that confirms the payment.
    `TransactionDetails::sender_reported_posted_at` reports the stored time while the payment
    waits and the report is younger than `POSTED_REPORT_WINDOW` (one hour), after which the
    chain has answered whatever the notice said. The row stays, one per received payment
    whose sender reported it, and is read only for a payment that waits.
  - An older LEPIC build knows `posted` only for invoices, finds no payment, and acknowledges
    and drops it. On two installs of one recovery phrase the install that did not answer the
    S1 holds no S2 and drops the notice, which the relay then deletes for both; the other
    install's refresh still confirms the payment.
  - A payment sent through a paired contact's mailbox (RFC 0002 9.1) gets the same `posted`,
    sealed and signed to the contact's mailbox and queued in its outbox, once its S2 was
    finalized and pushed in a collect. The receiver accepts it as the contact's (RFC 0002
    11.4) by the transaction it exchanged with that contact, with the same excess rule.

- Amendment, RFC 0002 7.6: `unpaired`, `{"lepic":1,"type":"unpaired"}` with no slate id,
  padded like the others, only sealed and signed in a contact mailbox. It says the sender
  removed the pairing; the receiver marks that pairing and keeps it. It names no slate, so a
  build that knows only the kinds above classifies it as unknown and ignores it.

- Amendment, sender cancel: `cancelled` for ordinary sends. Mimblewimble gives the receiver of
  a payment no way to see that its sender cancelled: the receiver answered with S2 and waits for
  a post that never comes, until its no-TTL window of 10,080 blocks ends the payment. The sender
  now tells it, with `{"lepic":1,"type":"cancelled","slate_id":"<uuid>"}`, padded like the
  others.
  - Sending, best effort, to a receiver proven to run LEPIC, or sealed to a paired contact's
    mailbox for a payment sent through one, and once per send (the mark
    `tx_marks.cancelled_answered`):
    - after the owner's cancel or release of an outgoing ordinary payment over Epicbox whose
      receiver's S2 this wallet finalized (its S3 is stored), as when the post failed or the
      network dropped it. A send cancelled before any answer arrived sends nothing then: the
      receiver may not hold the S1 yet, and a stock receiver is not proven.
    - in answer to a marked S2 that arrives, in a listen or drain, from the key the send went
      to, for a send already cancelled here. The S2 is refused as before; the answer is kept
      unacknowledged while the notice cannot be delivered, up to the hold bound, as a late I2
      of a withdrawn invoice is. A contact's S2 for a send cancelled here gets the notice in
      its mailbox the same way. An unmarked S2, or one from another key, gets nothing.
    A failure to send never fails the cancel or the release.
  - Accepting: an incoming transaction under the slate id with its S2 stored, so a payment this
    wallet answered, exchanged over Epicbox with the notice's `from` as its counterparty key, or
    with the paired contact that sealed it. Anything else, including any invoice, is
    acknowledged and dropped. For a payment still `received`, the first such notice stores the
    time it arrived (`tx_marks.sender_cancelled_at`) and raises `Event::PaymentCancelled`; a
    repeat, and a notice for a payment that is confirmed, cancelled or expired here, is noted
    with no event.
  - Effect. Advisory: the notice changes no state, unlocks nothing and asks the node nothing.
    Whether to end the payment is the host's choice; a cancel it then makes is the owner's
    cancel with its usual checks of the node's pool and chain, and keeps the kernel watched, so
    a sender that posts after all still confirms the payment. A sender that lies only makes the
    receiver's host offer that cancel early. `TransactionDetails::sender_reported_cancelled_at`
    reports the stored time while the payment is not confirmed, also after it ended here, with
    no window.
  - An older LEPIC build classifies `cancelled` as a notice of an unknown type, acknowledges it
    and ignores it; a stock wallet never gets one. The two marks are new columns of `tx_marks`
    (schema version 11), a migration that only adds columns; a build before it refuses the
    upgraded store as too new.

- Amendment, schema version 12: proof expires, falls back, and is checked per exchange. A peer
  "proven" once stayed proven for good, and `posted` went out after any finalized answer from
  it, marked or not. So the statement above that a stock receiver is never sent a notice was
  false for a key that ran LEPIC once and answers from another wallet now, for example Stack
  Wallet on the same recovery phrase. That wallet never acknowledges a notice, and the relay
  drops the address's whole queue after three unacknowledged rounds (`docs/compat/epicbox.md`,
  "Relay retention"). It is true again under these rules:
  - Facts, not a verdict. The store keeps, per Epicbox key, only: the last marked message
    (a marked S1, S2 from the send's target, I1 parked, I2, or an accepted notice), the last
    unmarked slate over Epicbox (S1, S2, I2, or an I1 sent back unchanged), the feature bits
    the latest marked message claimed, the bits that worked, and when bits were last claimed.
    File, paste, QR and HTTP slates are tied to no key and recorded for none. Every unmarked
    slate is recorded before any notice for its exchange is decided.
  - Derived, never stored. A key is LEPIC while its last marked message is newer than its last
    unmarked one, and Epic otherwise, as one group: no other wallet is told apart.
    `PeerInvoiceSupport` is that: no row Unknown, LEPIC Lepic, Epic NoInvoices.
  - Sending. Every plain notice to a payments address (`posted`, `cancelled`, `withdrawn`,
    `declined`) needs the key LEPIC with a marked message in the last 30 days, and the
    exchange's own incoming slate marked: the S2 or I2 just finalized for `posted`, the send's
    latest S2 for `cancelled` (the new column `tx_marks.answer_marked`), the parked I1 for
    `declined`. For `withdrawn` the exchange is the I1 this wallet issued over Epicbox, which
    always carries the marker, to an invoice address, which no stock wallet reads; an I2 that
    answers it unmarked is recorded first and turns the key Epic. Sealed notices to mailboxes
    are unchanged.
  - Twins. Two installs on one phrase, one LEPIC and one not, flip the key as either answers;
    each flip is right for the moment it describes. A notice the LEPIC twin acknowledges was
    still handed to the other socket first and counts toward its rounds; the per-exchange rule
    keeps that to one notice per marked exchange, the residue this design accepts.
  - Storage. The facts are sealed per row (XChaCha20-Poly1305 under the private context key)
    and found by a keyed BLAKE2b hash of the key under its own seed subkey
    `lepic-wallet peer tag v1`; the hash is in the row's associated data, so a row moved under
    another hash does not open. The table `peer_compat (key_tag, sealed)` names no peer. The
    sealed record is versioned, so later fields need no migration (vector
    `testdata/vectors/store/peer_compat.json`). Rows whose newest date is older than the
    host's limit are deleted by `forget_peers`; the app passes 180 days. A forgotten key is
    unknown and gets no notice. The rows are in no backup or export and are relearned.
  - Migration 11 to 12, in one transaction with the rest of the schema change: a `lepic` row
    becomes its date as the last marked message with bit 0 claimed and working; `no-invoices`
    its date as the last unmarked one; an undecodable row is dropped. The old table goes. So a
    key proven months ago is LEPIC by dates but gets no notice until a marked exchange in the
    last 30 days, and sends answered before the update count as unmarked. A build before it
    refuses the upgraded store as too new.

## Alternatives considered

- Notices as a new slate stage or a field in a slate: a stock listener would act on or reject a
  slate it cannot finalize, and the legacy codecs are frozen.
- Sending notices to every peer: stock processes only slates (fact 3), so a notice is for
  LEPIC peers only.
- Retrying undelivered notices from an outbox: the information is advisory and the state each
  side keeps is enough; a retry queue would add storage for no change in what funds do.
