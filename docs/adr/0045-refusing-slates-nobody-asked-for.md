# ADR 0045: Refusing slates nobody asked for

Status: proposed

## Context

A wallet whose profile says it takes no payments (ADR 0041, bit 0) tells its contacts so and does
nothing else. A payer who sends to its payments address anyway, or who has it as a contact and
ignores the profile, gets an S1 answered like any other: the receiver signs and the payment
completes. A service such as a name-service wallet needs a wallet that receives nothing it did not
ask for, and a payer that learns this at once instead of waiting for an answer.

Mimblewimble gives the receiver a veto: without its partial signature the payment cannot complete.
A receiver that refuses an S1 and never answers it leaves the sender's inputs locked until the
sender cancels. An S1 that was never answered is safe to cancel on the sender's side.

## Decision

### Two switches

`WalletPolicy` has two switches, both off by default and independent of the profile bits:

- `refuse_unsolicited_payments`: a new S1 that arrives at the payments address over Epicbox, over
  HTTP or Tor, or in a contact's mailbox is neither signed nor stored.
- `refuse_unsolicited_invoices`: an I1 from a contact is refused instead of parked. A plain Epicbox
  I1 is refused whatever this says.

Not affected: the wallet's own sends and invoices and their answers (S2, I2); an S1 for a
payment-request listing, which the wallet asked for; slates the user takes by hand from a file, a
paste or a sealed envelope; an S1 received before, whose stored S2 goes back again.

### The answer

A refused slate is answered with the existing `declined` notice (ADR 0016), with no new wire shape:

- Over Epicbox, the notice goes to the S1's sender when the S1 came marked from a key lately shown
  to run LEPIC, as every plain notice does. Nothing goes for a slate id the wallet holds a
  transaction or invoice of. A notice that cannot be delivered for a reason that passes holds the
  message up to the hold bound.
- To a contact, the notice is sealed into the contact's mailbox, under the stage the wallet would
  have answered with. A slate sent again while its `declined` waits in the outbox queues nothing
  more.
- Over HTTP and Tor, `receive_unsolicited` fails with `ReceiveError::Refused` and the request fails
  at once with `slate refused`.

### The sender

A sender takes a `declined` for its own S1 only from the S1's recorded receiver key or contact, and
only while the send is `sent` with no S2 stored. It then:

1. cancels the send, which frees its inputs;
2. raises `PaymentDeclined` once;
3. records the time in the setting `notice.send_declined.<slate id>`, which
   `TransactionDetails::receiver_declined_at` reads.

A cancel that fails because the wallet is locked or the store does not answer keeps the notice for
the next delivery. A `declined` for a send that was answered or ended is noted only.

### Host settings

The CLI has the settings `refuse_unsolicited_payments` and `refuse_unsolicited_invoices`
(`LEPIC_REFUSE_UNSOLICITED_PAYMENTS`, `LEPIC_REFUSE_UNSOLICITED_INVOICES`). The binding's
`HostPolicy` has two optional fields of the same names (ADR 0036). LEPIC sets no limit and ties
nothing to the profile; a host that states "takes no payments" chooses whether to turn the refusal
on too.

## Consequences

- No store migration: the switches live in the wallet's config and the sender's record is a
  setting.
- Nothing is added to the wire. A LEPIC sender that does not act on a `declined` for its own S1 acknowledges
  it and ignores it: the send stays "Sent" until its user cancels it.
- Wallets that never read notices (the `epic-wallet` CLI and GUI, Stack Wallet) send unmarked S1s
  over Epicbox and get no notice; their send waits until their user cancels it. Over HTTP or Tor
  they see the request fail.
- A self-send to the wallet's own payments address, or between two installs of one wallet, is
  refused like any other S1 while the switch is on.
- A contact's S1 is refused whatever its purpose. A service that pays its users from a wallet with
  the switch on is not affected, since its own sends are not.

## Related

- ADR 0016: Epicbox notices and the per-exchange rule.
- ADR 0036: policy values are host parameters.
- ADR 0041: the owner's profile.
