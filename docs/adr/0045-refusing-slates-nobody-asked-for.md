# 0045 Refusing slates nobody asked for

Status: proposed
Date: 2026-11-06

Extends 0016 (notices) and 0041 (the owner's profile).

## Context

A wallet whose profile says it takes no payments (0041, bit 0) only tells its contacts so. A
payer who sends to its payments address anyway, or who has it as a contact and ignores the
profile, gets an S1 answered as any other: the receiver signs, and the payment completes. A
service such as a name service wallet wants its wallet to receive nothing it did not ask for,
and the payer to learn at once, instead of a send that waits unanswered.

Mimblewimble gives the receiver a veto: without its partial signature the payment cannot
complete. A receiver that refuses an S1 and never answers it leaves the sender's inputs locked
until the sender cancels. An S1 that was never answered is safe to cancel on the sender's side.

## Decision

Two policy switches in `WalletPolicy`, both off by default and independent of the profile bits:

- `refuse_unsolicited_payments`: an S1 that arrives at the payments address over Epicbox, over
  HTTP or Tor, or in a contact's mailbox is refused. Nothing is received.
- `refuse_unsolicited_invoices`: an I1 from a contact is refused instead of parked. A plain
  Epicbox I1 is refused already.

Not affected: the wallet's own sends and invoices and their answers (S2, I2); an S1 for a
payment-request listing, which the wallet asked for; slates taken by hand from a file or a
paste; an S1 the wallet received before, whose stored S2 goes back again.

A refused slate is answered with the existing `declined` notice (0016), with no new wire shape:

- Over Epicbox, it goes to the S1's sender when the S1 came marked from a key lately shown to
  run LEPIC, as every plain notice does. Nothing goes for a slate id this wallet holds a
  transaction or invoice of.
- To a contact, it goes sealed into the contact's mailbox, under the stage the wallet would
  have answered with. A slate sent again while its `declined` still waits queues nothing more.
- Over HTTP and Tor, the request fails at once with `slate refused`.

A sender with this decision takes a `declined` for its own S1 only from the S1's recorded
receiver key or contact, and only while the send is `sent` with no S2 stored. It then cancels
the send, which frees its inputs, raises `PaymentDeclined` once and records the time in a
setting (`notice.send_declined.<slate id>`), which `TransactionDetails::receiver_declined_at`
reads. A cancel that fails because the wallet is locked or the store does not answer keeps the
notice for the next delivery. A `declined` for a send that was answered or ended is noted only.

Hosts expose the switches as settings: `refuse_unsolicited_payments` and
`refuse_unsolicited_invoices` in the CLI (`LEPIC_REFUSE_UNSOLICITED_PAYMENTS`,
`LEPIC_REFUSE_UNSOLICITED_INVOICES`), and two optional fields of the binding's `HostPolicy`.
Core sets no limits and ties nothing to the profile; a host that states "takes no payments"
chooses whether to turn the refusal on too.

## Consequences

- No store migration: the switches live in the wallet's config, and the sender's record is a
  setting.
- The wire is unchanged. LEPIC 26.11.3 (b6f5003f) and older acknowledge a `declined` for their
  own S1 and ignore it: their send stays "Sent · Not collected" until their user cancels it.
- Wallets that never read notices (epic-wallet CLI and GUI, Stack Wallet) send unmarked S1s over
  Epicbox and get no notice; their send waits until their user cancels it. Over HTTP or Tor they
  see the request fail.
- A self-send to the wallet's own payments address, or between two installs of one wallet, is
  refused like any other S1 while the switch is on.
- A contact's withdrawal is an S1 and is refused too; a service that pays its users from a wallet
  with the switch on is not affected, since its own sends are not.
