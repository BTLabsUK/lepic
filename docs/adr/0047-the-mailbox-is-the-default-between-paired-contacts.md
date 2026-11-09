# ADR 0047: The mailbox is the default between paired contacts

Status: accepted

## Context

A send to a paired contact over Epicbox can go to the contact's payments address as a plain slate, or
through the pairing as a sealed slate in the contact's mailbox. The two differ in what they reveal
and in who can read them: a mailbox carries only sealed envelopes, and a stock wallet on the same
seed cannot read it.

The core already sends through the pairing (`Wallet::contact_send`) and checks the contact before it
locks any input. The open question is which route a host offers first.

## Decision

The host picks the default route for a send to a paired contact. The core states no default. The
reference host sends through the pairing when the pairing can carry payments and keeps the payments
address (card tag `09`) as the fallback.

| Case | Route |
|---|---|
| Paired or verified contact, card opens sealed, Epicbox online, no reason below | Pairing |
| Contact not paired, or the pairing is waiting, paused, ended or has changed keys | Payments address, as for any unpaired contact |
| The send call fails | The user may send to the public address; nothing is locked, because the core cancels a send it could not queue |
| No answer within the host's bound | The user is asked first; the host then cancels the waiting send and sends an ordinary one to the payments address. Later sends to that contact default to the address until a sealed message arrives |
| The receiver refuses the slate (ADR 0045) | No fallback; the receiver refuses plain slates too |

The fallback is never automatic. It moves money and leaves two transaction rows. It is safe because
it goes to an address the pairing proved (ADR 0034).

Tag `09` stays in every contact card.

After `Event::ContactKeysRestored`, the core redirects the queued outbox entries to the restored
mailbox. A host may post a waiting send again with `contact_post_slate`.

Rules of the route are in RFC 0002 §9.1. The mailbox path does not ask the contact's "Seal payments"
switch, which governs files and pastes only.

## Consequences

- The route needs no wire change, no stored-data change and no core default.
- A peer that does not collect contact slates never answers a mailbox send; a send that waits this
  way is the no-answer case in the table.
- A pairing without a proven payments address sends through the mailbox. Its fallback goes to the
  address stored in Contacts, which the pairing did not prove.
- A stock wallet on the same seed cannot read the mailbox. While it answers plain slates, the host
  keeps the default on the address.

## Alternatives considered

- Automatic fallback: cancel and send again with no user step. Money moves without the user.
- A plain resend of the same slate over Epicbox, one row: it needs a core call that lifts the refusal
  of a plain resend of a contact-linked S1 and sets the counterparty so the S2 is accepted. That is a
  new path for a rare case; cancel and send again works.
- The core reposts delivered entries on `ContactKeysRestored`: deciding when a send counts as lost is
  host policy, and the host can do it with `contact_post_slate`.
- Leave tag `09` out of invite and QR cards and keep it only in request cards. More than the fallback
  send breaks:
  1. Attaching such a pairing to a contact that has an Epicbox address fails with
     `AddressProofMissing` (`contact_attach`, `check_attach_address`), so the app offers only "Save as
     a new contact". This covers pairing by QR with someone already in Contacts and re-pairing after
     a restore from the phrase alone.
  2. The duplicate-pairing guards look contacts up by payments key (`check_free`,
     `live_pairing_with`, `unheard_with`). Without it, a request to or from a contact already paired
     by QR is not stopped.
  3. The core learns compatibility from the pairing (`learn_from_pairing`). Without it, eligibility
     for unasked requests and the detection of other apps know less.
  4. `OtherAddress` can no longer fire.

  Narrowing would also need `queue_card_update` and `confirm_proofs` to follow the new rule.
  Relaxing `contact_attach` for unproven pairings would not restore cases 2 and 3.

## Related

- ADR 0033: keys and domains (the address proof).
- ADR 0034: trust, versioning and probing.
- ADR 0045: refusing slates nobody asked for.
- RFC 0002: contact pairing.
