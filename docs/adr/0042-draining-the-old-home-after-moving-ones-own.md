# ADR 0042: Draining the old home after moving one's own

Status: accepted; how a previous home is read is superseded in part by
[ADR 0062](0062-the-address-decides-the-protocol.md)

## Context

A wallet that moves its own home mailbox (ADR 0040) tells each contact once, in one contact update
posted to the slot the contact reads now. A mailbox keeps a message 7 days. A contact away longer
misses the update, keeps writing to the old slot and gets no answer to its contact check. The
only way back is a new pairing.

A service that moves can keep reading the old slots for a while, at a cost it chooses. Core
already reads a previous home after following a contact's move (ADR 0039), and reading one after
one's own move uses the same slot and the same collect path.

A host that decides how to treat a contact's move also needs to know who the contact is. It can
recognise a service by the key on its card, so the contact view shows that key.

## Decision

1. **A drain duration.** `ContactBook::contacts_move_home(relays, host, drain)` takes a duration,
   at most a year (`MAX_HOME_DRAIN`); core cuts a longer one to it. `EpicWallet::contacts_move_home
   (mailbox, drain_days)` and `lepic contact move-home <HOST> --drain-days N` take whole days, 0 to
   365. Both refuse more. The default of `--drain-days` is 0.
2. **The previous home.** With a non-zero drain, each moved contact's slot keeps a previous
   home: the old home mailbox, the contact's unchanged slot, this wallet's old slot and the
   end of the drain. Every collect, `lepic serve` included, reads the old slot until that end.
3. **What arrives there.** It is handled as at the current slot. A contact check is answered
   with the current card, which names the new slot; the answer goes to the contact's slot,
   which did not change. A contact that missed the move learns of it from that answer.
4. **One slot.** A contact has one previous-home slot. A drain from this wallet's own move
   replaces one left by following that contact's move.
5. **Zero drain.** A zero drain sets no previous home: one update, the old slots not read
   again. A drain left by following a contact's move continues to its end.
6. **Many mailboxes.** On a foreground tick with slots on more than three mailboxes (`FEW_RELAYS`),
   collect reads only the contacts that are active or have something pending. A previous home
   still drained is always read, since a contact that missed the move is quiet by nature. Each
   drain reads at most `MAX_MAILBOXES_PER_DRAIN` slots, taken in turn across ticks.
7. **The card key.** `ContactView.peer_enc_key` is the X25519 encryption key of the contact's
   stored card: `Option<[u8; 32]>` in core and `Option<Vec<u8>>` over FFI, `None` before a card
   arrived. A completed pairing shows that the contact holds the key, so a host may recognise a
   service by it.

RFC 0002 8.5 describes the move.

## Consequences

- A contact away longer than the mailbox's 7 days can still reach a mover during its drain, and is
  asked to follow when it checks.
- A drained mover reads one more slot per contact on every collect until the drain ends.
- Messages sent to the old slot after the drain ends are lost.
- A drain of this wallet's own move ends a follow drain for the same contact early. Messages the
  contact sent to that older home and not yet read are lost.
- The CLI report gives the end of the drain in RFC 3339.

## Alternatives considered

- Drain until each contact follows: a service cannot rely on its contacts (ADR 0040).
- A second previous-home slot, so that both drains run side by side: a store change for a rare
  overlap.
- A fixed drain period in core: the period is the mover's cost, so the host chooses it.
- Recognising a service by its mailbox host or a domain proof: a mailbox host proves nothing, and the
  card key is already verified by the pairing.

## Related

- ADR 0039: the host applies a mailbox move.
- ADR 0040: the contact check and moving one's own home mailbox.
