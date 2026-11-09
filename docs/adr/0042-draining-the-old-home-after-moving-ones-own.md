# ADR 0042: Draining the old home after moving one's own

Status: accepted

## Context

A wallet that moves its own home relay (ADR 0040) tells each contact once, in one contact update
posted to the mailbox the contact reads now. A relay keeps a message 7 days. A contact away longer
misses the update, keeps writing to the old mailbox and gets no answer to its contact check. The
only way back is a new pairing.

A service that moves can keep reading the old mailboxes for a while, at a cost it chooses. Core
already reads a previous home after following a contact's move (ADR 0039), and reading one after
one's own move uses the same slot and the same collect path.

A host that decides how to treat a contact's move also needs to know who the contact is. It can
recognise a service by the key on its card, so the contact view shows that key.

## Decision

1. **A drain duration.** `ContactBook::contacts_move_home(relays, host, drain)` takes a duration,
   at most a year (`MAX_HOME_DRAIN`); core cuts a longer one to it. `EpicWallet::contacts_move_home
   (relay, drain_days)` and `lepic contact move-home <HOST> --drain-days N` take whole days, 0 to
   365. Both refuse more. The default of `--drain-days` is 0.
2. **The previous home.** With a non-zero drain, each moved contact's mailbox keeps a previous
   home: the old home relay, the contact's unchanged mailbox, this wallet's old mailbox and the
   end of the drain. Every collect, `lepic serve` included, reads the old mailbox until that end.
3. **What arrives there.** It is handled as at the current mailbox. A contact check is answered
   with the current card, which names the new mailbox; the answer goes to the contact's mailbox,
   which did not change. A contact that missed the move learns of it from that answer.
4. **One slot.** A contact has one previous-home slot. A drain from this wallet's own move
   replaces one left by following that contact's move.
5. **Zero drain.** A zero drain sets no previous home: one update, the old mailboxes not read
   again. A drain left by following a contact's move continues to its end.
6. **Many relays.** On a foreground tick with mailboxes on more than three relays (`FEW_RELAYS`),
   collect reads only the contacts that are active or have something pending. A previous home
   still drained is always read, since a contact that missed the move is quiet by nature. Each
   drain reads at most `MAX_MAILBOXES_PER_DRAIN` mailboxes, taken in turn across ticks.
7. **The card key.** `ContactView.peer_enc_key` is the X25519 encryption key of the contact's
   stored card: `Option<[u8; 32]>` in core and `Option<Vec<u8>>` over FFI, `None` before a card
   arrived. A completed pairing shows that the contact holds the key, so a host may recognise a
   service by it.

RFC 0002 8.5 describes the move.

## Consequences

- A contact away longer than the relay's 7 days can still reach a mover during its drain, and is
  asked to follow when it checks.
- A drained mover reads one more mailbox per contact on every collect until the drain ends.
- Messages sent to the old mailbox after the drain ends are lost.
- A drain of this wallet's own move ends a follow drain for the same contact early. Messages the
  contact sent to that older home and not yet read are lost.
- The CLI report gives the end of the drain in RFC 3339.

## Alternatives considered

- Drain until each contact follows: a service cannot rely on its contacts (ADR 0040).
- A second previous-home slot, so that both drains run side by side: a store change for a rare
  overlap.
- A fixed drain period in core: the period is the mover's cost, so the host chooses it.
- Recognising a service by its relay host or a domain proof: a relay host proves nothing, and the
  card key is already verified by the pairing.

## Related

- ADR 0039: the host applies a relay move.
- ADR 0040: the contact check and moving one's own home relay.
