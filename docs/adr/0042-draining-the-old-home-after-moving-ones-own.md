# 0042 Draining the old home after moving one's own

Status: accepted
Date: 2026-11-06

Amends 0040 decision 6 and RFC 0002 8.5.

## Context

ADR 0040 lets a wallet move its own home relay. It tells each contact once, in one contact
update posted to the mailbox the contact reads now, and never reads the old mailboxes again. A
relay keeps a message 7 days. A contact away longer misses the update, keeps writing to the old
mailbox, and its contact check goes unanswered. The only way back is a new pairing.

A service that moves knows this cost and can pay for it: it can keep reading the old mailboxes
for a while. Core already reads a previous home after following a contact's move (ADR 0039).
Reading one after one's own move uses the same slot and the same collect path.

A host that decides how to treat a contact's move also needs to know who the contact is. A
service is recognised by the key on its card, and the host could not read that key.

The owner decided on 2026-11-06 that the mover may drain its old mailboxes for a period it chooses,
and that the contact view shows the contact card's encryption key.

## Decision

1. `ContactBook::contacts_move_home(relays, host, drain)` takes a drain duration, at most a year
   (`MAX_HOME_DRAIN`); core cuts a longer one to it. `EpicWallet::contacts_move_home(relay,
   drain_days)` and `lepic contact move-home <HOST> --drain-days N` take whole days, 0 to 365,
   and refuse more.
2. With a non-zero drain, each moved contact's mailbox keeps a previous home: the old home
   relay, the contact's unchanged mailbox, our old mailbox, and the drain's end. Every collect,
   `lepic serve` included, reads the old mailbox until that end.
3. What arrives there is handled as at the current mailbox. A contact check is answered with the
   current card, which names the new mailbox; the answer goes to the contact's mailbox, which
   did not change. A contact that missed the move learns of it from that answer.
4. A contact has one previous-home slot. A drain from our own move replaces one left by
   following that contact's move.
5. A zero drain keeps ADR 0040's behaviour: one update, the old mailboxes not read again, and a
   follow drain already running continues to its end.
6. On a foreground tick with mailboxes on more than three relays, collect reads only the
   contacts that are active or have something pending. A previous home still drained is always
   read: a contact that missed the move is quiet by nature. Each drain still reads at most
   `MAX_MAILBOXES_PER_DRAIN` mailboxes, taken in turn across ticks.
7. `ContactView.peer_enc_key` is the X25519 encryption key (card tag `05`) of the contact's
   stored card: `Option<[u8; 32]>` in core and `Option<Vec<u8>>` over FFI, `None` before a card
   arrived. A completed pairing shows the contact holds the key, so a host may recognise a
   service by it.

## Consequences

- A contact away longer than the relay's 7 days can still reach a mover during its drain, and
  is asked to follow when it checks.
- A drained mover reads one more mailbox per contact on every collect until the drain ends.
- Messages sent to the old mailbox after the drain ends are lost, as under ADR 0040.
- Our own drain ends a follow drain for the same contact early. Messages the contact sent to
  that older home and not yet read are lost.
- The CLI report gives the drain's end in RFC 3339.
- New FFI parameter and field; the Flutter binding needs regenerating.

## Alternatives considered

- Drain until each contact follows: rejected in ADR 0040, since a service cannot rely on its
  contacts.
- A second previous-home slot, so our own drain and a follow drain run side by side: a store
  change for a rare overlap.
- A fixed drain period in core: the period is the mover's cost, so the host chooses it.
- Recognising a service by its relay host or a domain proof: a relay host proves nothing, and
  a domain proof needs a wire change. The card key is already verified by the pairing.
