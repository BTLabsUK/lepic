# ADR 0040: The contact check and moving one's own home relay

Status: accepted

## Context

A wallet back after a long gap cannot tell whether a paired service still answers or has moved.
Nothing a contact sends asks the other side to reply: the key check (RFC 0002 7.8) runs only over
a new pairing, and status notices are one-way. A relay keeps a message 7 days, and a move reaches
a contact as one contact update posted to its old mailbox, so a wallet away longer than that
misses it.

A wallet or service on LEPIC also needs to move its own home relay. The follower's side is
`apply_relay_move` (ADR 0039). A service cannot rely on its contacts to follow, so the move does
not wait for them.

## Decision

1. **The check.** Envelope type `09` is a contact check: signed, with an empty body, sent to the
   contact's mailbox like any other contact message. Byte `08` is unused; the vector `tlv_type_08`
   (`testdata/vectors/pairing/malformed.json`) pins it as an unknown type.
2. **The answer.** A wallet that takes a check from a paired contact whose pairing has not ended
   queues a contact update (`05`) in its outbox. The update carries its current card with `seq`
   raised by one, the payments address and its proof. A private pairing carries no checks.
   `lepic serve` answers by itself, since every collect does.
3. **Pace.** Answers are paced per contact by two policy values (ADR 0036):
   `contact_check_answers_per_hour`, default 1, and `contact_check_answers_per_day`, default 3 and
   at most `MAX_CONTACT_CHECK_ANSWERS_PER_DAY` (24). Checks beyond them are acknowledged and
   dropped.
4. **Taking the answer.** The answer is an ordinary contact update, so the asking wallet takes it
   on the existing path: any answer sets when the contact was last heard (`last_sealed_in`,
   `last_heard` in `lepic contact list`), a card on the same relay refreshes the record, and a
   card on another relay raises `ContactRelayMoveRequested`. The update limits of RFC 0002 8.5
   apply to the receiver.
5. **Entry points.** `ContactBook::contact_check(relays, contact_id)`, `EpicWallet::contact_check`
   and `lepic contact check <CONTACT>` send one. It fails with `Ended` for an ended pairing,
   `WrongClass` for a private pairing and `UnknownContact` for a contact not paired. Which contacts
   to check, when, and how long to wait for the answer stay with the host.
6. **Moving home.** `ContactBook::contacts_move_home(relays, host, drain)`,
   `EpicWallet::contacts_move_home(relay, drain_days)` and `lepic contact move-home <HOST>
   [--drain-days N]` move the wallet's home relay for its contacts. Each paired contact pairing
   that has not ended and is not at home on `host` gets this wallet's card naming its mailbox
   there, once, in a `05` queued for the mailbox the contact reads now. This wallet's mailbox for
   it moves to `host` in the same write. The call returns how many moved. Private pairings and
   pairings in progress keep their relay.
7. **The drain.** With a non-zero drain the old mailboxes are still read, and a check there is
   answered with the card naming the new mailbox (ADR 0042). With a zero drain, the default of
   `--drain-days`, they are not read again: there is no keep period and no wait on contacts. A
   drain left by following a contact's own move (ADR 0039) runs to its end.
8. **No feature bit.** A wallet without type `09` reads the type field after it opens the
   envelope and before it checks the signature, finds an unknown type and drops the envelope as
   malformed: acknowledged on the relay, remembered as seen, attributed to nobody, with no heard
   time and no answer. The asking wallet sees no answer.

RFC 0002 sections 3.3 (type `09`), 8.5 (the check and the move) and 10.4 carry the rules.

## Consequences

- A contact that takes the move's update while online sees `ContactRelayMoveRequested` and follows
  when its host applies it. A contact that misses it keeps writing to a mailbox nobody reads when
  the drain is zero, and its check gets no answer; the app offers to pair again.
- Messages a contact sends to the old mailbox between the move and its following are lost without
  a drain. A slate in flight there times out like any undelivered slate.
- The host switches its own Epicbox relay to `host` as well, so new invites name it. A pairing in
  progress homes on the old relay and needs another move once paired.
- A check costs the answering wallet one update per pace window and the asking wallet one update
  within its own receive limits.
- Peers on builds without type `09` never answer.
- The binding has `contact_check` and `contacts_move_home` entry points.

## Alternatives considered

- Drain the old mailboxes until each contact follows: a service cannot rely on its contacts and
  cannot drain without end, so the drain is a period the host chooses.
- A feature bit so that peers without the type are not asked: a peer that cannot answer only
  leaves the check unanswered.
- Type `08`: the vector `tlv_type_08` pins it as refused.
- A card in any envelope carrying a move: ADR 0039 keeps moves to `05` updates within the update
  limits.

## Related

- ADR 0039: the host applies a relay move.
- ADR 0042: draining the old home.
- ADR 0036: host policy values.
- RFC 0002: contact pairing.
