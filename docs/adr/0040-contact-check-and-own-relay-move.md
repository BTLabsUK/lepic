# 0040 The contact check and moving one's own home relay

Status: accepted
Date: 2026-11-04

## Context

A wallet back after a long gap cannot tell whether a paired service still answers, or whether
it moved. Nothing a contact sends asks the other side to reply: the key check (RFC 0002 7.8)
runs only over a new pairing, and status notices are one-way. A relay keeps a message 7 days,
and a move reaches a contact only as one contact update posted to its old mailbox, so a wallet
away longer than that misses it. And no wallet or service on LEPIC could move its own home
relay: core had only the follower's side, `apply_relay_move` (ADR 0039).

The owner decided on 2026-11-04 that core gets a contact check and a move of one's own home relay
that announces once and does not drain the old mailboxes. A service cannot rely on its
contacts to follow, so it does not wait for them.

## Decision

1. A new envelope type `09`, contact check: signed, empty body, sent to the contact's mailbox
   like any other contact message. Byte `08` stays unused: the kit's vectors refuse it as an
   unknown type.
2. A wallet that takes a check from a paired contact whose pairing has not ended answers with a
   contact update (`05`) carrying its current card with `seq` raised by one, the payments
   address and its proof, through its outbox. `lepic serve` answers by itself, since collect
   does. A private pairing does not carry checks.
3. Answers are paced per contact by two host parameters (ADR 0036):
   `contact_check_answers_per_hour`, default 1, and `contact_check_answers_per_day`, default
   3, at most 24. Checks beyond them are acknowledged and dropped.
4. The answer is an ordinary update, so the asking wallet takes it on the existing path: any
   answer sets when the contact was last heard (`last_sealed_in`, `last_heard` in `lepic
   contact list`), a card on the same relay refreshes the record, and a card on another relay
   raises `ContactRelayMoveRequested`. The receiver's update limits of RFC 0002 8.5 apply.
5. `ContactBook::contact_check(relays, contact_id)`, `EpicWallet::contact_check` and `lepic
   contact check <CONTACT>` send one. Which contacts to check, when, and how long to wait for
   the answer stay with the host; BT Wallet's 120 s and 7 days are its own values.
6. `ContactBook::contacts_move_home(relays, host)`, `EpicWallet::contacts_move_home` and
   `lepic contact move-home <HOST>` move the wallet's home relay for its contacts. Every paired
   contact pairing that has not ended and is not at home on `host` gets our card naming our
   mailbox there, once, in a `05` queued for the mailbox it reads now, and our mailbox for it
   moves to `host` in the same write. The old mailboxes are not read again: there is no drain,
   no keep period and no wait on contacts. A drain left by following a contact's own move
   (ADR 0039) runs to its end. Private pairings and pairings in progress keep their relay.
7. No feature bit. A wallet that predates type `09` reads the type field after it opens the
   envelope and before it checks the signature, finds an unknown type, and drops the envelope
   as malformed: acknowledged on the relay, remembered as seen, attributed to nobody, no heard
   time, no answer. The asking wallet sees no answer.

## Consequences

- A contact that takes the move's update while online sees `ContactRelayMoveRequested`, and
  follows when its host applies it. A contact that misses it keeps writing to a mailbox nobody
  reads; its check gets no answer, and the app offers "Pair again".
- Messages a contact sends to the old mailbox between the move and its following are lost.
  A slate in flight there times out like any undelivered slate.
- The host switches its own Epicbox relay to `host` as well, so new invites name it; a pairing
  in progress homes on the old relay and needs another move once paired.
- A check costs the answering wallet one update per pace window and the asking wallet one
  update within its own receive limits.
- Breaking for peers on older builds, which never answer, under the no-compat rule.
- New FFI calls; the Flutter binding needs regenerating.
- This amends RFC 0002 3.3 (type `09`), 8.5 (the check, its pace, and the mover that
  announces once and does not drain) and 10.4.

## Alternatives considered

- Keep draining the old mailboxes until each contact follows or a keep period ends: rejected.
  A service cannot rely on its contacts and cannot drain without end.
- A feature bit so older peers are not asked: compat code for a case the no-compat rule
  accepts.
- Type `08`: the kit's vector `tlv_type_08` already pins it as refused.
- Letting a card in any envelope carry a move: ADR 0039 keeps moves to `05` updates within the
  update limits.
