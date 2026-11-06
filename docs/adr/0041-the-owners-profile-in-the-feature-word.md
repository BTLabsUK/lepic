# 0041 The owner's profile in the feature word

Status: accepted
Date: 2026-11-05

Extends 0034 and RFC 0002 (envelope extension `82`).

## Context

A paired contact often runs on a host: a service, a bot, a wallet kept for deposits only. The other
side's app should offer less, or word things differently, for such a host: no "send" button for a
wallet that takes no payments, a note that replies come from a script. The pairing already carries
one word from each side (0034), refreshed by every reply, confirm, contact update and contact check
answer, and stored with the pairing. Its upper 16 bits were unused.

The contact card cannot carry it: its signature field is tag `0e`, so a field above it is refused
(RFC 0002 6.1 order rule), and a card change would need new vectors.

## Decision

The feature word, extension `82` of the pairing envelope, has two halves and keeps this form
permanently:

- Bits 0-15 are capabilities, the registry of 0034. The marker may claim them (`claimed()`).
- Bits 16-31 are the owner's profile: 16 bits, named by the host. The library carries the number
  and gives no bit a meaning; `lepic-cli` names bit 0 `no-payments` and bit 1 `automated`, and an
  app names its own.

Rules for the profile half:

- It goes to paired contacts only, in the pairing's own envelopes. It is never in the marker, so a
  plain sender and a stranger learn nothing.
- It only removes an offer or changes wording. It is never an identifier and grants nothing.
- A bit once given a meaning is never reused for another.
- It is not in the pairing backup, which keeps no features word. A restored pairing shows profile 0
  until the next update or contact check answer from the peer brings it back; an app checks every
  restored pairing right after a restore.
- It is refreshed by every envelope that carries the word: a changed profile reaches each paired
  contact in a contact update (`contacts_set_own_profile`), and the configured value rides in
  replies, confirms, other updates and contact check answers.
- A receiver stores all 32 bits as received; an old LEPIC keeps the upper half in the stored word
  and ignores it.

`WalletConfig.profile` (u16) is the configured value; `ContactView.peer_profile` is the peer's
upper half. The CLI sets it with `profile`, `LEPIC_PROFILE`, `--profile` or `--profile-bits`.

## Kind

The card's and the invite's `kind` (person, shop, exchange) is an assumption about the peer, and
it is deprecated. It stays on the wire and in the store, and is still parsed (one byte, 1 to 3),
but a new wallet writes `person` at every invite and every first card, whatever a request says
(the request fields stay so the host API does not change). A pairing keeps the kind it started
with: a later card clones our stored card, and the inviter's confirm carries the stored card, so
the checks of shipped readers hold (a confirm whose kind differs from its invite is refused with
`KindDiffers`; a card update whose kind differs from the stored one is dropped). Nothing reads
the kind for meaning. Removal, in order:

1. A release whose readers accept a card and an invite without the kind field or with any byte,
   and ignore kind in the update and confirm checks.
2. Installs older than that release age out.
3. Writers stop writing tag `03`.
4. The store columns stay; dropping them is a migration of its own.

## Consequences

- No card change, no new vectors, no schema change.
- `contacts_set_own_profile` queues one update for each eligible contact, because nothing stored
  records what a contact was told. The session value is not kept: later name changes and check
  answers tell the configured value again, so a service sets `profile` in its config as well.
- Updates share the rate limit (3 a day per contact, 100 an hour in all), so a profile changed
  often is dropped for the contacts past it.

## Alternatives considered

- A card extension: refused by the card's field order.
- A new envelope extension: the word already has the right reach and lifetime.
- Profile bits in the marker: would show the host's nature to any sender.
