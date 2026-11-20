# ADR 0041: The owner's profile in the feature word

Status: accepted

## Context

A paired contact often runs on a host: a service, a bot, a wallet kept for deposits only. The
other side's app should offer less, or word things differently, for such a host: no "send" button
for a wallet that takes no payments, a note that replies come from a script. The pairing already
carries one feature word from each side (ADR 0034), refreshed by every reply, confirm, contact
update and contact check answer, and stored with the pairing. The upper 16 bits of the word hold
the profile.

The contact card cannot carry it: its signature field is tag `0e`, so a field above it is refused
(RFC 0002 6.1 order rule), and a card change would need new vectors.

## Decision

### Two halves of the word

The feature word, extension `0x82` of the pairing envelope, has two halves:

- Bits 0 to 15 are capabilities, the registry of ADR 0034. The marker may claim them.
- Bits 16 to 31 (`HOST_PROFILE`, shift `PROFILE_SHIFT` = 16) are the owner's profile: 16 bits,
  named by the host. The library carries the number and gives no bit a meaning. `lepic-cli`
  names bit 0 `no-payments` and bit 1 `automated`; an app names its own.

### Rules for the profile

- It goes to paired contacts only, in the pairing's own envelopes. It is never in the marker, so a
  plain sender and a stranger learn nothing.
- It only removes an offer or changes wording. It is never an identifier and grants nothing.
- A bit once given a meaning is never reused for another.
- It is not in the pairing backup, which keeps no feature word. A restored pairing shows profile 0
  until the next update or contact check answer from the peer brings it back, so an app checks
  every restored pairing right after a restore.
- Every envelope that carries the word refreshes it. A changed profile reaches each paired
  contact in a contact update (`contacts_set_own_profile`), and the configured value rides in
  replies, confirms, other updates and contact check answers.
- A receiver stores all 32 bits as received. A build that does not know the profile keeps the
  upper half in the stored word and ignores it.

`WalletConfig.profile` (`u16`) is the configured value, and `ContactView.peer_profile` is the
peer's upper half. The CLI sets the configured value with `profile` in its settings,
`LEPIC_PROFILE`, `--profile` or `--profile-bits`, and tells paired contacts a new one with
`lepic profile set`.

### The contact kind

The `kind` of a card and an invite (person, shop, exchange) is an assumption about the peer, and
it is deprecated. It stays on the wire and in the store and is parsed (one byte, 1 to 3), but a
wallet writes `person` in every invite and every first card, whatever a request says; the request
fields stay so that the host API does not change. A pairing keeps the kind it started with: a
later card clones the stored card, and the inviter's confirm carries the stored card, so the
checks of existing readers hold. A confirm whose kind differs from its invite is refused with
`KindDiffers`, and a card update whose kind differs from the stored one is dropped. Nothing reads
the kind for meaning.

The kind is removed in this order:

1. A release whose readers accept a card and an invite without the kind field or with any byte,
   and ignore the kind in the update and confirm checks.
2. Installs older than that release age out.
3. Writers stop writing tag `03`.
4. The store columns stay; dropping them is a migration of its own.

## Consequences

- No card change, no new vectors and no schema change.
- `contacts_set_own_profile` queues one update for each eligible contact, because nothing stored
  records what a contact was told. The session value is not kept: later name changes and check
  answers tell the configured value again, so a service sets `profile` in its config as well.
- Updates share the rate limit (3 a day per contact, 100 an hour in all, RFC 0002 8.5), so a
  profile changed often is dropped for the contacts past it.

## Alternatives considered

- A card extension: the card's field order refuses it.
- A new envelope extension: the word already has the right reach and lifetime.
- Profile bits in the marker: they would show the host's nature to any sender.

## Related

- ADR 0034: trust, versioning and probing, the feature registry.
- RFC 0002: contact pairing.
