# 0024 Contact pairing, sealed slates, and invoice trust on paired contacts

Status: proposed
Date: 2026-10-24

## Context

Slates sent as files or pasted into chats are plain text that every holder of a copy can read.
Invoices over Epicbox trust senders by an address allowlist: the trust is tied to an
Epicbox key and a relay, the user has to hand out a separate invoice address, and nothing
authenticates a request beyond the relay's signature. Exchanges would rather take deposits by
invoice, because then the exchange, not the phone, finalizes and posts; that needs a trust
relationship that survives relay changes and a delivery path that survives a sleeping phone.

The envelope research of 2026-10-24 and RFC 0001's draft sections 5 and 6 recommend HPKE with a
fresh key per message, on keys kept apart from the Epicbox, Tor and payment-proof keys.

## Decision

Adopt RFC 0002:

- A contact-identity branch from the seed (`m/<a>/2/0`, then HKDF), and per contact a random
  `contact_id` that derives an X25519 key, an Ed25519 key, a hint key and an Epicbox mailbox key.
  None of these is the Epicbox, Tor or payment-proof key.
- A sealed envelope: HPKE base mode, suite `0x0020`/`0x0001`/`0x0003`, a versioned 16-byte
  header, an 8-byte recipient hint, Ed25519-signed inner fields between paired contacts,
  armored as `BEGINEPICSEALED. … ENDEPICSEALED.` and stored as `.epicsealed` files. It wraps the
  V3 JSON slate LEPIC already writes. This amends RFC 0001 D1 (a dedicated key, not the
  payment-proof key) for the envelope; the `lepic.v1` binary slate stays under OD-5.
- The LEPIC marker carries a one-time reply key on every S1 and I1, so a LEPIC receiver seals its
  answer with no setup.
- Pairing in person by QR, or online by a one-time invite and throwaway Epicbox mailboxes derived
  from the invite, with an inviter commitment and a 32-bit SAS shown as four emoji with names.
- A home relay per pairing, where each side has a per-contact mailbox; all of the relationship's
  messages go there, collected by one-off drains on open and in the foreground. A user's own relay
  switch needs no message.
- Invoice trust is a per-contact switch, available once the contact is verified. Invoices,
  withdrawals, notices and their answers between contacts travel sealed and signed through the
  contact mailboxes.
- The address allowlist, the invoice address (`m/0/1/<index>`, index 1 and up), its connection,
  its prefilter and their FFI calls are removed. There are no users of them yet.
- A reference exchange kit in Python implements the protocol beside `epic-wallet`'s owner API and
  generates the test vectors LEPIC checks.

## Consequences

- New dependencies `hpke` (X25519, HKDF-SHA256, ChaCha20-Poly1305 only) and `x25519-dalek`, under
  ADR 0010's rules; `hkdf`, `hmac`, `sha2`, `ed25519-dalek`, `chacha20poly1305` and `base64` are in
  the workspace.
- New store tables (`contact`, `contact_mailbox`, `pairing`, `outbox`), `allowed_peer` dropped: a
  breaking store migration on unreleased data.
- Breaking FFI changes: invoice-address and allowlist calls go; pairing, contact, sealing and
  outbox calls and events come; error codes start at 56 (ADR 0025 takes 51 to 55).
- Stock wallets are unaffected: sealed data, cards and invites go only to paired contacts, and
  stock ignores the marker's extra key. Epic Pay's handling of the marker is checked before
  release.
- ADR 0016 changes: notices between contacts are sealed and travel through contact mailboxes;
  "proven peer" becomes "paired contact"; a signed `withdrawn` for a paid invoice cancels it
  automatically (RFC 0002 OD-P3).
- ADR 0003's Epicbox format policy is unchanged for person-to-person payments.
- The earlier invoice-address documentation in `docs/compat/epicbox.md` is replaced when W-30 lands.

## Alternatives considered

RFC 0002 "Options considered" lists them: the payment-proof or Epicbox key for encryption, age or
the Epicbox cipher, HPKE auth mode, a binary slate first, a rendezvous server, SAS without a
commitment, BIP39 or PGP words, keeping the address allowlist, per-wallet addresses with
relay-change notices, and LEPIC as the exchange's wallet.
