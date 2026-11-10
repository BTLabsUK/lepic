# ADR 0024: Contact pairing, sealed slates and invoice trust on paired contacts

Status: proposed

## Context

A slate sent as a file or pasted into a chat is plain text that every holder of a copy can read.
Invoices over Epicbox need a trust relationship between two wallets that does not depend on one
Epicbox key or one relay, and a delivery path that works while a phone sleeps. Sealing a slate
needs keys that are kept apart from the Epicbox, Tor and payment-proof keys.

## Decision

The design is RFC 0002 ([RFC 0002](../rfcs/0002-contact-pairing.md)).

- **Keys.** A contact root derives from the seed, the account and the network
  (`lepic-wallet-contacts`, `key_schedule.rs`). Per contact a numbered slot below 65,536
  derives an X25519 encryption key, an Ed25519 signing key and a hint key, and a random 16-byte
  salt keys the contact's mailbox. None of these is the Epicbox, Tor or payment-proof key. A
  pairing record holds no secret. A restored wallet finds the slot of a contact again from the
  contact's card, so keys do not change.
- **Sealed envelope** (`lepic-seal`). HPKE base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
  and ChaCha20-Poly1305 (crate `hpke`), a 16-byte header with a magic, version, network, suite
  and an 8-byte recipient hint, and inner TLV fields signed with Ed25519 between paired
  contacts. Armored as `BEGINEPICSEALED. ... ENDEPICSEALED.`, at most 96 KiB, and stored as
  `.epicsealed` files. An envelope to the one-time reply key in the LEPIC marker (ADR 0015) is
  anonymous.
- **Pairing** (`lepic-contact`, `lepic-wallet-contacts`). In person by scanning each other's
  cards, or online by an invite, which is a link (`epiccash://pair/1/...`) or five pairing words
  that find it in a rendezvous mailbox on the meeting relays. A request can also go to a
  contact's Epicbox address. Both screens show a short authentication string of four emoji with
  names, from a 256-entry table. A private pairing joins two wallets of one owner over a channel
  key from two secrets.
- **Home relay.** Each pairing names the home relay of each side. All later messages between the
  contacts travel sealed and signed through per-contact mailboxes there. Wallets collect them
  with one-off drains, grouped by relay with backoff, and send through a stored outbox that
  retries.
- **Invoice trust** is a per-contact switch, `allow_invoices`, which can be turned on only for a
  verified contact. Turning it off deletes the contact's unpaid parked invoices and queues a
  sealed `declined` for each. Invoices, payments, withdrawals and notices between contacts
  travel through the contact mailboxes (`invoices.rs`).
- **Removed.** The address allowlist (`allowed_peers` is dropped by the migration to schema
  version 6 and `lepic-ffi` has no call for it) and the separate invoice address.
- **Store.** Tables `contacts`, `contact_slot_counters`, `contact_mailboxes`,
  `contact_relay_backoff`, `pairings`, `contact_outbox`, `contact_seen`, `pair_requests` and
  `contact_status_out`.
- **FFI.** Pairing, contact, sealing and outbox calls and events in `crates/lepic-ffi/src/api`
  (`contact.rs`), with error codes from 56.

## Consequences

- New dependencies `hpke` and `x25519-dalek`, under ADR 0010's rules. `hkdf`, `ed25519-dalek` and
  `chacha20poly1305` are shared with the rest of the workspace.
- Stock wallets are unaffected: sealed data and invites go only to paired contacts, and a stock
  wallet ignores the extra key in the marker.
- Pairing records go into the `.wfeh` history payload (`docs/compat/wfeh.md`) and hold no secret.
- A contact whose key is lost has to be paired again.
- Epicbox format policy (ADR 0003) is unchanged for person-to-person payments.

## Related

- ADR 0003, ADR 0010, ADR 0015, ADR 0016, ADR 0034
- [RFC 0002](../rfcs/0002-contact-pairing.md)
