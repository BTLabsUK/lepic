# 0029 Contacts are a crate on top of the engine

Status: accepted
Date: 2026-10-28

## Context

Contact pairing (RFC 0002, ADR 0024) grew inside `lepic-wallet`: by October 2026 the
`contact` module held about 8,000 of the crate's 29,000 lines, and the longest functions of the
crate were contact handlers. A reviewer auditing the money core (keys, selection, slate
building, finalize, cancel, refresh, scan) had to read past it, and the core itself called into
it: sending a file S1 derived a contact reply key, a notice about a contact's slate was sealed
into the contact's mailbox, and the `Event` type carried a contact type. The 2026-10-27
security audit asked for the split.

## Decision

- A new crate, `lepic-wallet-contacts`, holds the contact engine: pairing, contact mailboxes and
  collecting, sealed slates, contact invoices, key checks, app payloads and private pairings. It
  depends on `lepic-wallet` and drives it from outside; `lepic-wallet` does not depend on it.
- The host borrows a wallet's contact engine as `ContactBook` with
  `WalletContacts::contact_book()`, and calls `lepic_wallet_contacts::install(&wallet)` once per
  wallet handle. The method names are the ones the wallet had (`pairing_invite`,
  `contacts_collect`, `contact_seal_slate`, ...).
- The engine offers what the contact engine needs and nothing contact-specific:
  - `lepic_wallet::extension`: two hooks `install` sets. `ReplyKeys` gives a file or paste S1 and
    an I1 the reply key of the LEPIC marker; `ContactNotices` seals a notice about a contact's
    slate into the contact's mailbox. Without them those slates carry no marker and such
    notices are withheld.
  - `lepic_wallet::contact_link`: which contact a slate or transaction was exchanged with, the one
    piece of contact data the engine's own paths read (to keep a contact's slates on its
    mailbox and to match its notices).
  - Public wallet calls the contact engine uses: `session`, `blocking`, `emit`, `contact_turn`,
    `issue_unsent`, `pay_decoded`, `receive`, `finalize`, `finalize_invoice`, `cancel`,
    `apply_contact_notice`, `notify_posted`, and a few helpers of `inbox`, `account`,
    `epicbox_invoice` and `receive`.
- `PairingFailure` moves to `lepic_wallet::event`, next to the event that carries it; the contacts
  crate re-exports it.
- The contact integration tests stay in `lepic-wallet/tests` with `lepic-wallet-contacts` as a
  dev-dependency, so both crates keep one test harness.

## Consequences

- The money core's review scope no longer includes contact code; `docs/architecture.md` lists
  the new crate and its edges.
- Hosts (the CLI, the FFI) call `install` after `Wallet::new` and reach contact calls through
  `contact_book()`. The FFI API is unchanged.
- The engine's public surface grows by the calls above. They are documented as the extension
  surface and carry no contact logic.

## Alternatives considered

- An extension trait with every contact call on `Wallet`: keeps `wallet.pairing_invite(...)`
  call sites, but forty async methods would need `impl Future + Send` signatures twice.
- Keeping contacts in `lepic-wallet` with a documented module boundary: cheap, but the core would
  still call into contact code and reviewers would still have to rule it out.
