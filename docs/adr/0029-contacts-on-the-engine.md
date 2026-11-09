# ADR 0029: Contacts are a crate on top of the engine

Status: accepted

## Context

Contact pairing (RFC 0002, ADR 0024) is a large feature: invites, mailboxes, sealed slates,
contact invoices, key checks and app payloads. A reviewer auditing the money core (keys,
selection, slate building, finalize, cancel, refresh, scan) needs to read that core without the
contact code, and the core must not depend on it.

## Decision

- `lepic-wallet-contacts` holds the contact engine: pairing, contact mailboxes and collecting,
  sealed slates, contact invoices, key checks, app payloads and private pairings. It depends on
  `lepic-wallet` and drives it from outside. `lepic-wallet` does not depend on it; its tests use
  the crate as a dev-dependency (feature `test-support`), so both crates keep one test harness.
- The host borrows a wallet's contact engine as `ContactBook` with
  `WalletContacts::contact_book()`, and calls `lepic_wallet_contacts::install(&wallet)` once per
  wallet handle, before the wallet's first send.
- `lepic-wallet` offers what the contact engine needs and nothing contact-specific:
  - `lepic_wallet::extension`: four hooks that `install` sets. `ReplyKeys` gives a file or paste
    S1 and an I1 the reply key of the LEPIC marker. `NativeSlates` converts between the V3 JSON
    the engine stores and the `lepic.v1` body of a native slate over Epicbox. `ContactNotices`
    seals a notice about a contact's slate into the contact's mailbox. `PairRequests` takes a
    pairing request sent to the payments address. Without a hook, those slates carry no marker,
    native slates are refused, such notices are withheld and such requests are ignored.
  - `lepic_wallet::contact_link`: which contact a slate or transaction was exchanged with, the one
    piece of contact data the engine's own paths read, to keep a contact's slates on its mailbox
    and to match its notices.
  - Public wallet calls the contact engine uses: `session`, `blocking`, `emit`, `contact_turn`,
    `issue_unsent`, `pay_decoded`, `receive`, `finalize`, `finalize_invoice`, `cancel`,
    `apply_contact_notice`, `notify_posted` and a few helpers of `inbox`, `account` and
    `epicbox_invoice`.
- `PairingFailure` lives in `lepic_wallet::event`, next to the event that carries it; the contacts
  crate re-exports it.
- The LEPIC marker codecs live in `lepic-transport::marker`, below both crates.

## Consequences

- The money core's review scope does not include contact code; `docs/architecture.md` lists the
  crate and its edges.
- Hosts (the CLI, the FFI) call `install` after `Wallet::new` and reach contact calls through
  `contact_book()`.
- The engine's public surface includes the calls above. They are the extension surface and carry
  no contact logic.

## Alternatives considered

- An extension trait with every contact call on `Wallet`: keeps `wallet.pairing_invite(...)` call
  sites, but forty async methods would need `impl Future + Send` signatures twice.
- Keeping contacts in `lepic-wallet` behind a module boundary: the core would still call into
  contact code and reviewers would still have to rule it out.

## Related

- ADR 0024, RFC 0002
