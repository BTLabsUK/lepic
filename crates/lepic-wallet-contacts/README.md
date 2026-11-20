# lepic-wallet-contacts

The contact engine of a LEPIC wallet: pairing with contacts (RFC 0002), the contact mailboxes
each side collects, sealed slates, contact invoices, app payloads, native slates to epic1
addresses and in person (RFC 0003), and the delivery layer that posts and reads all of their
mail. It drives the engine of `lepic-wallet`
from outside: a host borrows a wallet's `ContactBook` and calls it, and the engine keeps no
contact code of its own.

## Where it fits

| Direction | Crates |
|---|---|
| Depends on | `lepic-wallet` (the engine), `lepic-store`, `lepic-contact` (cards and envelopes), `lepic-seal`, `lepic-native-slate`, `lepic-epic1`, `lepic-methods` (features `epicbox`, `http`), `lepic-epicbox`, `lepic-peer` |
| Used by | `lepic-cli`, `lepic-ffi`; `lepic-wallet` in its tests |

Features:

| Feature | Default | Effect |
|---|---|---|
| `sqlite` | on | Contact backups read and write the SQLite store |
| `test-support` | off | `in_person_testing` and `epic1_testing`: codes, links and answers outside the rules, for tests of wallets that refuse them |
| `tor` | off | `onion_dialer`, which dials a listener's onion through the wallet's Tor |

What it does not do:

- It does not touch the wallet's payments address, its listener or the node. Contact mailboxes
  have keys of their own.
- It does not fetch a domain's well-known file. `domain_verify` takes the bytes the host
  fetched.
- It does not read app payloads. The host sends and judges them.
- It does not retry quarantined messages or apply a contact's relay move by itself. The host
  decides both.

## Core concepts

### Setup

```rust
use lepic_wallet_contacts::{install, ContactRelays, RelayMode, WalletContacts};

install(&wallet); // once per wallet handle, before its first send
let relays = ContactRelays::new(epicbox, RelayMode::Online).with_mailboxes(mailboxes);
let book = wallet.contact_book();
```

`install` gives the engine what it takes from this crate: sealed notices to contacts.
`ContactRelays` holds the wallet's `Epicbox` method, the wallet's mailbox list (`MailboxList`:
the shipped mailboxes, plus the ones the user added, minus the shipped ones the user removed;
`with_mailboxes`, read by `ContactRelays::list`), the wallet's Tor for a link's `tor` entries
(`with_tor`), and the `RelayMode`:

| `RelayMode` | Relays reached |
|---|---|
| `Online` | The mailboxes of the list and the mailbox of each contact's card |
| `Offline` | None; calls that would connect fail with `ContactError::Offline` |

### Keys and records

A contact record holds no secret. This wallet's keys for a contact come from one
`ContactRoot`, which depends on the seed, the account and the network, plus the record's slot
and its box salt (RFC 0002 2.1 to 2.3). Slots are numbered so a restored wallet finds its keys
for a contact again. Slots from `PRIVATE_SLOT_BASE` up hold private pairings. The secrets of a
pairing in progress are sealed in the store.

### Pairing

| Way | Calls | RFC 0002 |
|---|---|---|
| Invite link | `pairing_invite`, `pairing_preview`, `pairing_accept`, `pairing_enter_link` | 7.1 to 7.3 |
| Standing invite | `pairing_standing_invite` | 7.1; ADR 0034 |

An invite names a home relay. The invitee posts its reply to a throwaway mailbox there and on
every usable relay of the list, the inviter's next collect takes it and posts a confirm the
same way, and both sides then have a mailbox on that relay for the other. `pairing_sas` records
the user's check of the four SAS entries both
screens show (7.5): a match makes the contact verified, a mismatch ends the pairing.
`pairing_cancel` cancels one in progress. A pairing waits until the contact is heard in it;
an inviter that does not hear the contact during `NEVER_FINISHED_AFTER` (seven days) of
collecting ends it. `PairingStatus` says where it stands.

A private pairing links two wallets of one owner. Its channel carries only app payloads, and
only once both sides matched the words check.

### Collecting

`contacts_collect` reads every mailbox the wallet watches once. Every mailbox is read from the
contacts' `mux/1` sessions (`lepic_epicbox::sessions`): a cycle first makes the watched set equal to
the pairing, contact and previous-home mailboxes the records name, the delivery mailbox of each
account's epic1 address and the reply mailboxes of epic1 payments and in-person codes, then claims them
on one shared session per relay, spread over more sockets when the relay allows fewer mailboxes per
socket. Each message is acknowledged only once its
effect is stored, so mail left unacknowledged by a cut is pushed again and handled once. A relay
that does not answer, or does not offer `mux/1`, is not read at all: it is listed in `unreachable`
and raises `HomeRelayUnreachable`. What happened reaches the host as `lepic_wallet::event::Event`s,
such as `PairingReplied`, `ContactUpdated` and `HomeRelayUnreachable`, and as a `CollectReport`.

A cycle starts with a `CollectTrigger`. `Open` and `Pull` have a session waiting to reconnect
try at once and run the whole outbox. `Foreground` asks each relay what waits and reads it.
`Push` reads only what the sessions queued and asks the relays nothing. `ContactView::awaiting`
is the pending rule: a message waiting to go out, a payment not yet finished, or an invoice from
the contact waiting for an answer.

A message that opened under a contact's key but could not be taken is kept in quarantine
(ADR 0049): `contact_quarantine`, `contact_quarantine_retry`, `contact_quarantine_discard`.

A contact update can ask to move to another relay. The host applies it with
`apply_relay_move` (ADR 0039). `contacts_move_home` moves this wallet's own home and keeps
draining the old mailboxes for up to `MAX_HOME_DRAIN` (a year, ADR 0042). `contact_check` asks
a contact for its current card, which comes back as a contact update (RFC 0002 8.5, ADR 0040).

### Delivery

The `delivery` module posts and reads the native mail of every flow of this crate: epic1
payments, their answers and notices, in-person answers, contact mail and pairing mail. A classic
address never reaches it. Its parts:

| Module | Job |
|---|---|
| `reconcile` | Makes the watch set, one row per mailbox and relay, equal to the records it comes from |
| `watch` | The rows of the watch set with the key each names, and what a pass did on each relay |
| `carrier` | Claims the rows on the contacts' `mux/1` session of each relay and lets go of the rest |
| `router` | Hands each pushed message to the handler of its class, in push order, and acknowledges it once the handler stored it |
| `outbox` | Holds every post owed, one row per route, stored in the write that makes it owed; a row is `queued`, `posted`, `uncertain` or `failed` |
| `epicbox`, `peer` | Post an envelope on a relay, or on a link's `http` or `tor` entry |

The core runs no timer; the host drives it with these calls:

| Call | Does |
|---|---|
| `contacts_collect(relays, trigger)` | One cycle: reconciles and claims the watch set, reads what the sessions queued, posts what the outbox owes |
| `claim_pushed(relays)` | Watches the mailboxes of a pairing, link or payment made since the last cycle, reading nothing |
| `contacts_outbox_deliver(relays)` | Posts the outbox rows that are due, reading nothing |
| `epic1_post_next` | Posts a payment again on its link's next route, the only way past an `uncertain` post |

[Delivery](../../docs/protocols/delivery.md) has the relay list, where each kind of mail goes,
the outbox's waits and the triggers.

### Slates between contacts

| Route | Calls | Format |
|---|---|---|
| Mailbox | `contact_send`, `contact_post_slate` | Sealed envelope through the outbox (ADR 0047) |
| File or paste | `contact_seal_slate`, `sealed_open`, `sealed_peek`, `sealed_receive`, `sealed_pay`, `sealed_finalize` | `BEGINEPICSEALED.` text, or `lepic.v1` for an answer to a native slate |

Every contact message is sealed to the pairing's keys and signed. A new slate goes as V3 JSON
in a type `01` envelope. A native slate a contact sends (`lepic.v1` in a type `0A` envelope,
RFC 0003) is read, and its answer goes native too.

The outbox keeps sealed messages that must reach a contact's mailbox: payments of invoices,
answers to withdrawals, notices. It lives in the store, so a closed app loses nothing, and
retries at once, after 30 s, 2 min, 10 min, then every 30 min. `contact_outbox`,
`contact_outbox_resend` and `contacts_outbox_deliver` show and drive it.

Contact invoices (RFC 0002 11 and 12) go only to a verified contact, and park only when the
contact is verified and `contact_set_allow_invoices` allows them; otherwise a paired contact is
answered `declined`: `contact_issue_invoice`, `contact_invoices`, `contact_pay_invoice`,
`contact_decline_invoice`.

### Native slates outside pairings

| Call | Route | Spec |
|---|---|---|
| `DirectHandler` | The `/api/v1/inbox` of an HTTP or Tor listener with an epic1 address, for envelopes sealed to it | RFC 0003 5.15 |
| `epic1_link`, `epic1_pay` and others | The delivery mailbox of the account's epic1 address on at most 3 usable relays, or a link's `http` and `tor` entries | RFC 0003 5.14 |
| `in_person_send`, `in_person_invoice`, `in_person_take`, `in_person_finalize` and others | A code shown on one screen and scanned by the other | RFC 0003 9 |

### Checks between paired wallets

- The address proof shows a verifier that a contact holds the key of the payments address its
  card names. It is a MAC only the two of them can check. `ContactView::payments_address` is set
  only when it verified.
- The domain proof (ADR 0043): a contact may claim a domain, and `domain_verify` checks the
  claim against the domain's `/.well-known/epic-wallet.json`, which lists its domain keys.
- The key check (RFC 0002 7.8): after a restore, `contact_key_check` and
  `contact_keys_resolve` fold a pairing made again into the old record when both sides prove
  the old keys within `KEY_CHECK_WINDOW` (a day).

### Managing contacts

`contacts`, `contact`, `pairings_pending` and `private_pairings` list what is stored as
`ContactView` and `PendingPairingView`; neither holds a key. `contact_set_label`,
`contact_set_seal`, `contact_remove` and `contact_unpair` change one contact, and
`contacts_export` and `contacts_import` back up the pairing records (RFC 0002 10.5).
`contact_post_payload`, `contact_payloads` and `contact_payloads_ack` carry app payloads of up
to `MAX_APP_PAYLOAD_LEN` (65,535 bytes).

## Public API

| Item | Purpose |
|---|---|
| `ContactBook`, `WalletContacts`, `install` | The engine, borrowed from a wallet |
| `ContactRelays`, `RelayMode`, `MailboxList`, `parse_mailbox` | The mailboxes it reaches |
| `ContactView`, `PendingPairingView`, `PairingStatus`, `EndedPairing` | What is stored, for the host |
| `InviteRequest`, `InviteOffer`, `InvitePreview`, `AcceptRequest`, `AcceptOutcome`, `SasDecision` | Pairing |
| `SealedSlate`, `SealedPayment`, `SealedReceived`, `SealedAnswer`, `payment_file`, `is_epictx` | Sealed slates |
| `ContactInvoice`, `InvoiceDetails`, `OutboxView`, `OutboxReport` | Invoices and the outbox |
| `CollectTrigger`, `CollectReport` | Collecting |
| `DirectHandler`, `Epic1Keys`, `InboxRoute` | Native slates a listener receives |
| `Epic1LinkRequest`, `Epic1PayRequest`, `Epic1Paid`, `Epic1Refusal` and the other `Epic1*` types | epic1 addresses |
| `InPersonCode`, `InPersonRead`, `InPersonPaid`, `InPersonRefusal` and the other `InPerson*` types | Slates in person |
| `DomainFile`, `DomainVerdict`, `verify` | Domain proofs |
| `ContactRoot`, `ContactKeys`, `contact_root`, `pairing_mailbox_keys` | Contact keys |
| `ContactError` | Every failure |

## Related

- [Delivery](../../docs/protocols/delivery.md), [Pairing](../../docs/protocols/pairing.md),
  [EPICTX](../../docs/protocols/epictx.md),
  [epic1](../../docs/protocols/epic1.md), [Epicbox](../../docs/protocols/epicbox.md)
- [RFC 0002 contact pairing](../../docs/rfcs/0002-contact-pairing.md),
  [RFC 0003 EPICTX native slates](../../docs/rfcs/0003-epictx-native-slates.md)
- ADRs: [0039 the host applies a relay move](../../docs/adr/0039-the-host-applies-a-relay-move.md),
  [0040 contact check and own relay move](../../docs/adr/0040-contact-check-and-own-relay-move.md),
  [0042 draining the old home](../../docs/adr/0042-draining-the-old-home-after-moving-ones-own.md),
  [0043 domain proof](../../docs/adr/0043-domain-proof-for-paired-contacts.md),
  [0047 the mailbox between paired contacts](../../docs/adr/0047-the-mailbox-is-the-default-between-paired-contacts.md),
  [0049 keeping messages](../../docs/adr/0049-keeping-messages-that-cannot-be-taken-yet.md),
  [0052 legacy at the edge](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md),
  [0062 the address decides the protocol](../../docs/adr/0062-the-address-decides-the-protocol.md),
  [0063 the epic1 address carries its own mailbox](../../docs/adr/0063-the-epic1-address-carries-its-own-mailbox.md)
- [`lepic-wallet`](../lepic-wallet/README.md), [`lepic-methods`](../lepic-methods/README.md),
  [`lepic-epicbox`](../lepic-epicbox/README.md), [`lepic-peer`](../lepic-peer/README.md)
