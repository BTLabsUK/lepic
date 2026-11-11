# lepic-wallet-contacts

The contact engine of a LEPIC wallet: pairing with contacts (RFC 0002), the contact mailboxes
each side collects, sealed slates, contact invoices, app payloads, and native slates to
listeners, to epic1 addresses and in person (RFC 0003). It drives the engine of `lepic-wallet`
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
let relays = ContactRelays::new(epicbox, RelayMode::Online).with_meeting(meeting);
let book = wallet.contact_book();
```

`install` gives the engine what it takes from this crate: the reply key a file or paste S1 or
I1 carries, the `lepic.v1` conversions of native slates over Epicbox, sealed notices to
contacts, and pairing requests. `ContactRelays` holds the wallet's `Epicbox` method, whose
relay is the home relay of this wallet's invites, the meeting relays for pairing words, and the
`RelayMode`:

| `RelayMode` | Relays reached |
|---|---|
| `Online` | Home relays, contacts' relays and meeting relays |
| `Offline` | None; calls that would connect fail with `ContactError::Offline` |
| `EpicboxOff` | None, home relays included; `ContactError::EpicboxOff` |

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
| Request over Epicbox | `pairing_request_send`, `pairing_requests`, `pairing_request_dismiss`, `pairing_standing_invite` | 7.1; ADR 0034 |

An invite names a home relay. The invitee posts its reply to a throwaway mailbox there, the
inviter's next collect takes it and posts a confirm, and both sides then have a mailbox on
that relay for the other. `pairing_sas` records the user's check of the four SAS entries both
screens show (7.5): a match makes the contact verified, a mismatch ends the pairing.
`pairing_cancel` cancels one in progress. A pairing waits until the contact is heard in it;
an inviter that does not hear the contact during `NEVER_FINISHED_AFTER` (seven days) of
collecting ends it. `PairingStatus` says where it stands.

A pair request goes to a contact's payments address and carries an invite of its own. It goes
only to a key that ran LEPIC lately and claims pair requests.

A private pairing links two wallets of one owner. Its channel carries only app payloads, and
only once both sides matched the words check.

### Collecting

`contacts_collect` drains the pairing mailboxes and the contact mailboxes once, one connection
per relay and at most 50 mailboxes in a cycle (RFC 0002 8.4). A relay that does not answer
backs off for 30 s, 2 min, 10 min, then 30 min. Each message is acknowledged only once its
effect is stored. What happened reaches the host as `lepic_wallet::event::Event`s, such as
`PairingReplied`, `ContactUpdated` and `HomeRelayUnreachable`, and as a `CollectReport`.

A message that opened under a contact's key but could not be taken is kept in quarantine
(ADR 0049): `contact_quarantine`, `contact_quarantine_retry`, `contact_quarantine_discard`.

A contact update can ask to move to another relay. The host applies it with
`apply_relay_move` (ADR 0039). `contacts_move_home` moves this wallet's own home and keeps
draining the old mailboxes for up to `MAX_HOME_DRAIN` (a year, ADR 0042). `contact_check` asks
a contact for its current card, which comes back as a contact update (RFC 0002 8.5, ADR 0040).

### Slates between contacts

| Route | Calls | Format |
|---|---|---|
| Mailbox | `contact_send`, `contact_post_slate` | Sealed envelope through the outbox (ADR 0047) |
| File or paste | `contact_seal_slate`, `sealed_open`, `sealed_receive`, `sealed_pay`, `sealed_finalize` | `BEGINEPICSEALED.` text, or `lepic.v1` when native |
| Plain fallback | `contact_plain_fallback` | The plain slate, for a contact that cannot open sealed text |

Every contact message is sealed to the pairing's keys and signed. A slate goes native
(`lepic.v1` in a type `0A` envelope, RFC 0003) when the host sets `native_direct` and the
contact's features claim native slates; never over a private pairing.

The outbox keeps sealed messages that must reach a contact's mailbox: payments of invoices,
answers to withdrawals, notices. It lives in the store, so a closed app loses nothing, and
retries at once, after 30 s, 2 min, 10 min, then every 30 min. `contact_outbox`,
`contact_outbox_resend` and `contacts_outbox_deliver` show and drive it.

Contact invoices (RFC 0002 11 and 12) park only when the contact is verified and
`contact_set_allow_invoices` allows them: `contact_issue_invoice`, `contact_invoices`,
`contact_pay_invoice`, `contact_decline_invoice`.

### Native slates outside pairings

| Call | Route | Spec |
|---|---|---|
| `direct_send`, `direct_resend`; `DirectHandler` | An HTTP or Tor listener's `/v1/peer/slates`, when it advertises the endpoint | ADR 0052, RFC 0003 5.15 |
| `epic1_link`, `epic1_pay`, `epic1_post_answer` and others | Link mailboxes of an epic1 address | RFC 0003 5.14 |
| `in_person_send`, `in_person_invoice`, `in_person_take`, `in_person_finalize` and others | A code shown on one screen and scanned by the other | RFC 0003 9 |

A direct send pins the listener's seal key under its origin on the first exchange that
succeeds. A later send to that origin that cannot go native fails; it never falls back to the
legacy dialect by itself.

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
to `MAX_APP_PAYLOAD_LEN` (64 KiB).

## Public API

| Item | Purpose |
|---|---|
| `ContactBook`, `WalletContacts`, `install` | The engine, borrowed from a wallet |
| `ContactRelays`, `RelayMode`, `meeting_relays`, `meeting_host` | The relays it reaches |
| `ContactView`, `PendingPairingView`, `PairingStatus`, `EndedPairing` | What is stored, for the host |
| `InviteRequest`, `InviteOffer`, `InvitePreview`, `AcceptRequest`, `AcceptOutcome`, `CardRequest`, `CardOffer`, `SasDecision` | Pairing |
| `SealedSlate`, `SealedPayment`, `SealedReceived`, `SealedAnswer`, `payment_file`, `is_epictx` | Sealed slates |
| `ContactInvoice`, `InvoiceDetails`, `OutboxView`, `OutboxReport` | Invoices and the outbox |
| `DirectHandler`, `DirectSent`, `Dialect`, `DirectError` | Native slates to a listener |
| `Epic1LinkRequest`, `Epic1PayRequest`, `Epic1Paid`, `Epic1Refusal` and the other `Epic1*` types | epic1 addresses |
| `InPersonCode`, `InPersonRead`, `InPersonPaid`, `InPersonRefusal` and the other `InPerson*` types | Slates in person |
| `DomainFile`, `DomainVerdict`, `verify` | Domain proofs |
| `ContactRoot`, `ContactKeys`, `contact_root`, `pairing_mailbox_keys` | Contact keys |
| `ContactError` | Every failure |

## Related

- [Pairing](../../docs/protocols/pairing.md), [EPICTX](../../docs/protocols/epictx.md),
  [epic1](../../docs/protocols/epic1.md), [Epicbox](../../docs/protocols/epicbox.md)
- [RFC 0002 contact pairing](../../docs/rfcs/0002-contact-pairing.md),
  [RFC 0003 EPICTX native slates](../../docs/rfcs/0003-epictx-native-slates.md)
- ADRs: [0039 the host applies a relay move](../../docs/adr/0039-the-host-applies-a-relay-move.md),
  [0040 contact check and own relay move](../../docs/adr/0040-contact-check-and-own-relay-move.md),
  [0042 draining the old home](../../docs/adr/0042-draining-the-old-home-after-moving-ones-own.md),
  [0043 domain proof](../../docs/adr/0043-domain-proof-for-paired-contacts.md),
  [0047 the mailbox between paired contacts](../../docs/adr/0047-the-mailbox-is-the-default-between-paired-contacts.md),
  [0049 keeping messages](../../docs/adr/0049-keeping-messages-that-cannot-be-taken-yet.md),
  [0052 legacy at the edge](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)
- [`lepic-wallet`](../lepic-wallet/README.md), [`lepic-methods`](../lepic-methods/README.md),
  [`lepic-epicbox`](../lepic-epicbox/README.md), [`lepic-peer`](../lepic-peer/README.md)
