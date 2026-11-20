# ADR 0067: One notice path

Status: accepted
Date: 2026-11-19

## Context

A notice is a short sealed message about a payment or a pairing: `posted`, `cancelled`,
`declined`, `withdrawn`, the pairing status kinds and `unpaired`. Before this record each family
had its own enum, its own parser, its own send function and its own intake. Contact notices,
epic1 notices to an address key, refusals to a reply key, pairing status and the host's app
payloads each took a different path. Some intakes changed the engine: a `declined` cancelled the
send, and a `withdrawn` could touch a paid invoice. A review of the branch before release listed
the duplicates and the places where a notice moved coins.

The owner's rules for the change:

- One generic way to send and to take sealed notices.
- No notice affects the engine. None changes a transaction's state, moves coins or changes a
  balance.
- Linked devices are an app feature.
- Minimal, no duplicates. What is replaced is deleted. No new limits or policy.
- The wire stays byte for byte as it is.
- Unknown kinds are ignored.

## Decision

### 1. One kind set and one codec

`lepic_wallet::notice::Notice` holds every kind. One writer pads a notice to a given length. One
parser reads every kind. The JSON is `{"lepic":1,"type":…}`, unchanged. A kind or version the
parser does not know reads as unknown and is dropped.

The host's kind, `app`, is in the same enum as `Notice::App { id, body }`. It has no JSON form.
It goes on the wire as the app payload message type of a pairing, with its id as the reference,
as it always has. LEPIC does not read the body.

### 2. One send path

`notice_out::send_notice` seals a notice for where it goes and stores it as an outbox row marked
as a notice. The outbox posts it with the back-off of any row. A notice row has no slate stage
and no delivery state. It raises no delivery event, and no outbox report counts it.

It goes to one of three places:

- a paired contact, to its mailbox, padded and signed to its card;
- the payee of an epic1 payment, at the delivery mailbox the payment went to, sealed to the seal
  key of the address it paid;
- the payer of a payment, at the reply slot the payment named, on the mailbox the payment was read from, sealed to its reply key.
  ADR 0065 §3: the 2 healthiest other mailboxes of the list get the same copy.

An `app` notice goes only to a pairing.

### 3. One intake

Every notice is taken by `Wallet::take_notice(notice, from)`. `from` is the envelope and the key
that opened it. `accepts` holds the table below in one place. A kind its source may not send is
refused and changes nothing.

| Kind | Anonymous | Pairing | Private pairing | Core does |
|---|---|---|---|---|
| posted, cancelled | address key | yes | no | mark "reports", event |
| declined | reply key | yes | no | mark, event; no cancel |
| withdrawn | no | yes | no | mark on the invoice, event |
| pair-*, unpaired | no | yes | unpaired only | contact status |
| app | no | yes | yes | keep for the host, event |

"Anonymous" means a notice sealed to a key, with no pairing behind it. "Address key" is the
epic1 address key that took the payment. "Reply key" is the key the send named for its answer.

### 4. No notice but `declined` affects the engine

A notice stores a mark and raises an event. It never cancels, confirms or finalizes a
transaction and never moves coins.

- A `declined` records `receiver_declined_at` and raises `PaymentDeclined`. The host cancels the
  send if it wants to.
- Note, 2026-11-19: the sentence above is out of date. A send the receiver declines never
  happened: the payer erases it and frees its inputs, `PaymentDeclined` carries the id of a send
  that no longer exists, and `GET /payments/{id}` answers 404 `payment_declined`. There is
  nothing for the host to cancel. A synchronous refusal from an HTTP or Tor endpoint stays
  `Undelivered`. A mailbox's report that it cancelled a copy (`RelayCancelApplied`) changes
  nothing in the wallet either. Tests named below as "its host cancels it" follow the new rule.
- A `withdrawn` for an invoice already paid is recorded and raised. The payment stays. The host
  decides what to tell the user.
- `posted` and `cancelled` are reports. They show in the transaction's details and raise their
  events. The chain decides the state.

### 5. `posted` is sent once, at the first post

The `posted` notice is queued when a transaction moves from finalized to posted, once. A wallet
that stops between the post and the queuing sends none. A transaction confirmed by a scan with no
post here sends none. The counterparty then learns of it from the chain.

### 6. `app` is the host's kind

The host's app payloads are `app` notices. The host API (post, list, acknowledge) and its events
behave as before. The core keeps each payload under its id, one copy per id, until the host
acknowledges it. The caps, parking on the mailbox and `ContactPayloadsParked` are unchanged.

## Compatibility

The wire is unchanged, so older and newer builds read each other's notices.

| Case | What happens | Test |
|---|---|---|
| A notice of a kind or version this build does not know | Read as unknown and dropped. From a pairing it is kept in quarantine only when the host keeps one. | `notice::tests::unknown_versions_and_types_are_unknown`, `contact_invoices::quarantine::an_unknown_notice_is_kept_and_a_failed_retry_counts` |
| A field a kind does not use | Ignored. | `notice::tests::fields_a_kind_does_not_use_are_ignored` |
| An outbox row of an older build: a notice stored with a stage, or an app payload stored as an S1 row | V22 marks the notice rows. App payload rows stay stage rows and are posted as before. | `sqlite::tests::old_notice_rows_are_marked_as_notices_and_still_load` |
| A notice about a slate this wallet does not hold | Dropped, or kept in the early-notice buffer when the host sets both caps. The buffer is bounded by count and age. | `epic1::a_notice_of_a_payment_never_taken_is_dropped`, `early_notice::tests::at_the_count_cap_the_oldest_goes` |
| A notice row that cannot be posted | The outbox retries it, then ends it a day after it was stored. | `delivery::outbox::tests::a_row_ends_a_day_after_it_was_stored` |
| A `declined` or `posted` that never comes | Nothing waits on it. A send ends by its TTL or the never-finished bound. A posted report shows for one hour. | no test of its own |
| A `declined` for a send of this build | Recorded and raised. The host cancels the send. An older build still cancels on its own. | `epic1::a_payer_whose_payment_the_payee_refuses_is_told_and_its_host_cancels_it` |

## Consequences

- The separate enums, parsers, send functions and intakes are gone. `Notice` is no longer `Copy`.
- A host must cancel a send on `PaymentDeclined` itself and decide what a withdrawn paid invoice
  means.
- A notice no longer sets a transaction's transport.
- A contact notice for a record with no mailbox is not queued. Before, it failed with
  `UnknownContact`.
- App payloads no longer raise delivery events, no outbox report counts them, and the
  contact's outbox list (`contact_outbox`) no longer shows them.
- V22 is forward only. An older build refuses a store it has upgraded with `SchemaTooNew`.

## Related

- [ADR 0016](0016-epicbox-notices.md): the notices over a mailbox. The forwarding of unmatched
  notices is gone.
- [ADR 0045](0045-refusing-slates-nobody-asked-for.md): refusals. `declined` is now status only.
- [ADR 0049](0049-keeping-messages-that-cannot-be-taken-yet.md): the early-notice buffer and
  the quarantine.
- [ADR 0063](0063-the-epic1-address-carries-its-own-mailbox.md) §9: the declined notice of an
  epic1 refusal.
