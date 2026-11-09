# ADR 0049: Keeping messages that cannot be taken yet

Status: accepted

## Context

A contact message can open under the contact's key and still be one this version cannot take: the
slate does not decode, the notice kind is unknown, or the message has reached a bound. A notice
can also reach a wallet before the slate it is about. A host may want both kept locally, so that
nothing a contact sent is lost and a later version or a user decision can still act on it.

The mechanism belongs in LEPIC. Every number and every policy belongs to the host (ADR 0036).

## Decision

### Storage

Both stores are rows of the `settings` table, written in one store transaction with the change
they go with. They need no schema version, no migration and no change to the `Repositories` trait.
The prefixes are `contact.quarantine.entry.`, `contact.quarantine.body.` and `notice.early.`.
Nothing here changes the wire.

### The quarantine

`quarantine_max_bytes` on `WalletPolicy` and `HostPolicy` turns the quarantine on. It is the
wallet-wide total of stored envelope bytes, at most 64 MiB (`WalletPolicy::MAX_QUARANTINE_BYTES`).
`None`, the default, keeps nothing.

A message is quarantined when it opened under the contact's key and would otherwise be dropped.
`QuarantineReason` names the cases:

| Reason | Case |
|---|---|
| `hold_bound` | The message reached the hold bound |
| `undecodable_slate` | The slate does not decode |
| `unknown_notice` | The notice kind is not known |
| `receipt_cap` | The receipt cap is open |
| `receive_refused` | The wallet's receive refused the slate |

The entry and the end of the message's hold are one transaction. The relay is acknowledged after
that, and the message is remembered as seen.

Over the cap, the contact's own oldest entry goes first, then the wallet's oldest, so a contact
that fills the quarantine loses its own entries first. An envelope larger than the cap is not
kept. It is logged and counted in `quarantine_dropped` of the collect report.

While the quarantine is on, hold counts are kept for 14 days. That is past the time a relay keeps
a message, so a message the relay delivers late still reaches the hold bound.

### Retry and discard

The host lists, retries and discards entries (`contact_quarantine`, `contact_quarantine_retry`,
`contact_quarantine_discard`). A listing never carries the envelope.

A retry runs the normal handling on one entry or on all, oldest first. An entry that is handled
leaves the quarantine. Any other stays with one more attempt counted. LEPIC never retries on its
own. Removing a contact removes its entries.

### Early notices

`early_notice_max_count` and `early_notice_max_age_s` on `HostPolicy` (`early_notice_max_count` and
`early_notice_max_age` on `WalletPolicy`) turn the early-notice buffer on. It is off unless both
are set. Setting one alone fails with `InvalidArgument`. The count is at most 10,000 and the age at
most 30 days.

A `declined`, `withdrawn` or `cancelled` notice for a slate this wallet does not hold is kept
under the slate and its sender, with the sender recorded. A repeat keeps its first time.
`Event::NoticeUnmatched` is raised all the same, for the host to forward to its other installs.

When the slate arrives, an S1 received or an I1 parked, its entries leave the buffer and apply in
one transaction under the rules of a notice just received: only the slate's recorded counterparty
has an effect. An S1 is answered after this, so a payment its sender cancelled is not answered,
also when the S1 is delivered again.

An entry past the age cap goes at the next write or apply. At the count cap the oldest entry goes,
so older entries never stop newer ones.

### What is not kept

- Messages with no contact key behind them, on the contact or the pairing mailbox. There is nothing
  to attribute them to.
- Deliberate policy drops: an ended pairing, invoices not allowed, and the refusals of ADR 0045.
  The wallet decided those, and a retry would decide the same.
- `posted`, which only concerns a slate this wallet answered.

## Consequences

- `InboxSummary`, the contact `CollectReport` and the binding's reports carry counts, so a kept
  message or notice is not reported as dropped.
- `lepic contact quarantine` lists entries. The CLI sets no cap and retries nothing.
- A build without this code ignores the rows.
- Nothing depends on the other side being a newer version.

## Alternatives considered

- New tables: a migration for data that is a bounded local cache, and an update path to carry.
- Sending the message back to the relay, or asking the sender again: a wire change that needs the
  other side to be new.
- Retrying on a timer in LEPIC: when to retry is the host's decision.

## Related

- ADR 0036: policy values are host parameters.
- ADR 0045: refusing slates nobody asked for.
