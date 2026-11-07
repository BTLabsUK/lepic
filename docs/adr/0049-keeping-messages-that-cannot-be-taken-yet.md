# 0049 Keeping messages that cannot be taken yet

Status: accepted
Date: 2026-11-06

## Context

A contact message that opens under the contact's key can still be one this version cannot take,
and a notice can reach a wallet before the slate it is about. An app may want both kept locally.
The mechanism belongs in LEPIC and every number and every policy in the app (ADR 0036).

## Decision

- Both are stored as rows of the existing `settings` table, written in one store transaction with
  the change they go with. There is no schema version, no migration and no change to the
  `Repositories` trait, and a build without this code ignores the rows. The prefixes are
  `contact.quarantine.` and `notice.early.`.
- Nothing here changes the wire, and nothing depends on the other side being new.
- `quarantine_max_bytes` on `WalletPolicy` and `HostPolicy` turns the local quarantine on: the
  wallet-wide total of stored envelope bytes, up to 64 MiB. `None`, the default, keeps nothing
  and leaves everything as it was, including how long hold counts are kept.
- A message is quarantined when it opened under the contact's key and would otherwise be dropped:
  at the hold bound, a slate that does not decode, a notice kind not known, an open receipt cap,
  or a receive refused. The entry and the end of its hold are one transaction, the relay is
  acknowledged after that, and the message is remembered as seen.
- At the cap the oldest entry of that contact goes first, then the wallet's oldest. An envelope
  larger than the cap is not kept; it is logged and counted in `quarantine_dropped`.
- While the quarantine is on, hold counts are kept past relay retention, so a message the relay
  delivers late still reaches the bound.
- The host lists, retries and discards entries. A retry passes the seen-before check; an entry that
  is handled goes, any other stays with one more attempt. LEPIC never retries on its own. Removing
  a contact removes its entries. A listing never carries the envelope.
- `early_notice_max_count` and `early_notice_max_age_s` turn the early-notice buffer on. It is off
  unless both are set, and one alone fails with `InvalidArgument`. The count runs to 10,000 and
  the age to 30 days.
- A `declined`, `withdrawn` or `cancelled` for a slate this wallet does not hold is kept under the
  slate and its sender, with the sender recorded. `Event::NoticeUnmatched` and the forward to
  linked devices stay as they are. A repeat keeps its first time.
- When the slate arrives, an S1 received or an I1 parked, its entries leave the buffer and apply
  in one transaction, under the same check as a notice just received: only the slate's recorded
  counterparty has an effect. An S1 answers after this, so a payment its sender cancelled is not
  answered, also when the S1 is delivered again.
- An entry past the age cap goes at the next write or apply. At the count cap the oldest entry
  goes, so older entries never stop newer ones.

## Consequences

- `lepic-wallet`'s `InboxSummary`, the contact `CollectReport` and the FFI reports gain counts, so
  a kept message or notice is not reported as dropped.
- `lepic-cli` only reads: `lepic contact quarantine` lists entries, and the reports print the
  counts. It sets no cap and retries nothing.
- Messages with no contact key behind them are not quarantined, on the contact or the pairing
  mailbox: there is nothing to attribute them to.
- Deliberate policy drops are not quarantined: an ended pairing, invoices not allowed,
  `refuse_unsolicited_*`. The wallet decided those, and a retry would decide the same.
- `posted` is not buffered: it only concerns a slate this wallet answered.

## Alternatives considered

- New tables: a migration for data that is a bounded local cache, and an update path to carry.
- Sending the message back to the relay, or asking the sender again: a wire change that needs the
  other side to be new.
- Retrying on a timer in LEPIC: when to retry is the app's call.
