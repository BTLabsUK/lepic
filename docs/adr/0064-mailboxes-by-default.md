# ADR 0064: Mailboxes by default; the Epicbox switch governs only the classic address

Status: accepted; mailbox health, failover and the mailbox list, left open here, are decided in
[ADR 0065](0065-mail-goes-where-the-receiver-reads.md)
Date: 2026-11-18

Terms: this record uses the glossary of 2026-11-19 (ADR 0066): a mailbox is a server that runs
Epicmail, and a slot is the box of one key on a mailbox.

## Context

RFC 0002 8.7 gave contacts a third mailbox mode, Epicbox off, which behaved as Offline: no
mailbox connected, so pairing, contact invoices, linked devices, epic1 links and in-person codes
paused while the app's Epicbox switch was off. The contacts engine never reads the classic
Epicbox address; the payments listener does. The switch therefore stopped two unrelated things.

The owner's rule: everything LEPIC adds goes through mailboxes by default, with the mailboxes
managed for the user; the old Epicbox protocol is used only for old Epicbox addresses; the
default transport may change later.

## Decision

- Mailboxes are the transport of every contact, device, epic1, in-person and pairing call.
- The mailbox mode for these calls is `Online` or `Offline`. `Offline` connects to nothing. The
  Epicbox-off mode, its error kind (FFI code 57, now unused), the CLI flag `--epicbox-off` and
  the wallet API code `epicbox_off` are removed.
- The Epicbox switch in an app governs only the classic address: reading it and sending to
  classic addresses. Node only and the kill switch still stop all mailbox traffic, through
  `Offline`.
- The choice of transport for a feature sits in one place on each side: the mailbox mode the
  host passes to LEPIC, and in the app the single gate that derives it. A later change of
  transport changes those, not each feature.

## Consequences

- A wallet with the classic switch off still pairs, syncs linked devices and takes epic1
  payments and contact invoices.
- Nothing stored held the removed mode, so existing wallets open unchanged. A script or shell
  history line with `--epicbox-off` now gets a usage error.
- Mailbox health picking, reconnect and failover across mailboxes, and user control of the mailbox
  list are not part of this decision.
