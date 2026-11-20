# ADR 0060: Epicbox 3.1.0 transaction cancel and the txcancel/1 mux extension

Status: accepted; the local-only `POST /payments/{id}/cancel` is superseded by
[ADR 0062](0062-the-address-decides-the-protocol.md)
Date: 2026-11-15

## Context

Until now a cancelled payment was cancelled on one side only. The other wallet kept a payment it
could still answer, and a receiver's reply could cross a sender's cancel. Epicbox protocol 3.1.0
gives each posted slate a transaction id and lets either party tell the mailbox to cancel it; the
mailbox then reports the cancel to the other party. The reference is the `ebox-cancel-txs` branch of
`who-biz/epic-wallet` (`d03b43d7`) and the public `epicboxnodejs` `cancel-tx` branch (`774855d`).

## Decision

Protocol, in `lepic-epicbox` (details in [compat/epicbox.md](../compat/epicbox.md)):

- The client reads the mailbox version from `GetVersion` and subscribes with `ver` 3.1.0 when the
  mailbox reports 3.1.0 or a later 3.x. Any other answer keeps exact 3.0.0 behaviour.
- On 3.1.0 a `PostSlate` carries `epicboxtxid` (a UUIDv4 in simple form, not the slate id) and
  `epicboxtxidsig`, a signature over the txid by the `from` key.
- `CancelTx` goes over a mux/1 session on the same mailbox whose socket negotiated `txcancel/1`
  (below). Without one (no session, the mailbox does not offer `txcancel/1`, or the socket is down)
  it goes over a short classic connection. The answers are `TransactionCancelled`, a plain `Ok`
  (the mailbox does not say whether the txid is unknown or the address is not a party), or an
  `Error`. An `Error` over mux is returned as is, with no second try on a classic connection.
- A `TransactionCancelled` pushed to a listener or drain is surfaced to the wallet. The mailbox takes
  the next `Subscribe` as the acknowledgement, so LEPIC sends it only after the wallet applied the
  cancel. An unapplied cancel is delivered again.
- `cancelrequestid` passes between mailboxes. LEPIC never sends it and accepts it.
- The cancel connection ignores `Slate` frames, so it never finalizes and posts a reply that was
  queued for the wallet. Biz's wallet does finalize one.
- mux/1 gets an optional extension, `txcancel/1`, with `CancelTx`, `TransactionCancelled`, a pushed
  `Cancelled` and `CancelAck` ([mux/1](../protocols/epicbox-mux.md)). A mailbox that offers it
  repeats it in its `Ok`; without it LEPIC sends none of these frames. A mux post to a cancelled
  transaction is answered `post_refused`. This is a deliberate choice: a cancelled transaction is
  not delivered later.

Wallet, in `lepic-wallet`:

- The sender makes one mailbox txid per send or invoice and keeps it in settings
  (`epicbox.txid.<slate_id>`, and the reverse `epicbox.txid_slate.<txid>`). It is written before
  the post, so a retry posts under the same id. No SQL migration.
- The receiver keeps the txid of the frame it took and replies under it.
- `Wallet::relay_cancel` asks the mailbox. `Wallet::apply_relay_cancellation` applies an incoming
  cancel: a local cancel without a notice, and a mark per party. A receiver or payer gets
  `sender_cancelled_at`, a sender gets the send-declined notice, an invoicer gets declined. The
  event fires on the first mark only. It never finalizes. A transaction already in the pool or on
  chain is kept.

Surfaces:

- FFI: `relay_cancel_transaction(tx_id)`, `TransactionDetails.relay_cancellable`, error kind
  `CancelledOnRelay` (code 115).
- CLI: `lepic tx cancel TX_ID [--local-only]` asks the mailbox first when the transaction is
  mailbox-cancellable, then always runs the local cancel. JSON `relay` is `cancelled`,
  `not_found_or_not_participant`, `no_relay_id`, `unsupported` or `failed` (with `relay_error`).
  A send the mailbox refuses as cancelled exits 7 and has serve error code `cancelled_on_relay`.
- `POST /payments/{id}/cancel` in `lepic serve` stays local-only.

App policy, outside LEPIC: the app offers spend-back only where a transaction exists that can land
without this wallet doing more, such as an invoice this wallet paid, or a send it finalized that
the network refused.

## Consequences

- An unopened payment is withdrawn at the mailbox, and the other wallet shows it cancelled.
- A receiver who cancels cannot stop a sender who has already finalized: a transaction in the pool
  or on chain stays.
- Limits:
  - Backups do not carry the txid settings.
  - A send made while the mailbox spoke 3.0.0 has no txid (`no_relay_id`).
  - A requeued twin copy carries no txid, because it cannot be signed again.
  - The mailbox's plain `Ok` does not tell not found from not a participant.
- Against a 3.0.0 mailbox nothing changes on the wire.

## Alternatives considered

- Follow the reference wallet and finalize a queued reply when cancelling: the cancelling wallet
  would post a transaction it is trying to stop.
- Cancel over the mux session only: a mailbox without `txcancel/1`, and a wallet with no session
  (the CLI listens on classic sockets), would have no cancel, so the short classic connection stays
  as the fallback.
- Cancel over a short classic connection only: a wallet that listens over mux would open a second
  socket per cancel, and a mailbox that speaks mux/1 with `txcancel/1` need not keep the classic
  3.1.0 path.
- Allow a mux post to a cancelled transaction: the other party has already been told it is
  cancelled, so a late delivery would contradict that.
- Put the txid in the slate or in a SQL column: the slate is a wire format shared with other
  wallets, and a column needs a migration for a value only the mailbox uses.

## Related

- ADR 0058: serve for service wallets (boost).
- [compat/epicbox.md](../compat/epicbox.md), [protocols/epicbox-mux.md](../protocols/epicbox-mux.md).
