# 0004 Async Epicbox client with listen and drain modes, acknowledge after store

Status: accepted
Date: 2026-10-02

## Context

The `epic-wallet` Epicbox client is synchronous and built around a long-running listen loop, which
suits a desktop process. A phone suspends apps in the background, so a mobile wallet needs a client it
can start, stop and resume at any point, and that can catch up in one short session.

Relays store messages until the recipient acknowledges them, redeliver on reconnect, and deliver
oldest first per address. A message can therefore arrive more than once and out of order relative to
other transactions. Protocol facts are in `docs/compat/epicbox.md`.

## Decision

- Async client on Tokio and `tokio-tungstenite` with rustls (ADR 0006). One connection manager per
  wallet, owned by an explicit handle with `stop()`. Cancellation is a token checked at every await.
- Two modes. `listen` holds the connection, keeps it alive below the relay's idle timeout with
  websocket pings, and reconnects with capped exponential backoff and jitter. `drain` connects,
  subscribes, processes everything pending, and disconnects. Mobile background work uses `drain`.
- Protocol 3.0.0 is the baseline and works with the public relay. Extensions of later protocol
  versions are enabled only after the relay reports a version that supports them.
- Inbound processing is idempotent on the relay message id and on `(slate_id, stage)`.
- Acknowledgement: send `Made` only after the inbound slate's effect is committed to storage, or
  after it was rejected permanently (undecodable, bad signature, not addressed to us) and the
  rejection is recorded. A transient failure sends no `Made`, so the relay redelivers. Processing of
  one message never affects the handling of the next.
- Unknown message types and non-JSON keepalive frames are logged at `debug` and ignored.
- Outbound: sign exactly the string sent, wait for the relay's answer, and treat a resend as safe
  because receivers deduplicate.
- Address index 0 by default, because `epic-wallet` always uses index 0.

## Consequences

- The client needs a mock relay that implements the relay semantics, for deterministic tests (task
  E-02), and an interop run against the public relay software in a container (task V-02).
- A wallet seed used by two clients at once competes for one relay subscription. The app warns.

## Alternatives considered

- Wrap the existing client. Its loop-based design does not fit start, stop and drain on mobile.
- Acknowledge on receipt. Simpler, but a crash between receipt and storage would lose the slate.

## Amendment 2026-10-05: an invoice address beside index 0

A later change adds a second identity: the invoice address, the address key at index 1 or higher derived
as index 0 is, so a seed restores it. The relay serves a socket as the address it last subscribed
with (`docs/compat/epicbox.md`), so the invoice address runs on its own connection, and the host
drains it on demand; nothing listens on it in the background. Its client carries a prefilter: a
message whose sender key is not on the wallet's allowlist is acknowledged and dropped before the
signature check, key agreement, decryption or any store write. An allowed sender's I1 is parked in
the store before `Made`, within caps on parked invoices in total and per sender; one over a cap is
acknowledged and dropped. Index 0 is unchanged, except that it now also finalizes an I2 answering an
invoice the wallet issued, and recognises an I1 sent back unchanged by a peer that does not pay
invoices. After a restore the invoice address starts at index 1; the host may set the index it kept.
