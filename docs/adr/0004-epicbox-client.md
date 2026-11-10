# ADR 0004: Async Epicbox client with listen and drain modes, acknowledge after store

Status: accepted

## Context

The `epic-wallet` Epicbox client is synchronous and built around a long-running listen loop,
which suits a desktop process. A phone suspends apps in the background, so a mobile wallet needs
a client it can start, stop and resume at any point, and that can catch up in one short session.

Relays store messages until the recipient acknowledges them, redeliver on reconnect, and deliver
oldest first per address. A message can arrive more than once and out of order relative to other
transactions. Protocol facts are in `../compat/epicbox.md`.

## Decision

- The client is async, on Tokio and `tokio-tungstenite` with rustls (ADR 0006). One task owns a
  connection. It answers every relay challenge with a fresh `Subscribe`, sends one request at a
  time, and sends websocket pings to keep the connection below the relay's idle timeout.
- Two modes. `listen` holds the connection and reconnects with capped exponential backoff and
  jitter (`Backoff`: the delay doubles from an initial value to a maximum, and each wait is drawn
  between half the ceiling and the ceiling). `drain` connects, subscribes, processes what is
  pending, and disconnects. Mobile background work uses `drain`.
- Protocol 3.0.0 is the baseline and works with the public relay. Extensions of later protocol
  versions are used only after the relay reports a version that supports them.
- Inbound processing is idempotent on the relay message id and on `(slate_id, stage)`. A
  redelivered S1 is answered with the S2 stored the first time.
- A message is acknowledged (`Made`) once its effect is stored, or once it is rejected for good
  (undecodable, bad signature, not addressed to the wallet) and the rejection is recorded. A
  transient failure sends no `Made`, so the relay redelivers. A held message holds back those
  behind it, and the relay discards the queue of an address when one message stays
  unacknowledged for long, so holds are bounded by an attempt count and a patience interval
  (`lepic-wallet/src/inbox.rs`). Past the bound the message is settled with an event.
- Unknown message types and non-JSON keepalive frames are logged at `debug` and ignored.
- Outbound: the signed string is the string sent. The client waits for the relay's answer, and a
  resend is safe because receivers deduplicate.
- The payments address is the address key at index 0 of the account, as `epic-wallet` uses.
- The payments address also finalizes an I2 that answers an invoice the wallet issued, and
  recognises an I1 that a peer returns unchanged because it does not pay invoices.
- A client can carry a `Prefilter` for an address that accepts only known senders. It runs before
  the signature check, key agreement and decryption; a message from a sender it refuses is
  acknowledged and dropped without any store write. The shared invoice address that used it
  (address key index 1 and up) is retired: nothing derives or listens on it, and its indexes stay
  reserved (ADR 0033). Invoices arrive from paired contacts (RFC 0002).
- `set_servers` on an open wallet moves it to another node and relay without locking it. The
  binding registers the Epicbox transport behind a slot it can replace, so the engine's method
  registry is unchanged. A switch waits until running calls end and holds new ones until it is
  done. A running listener is asked to finish with `ListenHandle::finish`: the message in hand is
  settled and acknowledged, one waiting for a retry stays on the relay, and after 30 seconds the
  message in hand is abandoned to the old relay. The listener then subscribes on the new relay
  as `<key>@<new relay>`, and its event stream continues. A listener is not rerouted inside its
  subscription, as a route change of the same relay is (ADR 0021): the relay endpoint and the
  identity's domain are fixed per client. Messages sent to the old address stay on the old relay
  until the wallet returns to it.

## Consequences

- Tests use a mock relay with the relay's semantics (`lepic-epicbox`, feature `mock-relay`), and
  the interop run uses the public relay software in a container.
- A wallet seed used by two clients at once competes for one relay subscription. The app warns.
- Settling a message after storing it means a crash between receipt and storage loses nothing.

## Related

- ADR 0005: storage and the parked-invoice caps.
- ADR 0033: reserved key paths.
- [RFC 0002](../rfcs/0002-contact-pairing.md): contact pairing and invoices.
- ADR 0021: route changes of a relay.
