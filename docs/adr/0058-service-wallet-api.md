# ADR 0058: Serve for service wallets: boost, webhooks, and payment fields

Status: proposed
Date: 2026-11-13

## Context

Services that take Epic through the BT Labs payment card run `lepic serve` and match each payment
to an order. Running them showed these gaps:

- Pairing and replies wait for serve's collect tick, which is once a minute.
- A service must hold an SSE stream open to hear about payments. Most service stacks expect a
  webhook.
- `POST /payments` refuses `to: "epic:..."`, while `POST /open` says an `epic:` link is paid with
  `POST /payments`.
- An incoming epic1 payment does not say which link it paid.
- `ttl_blocks` on an invoice does nothing in serve.
- The message of a contact invoice shows on neither side's payment.
- A service cannot be told when a payment reaches the confirmations it waits for.
- `POST /inspect` does not read the amount and message of an `epic:` URI.

The rule for all of it: least code, reuse the event log, SSE, settings and parsers, and follow the
API's conventions (snake_case, problems with codes, `{items, next_cursor}`).

## Decision

### 1. Boost: poll faster for a while

One primitive in `lepic-wallet` (`boost.rs`), held by the `Wallet`, where serve, the contacts crate
and the FFI can all call it. Today only serve's handlers call it; the app and the FFI move onto it
later (job `boost-unify`).

```rust
pub enum Poller { Relays, Node }

pub struct Window { pub poller: Poller, pub until: Timestamp, pub interval: Duration }

impl Wallet {
    /// Polls `poller` every `interval` for `duration` from now, merged with the boost it has,
    /// and returns the window that took effect.
    pub fn boost(&self, poller: Poller, duration: Duration, interval: Duration) -> Window;
    /// The wallet's boosts, for the loops that poll.
    pub fn boosts(&self) -> &Boosts;
}

impl Boosts {
    /// How long `poller` sleeps from now: the boost's interval while one runs, else `base`.
    pub fn interval(&self, poller: Poller, base: Duration) -> Duration;
    /// The boost `poller` has now, if any.
    pub fn window(&self, poller: Poller) -> Option<Window>;
    /// Changes each time a boost starts or changes, so a loop asleep on the old interval wakes.
    pub fn changed(&self) -> watch::Receiver<u64>;
}
```

- **Pollers.** `Relays` is the collect cycle: every contact mailbox, pairing mailbox and live
  epic1 link mailbox, on the relays the wallet already uses. `Node` is the wallet refresh. These
  are the two loops that exist. A boost starts no new loop: the host's loop asks
  `boosts().interval` before each sleep and wakes on `boosts().changed()`.
- **Merge.** One boost per poller at most. A call that overlaps a running boost keeps the later
  end and the shorter interval. When the window ends the poller goes back to its base interval.
- **Limits, set by LEPIC.** The interval is at least 5 s, the duration at most 10 minutes. A
  value outside is clamped, never refused, and the call returns the window that took effect.
  Because boosts merge per poller, at most two run at once: that is the cap on concurrent
  boosts. A caller that boosts again and again keeps one poller at one cycle every 5 s, the rate
  the app already uses while it waits for a pairing.
- **Base intervals.** Serve's base collect interval goes from 60 s to 30 s. The refresh stays at
  60 s, about one block.
- **Serve's own callers.** These boost `Relays` for 2 minutes at 5 s, after they succeed:
  `POST /payments` (sends and invoices, epic1 pays), `POST /contacts` (an invite),
  `POST /pair-requests/{id}/accept`, and `POST /links`.
- **API.** `POST /sync/boost`, role `receive` like `POST /sync`:

  ```json
  {"poller": "relays", "duration_seconds": 120, "interval_seconds": 5}
  ```

  answers 200 with the window that took effect:

  ```json
  {"poller": "relays", "until": "2026-11-13T15:02:00Z", "interval_seconds": 5}
  ```

  A missing or unknown `poller` is 400 `invalid_field`. `GET /status` shows a running boost as
  `boost` inside `collect` (relays) or `refresh` (node).

### 2. Webhooks: one endpoint, fed from the event log

A webhook is the event log delivered by HTTP POST. It reuses the log's ids, types, filters and
retention, so the webhook, `GET /events` and SSE carry the same events.

- **Config.** Settings keys, like every other serve setting:
  - `webhook_url`: the endpoint. `https://` only.
  - `webhook_secret_file`: a file readable by its owner only, one `whsec_<base64>` secret per
    line (Standard Webhooks). Serve reads it before each delivery, so a new secret needs no
    restart.
  - `webhook_types`: the event types to send, as `GET /events` takes them (`payment.*`); all
    when unset.
  - `webhook_allow_private`: `true` lets the URL be `http://` and resolve to a loopback,
    private or link-local address, for a receiver on the same host or network. Off unless set.
- **Request.** `POST <webhook_url>`, `content-type: application/json`, one event per request.
  The body is the event as `GET /events` lists it: `{id, type, created_at, data}`.
  Headers follow Standard Webhooks:
  - `webhook-id`: the event id. A retry sends the same id, so the receiver can drop a
    duplicate.
  - `webhook-timestamp`: unix seconds of this attempt.
  - `webhook-signature`: `v1,<base64 HMAC-SHA256(secret, "{id}.{timestamp}.{body}")>`, one
    per line of the secret file, space-separated. To rotate: add the new secret as a second
    line, switch the receiver, then remove the old line.
- **Payload.** `data.object` keeps only what a service needs to match and settle: `id`,
  `kind`, `direction`, `state`, `state_reason`, `account`, `amount`, `fee`, `link_id`,
  `message`, `their_message`, `purpose`, `metadata`, `confirmations`, `confirmed_height`,
  `expires_at_height`, `created_at` and `updated_at`. Addresses, handoffs, answers and every
  other field stay out; read them with a `GET`. The other `data` fields (`from_state`,
  `to_state`, `reason`, `changed`, `count`) stay. No key, password, token or slate is in any
  event.
- **Answer.** Any 2xx within 10 s (5 s to connect) is delivered. Anything else is a failure:
  another status, a redirect (never followed), a timeout, a reset or a dropped connection. The
  body of the answer is not read.
- **Order and pace.** One request at a time, in event id order. An event is sent only after
  the one before it was delivered, so a failing event holds back the rest. Serve sends at most
  10 requests a second.
- **Retries.** At-least-once. After a failure the same event is tried again at 5 s, 5 min,
  30 min, 2 h, 5 h, 10 h and 10 h, each with ±20 % jitter. The cursor (the last delivered id),
  the attempt count and the next attempt time are in the wallet store, so a restart carries on
  with the same event and the same schedule. After the last attempt fails the webhook stops:
  its state is `disabled` and the events stay in the log.
- **Replay.** `POST /webhook/resume` with an optional `{"after": <event id>}` sets the cursor
  and starts sending again. Without `after` it carries on from the cursor. The log keeps events
  30 days; a cursor older than that gets an `events.skipped` event first, as `GET /events`
  sends.
- **Status.** `GET /webhook` answers the URL, types, `state` (`active`, `retrying`,
  `disabled`), the cursor, the attempt count, the next attempt time and the last error. 404
  `not_found` when no webhook is set. Both calls are role `full`.
- **SSRF.** The URL's host is resolved before each attempt. Serve connects only to an address
  that is public unicast: not loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7),
  link-local, CGNAT (100.64/10), benchmarking (198.18/15), NAT64 (64:ff9b::/32), multicast,
  unspecified, documentation or broadcast, and an IPv4-mapped IPv6 address is checked as IPv4. It connects to the address it checked, so a
  second resolution cannot point elsewhere. No proxy, no redirect. `webhook_allow_private`
  lifts the address check and allows `http://`.

### 3. `POST /payments` pays `epic:` text

This is a bug fix: the document lists `epic:` as a `to` form and `POST /open` points there.

- `epic:<epic1 link>` pays the link as `lepic epic1 pay` does. `amount` may be left out: the
  link's amount is used. When both are given they must match, else 400 `invalid_field`.
- `epic:<address>?amount=&message=` (FORMATS.md section 1) is split into the address, the
  amount and the message, then sent as for that address. A body `amount` that differs is 400
  `invalid_field`. A body `message` wins over the URI's.
- One small parser for the classic form, shared with `POST /inspect`.

### 4. An incoming epic1 payment names its link

- **Added.** One settings row per payment taken at a link: key `epic1.taken.<tx id>`, value
  `<account>.<screen|printed>.<n>`, about 30 bytes. It is written in the same store write that
  marks the link used. The contacts crate reads it with `epic1_taken_at(tx_id)`. No table, no column, no schema change, no migration. Payments taken
  before this change have no row and no `link_id`.
- **Shown.** `Payment.link_id` (already in the document) as `<account>.<kind>.<n>`, the id
  `GET /links` uses. So it is in `GET /payments`, in each payment event, and in the webhook.
- **Who sees it.** This wallet only. Nothing new travels to the payer, a relay or a contact:
  the wallet already knew which link mailbox the payment came from.
- **Concerns.** A link id is reused after the link is retired. A service matches by link id
  while the link is live and retires it once paid. A payment to a retired link is not taken,
  because a retired link's mailbox is not read.
- **Payer's message.** It travels in the slate as the sender's signed message, as for any
  send, and shows as `their_message`. Nothing new.
- **Paired invoices.** They match by payment id and slate id as before; nothing new.

### 5. Invoice `ttl_blocks`

A bug fix. Serve passes `ttl_blocks` to the invoice it issues, and `lepic invoice issue` and
`lepic contact invoice` take `--ttl-blocks`. The I1 carries the TTL. The refresh already
expires an issued invoice past its cutoff, and `expires_at_height` already shows it.

### 6. The invoice message on both sides

- **Where it is.** An epicbox or file invoice already carries its message in the I1, signed
  by the issuer. The issuer's payment shows it as `message` and the payer's as `their_message`.
- **The gap.** Serve sent a contact invoice's `message` as the sealed contact `reference`,
  which neither side's payment shows. Serve now puts it in the I1, as for the other invoices,
  through a new `--message` on `lepic contact invoice`. `--reference` stays for the CLI.
- **Where it shows.** `GET /payments`, events and webhooks (`message` and `their_message`),
  `lepic contact invoices` (the payer's waiting list, new `message` field), `lepic tx show` (the
  slate messages), and the FFI, whose transaction details already carry the
  verified slate messages (`TransactionDetails.messages`). The app shows whatever its history
  screen reads from there; the app is not changed.
- **Cost and privacy.** No new storage: the slate is stored already. The message now travels
  in the slate sealed to the contact, the same reader the reference had. A slate message is at
  most 256 bytes and signed.

### 7. Confirmations reached

- Setting `payment_confirmations`, default 6, from 1 to 1440.
- When the tip reaches a confirmed payment's `confirmed_height + payment_confirmations - 1`,
  serve logs `payment.confirmations_reached` with the payment snapshot. It goes to SSE,
  `GET /events` and the webhook like every event.
- Serve keeps the last tip it checked in one setting, so a restart sends the events for the
  blocks it missed and none twice. The first start after this change sends none for older
  payments.
- `confirmations` in `GET /payments` already counts from the tip at each read. The state
  `confirmed` does not change.

### 8. `POST /inspect` reads `epic:` URIs

A bug fix. For `epic:` text the summary gets `amount` and `message`: from the classic URI's
query, or from the epic1 link as `epic1 read` reads it.

## Considered and cut

- A live Epicbox subscription for pairing mailboxes. A connection holds one subscription, and
  RFC 0002 section 8.2 keeps one-off drains apart from the listener; the boost does the job
  with the loop that exists.
- A `servers` list on a boost. Each poller already reaches the servers that can answer: the
  cycle reads every relay its contacts and links use, the refresh asks the wallet's node. A
  narrower list would miss replies, and no caller has one.
- A cap on boosts apart from one per poller. Merging already bounds them.
- Several webhooks, an API to create them, and a CLI for them. One URL in the settings, with
  `GET /webhook` and `POST /webhook/resume` on the API, covers a service. More endpoints can
  come when someone needs them.
- Serve-generated secrets. The operator writes the secret file (`whsec_` and 32 random bytes in
  base64); rotation is two lines.
- Batching several events per request, and parallel deliveries. Both break the order a
  receiver can rely on.
- A dead-letter queue. The log is the queue: a disabled webhook resumes from its cursor.
- Full objects in webhooks. A payload that leaks addresses or handoffs to a receiver that
  logs requests is worse than one `GET`.
- A confirmation count per webhook. One setting serves SSE, the log and the webhook alike.

## Consequences

- A service sees a pairing or a reply within about 5 s of acting, and within 30 s otherwise.
  Relay load from an idle serve doubles: one cycle every 30 s instead of 60 s.
- A service needs no open stream: it sets `webhook_url` and a secret file.
- Webhook delivery is in order and holds back on a failing event; a receiver that answers
  2xx fast and works afterwards never blocks it.
- One settings row per payment taken at a link, and a few for the webhook and the tip; no
  schema change.
