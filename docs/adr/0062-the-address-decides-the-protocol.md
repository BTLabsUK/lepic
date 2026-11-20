# ADR 0062: The address decides the protocol, and native mail arrives by push

Status: accepted; §3 `epicbox` link entries, §4 link bounds and two tests superseded by
[ADR 0063](0063-the-epic1-address-carries-its-own-mailbox.md); in §3 the invoices and pair
requests to an epic1 address by ADR 0063 §8, and the separate native mailbox setting and the
refusal of epic1 on a mailbox without mux/1 by [ADR 0065](0065-mail-goes-where-the-receiver-reads.md)
§1 and §7; §5 "does not attach that slot again" by [ADR 0066](0066-one-address-per-account.md) §4;
in §6 the kept epic1 addresses and the migration in place by ADR 0063 and ADR 0066 §7; in §7 the
new `openapi.json` version by ADR 0066 §5
Date: 2026-11-17

Terms: this record uses the glossary of 2026-11-19 (ADR 0066): a mailbox is a server that runs
Epicmail, and a slot is the box of one key on a mailbox.

## Context

On main at `ce90ca04a` a LEPIC wallet mixes two protocols on one address. Every S1 to a classic
Epicbox address carries the LEPIC marker, and notices (ADR 0016), invoices, pair requests and, with
`native_direct`, sealed slates follow it onto the payments slot at key index 0. A URL or onion
send reads a `lepic` advert in the stock `check_version` answer and may switch to `lepic.v1`.

Native mail is read by several unrelated paths. Only contact and pairing slots are pushed
(`PushedMail`). epic1 link slots, epic1 reply slots and in-person slots are drained by
one-off 3.0.0 connections on every collect, 50 slots per connection, also on a mailbox that
offers mux/1 (`lepic-wallet-contacts/src/collect.rs`, `epic1.rs`, `in_person.rs`). A collect runs
every 30 s in `lepic serve` and every 45 to 300 s in the app. Each post opens its own connection.

Two service operators gave feedback on the service API on 2026-11-17. Their payouts go to classic
addresses. Their open pain is a payment that gets no answer, and both pin a LEPIC commit.

## Decision

### 1. Two rules

1. The address format decides the protocol. A classic Epicbox address, a URL or an onion means
   stock behaviour: plain V2 or V3 slates, no marker, no discovery, no LEPIC bytes. An epic1 or
   EPICTX address or link means native from the first byte.
2. Native traffic never uses the index-0 slot. It is not sent to the payments address and not
   read from it.

### 2. The legacy lane

- `lepic-methods` (epicbox, http, tor, file) with `lepic-legacy-slate`, `lepic-legacy-rpc` and
  `lepic-tor` is the legacy lane. The crate keeps its name (ADR 0051). It depends on no native
  crate; `cargo xtask deps-check` and a new `cargo xtask legacy-imports` scan of
  `lepic_wallet::inbox::legacy` enforce it.
- The legacy inbox decodes a slate, answers S1 with S2, completes S2 and posts. Anything else in
  the slot is acknowledged and dropped.
- The `lepic` advert leaves `check_version`. A URL or onion always means `/v2/foreign` with a
  plain slate. Stored pins for URL and onion origins are no longer consulted.
- No invoice and no pair request goes to a classic address over Epicbox. CLI and API refuse both
  with a clear error. Invoice files with a plain slate stay with the file method, unchanged.
- A wallet that refuses unasked payments (ADR 0045) stays silent on Epicbox, like a stock wallet
  that is offline. HTTP and Tor keep their failed request. epic1 and contacts keep the sealed
  "declined".
- Mailbox cancel (ADR 0060, 0061) stays on classic sends as transport behaviour. It also runs when
  the owner cancels through the API or the app, and when a refresh expires an unanswered send
  (`ttl_blocks`), on a mailbox that offers it. A recipient that was offline on such a mailbox then
  never receives the dead slate. A recipient that fetched the slate before the cancel, or whose
  mailbox does not offer the cancel, is not told. No time-based setting is added to the core.
- The classic address keeps its mux/1 push on a mailbox that offers it and falls back to a 3.0.0
  listener on a mailbox that does not.
- `lepic serve` always opens the classic listener. No `legacy_channel` switch is added.
- Listings and the twin-install requeue stay in the legacy lane, unchanged. Both use classic
  addresses and plain slates and work with stock senders. Both are deleted when the classic lane
  is retired.

### 3. The native lane

- Wire: Epicbox 3.0.0 with mux/1. No mailbox change and no new mailbox protocol.
- One delivery layer replaces the per-family drain and post code:
  - a watch set: one table of native slots (key reference, mailbox host, class, expiry);
  - a carrier interface, `watch(set)` and `post(envelope, route entry)`; the Epicbox carrier
    implements it with mux/1 sessions;
  - a router that calls the handler of a pushed mail's class and acknowledges after the result is
    stored;
  - one outbox for every post, with the states posted, uncertain and failed. The entry is stored
    before it is posted. A re-post sends the same slate under the same payment id and never after
    the payment's cutoff;
  - typed events for every native arrival, in the existing event log, SSE stream and webhook,
    with the same id rules.
> ADR 0065 §1 and §7: there is one mailbox list and no separate native mailbox setting. A mailbox
> without mux/1 stays in the list and is asked again later; no verdict is final.

- Native receiving requires mux/1 on the mailbox the wallet reads on. There is no polling path for
  native slots and no fallback. A wallet whose native mailbox does not offer mux/1 gives out its
  classic address only: creating an epic1 link and paying an epic1 link are refused with a clear
  error. Posting to another wallet's mailbox is a plain 3.0.0 post and needs no push there.
- Native traffic has its own default mailbox setting, separate from the classic address host. Both
  may name the same host. Only a mailbox that offers mux/1 is accepted for it. Whether a mailbox
  offers mux/1 is read from its greeting at connect. When a native mailbox stops offering mux/1,
  the wallet reports "epic1 is off on this mailbox" and the classic address keeps working.
- A link an earlier version made on a mailbox without mux/1 is not read. After the update the
  wallet lists such a link as "on a mailbox without push, print a new one". A payment sent to it
  gets no answer and ends at its cutoff.
- A previous home that is still drained (ADR 0042) is a watch set row that expires at the end of
  its drain. On a mailbox without mux/1 it is not read.
- Notices, invoices and pair requests to an epic1 address use the route the payment used: payer
  to payee through the link's slot, payee to payer through the reply slot. There is no
  separate inbox per address.
- Route entries are `(method id, value)` and carry the full host. epic1 links gain `http` and
  `tor` entries next to `epicbox`. A link carries at most 3 entries. The QR code carries the
  address, the first entry and the amount; the copied or shared link carries all entries. A
  sealed envelope from an `http` or `tor` entry goes to the native endpoint only, never to
  `/v2/foreign`. A local-network host from a link is refused unless it is on the wallet's own
  list. The mailbox pool, pool bits and shared mailbox list of ADR 0054 are dropped.
- Printed links with `epicbox=` stay valid on a mailbox that offers mux/1. The reader keeps reading
  `epicbox=` as the route entry of method `epicbox`. Link slot keys never change.
- When no answer comes, the host decides to send the same slate to the link's next route entry.
  The core moves on by itself only when the post itself failed. The core holds no timer for it.
- The plain fallback of ADR 0047 is removed. A contact's classic address is a second way to pay
  that the user picks by hand, and that payment is stock.
- Latency: a payment leg takes about 5 s, and at most 10 s at p99, while both wallets are open.
  The floonet suite asserts the time per leg.

### 4. Connections

- One mux/1 session per mailbox carries the classic address and every native slot the wallet
  reads there. The session service moves to `lepic-epicbox`, keyed by mailbox and group.
- With Tor on, the host keeps today's two groups (payments, contacts). Native slots join the
  contacts group. This is the existing `relay_sockets` behaviour, not a new setting.
- Posts to the wallet's own mailbox use the open session.
- The bounds stay: 256 slots per session, 50 on-screen and 32 printed links per account.

### 5. Two installs on one recovery phrase

> ADR 0066 §4: a replaced slot is attached again after a 10-minute hold-off. Two installs on one
> phrase without a link are unsupported (note of 2026-11-19 in ADR 0066 §4).

- For native mail either device receives. The mailbox gives a slot to one session, the newer one
  wins, and a session that was replaced does not attach that slot again.
- The other device sees the coins at its next chain refresh. Linked devices tell each other
  through the app's device link, which is app code and outside the core.

### 6. One release

> ADR 0063 and ADR 0066 §7: the epic1 address format changed, so every epic1 address and link
> changes; links and numbered addresses made by the 2026-11-17 pre-release build (schema 17), and their rows, are not migrated and no longer read.

- The change ships as one release with no intermediate steps. The marker codecs, the index-0 code
  for notices, invoices, pair requests and sealed slates, `--legacy`, the dialect functions,
  `native_direct`, `epicbox peer` and `peerCompat` are deleted in one step.
- An update keeps the classic address, epic1 addresses, link and contact slots, keys and
  stored ids. Stored data migrates in place. A settings file with retired keys loads without an
  error.
- Old LEPIC messages waiting on the index-0 slot are acknowledged and dropped. A send that was
  open at update time completes: a marked slate decodes as a plain slate.
- Accepted losses at update time: an Epicbox invoice or a pair request by address that was open
  expires on both sides; an epic1 payment whose answer waits on a mailbox without mux/1 is not
  completed and ends at its cutoff.
- Operators get a changelog of every API break and a commit to pin and test before the release.

### 7. Service API

> ADR 0066 §5: the API path and every version stay as they are; `openapi.json` gets no new
> version.

- The path stays `/api/v1`. The breaks are listed in `CHANGELOG.md` and `openapi.json` gets a new
  version.
- The body field `legacy` is removed. A request body that still carries it answers 400
  `invalid_body`.
- `GET /status` lists the Epicbox state per mailbox and is named in the API guide as the health
  check. The single `listeners.epicbox.state` stays as the summary.
- `GET /payments/{id}` finds a payment by id or alias without loading every transaction. Delivery
  state moves into tables with an index on both.
- `state_reason` gains values for an expiry: no answer before expiry, and not mined.
- A third expiry reason, `expired_rejected_by_node`: the wallet's own node's pool refused every
  push of a finalized send. Only the node's own pool refusal counts as refused; every other
  error (a proxy's 502 or 504, a timeout, an answer the wallet does not recognise) counts as
  unreachable and keeps the send open. The ended send keeps its kernel watch, so a transaction
  mined later still shows as confirmed. "Not mined" keeps only its existing case. An answered
  payment that the node accepted once never expires by itself.
- `GET /status` also carries the node tip as the last refresh saw it, with the time it last moved,
  open-payment counts per state, and the oldest payment awaiting an answer and the oldest
  finalized one. These fields only add data and never query the node.
- The outbox states map onto today's `delivery.state` values without changing them.
- `POST /payments/{id}/cancel` also asks the mailbox to cancel, on a mailbox that offers it.
- `POST /payments/{id}/deliver` can send the same slate to the next route entry of an epic1
  link, and an event is raised when a post fails or turns uncertain.
- Not added: the amount that waits for confirmation in the 422 answer. A service gates on
  `spendable` and the `account.balance_changed` webhook, and uses `change_outputs` to pay in
  parallel. A payment to several receivers in one transaction is not built.

### 8. Recover funds

- The core offers one last-resort action that gives the owner's coins back from any payment that
  holds them: a stuck send, a cancelled payment, or any other case. Stuck sends are handled
  first by the re-push to the node and the expiry above; recovery is for when the owner wants
  the coins back regardless.
- The sending wallet alone builds, finalizes and posts a transaction that spends all of the
  payment's inputs to one new output of its own, for one ordinary fee paid by the sender. Once
  it is mined, the old transaction is a double spend and can never be mined.
- If the old payment is mined first, the node refuses the recovery because its inputs are spent,
  and the payment counts as paid. If the recovery is mined first, the payment is cancelled.
  Either way the payee is paid at most once.
- An open payment is marked cancelled only after the recovery has a set number of
  confirmations. The core cannot recognise a resend under a new payment id; the API guide says
  to pay again only after the payment shows `recovered`. The recovery spends only that
  payment's inputs, never outputs locked by another open payment. A refusal for any reason other than spent inputs stops the recovery:
  the error is reported and the payment stays open.
- The core provides the action (recover a payment, in the API, the CLI and the FFI, with its
  state and events). When to call it is the host's or the service's policy; the core holds no
  threshold for it.
- The confirmation count is the account's spend confirmations; no new number is added.
  Note, 2026-11-19: a payment is confirmed at 1 confirmation, and `final` is a separate mark set
  at `final_confirmations` (default 6, 1 to 1440).
- The release of a send after 1,440 blocks without its kernel on chain is removed. Cancel on a
  posted send is refused with `use_recover`, and recover is the only way back for an
  answered send. A send released by an earlier version stays watched as before.

## Consequences

- A LEPIC user who hands out a classic address gets stock behaviour from every payer: no cancel,
  decline or posted notice, no invoice, no pair request. The app's Receive screen leads with the
  epic1 code and shows the classic address under it.
- Link, reply and in-person slots need new code to attach to a session. The five drain paths,
  the four posting paths, the 30 s collect for native mail, the app's check ladder for native
  slots and the boosts for them are deleted.
- A wallet on a mailbox without mux/1 has no epic1. A mailbox in the shipped list that does not
  offer mux/1 leaves the native list and stays usable for classic addresses.
- A wallet that printed a link on a mailbox without mux/1 prints a new one after the update.
- A sender to a classic address of a wallet that refuses unasked payments learns nothing. The
  funds stay locked until the sender cancels or the send expires.
- With one session per mailbox and Tor off, the mailbox operator sees in memory that the classic
  address and the native slots on that session belong to one wallet. Today the classic
  address and the contact slots already share a session with Tor off.
- Operators who pin a commit must change their client where the changelog says so.
- When the classic lane is retired later, its owner leaves the session and the 3.0.0 listener,
  the listing connections and the twin requeue are deleted. The session layout does not change.

## Tests the implementation needs

- Legacy gate: stock 4.x in both directions over Epicbox, HTTP, Tor and file, with a fixed case
  count, and no `lepic` key in any frame written.
- Upgrade fixtures from a store of the 2026-11-17 pre-release build (schema 17): an open marked send, an open Epicbox invoice on each side,
  a pending pair request, and a slot holding a notice, a sealed slate and an I1. One test per
  kind proves the queue does not stall.
- A reader of the 2026-11-17 pre-release build (schema 17) given a link with `http=` or `tor=` pays through the `epicbox=` entry.
- An epic1 link slot answers a repeated slate with the stored answer.
- The count of slots one contact uses, against the 256 per session.
- "Stored, then acknowledged" per slot class, and a lost S1 delivered by a re-post.
- A re-post or a send to the next route reuses the payment id and is refused after the payment's
  cutoff.
- A replaced session does not attach the slot again after a reconnect or a restart loop.
- A post to a mailbox the wallet does not read on works with and without mux/1 there.
- A mailbox that stops offering mux/1: epic1 turns off with a visible state and the classic address
  keeps working.
- Mailbox cancel is sent on API cancel and on expiry, and is a no-op on a mailbox without it.
- The time per leg on the floonet suite, and the classic address on push on a staging service
  wallet.
- Recovery: the old payment mined first and the recovery mined first, a refusal that stops it,
  only the payment's own inputs spent, and no cancel before the confirmations.
- A seeded store of 22,000 transactions: times for `GET /payments/{id}`, the listings and the
  build of a file send.

## Alternatives considered

- A new native protocol on the mailbox. It rebuilds what mux/1 has, binds native traffic to one
  mailbox implementation and needs a second stack for installed wallets.
- One slow poll for native slots on mailboxes without push, or one check kept for printed links
  only. Refused: one path to test, and a wallet on an old mailbox is treated as an old wallet.
- Dropping the twin-install requeue. It makes the legacy inbox simpler and breaks sends for a
  user with a phone and a computer on one wallet.
- Two session groups, classic and native, with Tor off. It hides nothing from a mailbox that sees
  one IP address, and costs a second connection.
- The core tries the next route after a set time. It puts a timer and a policy in the core.
- Two releases with a 30-day gap. Refused: one release, no compatibility between steps.
- Accepting `legacy` as an ignored field for one more version. Refused: ignored flags are
  removed, and operators adapt when they move their pin.

## Related

- Supersedes in part ADR 0054 (proposed): its mailbox pool, pool bits, shared mailbox list and the
  drain schedule of link slots. Its derived slots, link format and delivery states carry
  over.
- Supersedes in part ADR 0016 (notices on the payments address, the marker as proof of LEPIC),
  ADR 0034 (proposed: the marker, the feature word in it and the learning loop on payments
  addresses), ADR 0047 (the plain fallback) and ADR 0052 (the marker on legacy slates, the advert
  in `check_version`, pinning of URL and onion origins, sealed slates on the payments address).
- Supersedes in part ADR 0024 (proposed): the pair request to an Epicbox address, the reply key
  in the marker and collecting by one-off drains.
- Supersedes in part ADR 0042: a previous home is read by a session, and only on a mailbox that
  offers mux/1.
- Supersedes in part ADR 0045 (proposed): no "declined" message on a classic address over
  Epicbox.
- Supersedes in part ADR 0058 (proposed): the `Relays` poller and its boosts no longer read
  native slots.
- Supersedes in part ADR 0060: `POST /payments/{id}/cancel` asks the mailbox too, and so does an
  expiry at refresh. Its wire and ADR 0061's signature are used unchanged.
- Uses ADR 0051 (the methods crate; its edge to `lepic-peer` goes) and ADR 0055 (the API
  document).
- Unchanged: ADR 0043 (domain proof), ADR 0049 (held messages), ADR 0021 (Epicbox over Tor).
