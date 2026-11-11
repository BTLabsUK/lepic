# The wallet API v1: a guide for integrators

`lepic serve` holds one wallet open and answers an HTTP API under `/api/v1`. Use it from a shop, a
bot or a payment page. This page says how to connect and what the conventions are. The contract
is [openapi.json](openapi.json); `GET /api/v1/openapi.json` returns the same document from a
running serve. [ADR 0055](../adr/0055-the-wallet-api-v1.md) says why it is built this way.

The API is for the wallet's owner. It is not the endpoint other wallets pay to: that is
`/v2/foreign` and `/api/v1/inbox`, see [The public listener](#the-public-listener).

## Connecting

One serve holds one wallet, and no path names a wallet. To serve two wallets, run two serves with
their own sockets.

### The Unix socket

```sh
lepic serve --socket ./w.sock &
curl --unix-socket ./w.sock http://lepic/api/v1/status
```

The socket is `lepic.sock` in the data directory unless `--socket` says otherwise. Only the user
that runs serve can open it, so there are no tokens. The host in the URL is ignored; use `lepic`.
The socket always has the `full` role. Every answer carries `x-lepic-version`.

### Owner TLS

For a client on another machine, set `[api] owner_tls = "ip:port"` in settings.toml and start
`lepic serve --owner-tls`. Serve writes its certificate to `api-tls.pem` in the data directory.
The client trusts that file and presents a certificate of its own with an Ed25519 key.

```sh
lepic api client add till ./till-cert.pem --role receive
```

The role limits what the client may call:

| Role | May |
|---|---|
| `read` | Every call that changes nothing. The default. |
| `receive` | Also create invoices, addresses and links, and take payments. Never spends. |
| `full` | Everything the TLS listener answers. |

A call above the role answers 403 `role_required`. Three operations are socket-only and answer 403
`socket_only` over TLS: `PUT /wallet/password`, `POST /contacts/export` and `POST /contacts/import`.
Each operation's role is its `x-role` in the document. A payment created over TLS must carry an
`id` (see [Creating safely twice](#creating-safely-twice)). Over TLS, a send or a `deliver` to an
address of the computer serve runs on answers 400 `invalid_request`.

The file format and the commands are in [cli.md](../cli.md#owner-api-over-tls).

## Conventions

- **Names.** Fields are snake_case. Enum values are lower snake_case. A client must accept enum
  values it does not know.
- **Ids.** A payment's `id` is a UUID, its slate id. Other objects have ids that are strings; treat
  them as opaque.
- **Amounts** are decimal strings in EPIC with up to 8 decimals: `"1.5"`, `"0.00000001"`. Never a
  number.
- **Times** are RFC 3339 in UTC: `2026-11-11T01:51:28Z`.
- **Optional fields** are left out when empty. They are never `null`.
- **Bodies** are JSON with `content-type: application/json`. A field the document does not name is
  refused with 400 `invalid_body`.
- **Lists** answer `{"items": [...], "next_cursor": "..."}`. `limit` is 1 to 500 and defaults to
  50. Pass `next_cursor` back as `cursor` for the next page; it is missing on the last page. A
  cursor is bound to the list's other query parameters, so keep them the same across pages.

```sh
curl --unix-socket ./w.sock http://lepic/api/v1/accounts
```

```json
{"items":[{"label":"default","index":0,"balance":{"spendable":"0.00000000","confirming":"0.00000000","pending":"0.00000000","maturing":"0.00000000","locked":"0.00000000","total":"0.00000000"}}]}
```

## Creating safely twice

A create (payment, address, link, contact) may carry an `id` you choose. Use a UUID for
a payment. Serve records a digest of the body before it creates anything, so a retry after a
timeout is safe:

| You send | Serve answers |
|---|---|
| The `id` for the first time | 201 with the new object |
| The same `id` and the same body | 200 with the object as it is now |
| The same `id` and another body | 409 `idempotency_mismatch` |
| The same `id` while the first call is still being answered | 409 `in_progress`; wait and ask again |

A create refused with a 4xx, or a 502 from the node, made nothing and keeps no record: the
same `id` with a corrected body is a new create. `idempotency_mismatch` and `in_progress` are
the exceptions; they leave the earlier call with that `id` as it was. After a 500 or 503 the
object may exist: repeat the same body to find out.

An `id` that already names a payment is refused with 409 `idempotency_mismatch`, `param`
`/id`, for sends and invoices alike.

Over TLS a payment must carry an `id`, so a client that loses the answer can always ask again.

A real run. An invoice needs no funds, so it is the easy thing to try:

```sh
curl -i --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"4263265f-afde-45bf-ac7e-3041a7de8475","kind":"invoice","amount":"1","via":"file"}' \
  http://lepic/api/v1/payments
```

The first call answers `201 Created` with the payment. The same command again answers
`200 OK` with the same payment (the `handoff` is only in the 201). The same `id` with
`"amount":"2"` answers:

```
HTTP/1.1 409 Conflict
content-type: application/problem+json
```

```json
{"type":"about:blank","title":"Conflict","status":409,"detail":"this id was used before with another request body","code":"idempotency_mismatch","category":"conflict","param":"/id"}
```

A send keeps your `id` as the payment's `id`, and so does an invoice whose `id` is a version-4
UUID. An invoice under any other UUID gets an `id` of the wallet's own choosing, and your `id`
stays an alias: `GET /payments/{your id}` returns the same payment. Read `id` from the answer,
not from your request.

A create is safe to repeat after serve stopped while answering it: a payment, an address or a
link that was made is answered with 200 on the repeat, never made a second time.

## Payments

A payment is one object, whatever its kind: a send you make, an invoice you issue or pay, or a
payment found by a scan. `GET /payments` lists them, newest first. `state`, `kind`, `direction`
and `via` filter the list.

### The fields that steer you

| Field | Values |
|---|---|
| `kind` | `send`, `invoice`, `coinbase`, `unknown` (found by a scan). Only `send` and `invoice` can be created. |
| `direction` | `in`, `out`, `self` (between your own accounts, or splitting your own coins). |
| `state` | `needs_approval`, `awaiting_answer`, `awaiting_post`, `finalized`, `posted`, `confirmed`, `cancelled`, `declined`, `expired`. Serve does not set `awaiting_post` yet. |
| `state_reason` | Why a payment reached an end state: `by_us`, `by_them`, `superseded` and others. Accept values you do not know. |
| `via` | `epicbox`, `http`, `tor`, `contact`, `link`, `in_person`, `file`, `peer`, `chain`: how the slate travels. |
| `delivery.state` | `queued`, `sent`, `uncertain`, `held`, `failed`, `refused`, `by_hand`. `uncertain` means the send went out and you do not know it arrived. Serve sets only `by_hand`, `uncertain` and `sent`. `queued`, `held`, `failed` and `refused` are in the schema for later; a send the receiver refused reads `sent`. |
| `actions` | The calls that work on the payment now. |

`actions` is the list to read. A call not in it answers 409 `action_not_available` and changes
nothing. Today the values are:

| State | `actions` |
|---|---|
| `needs_approval` | `approve`, `decline` |
| `awaiting_answer` | `cancel`, and `deliver` for a send that has not reached the other wallet |
| `finalized` | `post`, `cancel` |
| `posted` | `post`, and `cancel` when the chain never took the payment (`cancellable_from_height`) |
| the other states | none |

`finalize` is in the contract, but no payment lists it yet: only in-person payments collect
several answers, and serve starts none. `POST /payments/{id}/finalize` answers
409 `action_not_available`.

### The destination, `to`

`POST /payments` takes `amount` and, for most routes, `to`. `to` is one of:

| Form | Route |
|---|---|
| `key@host` | Epicbox address |
| `http://…` or `https://…` | HTTP listener of another wallet |
| `….onion` | Tor |
| `epic:…` | A payment link |
| `contact:ID` | A contact |
| `account:LABEL` | One of your own accounts |

Serve does not make payments to `epic:` links or `account:` yet: open the link with `POST /open`
instead, and move coins between accounts with the CLI. Both answer 400 `invalid_field`.

Without `to`, `via` must be `file`: the payment is made for someone you hand it to. `via` forces
a route when `to` is not enough. `in_person`, `link`, `peer` and `chain` are in the contract but
serve does not start them yet; they answer 400 `invalid_field`. `POST /payments/estimate` takes the same body and
answers the fee, `max_amount` and the coins it would use, without changing anything.
`"amount":"max"` is for the estimate only.

### Send to an address

```sh
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"id":"5b0e2f6a-3c1d-4e8f-9a7b-2d4c6e8f0a1b","amount":"1","to":"KEY@epicbox.example","message":"rent"}' \
  http://lepic/api/v1/payments
```

The answer is `201` with the payment in `awaiting_answer` and `via: epicbox`. When the other
wallet answers, serve finishes and posts the payment by itself; poll `GET /payments/{id}` or
watch the [events](#events) for `posted`, then `confirmed`. A change in `actions` tells you when
`cancel` is possible.

### An invoice by file

1. Issue it: `{"kind":"invoice","amount":"3","via":"file"}`. The answer holds a `handoff` with
   the slate `text` and a `file_name`. Give the text to the payer: paste it, save it or show it
   as QR. `GET /payments/{id}/handoff` returns it again; `?qr=true` adds `qr_frames`.
2. The payer opens it in their wallet (below) and hands an answer back.
3. You open the answer with `POST /open`. The outcome is `finished` and the payment is posted.

### Take what is handed to you

`POST /open` takes pasted `text`, a file as `file_base64`, or scanned `qr_frames`, and acts on
it. `POST /inspect` takes the same and only says what it is, so use it to look first. Add
`expect` to refuse anything else: a text of another kind answers 422 `unexpected_input` and
nothing changes.

`outcome` says what happened: `received` (a payment was handed to you and `handoff` is the answer
to give back), `finished` (the answer to your payment arrived and it was posted),
`answer_added`, `invoice_parked`, `pairing_advanced` or `already_done` (you opened it before).
`already_done` hands back the answer stored the first time. An item given as `qr_frames` is
answered with `qr_frames` too, on a repeat as well.

Open never pays, which is the rule of ADR 0055 (D5).

A sealed file from a contact (`BEGINEPICSEALED.` text) is opened with this wallet's keys.
`inspect` answers `type: "sealed"` with the amount, the `contact_id` when the contact signed it,
the message and the next step, and stores nothing. `open` goes by what is inside: a send is
received and answered sealed (`receive`), an invoice is held for approval (`receive`), and the
answer to your own payment is finished (`full`). A sealed file that does not open with this
wallet's keys answers 409 `nothing_to_open`.

A plain slate that carries a LEPIC wallet's reply key is answered sealed to that key, so its
`handoff` has `format: "sealed"`. A sealed answer has no QR frames: `?qr=true` on its handoff
answers 409 `format_not_available`.

### An invoice that asks you to pay

An invoice that is scanned or pasted is always held for approval. Money leaves in two calls:

```sh
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"text":"<the invoice>"}' http://lepic/api/v1/open
```

The outcome is `invoice_parked`. The payment is in `needs_approval`, `actions` is
`["approve","decline"]` and nothing was spent. Look at `amount` and the issuer, then:

```sh
curl --unix-socket ./w.sock -H 'content-type: application/json' \
  -d '{"amount":"3"}' http://lepic/api/v1/payments/$ID/approve
```

You retype the amount. If it differs from the invoice, the answer is 400 `invalid_field` with
`param` `/amount` and the payment stays held. If it matches, serve pays and the answer is the
payment with a `handoff` to give the issuer when they are not online. `decline` refuses the
invoice and tells the issuer. After either, the other answers 409 `action_not_available`.
`deliver:false` on `approve` is not supported yet: it answers 400 `invalid_field` at `/deliver`.

At most 100 invoices wait for approval. One more answers 409 `too_many_held`; approve or decline
one first. Opening an invoice that is already held again does not count. A held invoice whose
`expires_at_height` is below the wallet's last known height drops out of the list; serve does
not ask the node for this.

### Handoff, deliver, post, cancel

- `POST /payments/{id}/deliver` sends the slate again to the payment's own address. `relay` and
  `to` are in the contract but not supported yet: they answer 400 `invalid_field`. `relay_ok` is
  taken and has no effect yet.
- `POST /payments/{id}/post` posts a finished payment to the node again. `{"fluff":true}` skips
  the stem phase.
- `POST /payments/{id}/cancel` ends a payment that is not on the chain and frees its coins. It
  answers the same payment when repeated.
- `PATCH /payments/{id}` sets `metadata`: up to 50 local notes, never sent.
- `deliver:false` on a create makes the payment and returns the `handoff` without sending it.

## Addresses and links

`used` on an address is always `false` for now. A link has an `address_index` when the wallet
knows the address it pays; a link mailbox that a restore found in use has none, and the field is
left out. A link lists with its `text`, whether the CLI or the API issued it.

## Contacts

`DELETE /contacts/{id}` on a contact whose pairing still waits cancels it: a request you sent is
withdrawn, an invite of yours is cancelled. A late answer is then refused, and you can ask the
same wallet again at once. On a paired contact it ends the pairing and tells the contact. With
`notify=false` the contact is not told and keeps its record until this wallet sends it a new pair
request; that request ends the old record there, if that wallet had heard from this one and the
request is newer than the pairing. When the pairing came from a request of this wallet, or the
contact held a request from this wallet when the pairing finished, newer is judged by this
wallet's clock alone, so a clock behind the contact's does not stop it.

A new request from a wallet whose earlier request you answered, and which never confirmed it,
replaces that pairing, so `acceptPairRequest` takes it.

Serve keeps a contact's `invite_link`, the `label` given while its pairing waited and its
`refused_relay` beside the contact in the wallet. They go when the wallet removes the contact,
whichever way it is removed: this API, `lepic contact remove`, the app, or a new pairing that
replaces it.

## Events

Serve keeps an event log. Each event has a rising integer `id`, a `type` like
`payment.state_changed`, a `created_at` and a `data` object, which holds a snapshot of the object
after the change where there is one. The types in the document are `payment.created`,
`payment.state_changed`, `payment.updated`, `contact.created`, `contact.state_changed`,
`contact.updated`, `contact.removed`, `pair_request.received`, `payload.received`,
`quarantine.added`, `account.balance_changed`, `wallet.progress`, `relay.updated`,
`slate.unmatched` and `events.skipped`. The set is open: skip a type you do not know.

`GET /events` returns a page, oldest first. `after` gives the last id you have; `types` takes a
comma list and allows `payment.*`.

```sh
curl --unix-socket ./w.sock 'http://lepic/api/v1/events?after=0&limit=50'
```

```json
{"items":[]}
```

With `Accept: text/event-stream` the same path streams. Each frame is

```
id: 42
event: payment.state_changed
data: {"id":42,"type":"payment.state_changed",...}

```

A comment line `: keepalive` comes every 15 seconds. To resume after a disconnect, send the last id
you saw as `Last-Event-ID` (or `?after=`). Without either, the stream starts at the next event.

```sh
curl -N -H 'Accept: text/event-stream' -H 'Last-Event-ID: 42' \
  --unix-socket ./w.sock http://lepic/api/v1/events
```

A `contact.state_changed` entry for a pairing that failed carries one of these as its `reason`:
`changed_on_the_way`, `kind_differs`, `expired`, `not_confirmed`, `refused`, `other_address`,
`address_proof_missing`, `crossed`. After a restart serve reads the newest logged objects back, so
`from_state` is present when the log holds the object. When it does not, the entry has `to_state`
and no `from_state`, and a `contact.updated` entry that does not know the fields has no `changed`.

Events are kept for 30 days by default. A client that falls behind, or asks from an id that is
pruned, gets an `events.skipped` event with the count and a `reason` of `lagged` or `pruned`.
Read the object again with a `GET`, then carry on from the new id.

A real run: this stream was open while an invoice was created (the `data` is cut here, and
`data.object` holds the payment).

```sh
curl -N -H 'Accept: text/event-stream' --unix-socket ./w.sock http://lepic/api/v1/events
```

```
id: 4
event: payment.created
data: {"id":4,"type":"payment.created","created_at":"2026-11-11T02:55:20.040280091Z","data":{"object":{"account":"default","actions":["cancel"],"amount":"1.00000000",...,"kind":"invoice","state":"awaiting_answer",...}}}

```

## Errors

An error is an RFC 9457 problem document with `content-type: application/problem+json`:

```sh
curl -i --unix-socket ./w.sock http://lepic/api/v1/nothing
```

```
HTTP/1.1 404 Not Found
content-type: application/problem+json
x-lepic-version: 0.4.0
```

```json
{"type":"about:blank","title":"Not Found","status":404,"detail":"no such path","code":"no_route","category":"not_found"}
```

- `code` is a stable, fine-grained name. A client must accept codes it does not know and fall back
  on `category`.
- `category` is one of `usage`, `config`, `wrong_password`, `wallet_state`, `not_found`,
  `rejected`, `funds`, `node`, `transport`, `internal`, `interrupted` and `conflict`.
- `param` is a JSON pointer to the bad field, when one field is to blame. `payment_id` and
  `contact_id` name the object an error is about; `errors` lists several faults.
- 502, 503 and 504 carry `Retry-After` when waiting is worth it.
- A path the document does not have is 404 `no_route`. A method it does not list is 405
  `method_not_allowed` with an `Allow` header.
- Any call may also answer 408 `body_too_slow` or 413 `body_too_large` while serve reads the body,
  and 500 `internal`.

### Every code

The status follows the code. A code that serve takes from the CLI keeps the status of its
category unless the table says another; `Retry-After` is set on 502, 503 and 504.

**Any call**

| Code | Status | Meaning |
|---|---|---|
| `no_route` | 404 | The path is not in the document. |
| `method_not_allowed` | 405 | The path does not take the method; `Allow` lists the ones it does. |
| `body_too_slow` | 408 | The body did not arrive in time. |
| `body_too_large` | 413 | The body is over the limit. |
| `role_required` | 403 | The TLS client's role is below what the call needs. |
| `socket_only` | 403 | The call is answered on the Unix socket only. |
| `client_not_listed` | 403 | The TLS client was removed from `api-clients` after it connected. |
| `invalid_request` | 400 | The request is malformed. |
| `invalid_body` | 400 | The body is not valid JSON for the operation, or names an unknown field. |
| `invalid_field` | 400 | One field is wrong; `param` points at it. |
| `invalid_cursor` | 400 | The `cursor` is not one this list issued. |
| `cursor_filters_changed` | 400 | The cursor was issued for other query parameters. |
| `not_found` | 404 | No object has that id. |
| `internal` | 500 | A bug in serve. |
| `interrupted`, `cancelled` | 503 | Serve is stopping, or the scan was cancelled. |

**Creating safely twice**

| Code | Status | Meaning |
|---|---|---|
| `idempotency_mismatch` | 409 | The `id` was used before with another body. |
| `in_progress` | 409 | A request with this `id` is still being answered. |
| `account_exists` | 409 | An account with that label exists. |

**Payments**

| Code | Status | Meaning |
|---|---|---|
| `action_not_available` | 409 | The payment's `actions` do not list the call. |
| `format_not_available` | 409 | The handoff is not available in that `format`. |
| `no_handoff` | 409 | The payment has nothing to hand over. |
| `nothing_to_open` | 409 | The text is already finished, needs nothing from this wallet, or is sealed for another wallet. |
| `too_many_held` | 409 | 100 invoices already wait for approval. |
| `unexpected_input` | 422 | `POST /open` found a kind not named in `expect`. |
| `insufficient_funds` | 422 | The account cannot pay the amount and the fee. |
| `change_too_small`, `too_heavy`, `nothing_to_consolidate` | by category | The coins cannot make this payment. |
| `invalid_slate`, `payment_expired`, `invoice_changed`, `amount_mismatch` | by category | The slate or invoice cannot be used as it is. |
| `invoice_already_paid`, `invoice_locked_above_tip`, `inputs_spent_elsewhere`, `inputs_spent_by_own_transaction`, `peer_inputs_spent` | 409 | The payment's state on the chain conflicts with the call. |
| `on_chain`, `in_pool`, `not_releasable`, `changed_during_cancel` | 409 | The payment cannot be cancelled in its present state. |
| `not_posted`, `not_delivered` | by category | A step before has not happened. |
| `plain_http_not_allowed`, `http_url_invalid`, `onion_address_invalid` | 400 | The destination is not usable as given. |

**Wallet and node**

| Code | Status | Meaning |
|---|---|---|
| `wrong_password` | 403 | The password is wrong. |
| `wallet_not_found` | 404 | There is no wallet in the data directory. |
| `wallet_already_exists`, `wallet_busy`, `locked`, `foreign_wallet` | 409 | The wallet is in a state the call cannot work with. |
| `restore_scan_required` | 503 | A restored wallet must finish its scan first. |
| `scan_running` | 409 or 503 | A scan is running; wait for it. |
| `node_unreachable` | 502 | The node did not answer. 504 when it timed out. |
| `offline` | 409 | The wallet is set to offline. |
| `tor_not_running`, `onion_unreachable` | 503, 502 | Tor is not up, or the onion service did not answer. |
| `transport_failed` | 502 | The relay or the other wallet could not be reached. |
| `damaged_database` | 500 | The wallet's database is damaged. |
| `wallet_too_new` | 409 | A newer LEPIC wrote the wallet. |
| `wrong_key` | 409 | The wallet's key does not open its files. |

**Contacts and pairing**

| Code | Status | Meaning |
|---|---|---|
| `contact_not_found`, `pairing_not_found` | 404 | No such contact, or no such pairing or request. |
| `invite_expired`, `already_paired`, `pairing_in_progress`, `pairing_crossed`, `pairing_ended`, `pairing_waiting`, `invite_dismissed`, `contact_not_verified`, `key_check_refused`, `relay_changed`, `keys_not_changed`, `domain_fixed`, `contact_cap_reached` | 409 | The pairing or contact is not in a state the call can use. |
| `wrong_pairing_class` | 400 | The call does not apply to a pairing of this class. |
| `other_address`, `address_proof_missing`, `peer_not_proven`, `no_free_slot` | 422 | The pairing cannot go on. |
| `contacts_offline`, `epicbox_off` | 409 | The switch the call needs is off. |

Codes from the CLI that this table does not list reach a client with their category's status:
`usage` 400, `wrong_password` 403, `not_found` 404, `wallet_state` and `conflict` 409, `rejected`
and `funds` 422, `node` and `transport` 502, `interrupted` 503, `internal` and `config` 500.
Read `category` for those, and accept codes you do not know.

## The public listener

`serve --http` and its onion address are open to other wallets, so they answer only two paths:
`/v2/foreign` for stock wallets and `/api/v1/inbox` for LEPIC wallets. Anything else, including
the rest of `/api/v1`, answers 404 there. The wallet API is on the socket and the owner TLS
listener only.
