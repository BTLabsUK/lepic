# The wallet API v1: a guide for integrators

`lepic serve` holds one wallet open and answers an HTTP API under `/api/v1`. Use it from a shop, a
bot or a payment page. This page says how to connect and what the conventions are. The contract
is [openapi.json](openapi.json); `GET /api/v1/openapi.json` returns the same document from a
running serve. [ADR 0055](../adr/0055-the-wallet-api-v1.md) says why it is built this way.

The API is for the wallet's owner. It is not the endpoint other wallets pay to: that is
`/v2/foreign` and `/api/v1/inbox`, see [The public listener](#the-public-listener).

TODO(payments): flows, kinds, states and `actions`, and the error-code table below wait for the
payments and contacts handlers.

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
`id` (see [Creating safely twice](#creating-safely-twice)).

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

A create (payment, address, link, contact, account) may carry an `id` you choose. Use a UUID for
a payment. Serve records a digest of the body before it creates anything, so a retry after a
timeout is safe:

| You send | Serve answers |
|---|---|
| The `id` for the first time | 201 with the new object |
| The same `id` and the same body | 200 with the object as it is now |
| The same `id` and another body | 409 `idempotency_mismatch` |
| The same `id` while the first call is still being answered | 409 `in_progress`; wait and ask again |

Over TLS a payment must carry an `id`, so a client that loses the answer can always ask again.

TODO(payments): a curl example of a repeated create, once `POST /payments` is implemented.

## Payments

TODO(payments): kinds, `via`, the forms of `to`, states and `actions`, and the flows: send,
invoice by file, handoff, finalize, cancel.

Two rules hold already (ADR 0055, D5). An invoice that is scanned or pasted is always held for
approval. `POST /open` never pays one.

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

Events are kept for 30 days by default. A client that falls behind, or asks from an id that is
pruned, gets an `events.skipped` event with the count and a `reason` of `lagged` or `pruned`.
Read the object again with a `GET`, then carry on from the new id.

TODO(payments): a stream example with a real payment event.

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

TODO(errors): the table of every `code`, with status and meaning, built from the merged code.

## The public listener

`serve --http` and its onion address are open to other wallets, so they answer only two paths:
`/v2/foreign` for stock wallets and `/api/v1/inbox` for LEPIC wallets. Anything else, including
the rest of `/api/v1`, answers 404 there. The wallet API is on the socket and the owner TLS
listener only.
