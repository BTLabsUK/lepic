# ADR 0055: The wallet API v1, served from one hand-written document

Status: accepted
Date: 2026-11-11

## Context

ADR 0050 gave `lepic serve` an owner API under `/v1`. Each route ran a CLI command and answered
with the JSON the CLI prints, and the OpenAPI document was generated from the report types with
`utoipa`. That kept the CLI and the API in step. It also made the CLI's reports the API's objects.

Integrators (a shop, a bot, a payment page, the console) need other things from it:

- A payment as one object, whatever its kind and transport, with a stable id the caller can choose
  before anything is sent.
- Creates that are safe to repeat after a timeout.
- Lists that page.
- An event log a client can resume after a disconnect.
- TLS clients that can read or take payments without being able to spend.

The CLI's reports carry a numeric transaction id, CLI wording and a different shape per command.

The design work for the new API, with its proposal, mapping and open points, is outside the
repository. the owner decided its open points on 2026-11-11 (D1 to D7). This record states what the
code does.

## Decision

### One document, written by hand

- `docs/api/openapi.json` (OpenAPI 3.1) is the contract and is written by hand. `serve` builds it in
  and serves it at `GET /api/v1/openapi.json`.
- The router is built from the document: each `operationId` is one operation, `x-role` is the
  least role that may call it, and `x-socket-only` marks operations the TLS listener refuses.
  - A path the document does not have answers 404 `no_route`.
  - A method it does not list for the path answers 405 `method_not_allowed` with `Allow`.
- The tests check every `/api/v1` answer they read against the document: the status, the media
  type, and the body's fields, types, enums and formats. Objects are closed, so a field the
  document does not name fails a test.
- `utoipa` is gone. The CLI's reports are no longer the API's schema.

### Paths, objects and conventions

- Every path is under `/api/v1` and names no wallet: one `serve` holds one wallet (D1). The version
  is v1 (D6).
- The objects are payments, accounts, outputs, addresses, links, contacts and their pair requests,
  payloads and quarantine, the relay, peers, the profile, the node, the wallet and the service.
- A payment is one object for every kind and transport. Its `id` is a UUID, its slate id.
- Field names are snake_case, and amounts are decimal strings in EPIC. Times are RFC 3339 UTC.
  Optional fields are left out, never null. Clients must accept enum values they do not know.
- Lists answer `{items, next_cursor}` with `limit` and an opaque `cursor`. The cursor is bound to
  the list's filters: a cursor sent with other filters is refused.

### Creates are idempotent

- A create (payment, address, link, contact, account) takes an optional caller-chosen `id`.
- The first call records a digest of its body before it creates anything. A repeat with the same
  body answers 200 with the object as it is now. One with another body answers 409
  `idempotency_mismatch`. While the first is still answered, a repeat gets 409 `in_progress`.
- Over TLS a payment must carry an `id`, so a client that loses the answer can ask again safely.

### Errors

- Errors are RFC 9457 problem documents with `code` (one closed list), `category` (the CLI's
  error kinds plus `conflict`), and where they apply `param`, `payment_id`, `contact_id` and
  `errors`.
- 502, 503 and 504 carry `Retry-After`.
- Each operation lists its statuses. The document's description lists the few any call may answer:
  - 408 `body_too_slow` and 413 `body_too_large` while the body is read;
  - 500 `internal`;
  - on the socket, 409 when a forwarded CLI command's caller headers differ from serve's (ADR 0053).

### Roles

- Each client in `api-clients` has one role: `read`, `receive` (also invoices, addresses and links,
  never a spend) or `full` (D3).
- A line without a role gives `read`. `lepic api client add --role` sets it.
- The socket is always `full`.
- A call above the client's role answers 403 `role_required`.
- `PUT /wallet/password`, `POST /contacts/export` and `POST /contacts/import` answer 403
  `socket_only` over TLS.
- Serve checks the socket-only mark, then the role, then reads the body.

### Events

- Serve keeps an event log with rising ids. Its types are `resource.what_happened`, for example
  `payment.created`, `payment.state_changed` and `contact.removed`. Each event carries the
  object's id and, where there is one, a snapshot after the change.
- `GET /api/v1/events` lists the log.
- With `Accept: text/event-stream` it streams. A stream resumes after `Last-Event-ID` or `after`;
  without either it starts at the next event.
- A client that falls behind, or asks for events already pruned, gets `events.skipped`.

### What the API no longer has

- Pairing cards and spoken pairing words (D2).
- Payment proofs: `epic1 pay --proof` and its FFI field are removed (D4). No proof data goes on
  the wire.
- Invoices that are scanned or pasted are always held for approval (D5): `POST /api/v1/open` never
  pays one.

### The listeners

- The socket and the owner TLS listener answer `/api/v1`. Transports, certificates, `api-clients`
  and bounds are as ADR 0050 decided.
- The public listeners (`serve --http`, its onion) answer two things only (D7):
  - `/v2/foreign`, unchanged for stock wallets;
  - `/api/v1/inbox`, the native endpoint between LEPIC wallets that replaces `/v1/peer` (ADR 0052,
    amendment 2026-11-11).

### CLI commands through serve

ADR 0053 still decides which commands run through a running serve and that they print what they
print on their own. How they travel changes.

- The CLI sends the parsed command to a private, socket-only `POST /cli/run`. That route is not in
  the document, and over TLS it answers 404 `no_route`.
- Serve runs the command on the wallet it holds. It answers with the command's report, rendered as
  text when asked for `text/plain`, or with a private error document the CLI turns back into the
  same error, exit code and hint.
- Files are still read and written by the CLI, never by serve.

The API's objects are not CLI reports, so mapping commands onto `/api/v1` calls would have
changed what the commands print.

## Consequences

- Clients of the old `/v1` owner API break: the console, scripts and integration apps move to
  `/api/v1`. No compatibility layer is kept.
- A change to the API is a diff of `docs/api/openapi.json` in review. The code can drift from it
  only where no test reads an answer. A coverage test walks every operation once.
- The CLI's JSON output can change without changing the API, and the other way round.
- Stock wallets see no change: `/v2/foreign` and its formats are untouched.
- The FFI loses the proof field, so the binding and the app move with this change.

## Alternatives considered

- **Keep generating the document from Rust types.** That needs a type per API object anyway. A
  generated document is reviewed as a side effect of code, and the contract is what integrators
  read first.
- **Map each CLI command onto `/api/v1` calls.** Payments have UUIDs, not the CLI's transaction
  ids, and API objects carry other fields than reports. Every forwarded command's output would
  change.
- **Keep `/v1` beside `/api/v1` for a release.** No released app or published integration depends
  on the old owner API. Two APIs would double the surface to secure and test.
- **Scopes per call instead of three roles.** Finer, but a client's file line would list calls,
  and every new call would need a decision per client. Three roles cover reading, taking payments
  and spending.

## Related

- ADR 0050: one wallet API. Its paths, generated document, CLI-shaped bodies and all-or-nothing
  TLS clients are superseded here. Its transports, bounds and console stand.
- ADR 0052: legacy at the edge, native between LEPIC wallets (the inbox).
- ADR 0053: CLI commands through a running serve. Its route mapping is superseded here.
- ADR 0017: direct transactions over HTTP (`/v2/foreign`).
