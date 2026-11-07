# 0050 One wallet API, served by `lepic serve`

Status: proposed
Date: 2026-11-07

## Context

`lepic serve` holds one unlocked wallet and answers other `lepic` commands over a Unix socket.
A request is a CLI command line and the reply is that command's output and exit code. That is a
private protocol: it has no version, no schema, and every CLI option reaches the running wallet,
the tor binary and relative file paths included. A wallet that runs `serve` cannot also take
payments over HTTP, because `http listen` needs the same data directory lock. There are no
metrics, no outputs list and no password change.

Integrators expect what wallets and payment servers ship today: one documented HTTP API with a
machine-readable schema, stable error codes and a version in the path.

| Daemon | Style | Schema | Owner auth | Remote | Docs UI |
|---|---|---|---|---|---|
| Docker Engine | REST | OpenAPI | Unix socket permissions | mutual TLS | from the spec |
| BTCPay Server Greenfield | REST, `/api/v1` | OpenAPI | API keys with permissions | HTTPS | Redoc at `/docs` |
| LND | gRPC and REST | protobuf, OpenAPI | macaroons | TLS, always | none built in |
| Core Lightning | JSON-RPC | JSON Schema per command | socket mode 0600 | runes, as plugins | none built in |
| bitcoind, monero-wallet-rpc | JSON-RPC | prose | cookie or password | none | none |
| grin-wallet, epic-wallet | JSON-RPC, v3 | prose | secret plus ECDH-sealed bodies | none | none |

None of them ships a dashboard in the wallet process: RTL, ThunderHub and similar are separate
programs that call the API.

## Decision

### One API, one specification

- The API is HTTP/1.1 with JSON bodies, resource-oriented (REST), described by one OpenAPI 3.1
  document, `docs/api/openapi.yaml`. The document is the contract: the binary embeds it and
  serves it at `GET /v1/openapi.yaml`, the docs render it, and tests check every response the
  API gives against it.
- Owner calls live under `/v1`. The payment endpoint other Epic wallets post to,
  `POST /v2/foreign` (JSON-RPC 2.0: `check_version`, `receive_tx`, `build_coinbase` when it is
  on), is part of the same document with no security requirement. Its wire format is the
  network's and does not change (ADR 0017).
- The response bodies are the JSON `lepic --output json` prints, so the CLI and the API share
  one schema. A handler builds the command's arguments from the request and runs the command the
  CLI runs; nothing is implemented twice.
- Amounts are decimal strings in EPIC. Transactions are addressed by `tx_id`; a send takes an
  optional client-chosen `slate_id`, which makes a repeated request safe (it reports the first
  send). Slates for the file method travel in request and response bodies, never as paths.
- Errors are RFC 9457 problem details (`application/problem+json`) with `status`, `title`,
  `detail` and a `code` member. `code` is the error kind the CLI already reports
  (`insufficient_funds`, `wrong_password`, `not_found`, ...), one closed list in the document,
  and each kind has one HTTP status.
- Versioning: `/v1` changes only by addition: new routes, new optional request fields, new
  response fields. Clients ignore fields they do not know. A breaking change is `/v2`, served
  beside `/v1` for at least one LEPIC minor release. `info.version` in the document is the API
  version, raised on every change.

### Transports and authentication

The connection proves who calls; no password, token or key travels in a request.

- The Unix socket (as today, mode 0600, peer uid checked) carries the whole API. The OS user is
  the credential.
- `serve --owner-tls` adds a TCP listener for owner calls from other machines, with mutual TLS
  1.3. The wallet's certificate key is an Ed25519 key derived as ADR 0033 lays out, under its own
  label (`lepic-wallet api tls v1`), so a restored wallet keeps its identity and clients keep their
  pin. The certificate is self-signed and has no expiry date (RFC 5280's `99991231235959Z`).
  Clients authenticate with their own Ed25519 certificate; the wallet accepts the keys listed in
  `api-clients` in the data directory, one name and SHA-256 key fingerprint per line, as
  `authorized_keys` does for SSH. `lepic api client add|list|remove` edits the file; `serve`
  rereads it when it changes. Every client listed may call every owner route.
- `serve --http [--internet] [--coinbase]` adds the payment listener on the wallet serve holds:
  `lepic_foreign::listen` with its own limits, answering `/v2/foreign` only, plain HTTP as other
  wallets send it.
- Addresses and ports come from `settings.toml`; nothing is listened on that the operator did not
  name.
- Commands that create or reveal secrets (`wallet init`, `restore`, `import-seed`, seed export)
  have no route.

### Bounds

Each listener has a cap on connections in flight (extra ones are closed), a deadline for the
request head and body, and a body size limit, set in `settings.toml` tuning as the HTTP listener's
are. Owner work has no deadline: a scan or a send over a slow relay takes what it takes, and the
client sets its own timeout. Connections are polled with `FuturesUnordered`; the accept back-off
no longer sleeps in the main loop. The runtime stays single-threaded: every wallet call waits on
one SQLite connection.

### What else serve answers

- `GET /v1/status`: uptime, requests served, in flight and refused, the state of each listener
  and of Epicbox, the wallet's height and the node's tip, and the refresh and collect results
  `serve status` reports today. Facts only: thresholds and alerts belong to the consumer.
- `GET /v1/events`: the engine's events as a server-sent event stream, so a shop or bot learns of
  a payment without polling.
- Two owner functions the CLI lacked, as commands and routes: `wallet password` (re-encrypts the
  vault under a new password) and `wallet outputs` (`Wallet::outputs`).

### What it replaces

`lepic --service` and the line protocol are removed; `curl --unix-socket` or any HTTP client
takes their place. The socket path and its file rules stay.

### The console

Stats, status, basic management and the rendered API reference are a separate program,
`lepic-console`, in its own workspace under `console/`. It is a client of the API like any
other: it reaches `serve` over the socket and serves a local web page on loopback. It depends on
no LEPIC crate, so it cannot pull policy into the wallet core, and the `lepic` binary carries no
HTML or JavaScript. The API reference is rendered with Scalar, vendored, with web fonts and its
request proxy off.

## Consequences

- One contract for the CLI's JSON and the API. A JSON shape change is an API change and follows
  the versioning rule; the schema tests fail on an unplanned one.
- Integrators use any HTTP client, generated or hand-written, against a published schema.
- Remote owner access needs no secret in requests and gets forward secrecy from TLS 1.3. It adds
  `rcgen` for the self-signed certificates and a client-key verifier of our own over rustls.
- The tor-binary, library-directory, relative-path and ignored-option problems of the line
  protocol go away with it: a route has only the fields its schema lists.
- Scripts that use `lepic --service` move to the API. Within LEPIC that is one acceptance step.
- The app and the binding do not use `serve`; the FFI and the receive wire format are unchanged.

## Alternatives considered

- **JSON-RPC 2.0 with an OpenRPC document** (bitcoind, Monero, Ethereum). Familiar to node
  operators, but one POST path hides the API from HTTP tooling, caches and gateways, and the
  documentation tools are thinner. epic-wallet's owner API is this shape.
- **Keep the line protocol and document it**. Least code, but it stays a CLI over a socket: no
  schema per call, every option reachable.
- **Sealed request bodies** (HPKE to the wallet's key, as epic-wallet v3 does with ECDH). Works
  over any HTTP path, but needs a LEPIC client library in every language, has no forward secrecy
  and has to build its own replay protection. TLS 1.3 already gives all three.
- **API keys or bearer tokens** (BTCPay). Familiar, but the secret travels in every request and
  ends up in logs and shell history.
- **A web UI inside serve**. A second network surface with HTML and session code in the process
  that holds the keys.
