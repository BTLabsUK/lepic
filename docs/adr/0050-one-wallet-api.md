# 0050 One wallet API, served by `lepic serve`

Status: proposed
Date: 2026-11-07

## Context

`lepic serve` holds one unlocked wallet and answers other `lepic` commands over a Unix socket.
A request is a CLI command line and the reply is that command's output and exit code. That is a
private protocol: it has no version, no schema, and every CLI option reaches the running wallet,
the tor binary and relative file paths included. There are no metrics and no outputs list, and
the wallet password cannot be changed.

Integrators expect what wallets and payment servers ship: one documented HTTP API with a
machine-readable schema, stable error codes and a version in the path.

| Daemon | Style | Schema | Local access | Remote access | Docs UI |
|---|---|---|---|---|---|
| Docker Engine | REST | OpenAPI | Unix socket permissions | opt-in: SSH, or TLS with client certificates | from the spec |
| BTCPay Server Greenfield | REST, `/api/v1` | OpenAPI | API keys | HTTPS | Redoc at `/docs` |
| LND | gRPC and REST | protobuf, OpenAPI | TLS and macaroons | TLS and macaroons | none built in |
| Core Lightning | JSON-RPC | JSON Schema per command | socket, owner-only | opt-in: runes over REST, gRPC, Commando | none built in |
| bitcoind | JSON-RPC | prose | cookie file, loopback TCP | "do not enable over the public Internet" | none |
| grin-wallet, epic-wallet | JSON-RPC, v3 | prose | secret plus ECDH-sealed bodies | none | none |

None of them ships a dashboard in the wallet process: RTL, ThunderHub and similar are separate
programs that call the API.

## Decision

### One API, one specification

- The API is HTTP/1.1 with JSON bodies, resource-oriented (REST), described by one OpenAPI 3.1
  document. Owner calls live under `/v1`. The payment endpoint other Epic wallets post to,
  `POST /v2/foreign` (JSON-RPC 2.0: `check_version`, `receive_tx`, `build_coinbase` when it is
  on), is part of the same document with no security requirement. Its wire format is the
  network's and does not change (ADR 0017).
- The document is generated from the Rust types and the route table with `utoipa`. Doc comments
  on the types and routes are the only hand-written source. The generated document is committed
  as `docs/api/openapi.json`, served at `GET /v1/openapi.json` and rendered by the docs and the
  console. A test fails when the committed file differs from what the code generates, so a change
  to the API shows in review as a diff of that file. OpenAPI documents are JSON or YAML only;
  generating the JSON means nobody writes either by hand.
- The response bodies are the JSON `lepic --output json` prints, so the CLI and the API share one
  schema. A handler builds the command's arguments from the request and runs the command the CLI
  runs; nothing is implemented twice.
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

- Local, the default and the only listener without a flag: the Unix socket, mode 0600, the peer's
  uid checked against the process's own (`SO_PEERCRED`, `getpeereid`). The OS user is the
  credential, as for the Docker socket and Core Lightning's `lightning-rpc`. There are no
  certificates, tokens or cookie files to manage. A loopback TCP port would be reachable by every
  local user and by any web page through DNS rebinding; a socket is reachable by neither.
- Remote, opt-in only: `serve --owner-tls` adds a TCP listener with mutual TLS 1.3 on the
  address `[api] owner_tls` in `settings.toml` names. The wallet's certificate key is an Ed25519
  key derived as ADR 0033 lays out, under its own label (`lepic-wallet api tls v1`), so a
  restored wallet keeps its identity and clients keep their pin. Where the key comes from once
  serve can hold several wallets, or none, is open with the process model; one function in
  `serve` chooses it. The certificate is self-signed, issued to the name `lepic-wallet`, and
  carries the "no expiry" date of RFC 5280, so it never needs renewing. serve writes it to
  `api-tls.pem` in the data directory at each start; a client pins it (`curl --cacert
  api-tls.pem` with that name, or `--pinnedpubkey`), and `GET /v1/status` reports its
  fingerprint. Clients authenticate with their own Ed25519 certificate; the wallet accepts the
  keys listed in `api-clients` in the data directory, one name and SHA-256 key fingerprint per
  line, as `authorized_keys` does for SSH. `lepic api client add|list|remove` edits the file;
  `serve` reads it at every handshake and again at every request, so a removed client is
  refused from its next request, and a TLS connection ends at an age limit, which ends an
  event stream too. Session resumption is off, since a resumed session would skip the
  handshake check. Each listener has its own connection cap. Every
  client listed may call every owner route except those marked `x-socket-only` in the
  document, which answer 403: the password change. An SSH tunnel to the socket remains the
  alternative that needs no LEPIC configuration.
  Decided 2026-11-08: multi-wallet management is dropped for now; serve holds one wallet, so
  the key's source is fixed.
- Payments: `serve --http [--internet] [--coinbase]` adds the payment listener on the wallet serve
  holds, answering `/v2/foreign` only, plain HTTP as other wallets send it, with its own limits.
- Windows has no `serve` today. Its local transport will be a named pipe with an owner-only ACL;
  that is a separate change.
- Addresses and ports come from `settings.toml`; nothing is listened on that the operator did not
  name.
- Seed export has no route: an owner connection that leaks should cost what is in the wallet,
  not the seed. Whether `serve` may create or restore a wallet while it holds none, on the socket
  only, is open.
  Decided 2026-11-08: multi-wallet management is dropped for now; serve holds one wallet; creating
  or restoring a wallet over the API is parked with it.

### Transaction methods

A send names its method (`epicbox`, `http`, `tor`, `file`) and its destination; the method
decides what the slate may carry (payment proof, TTL) and how it is encoded and delivered.
`GET /v1/methods` lists the methods the build and settings offer and what each carries. ADR 0051
places the methods in one crate outside the engine; the API contract does not depend on that
layout.

Decided 2026-11-08: multi-wallet management is dropped for now; serve holds one wallet; creating or
restoring a wallet over the API is parked with it.

### Bounds

The socket and the TLS listener share one cap on connections in flight (extra ones are closed),
a deadline for the request head and body, and a body size limit, set in the `[api]` tuning as the
HTTP listener's are. A TLS handshake has the head's deadline, and a failed one counts as refused. Owner work has no deadline: a scan or a send over a slow relay takes what it takes, and the
client sets its own timeout. Connections are polled with `FuturesUnordered`; the accept back-off
no longer sleeps in the main loop. The runtime stays single-threaded: every wallet call waits on
one SQLite connection.

Changed 2026-11-08: the TLS listener has its own cap of the same size, so connections from the network cannot use up the socket's.

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
HTML or JavaScript. Because a loopback page is reachable from the browser, it answers only
requests whose `Host` is its own address and refuses cross-origin writes. Any local process or
page can reach a loopback port, so the console also admits only a browser holding its secret:
at start it prints a link to stderr whose fragment carries a token, the page trades that token
once for a session kept in the tab's session storage, and every API call carries the session.
The token works once, so a link seen later is spent, and nothing is in a cookie, which a browser
would send to every port of the host. The API reference is
rendered with Scalar, vendored, with web fonts and its request proxy off.

### Writing the code and docs

Comments and docs describe concepts and behaviour. They do not restate numbers, limits, versions
or defaults that live in code or settings, since those change and the prose would not; they name
the setting or constant instead.

## Consequences

- One contract for the CLI's JSON and the API. A JSON shape change is an API change and follows
  the versioning rule; the drift test and the schema tests fail on an unplanned one.
- `utoipa` becomes a product dependency of `lepic-cli`, with its derive macros on the report
  types.
- Integrators use any HTTP client, generated or hand-written, against a published schema.
- Local use needs no setup beyond running `serve`. Remote owner access is off until the operator
  turns it on and lists a client; it needs no secret in requests and gets forward secrecy from
  TLS 1.3. It adds `rcgen` for the self-signed certificates and a client-key verifier of our own
  over rustls.
- The tor-binary, library-directory, relative-path and ignored-option problems of the line
  protocol go away with it: a route has only the fields its schema lists.
- Scripts that use `lepic --service` move to the API. Within LEPIC that is one acceptance step.
- The app and the binding do not use `serve`; the FFI and the receive wire format are unchanged.

## Alternatives considered

- **JSON-RPC 2.0 with an OpenRPC document** (bitcoind, Monero, Ethereum). Familiar to node
  operators, but one POST path hides the API from HTTP tooling, caches and gateways, and the
  documentation tools are thinner. epic-wallet's owner API is this shape.
- **A hand-written spec in YAML, or in TOML converted at build time.** A second source to keep in
  step with the code, and TOML is no OpenAPI format, so every tool would see only the converted
  file.
- **Keep the line protocol and document it**. Least code, but it stays a CLI over a socket: no
  schema per call, every option reachable.
- **TLS or tokens for local calls too** (LND). Certificates and macaroon files to manage on every
  machine, for a caller the socket already identifies.
- **Sealed request bodies** (HPKE to the wallet's key, as epic-wallet v3 does with ECDH). Works
  over any HTTP path, but needs a LEPIC client library in every language, has no forward secrecy
  and has to build its own replay protection. TLS 1.3 already gives all three.
- **API keys or bearer tokens** (BTCPay). Familiar, but the secret travels in every request and
  ends up in logs and shell history.
- **A web UI inside serve**. A second network surface with HTML and session code in the process
  that holds the keys.
