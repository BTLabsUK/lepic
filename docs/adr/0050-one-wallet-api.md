# ADR 0050: One wallet API, served by `lepic serve`

Status: proposed. The paths, the generated document, the bodies shared with the CLI and the
all-or-nothing TLS clients are superseded by [ADR 0055](0055-the-wallet-api-v1.md).

## Context

`lepic serve` holds one unlocked wallet. Integrators, such as a shop, a bot or a monitor, need to
call it from other programs. They expect what wallets and payment servers ship: one documented
HTTP API with a machine-readable schema, stable error codes and a version in the path.

A request that is a CLI command line has no version and no schema. Every CLI option would reach the
running wallet, including the tor binary and file paths relative to the server's directory. Some
owner functions need to exist as calls: a list of outputs, a password change, metrics.

## Decision

### One API, one specification

- The API is HTTP/1.1 with JSON bodies, resource-oriented, described by one OpenAPI 3.1 document.
  Owner calls live under `/v1`. The payment endpoint other Epic wallets post to, `POST /v2/foreign`
  (JSON-RPC 2.0), and the native endpoint `/api/v1/inbox` (ADR 0052) are in the
  same document with no security requirement. Their wire formats do not change with the API
  (ADR 0017).
- The document is generated from the Rust types and the route table with `utoipa`. Doc comments
  on the types and routes are the only hand-written source. It is committed as
  `docs/api/openapi.json`, served at `GET /v1/openapi.json` and rendered by the console. A test
  fails when the committed file differs from what the code generates, so a change to the API shows
  in review as a diff of that file.
- A handler builds the arguments of a CLI command from the request and runs the command the CLI
  runs. The response bodies are the JSON `lepic --output json` prints, so the CLI and the API
  share one schema and nothing is implemented twice.
- Amounts are decimal strings in EPIC. Transactions are addressed by `tx_id`. A send takes an
  optional client-chosen `slate_id`, which makes a repeated request safe: it reports the first
  send. Slates for the file method travel in request and response bodies, never as paths.
- Errors are RFC 9457 problem details (`application/problem+json`) with `status`, `title`,
  `detail` and a `code` member. `code` is the error kind the CLI reports, one closed list in the
  document, and each kind has one HTTP status.
- `/v1` changes only by addition: new routes, new optional request fields, new response fields.
  Clients ignore fields they do not know. A breaking change is a `/v2`. `info.version` in the
  document is the API version.

### Transports and authentication

The connection proves who calls. No password, token or key travels in a request.

- Socket, the listener every `serve` has: a Unix socket in the data directory (`lepic.sock`),
  mode 0600, with the peer's uid checked against the process's own. The OS user is the
  credential. A loopback TCP port would be reachable by every local user and by any web page
  through DNS rebinding; the socket is reachable by neither.
- Owner TLS, only with `serve --owner-tls`: a TCP listener with mutual TLS 1.3 on the address
  `[api] owner_tls` in `settings.toml` names. With no address set, `--owner-tls` refuses to start.
  - The server key is the wallet's `api tls` namespace key (ADR 0033, label
    `lepic-wallet api tls v1`), so a restored wallet keeps its identity and clients keep their pin.
    One function in `serve` chooses the key.
  - The certificate is self-signed, issued to the name `lepic-wallet`, with the "no expiry" date of
    RFC 5280, so it never needs renewing. `serve` writes it to `api-tls.pem` in the data
    directory at each start. A client pins it, and `GET /v1/status` reports its fingerprint (the
    SHA-256 of the public key info).
  - A client presents its own Ed25519 certificate. The wallet accepts the keys listed in
    `api-clients` in the data directory, one name and SHA-256 key fingerprint per line, as
    `authorized_keys` does for SSH. `lepic api client add|list|remove` edits the file.
  - `serve` reads the file at every handshake and again at every request, so a removed client is
    refused from its next request. A TLS connection ends at an age limit, which ends an event
    stream too. Session resumption is off, since a resumed session would skip the handshake check.
  - A listed client may call every owner route except those marked `x-socket-only`, which answer
    403. The password change is the only one. A send over this listener needs a `slate_id`, and an
    `http` send goes to other computers only.
- Payments: `serve --http [--internet] [--coinbase]` adds the payment listener on the wallet `serve`
  holds. It answers the endpoints without security requirement, over plain HTTP as other wallets
  send, with its own limits (ADR 0048 for `--coinbase`).
- `serve` runs on Unix only. On other platforms the command fails with `ServiceUnsupported`.
- Addresses and ports come from `settings.toml`. Nothing is listened on that the operator did not
  name.
- Seed export has no route, so a leaked owner connection costs what is in the wallet and not the
  seed. `serve` holds one wallet and does not create or restore one.

### Transaction methods

A send names its method (`epicbox`, `http`; ADR 0051) and its destination. The method decides what
the slate may carry and how it is delivered. `GET /v1/methods` lists the registered methods and
what each can do. The API contract does not depend on the crate layout of the methods.

### Bounds

The socket and the TLS listener each have a cap on connections in flight (extra ones are closed),
so connections from the network cannot use up the socket's. Both share a deadline for the request
head and for the body, and a body size limit. They are set in the `[api]` section of the CLI's
built-in configuration, as the HTTP listener's are. A TLS handshake has the head's deadline, and a
failed one counts as refused. Owner work has no deadline: a scan or a send over a slow relay takes
what it takes, and the client sets its own timeout.

The runtime is single-threaded, since every wallet call waits on one SQLite connection.
Connections are polled with `FuturesUnordered`.

### What else `serve` answers

- `GET /v1/status`: uptime, requests served, in flight and refused, the state of Epicbox and of
  each listener, the wallet's height and the node's tip, and the refresh and collect results. Facts
  only: thresholds and alerts belong to the consumer.
- `GET /v1/events`: the engine's events as a server-sent event stream, so a shop or bot learns of a
  payment without polling. A client that falls behind gets a `lagged` event.
- `PUT /v1/wallet/password` (re-encrypts the vault) and `GET /v1/outputs` (`Wallet::outputs`).
- The contact, in-person, epic1 and `.epictx` routes follow the same rules as the rest.

### The console

`lepic-console` shows stats, status, basic management and the rendered API reference. It is a
separate program in its own workspace under `console/` and a client of the API like any other. It
reaches `serve` over the socket and serves a local page on loopback. It depends on no LEPIC crate,
so it cannot pull policy into the wallet core, and the `lepic` binary carries no HTML or
JavaScript.

A loopback page is reachable from the browser, so the console:

- answers only requests whose `Host` is its own address, and refuses cross-origin writes;
- admits only a browser holding its secret: at start it prints a link to stderr whose fragment
  carries a token, the page trades that token once for a session kept in the tab's session
  storage, and every API call carries the session;
- keeps nothing in a cookie, which a browser would send to every port of the host;
- proxies a fixed list of API routes and nothing else.

The API reference is rendered with Scalar, vendored, with web fonts and its request proxy off.

### Code and docs

Comments and docs describe concepts and behaviour. They name the setting or constant rather than
restate numbers, limits, versions or defaults that live in code or settings.

## Consequences

- One contract for the CLI's JSON and the API. A JSON shape change is an API change and follows the
  versioning rule. The drift test and the schema tests fail on an unplanned one.
- `utoipa` is a product dependency of `lepic-cli`, with its derive macros on the report types.
- Integrators use any HTTP client, generated or hand-written, against a published schema.
- Local use needs no setup beyond running `serve`. Remote owner access is off until the operator
  turns it on and lists a client. It needs no secret in requests and gets forward secrecy from
  TLS 1.3. It needs `rcgen` for the certificate and a client-key verifier over rustls.
- A route has only the fields its schema lists, so no CLI option, tor binary or relative path
  reaches the wallet through it.
- The app and the binding do not use `serve`.

## Alternatives considered

- **JSON-RPC 2.0 with an OpenRPC document.** Familiar to node operators, but one POST path hides
  the API from HTTP tooling, caches and gateways, and the documentation tools are thinner.
- **A hand-written spec in YAML, or in TOML converted at build time.** A second source to keep in
  step with the code. TOML is no OpenAPI format, so every tool would see only the converted file.
- **Keep a CLI-line protocol and document it.** Least code, but it stays a CLI over a socket: no
  schema per call, every option reachable.
- **TLS or tokens for local calls too.** Certificates and key files to manage on every machine,
  for a caller the socket already identifies.
- **Sealed request bodies** (HPKE to the wallet's key). Works over any HTTP path, but needs a
  LEPIC client library in every language, has no forward secrecy and needs its own replay
  protection. TLS 1.3 gives all three.
- **API keys or bearer tokens.** The secret travels in every request and ends up in logs and shell
  history.
- **A web UI inside `serve`.** A second network surface with HTML and session code in the process
  that holds the keys.

## Related

- ADR 0017: direct transactions over HTTP.
- ADR 0033: keys and domains.
- ADR 0048: block rewards for this computer.
- ADR 0051: transaction methods in one crate.
- ADR 0052: legacy at the edge, native between LEPIC wallets.
