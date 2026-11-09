# ADR 0017: The wallet foreign API over HTTP in its own crate

Status: accepted

## Context

Direct transactions are first-class in LEPIC: HTTP and HTTPS send, an HTTP listener, and Tor on
top of both. The reference is `epic-wallet` `send -m http`, which posts JSON-RPC 2.0 to
`<url>/v2/foreign` (`check_version`, then `receive_tx` with the S1), and `listen -m http`, which
answers `receive_tx` with the S2 in the same exchange. Answers are wrapped in `result.Ok` or
`result.Err`.

The method needs an HTTP client with TLS, the stack `lepic-node` uses, and an HTTP server, which
no other crate has. The client and the server share the message shapes.

## Decision

### Crate

`lepic-legacy-rpc` holds the foreign API over HTTP: the JSON-RPC messages (`rpc`), the address
syntax (`url`), the client (`client`, `dial`), the listener (`server`) and the errors. It
depends on `lepic-peer`, `lepic-slate` and `lepic-transport`, plus hyper, hyper-util,
hyper-rustls, rustls and webpki-roots from the workspace table. The engine does not depend on
it.

The `http` transport, its format policy and the listener's `ReceiveHandler` are in
`lepic-methods` (`lepic_methods::http`), which re-exports the crate's types. `lepic-cli` and
`lepic-ffi` reach the crate through it. `lepic-tor` uses the same server behind an onion
service (ADR 0018).

### Client and transport

- The transport's outbound side posts the S1 and keeps the receiver's S2, keyed by the id of the
  S1, for the host to finalize. An answer that carries another slate id is refused. At most 64
  answers are held; the oldest is dropped and its sender can send again. The transport has no
  inbound side.
- The format policy matches `epic-wallet`: V3 and V2 accepted, a new slate in the V2 shape, a
  reply in the shape it answers.
- Plain `http` goes to loopback, or to another host only when the host app passes the user's
  consent (`PlainHttp::Allowed`). An `.onion` address is refused by the URL parser
  (`UrlError::OnionNeedsTor`) and goes through the Tor method.
- The default listener port is 3415 (`DEFAULT_LISTEN_PORT`).

### Listener

- It serves `check_version` and `receive_tx` at `/v2/foreign`. Every other method answers
  "method not found". Invoices (`finalize_invoice_tx`) and the owner API are not served. A
  listener also serves a mining node's `build_coinbase` when the host sets
  `ListenSettings::coinbase` (ADR 0046, ADR 0048); by default that method answers as unknown.
- It binds `127.0.0.1` (`Exposure::LocalOnly`) unless the user picks "From the internet"
  (`Exposure::Internet`, `0.0.0.0`, IPv4 only: a dual-stack socket needs a socket option that
  neither Tokio nor the standard library sets). On Unix a listener can also bind a socket path
  (`listen_unix`).
- Every caller is untrusted and its cost is bounded per listener: connections at once and from
  one remote address (kept in memory only), time for the headers, the body and the whole
  request, time for the caller to take the answer (a connection ends after the three together),
  body size (`MAX_BODY_LEN`, the slate size limit plus 64 KiB), requests per minute (more are
  answered 503), and `receive_tx` calls per minute whose slate has the fields of an S1 (`id`,
  `amount`, `participant_data`; other calls are not counted).
- The per-minute budgets cannot tell callers apart (behind an onion every caller is
  `127.0.0.1`), so requests that are not payments cannot use up the room payments have, and a
  payment the wallet refuses as invalid gives its share back.
- The values are the caller's (ADR 0030, ADR 0036): `ListenLimits` and `ClientSettings` have no
  default. The CLI ships them in `[http]` of `lepic-config.toml`: 16 connections, 4 per address,
  10 s for headers, 15 s for the body, 60 s for the request, 10 s for the answer, 120 requests
  and 30 payments a minute.
- The listener reaches the engine through a `ReceiveHandler` that the host implements over
  `Wallet::receive_unsolicited`. That applies the open-receipt caps of the wallet policy to
  receipts of the `http` transport, counted apart from Epicbox's. An HTTP sender has no key, so
  there is no per-sender cap. A payment refused at the cap is answered "wallet not ready"
  (`Refusal::Unavailable`); a slate refused for good is answered "slate refused".
- `receive` returns the same S2 for the same S1, so a sender whose answer was lost can retry.

## Consequences

- A LEPIC wallet can pay, and be paid by, any `epic-wallet` 4.x or GUI wallet over HTTP.
- Tor reuses the client through a connector (`RpcDialer`) and the listener behind an onion
  service.
- An invoice arriving unannounced would be paid by no one, and Epicbox carries invoices.

## Related

- ADR 0003, ADR 0018, ADR 0030, ADR 0036, ADR 0046, ADR 0052
