# 0017 The wallet foreign API over HTTP in its own crate

Status: accepted
Date: 2026-10-21

## Context

The owner decided (feature-gap assessment §10, D2) that direct transactions are first-class in
LEPIC and the app: HTTP and HTTPS send, the HTTP listener, and Tor on top of them. This
reverses the 1.0 non-goals for an HTTP listener and a foreign JSON-RPC server. The reference is
`epic-wallet` `v4.1.0` (D7): `send -m http` posts JSON-RPC 2.0 to `<url>/v2/foreign`
(`check_version`, then `receive_tx` with the S1), and `listen -m http` answers `receive_tx`
with the S2 in the same exchange. Answers are wrapped in `result.Ok` or `result.Err`.

The method needs an HTTP client with TLS, the same stack `lepic-node` uses, and an HTTP server,
which no crate has. The client and the server share the message shapes.

## Decision

- A new crate `lepic-foreign` holds the foreign API over HTTP: the JSON-RPC messages
  (`rpc`), the address syntax (`url`), the client, the listener and the `http` transport. It
  depends on `lepic-transport` and `lepic-slate` only, plus hyper, hyper-util, hyper-rustls,
  rustls and webpki-roots from the workspace table. `lepic-cli` and `lepic-ffi` depend on it.
  The engine does not: it sees the method as one more `Transport`, and the listener reaches the
  engine through a `ReceiveHandler` the host implements over `Wallet::receive_unsolicited`.
  That applies the total open receipt cap the Epicbox inbox uses (`MAX_OPEN_RECEIPTS`) to
  receipts of the `http` transport, counted apart from Epicbox's; an HTTP sender has no key,
  so there is no per-sender cap. A payment refused at the cap is answered "wallet not ready".
- The transport's outbound side posts the S1 and keeps the receiver's S2, keyed by the S1's
  slate id, for the host to finalize; an answer that carries another slate id is refused. It
  has no inbound side. Its policy matches the Epicbox method's: V3 and V2 accepted, a new
  slate in the V2 shape, a reply in the shape it answers.
- Plain `http` goes to loopback, or to another host only when the host app passes the user's
  consent (`PlainHttp::Allowed`); `.onion` addresses are refused until Tor exists.
- The listener serves only `check_version` and `receive_tx`; every other method answers
  "method not found". It binds `127.0.0.1` unless the user picks "From the internet"
  (`0.0.0.0`, IPv4 only: a dual-stack socket needs a socket option neither Tokio nor the
  standard library sets, and no crate in the workspace table offers it). Bounded per listener:
  16 connections at once and 4 from one remote address (kept in memory only, never logged),
  10 s for the headers, 15 s for the body, 60 s for the request, and every connection ends
  after header, request and answer time together (10 s more to take the answer); bodies up to
  the slate size limit; 120 requests a minute (more answer 503); and 30 `receive_tx` calls a
  minute whose slate has the fields of an S1 (`id`, `amount`, `participant_data`), the others
  not counted.

## Consequences

- A LEPIC wallet can pay, and be paid by, any `epic-wallet` 4.x or GUI wallet over HTTP.
- `docs/architecture.md` gains the crate and its edges; the project rules drop the
  HTTP listener and the foreign JSON-RPC server from the non-goals (D2).
- Tor reuses the client through a SOCKS5 connector and the listener behind an onion service.
- Invoices over HTTP (`finalize_invoice_tx`) are not served: an invoice arriving unannounced
  would be paid by no one, and Epicbox carries invoices.
