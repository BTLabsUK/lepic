# lepic-peer

The epic1 inbox endpoint between LEPIC wallets. A LEPIC listener that serves epic1 takes a
sealed EPICTX envelope on `POST /api/v1/inbox`, on the same socket as the `epic-wallet` foreign
API, and answers with the reply envelope. A LEPIC sender posts to it the address it read from an
epic1 link. This crate holds both sides: `PeerEndpoint` answers the route and `PeerClient` calls
it. It moves envelope bytes only; opening and sealing them is the wallet's work.

## Where it fits

| Direction | Crates |
|---|---|
| Depends on | external crates only |
| Used by | `lepic-wallet-contacts` (the route on the listener, the client) |

The crate has no features.

What it does not do:

- It does not listen. The listener in `lepic-legacy-rpc` owns the socket, the connection
  budgets and the timeouts, and hands `/api/v1/inbox` requests to the route
  `lepic-wallet-contacts` gives it (`InboxRoute`, over `PeerEndpoint`).
- It does not open or seal envelopes. The `SlateHandler` the host passes in does that on the
  listener's side, and the caller does it on the sender's side.
- It does not choose the protocol. The address does: an epic1 address takes an envelope, a
  classic address a stock slate on the legacy lane.

## Core concepts

### The route

`POST /api/v1/inbox` takes one envelope of type `application/vnd.lepic.epictx` and answers with
the reply envelope, same type. Any other method on the path answers 405.

The route refuses a body over `MAX_ENVELOPE_LEN` (68 KiB) before reading any of it. The
endpoint keeps the replies to the last `MAX_CACHED_REPLIES` (64) envelopes by SHA-256 digest:
the same envelope posted again gets the same reply, so a sender whose answer was lost can
retry. A refused envelope is not kept, and is asked of the handler again.
`PeerAnswer::received` is true only when the wallet took an envelope it had not seen, so the
listener charges only those to its payment budget.

### Problems

Every refusal is an RFC 9457 problem of type `application/problem+json`, with `type`
`about:blank` and a `code`:

| `ProblemCode` | `code` | Status | Meaning |
|---|---|---|---|
| `NotReady` | `not_ready` | 503 | The wallet cannot take slates yet; may carry `Retry-After` |
| `Refused` | `refused` | 422 | The wallet checked the slate and refused it |
| `TooLarge` | `too_large` | 413 | The body is over the limit |
| `RateLimited` | `rate_limited` | 429 | Too many requests; may carry `Retry-After` |
| `UnsupportedFormat` | `unsupported_format` | 415 | The envelope's format is not served |

A `SlateHandler` refuses with `PeerRefusal` (`Refused`, `NotReady`, `UnsupportedFormat`); the
listener sends the other two. `problem_response` builds any of them. `PeerClient` turns each
into its own `PeerClientError` variant.

### The client

`PeerClient` speaks HTTP/1.1 over rustls with the caller's TLS settings, follows no redirects
and reads at most `PeerClientSettings::max_response_bytes` of an answer, within its connect and
request timeouts.

- `to_other_computers` builds a client that refuses loopback and unspecified addresses with
  `PeerClientError::ThisComputer`. `AddressClass` names which kind was refused.
- `to_link_hosts` builds a client for a host read from a payment link. It refuses this
  computer the same way, and an address the caller's classifier names local with
  `PeerClientError::LocalNetwork`. Each resolved address is checked, and the connected one.
- `with_dialer` takes a `PeerDialer`, such as a tor stream; TLS and the `Host` header use
  the target's host.
- `post_slate(target, envelope)` posts one envelope and returns the reply bytes as they came.

`PeerTarget` is the endpoint to call: scheme, host, port and path. `Origin` is its scheme, the
lowercased host and the port, or the bare name of an onion.

## Public API

| Item | Purpose |
|---|---|
| `PeerEndpoint`, `SlateHandler`, `HandlerFuture` | The listener's side of the route |
| `PeerAnswer`, `PeerRefusal` | What came of a request |
| `Problem`, `ProblemCode`, `problem_response` | Refusals as problem details |
| `PeerClient`, `PeerClientSettings`, `PeerDialer`, `PeerStream`, `PeerDialFuture` | The sender's side |
| `PeerTarget`, `Origin`, `WebScheme`, `OriginError` | Where to post |
| `PeerClientError`, `PeerFormatError`, `AddressClass` | Errors |

Constants:

| Constant | Value |
|---|---|
| `PEER_PATH` | `"/api/v1/inbox"` |
| `ENVELOPE_MEDIA_TYPE` | `"application/vnd.lepic.epictx"` |
| `MAX_ENVELOPE_LEN` | 69,632 bytes (68 KiB) |
| `MAX_CACHED_REPLIES` | 64 |

## Related

- [EPICTX](../../docs/protocols/epictx.md), [HTTP](../../docs/protocols/http.md),
  [Tor](../../docs/protocols/tor.md)
- [RFC 0003 EPICTX native slates](../../docs/rfcs/0003-epictx-native-slates.md)
- ADRs: [0062 the address decides the protocol](../../docs/adr/0062-the-address-decides-the-protocol.md),
  [0044 the onion's own key](../../docs/adr/0044-the-onion-has-its-own-key.md)
- [`lepic-legacy-rpc`](../lepic-legacy-rpc/README.md), [`lepic-wallet-contacts`](../lepic-wallet-contacts/README.md)
