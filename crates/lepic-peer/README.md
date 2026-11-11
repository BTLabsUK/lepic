# lepic-peer

The native direct endpoint between LEPIC wallets (ADR 0052). A LEPIC listener serves the
`/api/v1/inbox` routes on the same socket as the `epic-wallet` foreign API and names them in its
`check_version` answer. A LEPIC sender reads that advert, then posts a sealed EPICTX envelope
to `/api/v1/inbox` instead of a legacy slate. This crate holds both sides: `PeerEndpoint`
answers the routes and `PeerClient` calls them. It moves envelope bytes only; opening and
sealing them is the wallet's work.

## Where it fits

| Direction | Crates |
|---|---|
| Depends on | `lepic-primitives` (the network) |
| Used by | `lepic-legacy-rpc` (serves the routes), `lepic-methods`, `lepic-wallet-contacts` |

The crate has no features.

What it does not do:

- It does not listen. The listener in `lepic-legacy-rpc` owns the socket, the connection
  budgets and the timeouts, and hands `/api/v1/inbox` requests to `PeerEndpoint`.
- It does not open or seal envelopes. The `SlateHandler` the host passes in does that on the
  listener's side, and the caller does it on the sender's side.
- It does not choose between the native and the legacy route. `lepic-methods` does, from the
  advert.

## Core concepts

### The advert

A LEPIC listener adds a `lepic` key to its `check_version` answer. `Advert` is that object:

```json
{
  "protocol": 2,
  "formats": ["lepic.v1"],
  "path": "/api/v1/inbox",
  "seal": "<64 hex digits>"
}
```

`seal` is the listener's seal key, the X25519 key a sender seals an envelope to.
`Advert::from_json` refuses a missing field, a key that is not 64 hex digits, a path that is
not absolute, or more than 16 formats or names longer than 64 characters. `Advert::offers`
tells whether a format is on the list. A listener without a `lepic` key speaks the legacy
foreign API only.

### Routes

| Route | Request | Answer |
|---|---|---|
| `PeerRoute::Info` | `GET /api/v1/inbox` | `PeerInfo` as JSON |
| `PeerRoute::Slates` | `POST /api/v1/inbox`, an envelope of type `application/vnd.lepic.epictx` | The reply envelope, same type |

`PeerInfo` describes the endpoint: `protocol`, `formats`, `network` (`"mainnet"` or
`"floonet"`) and `key`, the seal key in hex.

The slates route refuses a body over `MAX_ENVELOPE_LEN` (68 KiB) before reading any of it. The
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
- `with_dialer` takes a `PeerDialer`, such as a tor stream; TLS and the `Host` header use
  the target's host.
- `info(target)` reads `GET /api/v1/inbox` and checks it.
- `post_slate(target, envelope)` posts one envelope and returns the reply bytes as they came.

`PeerTarget` is the endpoint to call: scheme, host, port and the advert's path. `Origin` is
what a sender keeps a listener's seal key under (RFC 0003 §5.15): the scheme, the lowercased
host and the port, or the bare name of an onion.

## Public API

| Item | Purpose |
|---|---|
| `Advert`, `PeerInfo` | The advert in `check_version` and the answer of `GET /api/v1/inbox` |
| `PeerEndpoint`, `SlateHandler`, `HandlerFuture` | The listener's side of the routes |
| `PeerRoute`, `PeerAnswer`, `PeerRefusal` | Which route a request is for, and what came of it |
| `Problem`, `ProblemCode`, `problem_response` | Refusals as problem details |
| `PeerClient`, `PeerClientSettings`, `PeerDialer`, `PeerStream`, `PeerDialFuture` | The sender's side |
| `PeerTarget`, `Origin`, `WebScheme`, `OriginError` | Where to post, and what a pin is kept under |
| `PeerClientError`, `PeerFormatError`, `AddressClass` | Errors |
| `to_hex`, `key_from_hex` | Seal keys as text |

Constants:

| Constant | Value |
|---|---|
| `PROTOCOL` | `1`; an additive change keeps it, a break takes another path |
| `FORMAT_LEPIC_V1` | `"lepic.v1"` |
| `PEER_PATH` | `"/api/v1/inbox"`, the one path for `GET` and `POST` |
| `ENVELOPE_MEDIA_TYPE` | `"application/vnd.lepic.epictx"` |
| `MAX_ENVELOPE_LEN` | 69,632 bytes (68 KiB) |
| `SEAL_KEY_LEN` | 32 |
| `MAX_CACHED_REPLIES` | 64 |

## Related

- [EPICTX](../../docs/protocols/epictx.md), [HTTP](../../docs/protocols/http.md),
  [Tor](../../docs/protocols/tor.md)
- [RFC 0003 EPICTX native slates](../../docs/rfcs/0003-epictx-native-slates.md),
  [RFC 0001 LEPIC slate v1](../../docs/rfcs/0001-lepic-slate-v1.md)
- ADRs: [0052 legacy at the edge, native between LEPIC wallets](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md),
  [0044 the onion's own key](../../docs/adr/0044-the-onion-has-its-own-key.md)
- [`lepic-legacy-rpc`](../lepic-legacy-rpc/README.md), [`lepic-methods`](../lepic-methods/README.md)
