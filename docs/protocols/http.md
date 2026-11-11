# HTTP

A LEPIC wallet sends and receives slates over HTTP in two ways. With any Epic wallet it speaks
the wallet foreign API: JSON-RPC 2.0 at `/v2/foreign`, wire-compatible with epic-wallet v4.1.0
`send -m http` and `listen -m http` ([ADR 0017](../adr/0017-foreign-api-over-http.md)). A LEPIC
listener also advertises a native direct endpoint at `/api/v1/inbox`, where two LEPIC wallets swap
sealed `lepic.v1` slates
([ADR 0052](../adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)). This guide covers
addresses, the foreign API, sending, listening and the native endpoint. The same exchanges run
over [Tor](tor.md) at `<onion>:80`.

| Crate | Holds |
|---|---|
| [`lepic-legacy-rpc`](../../crates/lepic-legacy-rpc/README.md) | Listener addresses, the foreign API messages, the client and the listener |
| [`lepic-peer`](../../crates/lepic-peer/README.md) | The native endpoint: advert, routes, problems, client, origins |
| [`lepic-methods`](../../crates/lepic-methods/README.md) (`http`) | The HTTP method: `Http`, `Receiver`, `HttpPeer` |

## Addresses

`ListenerUrl::parse(input, plain_http)` reads the address of another wallet's listener:

- The scheme is `http` or `https`, in any case, and is required.
- A missing port is 3415 (`DEFAULT_LISTEN_PORT`) for `http` and 443 for `https`.
- A path is kept, and `/v2/foreign` is appended unless the path already ends with it.
- `?`, `#`, `@` or whitespace is refused: no credentials, query or fragment.
- A `.onion` host is refused; onions go through the [Tor](tor.md) method.

`PlainHttp` says whether plain `http` may reach another computer:

| Value | Plain `http` to |
|---|---|
| `LoopbackOnly` (default) | This computer only |
| `Allowed` | Any host; set only after the sender agreed that the slate travels unencrypted |

```rust
let url = ListenerUrl::parse("https://wallet.example", PlainHttp::LoopbackOnly)?;
assert_eq!(url.port(), 443);
```

| `UrlError` | Message |
|---|---|
| `NotHttp` | the address is not an http or https url |
| `NoHost` | the address has no host |
| `ExtraParts` | the address carries credentials, a query or a fragment |
| `InvalidPort` | the address has an invalid port |
| `PlainHttpNotAllowed` | plain http to another computer needs the sender's consent |
| `OnionNeedsTor` | onion addresses go through tor |

## The foreign API

Every call is a JSON-RPC 2.0 `POST` to `/v2/foreign`. An answer wraps its result in
`result.Ok`, or a refusal in `result.Err`.

### `check_version`

```json
{"jsonrpc":"2.0","method":"check_version","id":1,"params":[]}
```

A LEPIC listener answers:

```json
{"id":1,"jsonrpc":"2.0","result":{"Ok":{"foreign_api_version":2,"supported_slate_versions":["V3","V2"],"lepic":{"protocol":2,"formats":["lepic.v1"],"path":"/api/v1/inbox","seal":"<64 hex>"}}}}
```

The `lepic` key is the [advert](#the-advert); a listener without the native endpoint leaves it
out. The client reads the answer into `VersionInfo { foreign_api_version, v3, v2, lepic }`:

- a `foreign_api_version` below 2 is `Incompatible`;
- more than 16 slate versions is `Malformed`;
- a `lepic` key that does not read counts as no advert.

### `receive_tx`

```json
{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[<slate>,null,null,null]}
```

The three optional parameters are the account, a message and the sender's address. A LEPIC
listener uses only the slate and pays into the default account. The answer is the S2 in
`result.Ok`, which must be a JSON object. A refusal is
`{"Err":{"GenericError":"<reason>"}}`:

| `Refusal` | Reason | Meaning |
|---|---|---|
| `Rejected` | `slate refused` | The slate was checked and refused for good |
| `Unavailable` | `wallet not ready` | Locked, or the node is not ready; the sender may retry |

### `build_coinbase`

The node's call for a block reward. The listener answers it only when the host turns it on
(see [Listening](#listening)).

### Constants and errors

| Constant | Value |
|---|---|
| `FOREIGN_API_VERSION` | 2 |
| `MAX_BODY_LEN` | `MAX_WIRE_SLATE_LEN` + 64 KiB |
| `KEY_ID_LEN` | 17 |
| Parameters read | 4 |

| JSON-RPC code | When |
|---|---|
| -32700 | The body is not JSON |
| -32600 | Not a JSON-RPC 2.0 request |
| -32601 | Unknown method, or `build_coinbase` not served to this caller |
| -32602 | Invalid parameters |

| `RpcError` | Message |
|---|---|
| `TooLarge` | the body is larger than a foreign api message can be |
| `Malformed` | the body is not a foreign api answer |
| `NotJson` | the slate is not json |
| `Refused` | the other wallet refused the request |
| `Incompatible` | the other wallet speaks a foreign api older than version 2 |

## Sending

`Http::new(client)` is the HTTP method. Its `post` takes the address the user typed:

1. Parses it with `PlainHttp::Allowed`, as consent was given when the address was typed.
2. Calls `check_version` and requires version 2.
3. Calls `receive_tx` with the slate.
4. Checks that the answer's slate id is the sent one; another id is `Rpc(Malformed)`.

The answer is held for the wallet, which takes it with `take_reply(slate_id)`. At most 64
answers are held (`MAX_HELD_REPLIES`); when full, the oldest is dropped. `through(client)` gives
the same method over another client, and `is_direct(transport)` is true for `http` and `tor`.

`HttpPolicy` reads V3 then V2 by shape, writes V2 for a new slate, and replies in the shape it
answers.

`RpcClient` holds `ClientSettings { connect_timeout, request_timeout, max_response_bytes }` and a
rustls configuration. `webpki_tls_config()` builds one with the ring provider and the Mozilla
roots. The client follows no redirects. `RpcClient::to_other_computers` refuses an address that
resolves to loopback or unspecified; private and link-local addresses are allowed.

| `ClientError` | Message |
|---|---|
| `Url` | invalid destination |
| `TlsConfig` | tls configuration failed |
| `ThisComputer` | the address is one of this computer's own, which this client does not send to |
| `Unreachable` | could not reach the other wallet |
| `Timeout` | the other wallet did not answer in time |
| `Status` | the other wallet answered with http status {status} |
| `NotFound` | the other wallet has no foreign api at this address |
| `ResponseTooLarge` | the answer is larger than {max} bytes |
| `Rpc` | the answer could not be read |
| `NoCommonVersion` | the other wallet offers no slate version this wallet sends |

## Listening

`listen(settings, handler)` binds a TCP socket and serves `check_version` and `receive_tx` at
`/v2/foreign`. It takes payments only: invoices and the owner API are not served.
`listen_with(settings, handler, peer)` also serves the native endpoint and puts its advert in
`check_version`.

On Unix, `listen_unix(path, ...)` and `listen_unix_with` serve the same on a Unix-domain socket,
for a listener only the wallet's tor reaches. A file left at `path` is replaced, and every
connection counts as one address, as every sender does behind an onion.

| `Exposure` | Binds |
|---|---|
| `LocalOnly` | `127.0.0.1` |
| `Internet` | `0.0.0.0`, every IPv4 interface, for a port forwarded from the internet |

`ListenSettings::new(exposure, port, limits)` takes a `ListenLimits`; port 0 picks a free port.

| Limit | Bounds |
|---|---|
| `max_connections` | Connections at once |
| `max_connections_per_address` | Connections at once from one remote address |
| `header_timeout` | The request line and headers |
| `body_timeout` | The body, once the headers are in |
| `request_timeout` | First byte of the request to last byte of the answer |
| `answer_timeout` | The caller taking the answer |
| `requests_per_minute` | Requests of any kind in one minute |
| `receives_per_minute` | `receive_tx` calls carrying an S1 in one minute |

Past `requests_per_minute`, only `receives_per_minute` more requests are read, and only payments
among them are served; the rest get 503. A payment the wallet refuses as `Rejected` gives its
share of the budget back. A connection ends at the latest after
`header_timeout + request_timeout + answer_timeout`.

| Status | When |
|---|---|
| 404 | Another path |
| 405 | Not `POST` |
| 408 | The body, or the whole request, took too long |
| 413 | A body over `MAX_BODY_LEN` |
| 500 | The answer could not be encoded |
| 503 | Over budget |

`with_coinbase(access)` sets who gets `build_coinbase`:

| `CoinbaseAccess` | Served to |
|---|---|
| `Off` (default) | Nobody: answered as an unknown method |
| `LocalOnly` | Loopback callers: a node on this computer or a tunnel to it |
| `Remote` | Every caller, within the listener's limits |

| `ListenError` | Message |
|---|---|
| `PortInUse` | port {port} is in use |
| `Bind` | could not listen on port {port} |

### The wallet behind the listener

A `ReceiveHandler` receives one S1 and returns the S2. The same S1 sent again must return the
same S2, so a sender whose answer was lost can retry. In `lepic-methods`,
`Receiver::new(host, method, proof_key)` is the handler of both the HTTP and the Tor listener. It
keeps `Counts { received, repeated, refused }`, and refuses as `Rejected` when the same slate would
fail again and as `Unavailable` otherwise.

## The native endpoint

### The advert

| Key | Value |
|---|---|
| `protocol` | 2 |
| `formats` | `["lepic.v1"]`; at most 16, of at most 64 characters |
| `path` | `/api/v1/inbox`; at most 256 characters, starting with `/` |
| `seal` | The listener's seal key, 64 hex: kind `01` on the onion, `02` on the web listener |

`Advert::new(seal)`, `to_json` and `from_json` build and read it. A reader ignores unknown keys.
`Probe::new(scheme, host, port, advert)` in `lepic-methods` counts an advert of another
protocol, or one without `lepic.v1`, as none.

### Routes

| Request | Answer |
|---|---|
| `GET /api/v1/inbox` | `application/json`: `protocol`, `formats`, `network` (`mainnet` or `floonet`), `key` (64 hex) |
| `POST /api/v1/inbox` | The reply envelope, `application/vnd.lepic.epictx` |

The POST body is a slate envelope sealed anonymously to the listener's seal key, with a reply
key; see [EPICTX](epictx.md). Its `Content-Type` is `application/vnd.lepic.epictx`, and it is at
most 69,632 bytes (`MAX_ENVELOPE_LEN`). A declared length over that is refused before any of the
body is read. The listener seals the S2 to the reply key.

A payment sealed to one of the wallet's epic1 addresses is taken here only when the user turned
that on for the listener: `epic1_web_listener` or `epic1_onion_listener` in the CLI,
`set_epic1_at_listener` in the FFI. Both are off by default; the listener then answers such a
payment as one sealed to a key it does not hold, so whoever has an epic1 address cannot tell that
the listener is the same wallet. The setting takes effect at the next listener start.

The endpoint keeps the last 64 replies (`MAX_CACHED_REPLIES`) by the SHA-256 of the envelope, so a
repeated envelope gets the same bytes. Refusals are not cached. Peer routes spend the same budgets
as the foreign API.

| Constant | Value |
|---|---|
| `PROTOCOL` | 2 |
| `FORMAT_LEPIC_V1` | `lepic.v1` |
| `PEER_PATH` | `/api/v1/inbox` |
| `ENVELOPE_MEDIA_TYPE` | `application/vnd.lepic.epictx` |
| `MAX_ENVELOPE_LEN` | 69,632 |
| `SEAL_KEY_LEN` | 32 |

### Problems

Errors are RFC 9457 `application/problem+json` with `type` `about:blank` and a `code`. A late
body gets a bare 408.

| `code` | Status | Title |
|---|---|---|
| `not_ready` | 503 | Not ready |
| `refused` | 422 | Refused |
| `too_large` | 413 | Too large |
| `rate_limited` | 429 | Too many requests |
| `unsupported_format` | 415 | Unsupported format |

`not_ready` carries `Retry-After` in seconds. Over budget, a peer route gets `rate_limited` with
`Retry-After: 60`; a request that timed out in the wallet gets `not_ready`. The wallet behind the
endpoint, a `SlateHandler`, refuses with a `PeerRefusal`: `Refused` (422), `NotReady` (503) or
`UnsupportedFormat` (415).

### The client

`PeerClient::new` or `PeerClient::to_other_computers` builds a client; `with_dialer` sends over
another stream, such as SOCKS5. `info(target)` reads `GET /api/v1/inbox` and
`post_slate(target, envelope)` posts an envelope. `PeerClientSettings::default()` is a 15 s
connect timeout, a 60 s request timeout and answers of at most `MAX_ENVELOPE_LEN`. The client
reads at most 4096 bytes of a problem, reads `Retry-After` in seconds only, and follows no
redirects.

| `PeerClientError` | Message |
|---|---|
| `TlsConfig` | the TLS configuration could not be built |
| `Target` | the address could not be used: {0} |
| `EnvelopeTooLarge` | the envelope is longer than the endpoint takes ({len} bytes, at most {max}) |
| `ThisComputer` | the address is one of this computer's own ({class}) |
| `Unreachable` | the wallet could not be reached |
| `Timeout` | the wallet took too long to answer |
| `NotReady` | the wallet is not ready to take a payment |
| `Refused` | the wallet refused the slate |
| `TooLarge` | the wallet says the envelope is too large |
| `RateLimited` | the wallet is taking no more payments for now |
| `UnsupportedFormat` | the wallet does not read the slate's format |
| `NotFound` | the wallet serves no native endpoint |
| `Status` | the wallet answered with HTTP status {status} |
| `ResponseTooLarge` | the answer is larger than {max} bytes |
| `Format` | the answer could not be read: {0} |
| `NotEnvelope` | the answer is not an envelope |

| `PeerFormatError` | Message |
|---|---|
| `Malformed` | the answer is not the expected JSON |
| `Key` | the seal key is not 64 hex digits |
| `Path` | the endpoint path is not an absolute path |
| `Formats` | the format list is longer than any listener sends |

### Going native and pins

A send goes native only when the wallet has `native_direct` on, the caller did not ask for
legacy, and the listener's `check_version` carries the advert
([RFC 0003 §6.2](../rfcs/0003-epictx-native-slates.md#62-direct-http-or-tor-peer)):

1. The sender reads `check_version`. Without the advert it sends V2 or V3 JSON to `/v2/foreign`.
2. With it, the sender checks the seal key against its pin, seals the S1 to it with a reply key,
   and posts it to `/api/v1/inbox`.
3. The listener opens it, answers, and returns the S2 sealed to the reply key.
4. The sender opens and finalizes it.

A pin is kept per account and origin. The origin is the scheme, the lower-cased host and the
explicit port, such as `https://wallet.example:443`, or the onion name alone. `Wallet::pin_peer`
gives a `PinOutcome`:

| `PinOutcome` | When | Stored |
|---|---|---|
| `Pinned` | The origin had no pin | The key |
| `Seen` | The key equals the pin | The last seen date |
| `Changed { pinned }` | Another key is pinned | Nothing; the user forgets the pin to take the new key |

A pinned origin that stops advertising, or fails, is reported and never paid in legacy format.
The rules are in [RFC 0003 §5.15](../rfcs/0003-epictx-native-slates.md#515-advert-and-native-direct-endpoint).

## From the CLI

```sh
lepic tx send 1.5 --to https://wallet.example
lepic http listen --port 3415
lepic peer pins
lepic peer forget https://wallet.example:443
```

The CLI guide's [Send](../cli.md#send) covers `--allow-plain-http` and `--legacy`,
[After the send](../cli.md#after-the-send) resends and pins, and
[HTTP listener](../cli.md#http-listener) `--internet`, the listener's limits and `--coinbase`.
