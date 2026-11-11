# lepic-legacy-rpc

The wallet foreign API of `epic-wallet` over HTTP, on the wire: the JSON-RPC messages, a client
that posts a slate to a wallet listening at an `http(s)://` address, and a listener that takes
payments. It is wire-compatible with `epic-wallet` `v4.1.0` `send -m http` and
`listen -m http` (ADR 0017). The same listener serves the native `/api/v1/inbox` routes of
`lepic-peer` to other LEPIC wallets (ADR 0052). The HTTP method that uses this crate is
`lepic_methods::http`.

## Where it fits

| Direction | Crates |
|---|---|
| Depends on | `lepic-slate` (wire slates), `lepic-transport`, `lepic-peer` (the native routes) |
| Used by | `lepic-methods` (features `http` and `tor`), `lepic-tor` (listener settings) |

Features:

| Feature | Default | Effect |
|---|---|---|
| `testing` | off | The settings the app ships, for tests of this crate and the crates above it |

What it does not do:

- It does not build or sign slates. The listener hands each S1 to a `ReceiveHandler`, which
  is the wallet.
- It serves payments only. Invoices and the owner API are not served.
- It has no default limits. The host passes every timeout and budget; `testing` holds the
  app's values for tests.
- It does not reach onions itself. `ListenerUrl::parse` refuses `.onion` hosts; the Tor method
  in `lepic-methods` sends through an `RpcDialer` instead.

## Core concepts

### The messages

Every call is JSON-RPC 2.0, posted to `/v2/foreign`, and every answer wraps its value in
`result.Ok` or `result.Err`, as `epic-wallet` does.

| Method | Who calls it | Answer |
|---|---|---|
| `check_version` | A sender, before it posts | `foreign_api_version` 2, `supported_slate_versions` `["V3", "V2"]`, and a `lepic` advert on a LEPIC listener |
| `receive_tx` | A sender, with an S1 | The receiver's S2 |
| `build_coinbase` | A mining node | The reward output and kernel (`CoinbaseAnswer`), only when the listener serves it |

The functions in `rpc` encode and decode these messages over bytes, with no I/O, so the
client, the listener and the fuzz targets share them. A body is at most `MAX_BODY_LEN`: the
largest wire slate plus 64 KiB.

### Addresses

`ListenerUrl::parse(input, plain_http)` checks what a person typed:
`http(s)://host[:port][/path]`.

- The scheme is required, and matched without case.
- A missing port is `DEFAULT_LISTEN_PORT` (3415) for `http` and 443 for `https`.
- `/v2/foreign` is appended unless the path ends with it.
- Credentials, a query or a fragment are refused (`UrlError::ExtraParts`).
- `.onion` hosts are refused (`UrlError::OnionNeedsTor`).
- Plain `http` to another computer needs `PlainHttp::Allowed`, the user's consent. With
  `PlainHttp::LoopbackOnly` it fails with `UrlError::PlainHttpNotAllowed`.

For example, `HTTP://wallet.example:8080` becomes `http://wallet.example:8080/v2/foreign`.

### The client

`RpcClient` speaks HTTP/1.1 over rustls with the Mozilla roots (`webpki_tls_config`), follows
no redirects and reads at most `ClientSettings::max_response_bytes` of an answer.

- `check_version(url)` returns a `VersionInfo`; its `lepic` field holds the advert when the
  listener is a LEPIC wallet.
- `receive_tx(url, slate)` posts an S1 and returns the S2 as it came.
- `to_other_computers` refuses a host that is, or resolves to, a loopback or unspecified address
  (`ClientError::ThisComputer`). Private and link-local addresses count as other computers.
- `with_dialer` opens every connection through an `RpcDialer`, such as a tor stream. TLS and
  the `Host` header keep the host of the URL.

### The listener

`listen(settings, handler)` binds a TCP port and serves on the current Tokio runtime;
`listen_with` also serves the native `/api/v1/inbox` routes and adds their advert to
`check_version`. On Unix, `listen_unix` and `listen_unix_with` bind a socket file instead, for a
listener only a local tor reaches. A port another program holds fails with
`ListenError::PortInUse`.

`ListenSettings` sets where it listens and what it allows:

| Setting | Values |
|---|---|
| `exposure` | `Exposure::LocalOnly` (`127.0.0.1`) or `Exposure::Internet` (`0.0.0.0`, for a forwarded port) |
| `port` | 0 picks a free port |
| `coinbase` | `CoinbaseAccess::Off` (the default), `LocalOnly` or `Remote` |
| The `ListenLimits` fields | Connections, timeouts and per-minute budgets, below |

Everything a caller sends is untrusted, and each cost has a limit:

| Limit | Bounds |
|---|---|
| `max_connections`, `max_connections_per_address` | Connections at once, in all and from one address |
| `header_timeout`, `body_timeout` | Time to send the request line and headers, then the body |
| `request_timeout` | From the first byte of a request to the last byte of its answer |
| `answer_timeout` | Time for the caller to take the answer |
| `requests_per_minute` | Requests of any kind; past it only payments are served, others get `503` |
| `receives_per_minute` | `receive_tx` calls with an S1; more are refused as busy |

The budgets cannot tell callers apart: behind an onion every caller is `127.0.0.1`. So requests
that are not payments cannot use up the room payments have, and a payment the wallet refuses
as `Refusal::Rejected` gives its share of the budget back. On a listener that serves
`build_coinbase`, loopback peers have connections of their own and their calls spend no
budget.

The `ReceiveHandler` answers an S1 with an S2, or refuses it:

| `Refusal` | Meaning |
|---|---|
| `Rejected` | The slate was checked and refused for good |
| `Unavailable` | The wallet cannot take payments yet (locked, node not ready); the sender may retry |

The same S1 sent again must return the same S2, so a sender whose answer was lost can retry.

`ListenerHandle` reports `local_addr`, `socket_path`, `exposure` and `is_running`. `stop` stops
taking connections and lets requests in progress finish; `shutdown` also waits until the
socket is closed. Dropping the handle stops the listener.

## Public API

| Item | Purpose |
|---|---|
| `RpcClient`, `ClientSettings`, `webpki_tls_config` | Sends to another wallet's listener |
| `RpcDialer`, `RpcStream`, `RpcDialFuture` | Connections opened another way, such as tor |
| `listen`, `listen_with`, `listen_unix`, `listen_unix_with`, `ListenerHandle` | The listener |
| `ListenSettings`, `ListenLimits`, `Exposure`, `CoinbaseAccess` | What the listener allows |
| `ReceiveHandler`, `Refusal`, `BlockFees`, `CoinbaseAnswer` | The wallet behind the listener |
| `ListenerUrl`, `PlainHttp`, `Scheme`, `is_this_computer`, `DEFAULT_LISTEN_PORT` | Addresses |
| `rpc` module: `VersionInfo`, `Call`, `Request`, the `encode_*` and `decode_*` functions | The messages |
| `ClientError`, `ListenError`, `RpcError`, `UrlError` | Errors |
| `testing::listen_limits`, `testing::client_settings` | The app's values, with feature `testing` |

## Related

- [HTTP](../../docs/protocols/http.md), [Tor](../../docs/protocols/tor.md),
  [foreign API compatibility](../../docs/compat/foreign-api.md),
  [legacy slates](../../docs/compat/legacy-slates.md)
- ADRs: [0017 foreign API over HTTP](../../docs/adr/0017-foreign-api-over-http.md),
  [0046 a wallet for a mining node](../../docs/adr/0046-a-wallet-for-a-mining-node.md),
  [0048 block rewards for this computer](../../docs/adr/0048-block-rewards-for-this-computer.md),
  [0052 legacy at the edge, native between LEPIC wallets](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)
- [`lepic-peer`](../lepic-peer/README.md), [`lepic-methods`](../lepic-methods/README.md),
  [`lepic-tor`](../lepic-tor/README.md)
