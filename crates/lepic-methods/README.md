# lepic-methods

The transaction methods a wallet sends and receives slates over: file, Epicbox, HTTP and Tor
(ADR 0051). Each method is one module behind a feature of the same name, and implements the
`Method` and `Transport` ports of `lepic-transport`, so the engine calls a method without naming
it. A host builds the methods it offers into a `registry::Methods` and hands that to the
engine.

## Where it fits

| Direction | Crates |
|---|---|
| Depends on | `lepic-transport` (the ports and format policies); per feature `lepic-epicbox`, `lepic-legacy-rpc`, `lepic-peer`, `lepic-tor`, `lepic-wallet` |
| Used by | `lepic-cli`, `lepic-ffi`, `lepic-wallet-contacts`; `lepic-wallet` in its tests |

Features:

| Feature | Default | Effect |
|---|---|---|
| `legacy` | on | The legacy wire formats every method needs: V2 and V3 JSON slates, the LEPIC marker and the JSON-RPC foreign API (ADR 0052). Without it the registry holds no method |
| `file` | on | `file`: slates as files, from `lepic-transport` |
| `epicbox` | off | `epicbox`: the Epicbox policy and delivery through the relay client |
| `epicbox-wallet` | off | The Epicbox inbox loop, which hands each message to a `lepic_wallet::Wallet`, and listing addresses |
| `http` | off | `http`: sends to `http(s)://` listeners, the shared listener handler, and the native direct endpoint |
| `tor` | off | `tor`: the HTTP exchange over a SOCKS stream to an onion, through the wallet's tor |
| `loopback` | off | `lepic-transport`'s in-memory transport pair, for engine tests |
| `mock-relay` | off | `lepic-epicbox`'s in-process relay, for tests |

What it does not do:

- It does not hold transactions. The engine in `lepic-wallet` decides what a slate means and
  stores it.
- It does not run listeners or tor. The host starts the `lepic-legacy-rpc` listener and the
  `lepic-tor` process, and attaches them here.
- It does not open or seal native envelopes. `HttpPeer` and `TorPeer` move envelope bytes the
  caller sealed.

## Core concepts

### The registry

`Methods::new()` makes an empty registry. `register(method)` adds one and refuses an id that is
taken (`RegistryError`). `get(id)`, `ids()` and `iter()` read it, in registration order. A
payment stores the id of the method it went over, so the engine finds the method again later.

| Method | Module | `TransportId` |
|---|---|---|
| File | `file` | `"file"` |
| Epicbox | `epicbox` | `"epicbox"` |
| HTTP | `http` | `"http"` |
| Tor | `tor` | `"tor"` |

Each method has a format policy (ADR 0003): which slate shapes it accepts and which it writes.
The Epicbox and HTTP policies accept V3 and V2, detected by shape with V3 tried first, write a
slate the wallet starts in the V2 shape, and answer in the shape they received.

### Epicbox

`Epicbox::new(settings, network, connector)` exists before the wallet is unlocked, because the
registry is built first. `attach_wallet(wallet)` attaches the wallet's identity, the address key
of the default account at index 0, and returns its address; `detach` drops it when the wallet
locks. Clones share what is attached.

With `epicbox-wallet`, two loops hand messages to the engine with `Wallet::arrived`:

| Call | Mode | What it does |
|---|---|---|
| `drain(wallet)` | Background work on mobile | Takes every stored message once, stops at the first transient failure and leaves the rest on the relay |
| `listen(wallet, ...)` | App in the foreground | Holds a connection and handles messages as they arrive, retrying a held message with backoff |

A message is acknowledged once its effect is stored, or once its rejection is recorded. A
transient failure leaves it unacknowledged, and the relay holds back everything behind it. An
answer the engine gives as `Outcome::Requeue` is posted back to the address for another install
of the wallet before it is acknowledged.

A notice about a payment over Epicbox is padded to the length of a first slate the wallet
sends, one of three drawn at random (`NOTICE_LENGTHS`, `NATIVE_NOTICE_LENGTHS`,
`notice_lengths_for`). `EpicboxNotices` matches notices for a wallet with no relay to reach.
`address_at`, `sign_with_address_key_at` and `drain_at` serve listing addresses: one
address per listing, drained on its own connection.

### HTTP and Tor

Both send through the `epic-wallet` foreign API: `check_version`, then `receive_tx`. The
receiver answers with its S2 in the same exchange, so the method keeps that answer, keyed by the
slate id, until the caller takes it with `take_reply` to finalize. `is_direct(transport)` tells
whether a method answers this way. Neither has an inbound side: payments to the wallet reach
its listener.

- `Http::new(client)` posts with a `lepic_legacy_rpc::RpcClient`; `through(client)` gives the
  same method with another client.
- `Tor::new(client)` posts with an `OnionClient` over a SOCKS stream to `<onion>:80`.
  `attach(proxy)` takes the wallet's tor and `detach` drops it; a send without a tor fails
  with `TorSendError::NotRunning`. `ended(tor)` waits until a tor fails or stops.

The listener side is one handler for both: `http::Receiver` is the `ReceiveHandler`
that passes a slate to the engine's receive and signs payment proofs with the listener's
address key. `refuse` maps a failed receive to `Refusal::Rejected` when the same slate would
fail again, and to `Refusal::Unavailable` otherwise. `coinbase_request` and `coinbase_answer`
convert a mining node's `build_coinbase` for the engine.

### The native direct endpoint

Between LEPIC wallets, a listener's `check_version` answer carries an advert (ADR 0052).
`HttpPeer::probe(to)` and `TorPeer::probe(to)` read it as a `Probe`, and `Probe::target` gives
the `/api/v1/inbox` endpoint to post to. Both implement `DirectPeer`, which gives the origin a pin
is kept under and posts a sealed envelope the way the method reaches the listener.
`Tor::peer_dialer` routes a `PeerClient` through tor.

## Public API

| Item | Purpose |
|---|---|
| `registry::Methods`, `RegistryError` | The methods a host offers |
| `method`, `transport`, `policy`, `error`, `codecs` | Re-exports of `lepic-transport` |
| `file::FileTransport`, `file::FilePolicy`, `file::response_path` | The file method |
| `epicbox::Epicbox`, `EpicboxPolicy`, `EpicboxNotices`, `EpicboxTransportError`, `peer_key`, `relay_network` | The Epicbox method |
| `http::Http`, `HttpPolicy`, `is_direct`, `TRANSPORT_ID` | The HTTP method |
| `http::Receiver`, `Host`, `Counts`, `refuse`, `coinbase_request`, `coinbase_answer` | The listener's handler |
| `http::HttpPeer`, `DirectPeer`, `Probe`, `ProbeError` | The native endpoint over HTTP |
| `tor::Tor`, `OnionClient`, `TorPeer`, `TorSendError`, `exchange`, `ended` | The Tor method |

## Related

- [Epicbox](../../docs/protocols/epicbox.md), [HTTP](../../docs/protocols/http.md),
  [Tor](../../docs/protocols/tor.md), [EPICTX](../../docs/protocols/epictx.md)
- [Architecture](../../docs/architecture.md), [legacy slates](../../docs/compat/legacy-slates.md),
  [foreign API](../../docs/compat/foreign-api.md)
- ADRs: [0003 transport format policy](../../docs/adr/0003-transport-format-policy.md),
  [0004 Epicbox client](../../docs/adr/0004-epicbox-client.md),
  [0015 file method writes V3](../../docs/adr/0015-file-method-writes-v3.md),
  [0016 Epicbox notices](../../docs/adr/0016-epicbox-notices.md),
  [0051 transaction methods in one crate](../../docs/adr/0051-transaction-methods-in-one-crate.md),
  [0052 legacy at the edge, native between LEPIC wallets](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)
- [`lepic-wallet`](../lepic-wallet/README.md), [`lepic-epicbox`](../lepic-epicbox/README.md),
  [`lepic-legacy-rpc`](../lepic-legacy-rpc/README.md), [`lepic-peer`](../lepic-peer/README.md),
  [`lepic-tor`](../lepic-tor/README.md)
