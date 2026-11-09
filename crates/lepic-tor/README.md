# lepic-tor

Tor for a wallet on desktop and Android: the wallet's onion service, sends to other wallets'
onions, and Tor streams for the Epicbox relay and the node. The host bundles a `tor` binary;
this crate runs it as one child process per open wallet, drives it over its control port and
connects through its SOCKS port. It is an I/O crate under `lepic-methods`.

## Where it fits

| Direction | Crates |
|---|---|
| Depends on | `lepic-legacy-rpc` (the listener settings and body limit) |
| Used by | `lepic-methods` (feature `tor`), `lepic-ffi` |

Features:

| Feature | Default | Effect |
|---|---|---|
| `testing` | off | The settings the app ships, for tests of this crate and the crates above it |

What it does not do:

- It ships no tor. The host passes the path of its `tor` binary in `TorSettings`.
- It does not serve or send slates. `lepic-methods` holds the Tor method, which serves the
  foreign API from `lepic-legacy-rpc` behind the onion and posts to other onions through the
  SOCKS port.
- It does not restart a failed tor. Restarting is the host's choice.

## Core concepts

### One tor per wallet

`TorProcess::start(settings)` starts `tor` on private `auto` ports, with its files in
`TorSettings::data_dir`, a directory no other wallet shares. The crate authenticates to the
control port with `SAFECOOKIE` and follows bootstrap progress. On Unix the directory is created
with mode 0700; on Windows it must sit inside the user's profile.

`TorState` moves:

```text
Off ─> Starting ─> Bootstrapped ─> Publishing ─> Ready
           └───────────┴──────────────┴───────────┴──> Failed
```

| State | What works |
|---|---|
| `Bootstrapped` | Sending: the SOCKS port reaches onions |
| `Ready` | Receiving: the onion's first descriptor is uploaded |
| `Failed` | Nothing; the process has ended |

`TorProcess::subscribe` gives a `watch` channel of the state. `TorFailure` carries a
`FailureKind` and a short detail with no key or cookie in it:

| `FailureKind` | Meaning |
|---|---|
| `Missing` | No tor binary at the configured path |
| `Start` | Tor did not start, or its control port did not answer as expected |
| `Network` | No bootstrap progress for a while, or no full bootstrap in time |
| `Clock` | Tor reported the computer's clock as wrong before bootstrapping |
| `Listener` | The wallet's listener does not answer, so the onion would lead nowhere |
| `Stopped` | Tor exited or closed its control port after the bootstrap |
| `Publish` | The onion was added, but its descriptor was not uploaded in time |
| `Keys` | Tor refused the onion key, or published another onion |

`TorTimings::new(network)` takes the network-dependent waits (`TorNetworkTimings`: stall,
bootstrap, their cold-start versions, publish) and adds fixed local waits: 30 s for the control
port file, 15 s per command, 5 s for stop, 3 s for the listener check. A start without a cached
consensus gets the cold waits.

A phone may pause the app together with tor, and the network may change under it.
`TorProcess::refresh(network_changed)` wakes tor; after a network change it closes every
connection and builds new circuits, and tor publishes the onion again. `network_lost` turns
tor's network off at once (`DisableNetwork`); the next `refresh` turns it on.

### The onion service

`publish_onion_to(seed, target)` adds the wallet's onion, port 80 forwarding to `target`, and
waits for the first descriptor upload. `seed` is the 32-byte seed of the onion's ed25519 key,
expanded in memory and never written. The wallet's onion key is its own key in the LEPIC
namespace (`lepic_wallet::Wallet::onion_key`, ADR 0044). `add_onion_to` adds the previous
onion, whose key is the payment-proof key of account `m/0/0`, index 0, so senders that saved
that address reach the wallet.

`OnionTarget` is either a loopback port or a Unix socket in tor's folder:

| Item | Value |
|---|---|
| `ONION_SOCKET` | `"onion.sock"` |
| `PREVIOUS_ONION_SOCKET` | `"previous-onion.sock"` |
| `onion_socket_path`, `previous_onion_socket_path` | `None` on Windows, or for a path too long or holding a character `ADD_ONION` cannot carry |
| `listen_settings` | Listener settings for the onion: local only, port 0 |

Any program on the device can connect to a loopback port; only the wallet's user can reach a
socket in tor's folder.

### Onion addresses

`OnionAddress` is a v3 onion name: `ONION_NAME_LEN` (56) characters of base32 over the public
key, a checksum and the version byte. `onion_address(seed)` gives the address of a seed,
`parse_onion` reads what a person typed (with or without `.onion`, an `http://` prefix, a port or
a path, in any case), and `OnionError` names what is wrong (`Empty`,
`Format`, `Version`, `Checksum`).

### Sending over SOCKS

Sends go through tor's SOCKS5 port with the domain address type, so tor resolves the onion and
no DNS query leaves the device. Each send uses its own username and password, so
`IsolateSOCKSAuth` gives it its own circuit. Tor's extended replies say why an onion could not be
reached (`SocksReply`, `SendFailure`). `OnionClientSettings` holds the limits: connect timeout,
request timeout and the largest answer taken.

`FixedSocks` points at a SOCKS port of a tor the wallet does not run. It takes loopback
addresses only, because SOCKS is plain text; any other address gives no proxy. `SocksProxy` is
the trait both it and `TorProcess` serve the current SOCKS address through.

### Tor for the relay and the node

`RelayTor` (ADR 0021) opens streams to the Epicbox relay, or to the node, through tor while its
setting is on:

- `new(enabled, timeout)` waits for a tor while enabled; `direct` starts detached and connects
  directly until a tor is expected or attached.
- `attach` takes a `TorProcess`, `attach_socks` a `FixedSocks`, `detach` drops it.
- `expect` marks a tor as starting: connections wait for it instead of going directly.
- With the setting on, a connection never goes directly until the host detaches tor or turns
  the setting off.
- `open` gives each stream its own circuit. `open_in` with a `StreamGroup` keeps the streams of
  one group, such as those to one node, on one circuit.

### Control port bounds

Replies from the control port are bounded: lines of at most `control::MAX_LINE_LEN` (8 KiB),
at most `control::MAX_REPLY_LINES` (512) lines per reply.

The onion is added with `MaxStreams` set to `MAX_STREAMS_PER_CIRCUIT` (4): tor closes a
rendezvous circuit that opens more streams at once. The listener sees every sender as
`127.0.0.1`, so this is its per-sender limit. Under a flood, tor's proof-of-work defence makes
each new sender circuit cost a puzzle, and the queue takes `control::POW_QUEUE_RATE` (2)
requests a second with a burst of `control::POW_QUEUE_BURST` (10). A tor built without the
defence ignores it.

## Public API

| Item | Purpose |
|---|---|
| `TorProcess` | `start`, `state`, `subscribe`, `wait_bootstrapped`, `publish_onion`, `publish_onion_to`, `add_onion_to`, `refresh`, `network_lost`, `stop` |
| `TorSettings`, `TorTimings`, `TorNetworkTimings` | Where tor is, where its files go, and how long it may take |
| `TorState`, `TorFailure`, `FailureKind` | What tor is doing, and why it stopped |
| `RelayTor`, `StreamGroup`, `RelayTorError` | Streams to the relay and the node through tor |
| `FixedSocks`, `SocksProxy` | A SOCKS port the host runs |
| `OnionAddress`, `onion_address`, `parse_onion`, `public_key_of_seed`, `expanded_secret` | Onion names and keys |
| `OnionTarget`, `listen_settings`, `onion_socket_path` | Where the onion forwards to |
| `OnionClientSettings`, `SocksReply`, `SendFailure`, `SocksError` | Sends to an onion |

The modules `control`, `socks` and `process` expose the lower-level pieces, such as
`process::build_torrc`.

## Related

- [Tor protocol page](../../docs/protocols/tor.md), [HTTP](../../docs/protocols/http.md)
- [Architecture](../../docs/architecture.md), [configuration](../../docs/configuration.md),
  [FFI](../../docs/ffi.md)
- ADRs: [0018 Tor on desktop](../../docs/adr/0018-tor-on-desktop.md),
  [0021 Epicbox over Tor](../../docs/adr/0021-epicbox-over-tor.md),
  [0022 node over Tor](../../docs/adr/0022-node-over-tor.md),
  [0026 Tor as a build feature](../../docs/adr/0026-tor-as-a-build-feature.md),
  [0044 the onion's own key](../../docs/adr/0044-the-onion-has-its-own-key.md)
- [`lepic-methods`](../lepic-methods/README.md), [`lepic-legacy-rpc`](../lepic-legacy-rpc/README.md)
