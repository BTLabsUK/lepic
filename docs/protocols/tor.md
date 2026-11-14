# Tor

A LEPIC wallet runs one tor child process of its own while it is open
([ADR 0018](../adr/0018-tor-on-desktop.md)). Through it the wallet publishes an onion service
that takes payments, sends slates to other wallets' onions over SOCKS5, and can reach its
Epicbox relay and its node. This guide covers the onion and its key, the tor process and its
control port, sending and receiving, and the build feature. A slate sent over Tor is the same
foreign API exchange as over [HTTP](http.md), at `<onion>:80`.

| Crate | Holds |
|---|---|
| [`lepic-tor`](../../crates/lepic-tor/README.md) | Onion addresses, the tor process, the control port, SOCKS5, relay streams |
| [`lepic-methods`](../../crates/lepic-methods/README.md) (`tor` feature) | The Tor method: `Tor`, `OnionClient`, `TorPeer` |

## The onion and its key

The onion has a key of its own ([ADR 0044](../adr/0044-the-onion-has-its-own-key.md)). Its
32-byte seed is the keyed BLAKE2b-256 of the wallet seed over the label
`lepic-wallet onion key v1`, so a restore gives the same onion. `Wallet::onion_key()` returns
it.

A payment proof asked for over the onion names the onion's key as the receiver address and is
signed with it. A proof asked for over Epicbox, HTTP or a file is signed with the payment-proof
key.

### The previous onion

LEPIC 0.3.1 and earlier published another onion: the payment-proof key in onion form, the
address key of `m/0/0` at index 0. It is the address `epic-wallet address` prints, and the one
other Epic wallets publish. `Wallet::previous_onion_key()` returns it. A host may publish it
next to the onion for senders that still have it (FFI `Policy.publish_previous_onion`, off by
default). It gets a listener of its own, and a proof asked for there is signed with the
payment-proof key, so one key never answers for both addresses.

### Onion addresses

```text
name    = base32(public key (32) || checksum (2) || version (03))   56 characters
checksum = SHA3-256(".onion checksum" || public key || version)[..2]
```

```rust
use lepic_tor::{OnionAddress, onion_address, public_key_of_seed};

let onion = OnionAddress::parse(text)?;     // also "http://<name>.onion:80/path"
let host = onion.host();                     // "<56 characters>.onion"
let mine = onion_address(&seed);             // the name of a 32-byte seed
let key = public_key_of_seed(&seed);
```

`OnionAddress::parse` takes the bare name with or without `.onion`, with an `http://` or
`https://` scheme, a port and a path, which it drops, in any case. Input over 512 bytes is
refused. `expanded_secret(seed)` is the 64-byte key `ADD_ONION ED25519-V3` takes: the SHA-512
of the seed, clamped. It is built in memory and never stored.

| `OnionError` | Message |
|---|---|
| `Empty` | the address is empty |
| `Format` | the text is not an onion v3 address |
| `Version` | the onion address has an unknown version |
| `Checksum` | the onion address has a typo |

| Constant | Value |
|---|---|
| `ONION_NAME_LEN` | 56 |
| `ONION_PORT` | 80 |

## The tor process

`TorProcess::start(settings)` runs the tor binary the host gives. LEPIC does not bundle tor:
desktop hosts ship the Tor Expert Bundle's `tor`, and `lib_dir` names its libraries
(`LD_LIBRARY_PATH` on Linux).

| `TorSettings` field | Meaning |
|---|---|
| `tor_binary` | Path to `tor` |
| `lib_dir` | The bundle's library directory, or none |
| `data_dir` | Tor's folder, made `0700` on Unix |
| `timings` | `TorTimings` |
| `withheld_env` | Environment variables tor does not inherit |

Tor's folder holds `torrc`, `torrc-defaults`, `control.txt` (the control port's address),
`control.cookie` and `data/`. The `torrc`:

```text
SocksPort auto ExtendedErrors IsolateSOCKSAuth
ControlPort auto
ControlPortWriteToFile <dir>/control.txt
CookieAuthentication 1
CookieAuthFile <dir>/control.cookie
DataDirectory <dir>/data
__OwningControllerProcess <wallet pid>
Log notice stdout
AvoidDiskWrites 1
```

Both ports are picked by tor. `__OwningControllerProcess` and `TAKEOWNERSHIP` make tor exit with
the wallet. Dropping the `TorProcess` kills tor; `stop()` asks it to shut down first.

### States

```text
Off -> Starting { progress, tag } -> Bootstrapped -> Publishing -> Ready { onion }
                 any state -> Failed(TorFailure)
```

Sending works from `Bootstrapped`; receiving from `Ready`. `subscribe()` follows the state, and
`wait_bootstrapped()` returns the SOCKS address. A `TorFailure` reads
`tor failed (<kind>): <detail>`, with the detail cut to 300 characters.

| `FailureKind` | `as_str` | Meaning |
|---|---|---|
| `Missing` | `missing` | No tor binary at the configured path |
| `Start` | `start` | Tor did not start, or its control port did not answer as expected |
| `Network` | `network` | No bootstrap progress for a while, or no full bootstrap in time |
| `Clock` | `clock` | Tor reported the computer's clock as wrong before it bootstrapped |
| `Listener` | `listener` | The wallet's listener does not answer, so the onion would lead nowhere |
| `Stopped` | `stopped` | Tor exited or closed its control port after the bootstrap |
| `Publish` | `publish` | The onion was added, but its descriptor was not uploaded in time |
| `Keys` | `keys` | Tor refused the onion key, or published another onion than the wallet's |

A `Listener` or `Keys` failure leaves tor running for sending.

### Timings

`TorTimings::new(network)` sets the fixed timings and takes the network ones from the host.

| Timing | Value |
|---|---|
| `control_file` | 30 s for tor to write `control.txt` |
| `command` | 15 s for a control command |
| `stop` | 5 s for tor to exit |
| `listener_check` | 3 s for the listener to answer before publishing |
| `TorNetworkTimings` | `stall` and `bootstrap`, `cold_stall` and `cold_bootstrap` for a first start, `publish` |

### Network changes

- `refresh(false)`, after a pause: `SIGNAL ACTIVE`.
- `refresh(true)`, on another network: `DisableNetwork` on and off, a fresh SOCKS address and
  `SIGNAL NEWNYM`. Every connection closes, sends in progress fail, and tor publishes the onion
  again by itself.
- `network_lost()`: `DisableNetwork` on until the next refresh. It does nothing while tor
  bootstraps.

A tor that does not answer either call in time is ended with a `Stopped` failure, or `Start`
before the bootstrap.

## The control port

The wallet reads the port from `control.txt` and authenticates with `SAFECOOKIE` and the
32-byte cookie. It then sends `TAKEOWNERSHIP` and
`SETEVENTS STATUS_CLIENT STATUS_GENERAL HS_DESC`.

The onion is added with:

```text
ADD_ONION ED25519-V3:<expanded secret, base64> Flags=DiscardPK,MaxStreamsCloseCircuit MaxStreams=4 PoWDefensesEnabled=1 PoWQueueRate=2 PoWQueueBurst=10 Port=80,<target>
```

`<target>` is `127.0.0.1:<port>` or `unix:<path>`. The wallet waits for `HS_DESC UPLOADED`
before it reports `Ready`. Other commands are `DEL_ONION` and `SIGNAL SHUTDOWN`, `HALT`,
`ACTIVE` and `NEWNYM`.

| Constant | Value |
|---|---|
| `MAX_STREAMS_PER_CIRCUIT` | 4 |
| `POW_QUEUE_RATE` | 2 |
| `POW_QUEUE_BURST` | 10 |
| `MAX_LINE_LEN` | 8 KiB |
| `MAX_REPLY_LINES` | 512 |

| `ControlError` | Message |
|---|---|
| `Connect` | could not reach tor's control port |
| `Io` | the control connection failed |
| `Closed` | the control connection is closed |
| `Timeout` | tor did not answer in time |
| `LineTooLong` | a control reply line is longer than 8192 bytes |
| `ReplyTooLong` | a control reply is longer than allowed |
| `Malformed` | a control reply is malformed |
| `Rejected` | tor refused the command with status `{code}` |
| `InvalidArgument` | the command or its argument is invalid |
| `Cookie` | the control cookie is not 32 bytes |
| `ServerProof` | the control port did not prove it knows the cookie |
| `Randomness` | the system random generator failed |

## Receiving

`publish_onion_to(seed, target)` adds the onion and waits for its descriptor upload.
`add_onion_to(seed, target)` adds the previous onion without waiting. The listener behind each
onion is the foreign API listener of [HTTP](http.md), which answers payments only, never
invoices.

| `OnionTarget` | Used when |
|---|---|
| `Unix(path)` | On Unix, for an absolute path of at most 100 bytes with no space, comma, quote or backslash |
| `Port(port)` | Otherwise: `127.0.0.1` at a free port |

`onion_socket_path(tor_dir)` gives `<tor_dir>/onion.sock` (`ONION_SOCKET`) and
`previous_onion_socket_path(tor_dir)` gives `<tor_dir>/previous-onion.sock`
(`PREVIOUS_ONION_SOCKET`), or none when the path is unusable. Any program on the device can
connect to a loopback port; only the wallet's user can reach a socket in tor's folder.

Tor connects every sender from `127.0.0.1`. `listen_settings(limits)` therefore makes the
listener's whole connection cap the cap per address. Tor closes a sender's circuit that opens
more than 4 streams, and the proof-of-work defence queues introductions under load.

## Sending

A send opens a SOCKS5 stream to `<onion>:80` through the wallet's tor:

- the address type is a domain name, so no DNS query leaves the computer;
- each send gets a random 16-byte hex username and password, so tor (`IsolateSOCKSAuth`) gives
  it a circuit of its own.

`Tor::send(to, wire)` then makes two calls on that circuit:

1. `check_version`. A connect that fails in a way waiting can mend is tried again on a new
   circuit, after waits of 2, 5 and 10 seconds (`RETRY_WAITS`), within twice the connect
   timeout. These are a timeout and the tor replies `OnionNotFound`, `OnionIntroductionFailed`,
   `OnionRendezvousFailed`, `OnionIntroductionTimedOut`, `TtlExpired` and `HostUnreachable`. The
   first circuit to an onion can take much longer than the next, and a service that has just
   published its descriptor is not yet found everywhere. Each retry is logged as a warning.
2. `receive_tx` with the S1. The answer must name the same slate id, else it is refused as
   malformed. The S2 is held under the slate id until `take_reply(slate_id)` takes it to
   finalize. At most `MAX_HELD_REPLIES`, 64, are held.

Each call is `POST /v2/foreign` with `Content-Type: application/json`. The formats the method
reads and writes follow `HttpPolicy`. `OnionClientSettings` bounds a send with
`connect_timeout`, `request_timeout` and `max_response_bytes`.

| Constant | Value |
|---|---|
| `TRANSPORT_ID` | `tor` |
| `ENDPOINT` | `/v2/foreign` |
| `ONION_PORT` | 80 |
| `MAX_HELD_REPLIES` | 64 |

### Errors

Each `TorSendError` maps to a `SendFailure` class that says what the failure means for the
sender.

| `TorSendError` | Message | Class |
|---|---|---|
| `NotRunning` | tor is not running | `TorOff` |
| `Address` | invalid onion address | `InvalidAddress` |
| `Socks` | could not reach the other wallet over tor | From the SOCKS error |
| `Exchange` | the exchange with the other wallet failed | `Broken` |
| `Timeout` | the other wallet did not answer in time | `Broken` |
| `Status` | the other wallet answered with http status `{status}` | `NotEpic` |
| `NotFound` | the other wallet has no foreign api at this address | `NotEpic` |
| `ResponseTooLarge` | the answer is larger than `{max}` bytes | `NotEpic` |
| `Rpc` | the answer could not be read | `NotEpic`, `Refused` or `TooOld` |
| `NoCommonVersion` | the other wallet offers no slate version this wallet sends | `TooOld` |

An `Rpc` error that is malformed, not JSON or too large is `NotEpic`; a refusal is `Refused`;
any other is `TooOld`.

| `SendFailure` | Meaning |
|---|---|
| `TorOff` | The wallet's tor is not running or not bootstrapped |
| `Unreachable` | The recipient's wallet is not online with Tor on, or could not be reached in time |
| `InvalidAddress` | Not a valid onion address |
| `Broken` | The connection dropped or tor failed in another way; trying again may work |
| `ClientAuth` | The onion needs a client key this wallet does not have |
| `NotEpic` | Something answered, but not an Epic wallet's foreign API |
| `TooOld` | The recipient's wallet is too old to receive this way |
| `Refused` | The recipient's wallet refused the slate |

A `SocksError` takes its class as follows: `ProxyUnreachable` is `TorOff`, `Timeout` is
`Unreachable`, `HostTooLong` is `InvalidAddress`, and `Refused` takes the class of tor's reply.
With `ExtendedErrors`, tor names why an onion could not be reached:

| Reply | Code | Class |
|---|---|---|
| `OnionNotFound`, `OnionIntroductionFailed`, `OnionIntroductionTimedOut` | `0xF0`, `0xF2`, `0xF7` | `Unreachable` |
| `HostUnreachable`, `ConnectionRefused` | `0x04`, `0x05` | `Unreachable` |
| `OnionAddressInvalid` | `0xF6` | `InvalidAddress` |
| `OnionMissingClientAuth`, `OnionWrongClientAuth` | `0xF4`, `0xF5` | `ClientAuth` |
| Any other | | `Broken` |

| `SocksError` | Message |
|---|---|
| `ProxyUnreachable` | could not reach the socks proxy |
| `Timeout` | the connection was not made in time |
| `Io` | the socks connection failed |
| `Protocol` | the socks proxy answered outside the protocol |
| `AuthRefused` | the socks proxy refused the credentials |
| `Refused` | the socks proxy could not connect: `{reply}` |
| `HostTooLong` | the host name is too long for socks |
| `Randomness` | the system random generator failed |

### Native direct over the onion

Between LEPIC wallets the `check_version` answer can advertise the native direct endpoint
([RFC 0003 §5.15](../rfcs/0003-epictx-native-slates.md#515-advert-and-native-direct-endpoint)).
`TorPeer` reads that advert through the Tor method and posts the envelope to
`/api/v1/inbox` at `http://<onion>:80` through a `PeerClient` that dials with
`Tor::peer_dialer(connect_timeout)`, a circuit per connection. The rules are in
[RFC 0003 §6.2](../rfcs/0003-epictx-native-slates.md#62-direct-http-or-tor-peer) and the
endpoint in [HTTP](http.md).

## Epicbox over Tor

`RelayTor` takes the relay connection through the wallet's tor
([ADR 0021](../adr/0021-epicbox-over-tor.md)).

| Method | Effect |
|---|---|
| `new(enabled, timeout)` | Waits for a tor while `enabled` |
| `direct(enabled, timeout)` | Goes directly until a tor is expected or attached |
| `set_enabled(bool)` | The setting; off reaches the relay directly even while tor runs |
| `expect()` | A tor is being started: connections wait for it |
| `attach(tor)` / `attach_socks(FixedSocks)` | Connections go through the wallet's tor, or a tor already running at a loopback SOCKS address |
| `detach()` | No tor: connections go directly, and a waiting one fails |
| `open(host, port)` | A stream on a circuit of its own |
| `open_in(host, port, group)` | A stream that may share a circuit with the rest of a `StreamGroup` |

While the setting is on, no relay connection goes directly until the host detaches tor or turns
the setting off.

The relay is reached at an onion when one is known, else at its domain through a Tor exit:

1. an `OnionRoutes` entry the host gives, such as from its settings;
2. else the onion the relay names at `/.well-known/epicbox.json` (`DISCOVERY_PATH`, at most
   `MAX_DISCOVERY_LEN`, 4096 bytes). The document must name the relay's own domain, port and
   TLS name.

A route wins over discovery. TLS checks the relay domain's certificate and the websocket URL
keeps the domain, so the wallet's address does not change. A loopback relay is always reached
directly.

| `RelayTorError` | Message |
|---|---|
| `Off` | tor is off |
| `Tor` | tor is not connected to the tor network |
| `Socks` | tor could not reach the relay |

## Node over Tor

With node over Tor on, node requests go through the same tor
([ADR 0022](../adr/0022-node-over-tor.md)). The FFI's node dialer:

- keeps a loopback node direct;
- uses the node's `OnionRoutes` entry when there is one, else its host name, which tor
  resolves;
- refuses `http://` for any host that is not an onion, before it dials;
- puts the connections of one node backend in one `StreamGroup`, so they share circuits;
- connects directly only when tor is off and the host is not an onion. Any other tor failure is
  an error.

## Build feature

Tor is a cargo feature ([ADR 0026](../adr/0026-tor-as-a-build-feature.md)). In `lepic-ffi`:

```toml
[features]
default = ["tor"]
tor = ["dep:lepic-tor", "lepic-methods/tor"]
```

The `lepic-methods` `tor` feature pulls in `lepic-tor`, `hyper`, `http` and `tokio`. Without it
every Tor function keeps its signature and fails with `Unsupported` or reports Tor as off. The
CLI builds with `tor`.

## From the CLI

```bash
lepic tor address
lepic tor address --previous
lepic tor listen --tor-binary ~/tor/tor --lib-dir ~/tor
lepic tor listen --previous-onion --tor-binary ~/tor/tor --lib-dir ~/tor
lepic tx send 1.5 --to "$ONION" --tor-binary ~/tor/tor --lib-dir ~/tor
```

The CLI keeps its tor files in `tor/` inside the data directory, and in `tor-epicbox/` for the
relay connection. [docs/cli.md](../cli.md#tor-listener) has every option, with
[Tor for the relay and the node](../cli.md#tor-for-the-relay-and-the-node).
