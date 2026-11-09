# ADR 0018: Tor through a bundled tor child process

Status: accepted; the onion key is superseded in part by ADR 0044

## Context

Direct transactions are first-class in LEPIC, Tor included (ADR 0017): a wallet receives at its
`.onion` address and sends to another wallet's `.onion` address. The reference `epic-wallet`
derives that address from its payment-proof key. Its own Tor support writes the onion key in a
format that tor reads as a different key, so tor publishes another address, and it starts tor
without any way to learn whether it is ready.

The Epic GUI wallet runs tor itself, and that design works on Linux and Windows: one tor per
open wallet on private `auto` ports, a control port for readiness and errors, the onion added
with the correctly expanded key, and slates sent through tor's SOCKS port with the HTTP foreign
API.

Arti, the Rust implementation of Tor, can host onion services, but it has no official binaries
and no control port, and its onion-service support is newer than C tor's.

## Decision

### Crate

`lepic-tor` holds the onion v3 address codec, the expansion of an Ed25519 seed into the form
tor takes, a minimal control-port client, the tor child process and its state, a SOCKS5 client,
the listener settings behind the onion and the relay connection through tor. It depends on
`lepic-legacy-rpc` for the listener and the client. The `tor` transport, behind the `tor`
feature of `lepic-methods` (ADR 0026), is in `lepic-methods`. `lepic-cli` and `lepic-ffi` use
it; the engine does not.

### Process

- The host bundles a `tor` binary and passes its path in `TorSettings`. `lepic-tor` starts it
  per open wallet with a torrc in that wallet's directory: `SocksPort auto` with
  `IsolateSOCKSAuth`, `ControlPort auto` written to a file, `__OwningControllerProcess`, and
  `AvoidDiskWrites 1`. No shell is involved. The directory is created with mode 0700 on Unix.
- The control connection authenticates with `SAFECOOKIE`, so the cookie never crosses the
  connection, then sends `TAKEOWNERSHIP`, so tor exits with the wallet process or its control
  connection.
- A start first reads the control port file and cookie that an earlier run left. If that port
  proves it knows the cookie, `SIGNAL HALT` is sent and the start waits for it to close, since
  a tor left behind holds the data directory.
- Timeouts and intervals are the host's (`TorTimings`, ADR 0036).

### Onion

- `lepic-tor` expands the onion's Ed25519 seed in memory (SHA-512, clamped) and passes it to
  `ADD_ONION` with `Flags=DiscardPK,MaxStreamsCloseCircuit` and `Port=80,` the HTTP listener on
  `127.0.0.1` or, on Unix, a socket in tor's folder (`onion.sock`). The key is never written to
  disk or logged. The onion's key: see ADR 0044.
- The listener sees every sender as `127.0.0.1`. What `ADD_ONION` offers is used:
  - `MaxStreams=4` with `MaxStreamsCloseCircuit`: one circuit carries one sender's handful of
    streams (`MAX_STREAMS_PER_CIRCUIT`).
  - `PoWDefensesEnabled=1` with `PoWQueueRate=2` and `PoWQueueBurst=10`: once the service is
    flooded, tor asks senders for a proof-of-work puzzle and serves the hardest-working first.
    The rates are sized for a phone.
  - The listener's own budgets (ADR 0017): the per-address connection limit equals the whole
    connection cap, since every sender shares one address.
- The directory service options that export circuit IDs need a key directory in the torrc, which
  would put the key on disk; they are not used.

### State

`Off → Starting → Bootstrapped → Publishing → Ready`, or `Failed`. Sending needs `Bootstrapped`;
receiving needs `Ready`, the first `HS_DESC UPLOADED` for the wallet's service after the
`ADD_ONION` reply. A failure ends the process, and a restart is the host's choice. Failures are
typed (`missing`, `start`, `network`, `clock`, `listener`, `stopped`, `publish`, `keys`) and
carry no secrets.

### Sending

A send opens a SOCKS5 stream to `<onion>:80` with the domain address type, so tor resolves the
name, and fresh username and password credentials per send, so `IsolateSOCKSAuth` gives each send
its own circuit. The exchange is the foreign API of ADR 0017 with the same body limits and
format policy. A `check_version` that times out on connect is tried once more on a new circuit.

### Lifecycle

- A pause of the host (a phone's app freezer) moves the wallet's own deadlines by the pause, once
  one fires more than 2 s late, since tor treats the same freeze as idleness.
- `refresh(network_changed)` is the host's call on resume and on network changes: `SIGNAL ACTIVE`
  always; after a network change also `DisableNetwork` on and off, which closes every connection
  and builds new ones, then the new SOCKS address. The onion stays added and tor republishes it.
  A tor that does not answer is ended and reported, and the host starts a new one.
- On Android the host ships tor as a native library and passes its path; the same torrc serves.
  iOS cannot run a tor binary.

## Consequences

- A LEPIC wallet and any wallet that receives over Tor with a correctly published onion can pay
  each other.
- The desktop packages grow by the tor binary and its libraries. The host checks the bundle's
  hashes and ships tor's licence with it.
- The node connection goes through Tor as ADR 0022 says; the Epicbox connection goes through Tor
  when the setting is on (ADR 0021).
- The budgets bound all senders together. A flood of well-formed payments can use them up, at
  the cost that the proof of work puts on each circuit.

## Related

- ADR 0017, ADR 0021, ADR 0022, ADR 0026, ADR 0044
