# 0018 Tor on desktop through a bundled tor child process

Status: proposed
Date: 2026-10-22

## Context

The owner decided (D2, ADR 0017) that direct transactions are first-class, Tor included: a wallet
receives at its `.onion` address and sends to another wallet's `.onion` address. The reference
`epic-wallet` `v4.1.0` derives that address from its payment-proof key, so it is the one
`epic-wallet address` prints and it survives a restore from the phrase. Its own Tor support
does not work as shipped: it writes the onion key in a format tor reads as a different key, so
tor publishes another address, and it starts tor without any way to learn whether it is ready.

The Epic GUI wallet 6.1.6 brought Tor back by running tor itself, and that design was proven on
Linux and Windows with real onion sends: one tor per open wallet on private `auto` ports, with a
control port for readiness and errors, the onion added with the correctly expanded key, and
slates sent through tor's SOCKS port with the HTTP foreign API.

Arti, the Rust implementation of Tor, can host onion services, but it has no official binaries
yet and no control port, and its onion-service support is newer than C tor's.

## Decision

- A new crate `lepic-tor` depends on `lepic-foreign`, `lepic-transport` and `lepic-slate`. It
  holds the onion v3 address codec, the expansion of the wallet's key into the form tor takes,
  a minimal control-port client, the tor child process and its state, a SOCKS5 client, and the
  `tor` transport. `lepic-cli` and `lepic-ffi` depend on it; the engine does not.
- The host bundles a `tor` binary (the Tor Expert Bundle the GUI pins) and passes its path.
  `lepic-tor` starts it per open wallet with a torrc in that wallet's directory: SOCKS and
  control on `auto` ports, cookie authentication, `__OwningControllerProcess`, then
  `TAKEOWNERSHIP`, so tor exits with the wallet process or its control connection. No shell is
  involved.
- The onion's key is the payment-proof key: its seed is the wallet's address secret key for
  account `m/0/0`, index 0. `lepic-tor` expands it in memory (SHA-512, clamped) and passes it to
  `ADD_ONION` with `Flags=DiscardPK`, mapping port 80 to the HTTP listener on `127.0.0.1`
  (ADR 0017). The key is never written to disk or logged.
- Readiness comes from the control port: bootstrap progress, then the first `HS_DESC UPLOADED`
  for the wallet's service. Failures are typed (binary missing, start, network, clock, listener,
  stopped, publish, keys) and carry no secrets.
- Sending opens a SOCKS5 stream to `<onion>:80` with the domain address type, so tor resolves
  the name, and fresh username and password credentials per send, so `IsolateSOCKSAuth` gives
  each send its own circuit. The foreign API exchange is the one `lepic-foreign` speaks
  (`check_version`, then `receive_tx`), with the same body limits and format policy. The connect
  timeout is well under tor's own two minutes.

## Consequences

- A LEPIC desktop wallet and any wallet that receives over Tor with a correctly published onion
  can pay each other; the address matches `epic-wallet address`.
- The desktop packages grow by the tor binary and, on Linux, its libraries; the host checks the
  bundle's hashes and ships tor's licence with it.
- Mobile does not get Tor from this crate: Android and iOS cannot run a bundled tor binary the
  same way. That would need an embedded Tor, a later decision.
- Node traffic and Epicbox stay off Tor.

## Alternatives considered

- Arti in process: no child process and no bundled binary, but no official binaries and a
  younger onion-service implementation. Revisit when it is mature.
- Letting a system tor or Tor Browser serve the wallet: unreliable ports, no ownership, no
  control over the onion key, and a second wallet would clash.
- Writing the key file and letting tor load it as a hidden-service directory: puts the expanded
  key on disk for no gain.
