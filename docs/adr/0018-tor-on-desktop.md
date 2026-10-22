# 0018 Tor on desktop through a bundled tor child process

Status: accepted
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
  control on `auto` ports, cookie authentication (`SAFECOOKIE`, so the cookie never crosses
  the connection), `__OwningControllerProcess`, then `TAKEOWNERSHIP`, so tor exits with the
  wallet process or its control connection. No shell is involved.
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
  (`check_version`, then `receive_tx`), with the same body limits and format policy. Reaching
  the onion may take 75 s, close to the GUI wallet's 72 s and under tor's own two minutes; a
  `check_version` that times out is tried once more on a new circuit.

## Consequences

- A LEPIC desktop wallet and any wallet that receives over Tor with a correctly published onion
  can pay each other; the address matches `epic-wallet address`.
- The desktop packages grow by the tor binary and, on Linux, its libraries; the host checks the
  bundle's hashes and ships tor's licence with it.
- iOS does not get Tor from this crate: it cannot run a tor binary. Android does (addendum
  below).
- Node traffic and Epicbox stay off Tor.

## Alternatives considered

- Arti in process: no child process and no bundled binary, but no official binaries and a
  younger onion-service implementation. Revisit when it is mature.
- Letting a system tor or Tor Browser serve the wallet: unreliable ports, no ownership, no
  control over the onion key, and a second wallet would clash.
- Writing the key file and letting tor load it as a hidden-service directory: puts the expanded
  key on disk for no gain.

## Addendum 2026-10-22: Android, app lifecycle and receive limits

**Android.** The app ships the Tor Project's Android tor (`libTor.so` of the Android expert
bundle, a PIE executable needing only libc, libm and libdl) as the native library `libtor.so`;
the native library folder is the one place an app may execute a file from. `start_tor` runs it
as on desktop, with no library path. The same torrc serves: `AvoidDiskWrites`, cookie
authentication, a 0700 directory in the app's private storage, `__OwningControllerProcess`.

**Lifecycle.** Android may freeze the app with its tor, kill it, restart it, and change its
network.

- A tor left on the wallet's files (the host died before tor noticed, or a host restarted
  without stopping its tor) would hold the data directory lock, and the new tor would exit
  after tor's 5-second wait. A start first reads the old control port file and cookie and, if
  that port proves it knows the cookie (`SAFECOOKIE`), sends `SIGNAL HALT` and waits for it
  to close. The onion is derived from the wallet key, so every start publishes the same one.
- Tor itself treats a freeze of minutes as idleness: its monotonic clock and wall clock moved
  together, so it keeps its circuits (it assumes they are gone only after an hour). The wallet's
  own deadlines would have fired: one that fires more than 2 s late moves every deadline by
  the delay, and leaves at least a stall time from the thaw.
- `refresh_tor(network_changed)` is the app's call on resume and on network changes: `SIGNAL
  ACTIVE` always; after a network change also `DisableNetwork` on and off, which closes every
  connection whose route may be gone and builds new ones, then the new SOCKS address (`auto`
  ports move). The onion stays added, and tor rebuilds its introduction circuits and republishes
  it by itself. A tor that does not answer is ended and reported, and the app starts a new one.
- An upload event counts for an added onion only if tor sent it after the `ADD_ONION` reply,
  so adding the same onion again never reports `Ready` from the earlier upload.

**Receive limits.** Every sender reaches the listener behind the onion from `127.0.0.1`, so
the listener cannot tell senders apart. Tor 0.4.9 can export the circuit ID to the target
(`HiddenServiceExportCircuitID`), and has introduction-point DoS defences, only for services
configured in the torrc with a key directory, not for `ADD_ONION` services; using them would put
the wallet key on disk, which this ADR rejects. What `ADD_ONION` does offer is used:

- `MaxStreams=4` with `MaxStreamsCloseCircuit`: one circuit, one sender's handful of streams.
- `PoWDefensesEnabled=1` with `PoWQueueRate=2`, `PoWQueueBurst=10`: once the service is
  flooded, tor asks for a proof-of-work puzzle in the descriptor and serves the hardest-working
  senders first, so every new flooding circuit costs CPU. Tor clients from 0.4.8 solve it by
  themselves; without a flood the effort is zero and older senders are unaffected. The rates are
  sized for a phone, not for tor's large-service defaults.
- The listener's per-minute budgets keep one sender's junk from blocking another's payment:
  requests that are not payments cannot use the room payments have (past the request budget,
  as many requests as the payment budget are still read, and served only if they are payments),
  and a payment the wallet refuses as invalid gives its share of the payment budget back, for
  as many refusals a minute as the budget itself (some refusals come only after the wallet's
  costlier checks, so at most twice the payment budget reaches the wallet in a minute). The
  budgets still bound all senders together; a flood of well-formed payments can still use them
  up, at the cost the proof of work puts on each circuit.
