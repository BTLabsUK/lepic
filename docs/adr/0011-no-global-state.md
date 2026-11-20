# ADR 0011: No process-global state

Status: accepted; the contents of `ChainParams` are superseded by ADR 0013

## Context

The reference node keeps the chain type in a process-wide lock that coinbase maturity, address
version bytes and key derivation read. `epic-wallet` adds a global Tokio runtime, a global Tor
manager and global logger state. A process there cannot hold a mainnet wallet and a floonet
wallet, and a library user cannot control initialisation.

## Decision

- `Network` (mainnet or floonet) is a value passed to whatever needs it. `ChainParams` derived
  from it holds the network's consensus values. Contents: see ADR 0013.
- The engine, transports and node client receive their runtime, clock, RNG, paths and settings
  as arguments or trait objects.
- Statics are limited to:
  - the immutable secp256k1 context in `lepic-crypto`, created once on first use;
  - one cached value of the current user's Windows security identifier in `lepic-store`;
  - a mutex in `lepic-cli` that serialises password changes inside one process.
- A wallet's collaborators that are set after construction (reply keys, native slates, contact
  notices, pair requests) live in `OnceLock` fields of that wallet, not in statics.

## Consequences

- Two wallets on different networks run in one process. Tests run in parallel without
  interfering.
- Ported code that read a global takes a parameter instead. The conformance vectors confirm
  the values (ADR 0009).

## Related

- ADR 0013
