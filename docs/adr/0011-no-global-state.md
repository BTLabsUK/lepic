# 0011 No process-global state; network and settings are parameters

Status: accepted
Date: 2026-10-02

## Context

The node keeps the chain type in a process-wide lock that coinbase maturity, address version bytes and
key derivation read. `epic-wallet` adds a global Tokio runtime, a global Tor manager and global logger
state. A process can therefore not hold a mainnet and a floonet wallet, and a library user cannot
control initialisation.

## Decision

- `Network` (mainnet, floonet, and a test network) is a value passed to whatever needs it.
  `ChainParams` derived from it carries coinbase maturity, block weight limits, base fee and address
  version bytes.
- The engine, transports and node client receive their runtime, clock, RNG, paths and settings
  explicitly.
- Allowed statics: immutable tables (wordlists, constants) and the immutable secp context.

## Consequences

- Two wallets on different networks can run in one process, and tests run in parallel without
  interference.
- Ported code that read a global gets a parameter instead; the conformance vectors confirm the values.
