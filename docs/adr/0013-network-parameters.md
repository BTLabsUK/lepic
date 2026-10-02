# 0013 Network parameters live with the format that uses them

Status: accepted
Date: 2026-10-02
Supersedes: the `ChainParams` contents listed in ADR 0011. The rest of ADR 0011 stands.

## Context

ADR 0011 put address version bytes and a test network into `ChainParams`. While porting, the
version bytes turned out to belong to two unrelated formats: Epicbox addresses (`lepic-epicbox`) and
BIP32 extended keys (`lepic-keychain`). Putting them into `lepic-primitives` would make the
primitives crate know about formats it never parses. No test so far needs a third network.

## Decision

- `lepic-primitives` defines `Network` (mainnet, floonet) and `ChainParams` with the consensus values a
  wallet needs: coinbase maturity, block and transaction weight limits, base fee, protocol version.
- Each format crate maps `Network` to its own version bytes, next to the code that encodes them.
- A test network variant is added when a test needs values that differ from floonet, with vectors
  for those values.

## Consequences

- Still no process-global state: every crate takes `Network` as a parameter.
- Version-byte mistakes are caught by the vectors of the format that uses them.
