# ADR 0013: Network parameters live with the format that uses them

Status: accepted

## Context

A wallet needs consensus values (coinbase maturity, weight limits, fee) and, for two formats,
network-specific version bytes: Epicbox addresses and BIP32 extended keys. The version bytes
belong to the formats that encode them. The primitives crate does not parse those formats.

## Decision

- `lepic-primitives` defines `Network` (`Mainnet`, `Floonet`) and `ChainParams`, built with
  `Network::params()` or `ChainParams::for_network`. `ChainParams` holds the network and its
  consensus values: coinbase maturity (1,440 blocks on mainnet, 30 on floonet), the first hard
  fork height, block header version, base fee, block reward schedule and the protocol version.
  Block and transaction weight limits are constants shared by both networks, so decoders, which
  see no network, enforce them.
- Each format crate maps the network to its own version bytes, next to the code that encodes
  them:
  - `lepic-keychain` maps `Network` to the BIP32 private and public version bytes. Floonet's
    bytes serve every non-mainnet chain.
  - `lepic-epicbox` has its own `Network` enum and maps it to the two address version bytes.
- Every crate takes the network as a parameter (ADR 0011).
- A third network is added when a test needs values that differ from floonet, together with
  vectors for those values.

## Consequences

- Version-byte mistakes are caught by the vectors of the format that uses them.
- Callers that use both crates convert between the two `Network` types.

## Related

- ADR 0011
