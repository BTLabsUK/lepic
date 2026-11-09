# store

Written by `conformance/vectors/src/store`. Deterministic: every file regenerates byte for byte.

| Files | Upstream | What they pin down |
|---|---|---|
| `peer_compat`, `peer_compat_migrated`, `peer_compat_native` | none (the node pin is recorded for `blake2-rfc`, the BLAKE2b the node hashes with) | The two seed subkeys (`lepic-wallet private context key v1`, `lepic-wallet peer tag v1`), the key tag of a peer's Epicbox key text, the version 1 record of what is kept per key, and the sealed row: format byte, nonce, XChaCha20-Poly1305 ciphertext under the context key with the tag in its associated data (ADR 0016, schema version 12 amendment). The second is a row as the migration from schema version 11 writes a `lepic` one. The third is a version 2 record: the version 1 fields and the peer's native seal key (RFC 0003 5.15). |

The rows are sealed by code written from the format description, HChaCha20 checked against
draft-irtf-cfrg-xchacha-03 and `ring`'s ChaCha20-Poly1305, not by LEPIC. `lepic-store` replays the
tag and the row, `lepic-wallet` the subkeys.
