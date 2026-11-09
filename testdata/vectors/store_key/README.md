# store_key

Written by `conformance/vectors/src/store_key.rs`. The area is deterministic: every file
regenerates byte for byte. The envelope and encoding rules are in [../README.md](../README.md).

| Files | Upstream | What they pin down |
|---|---|---|
| `store_key_seed_a`, `store_key_seed_a_other_salt`, `store_key_seed_12_words` | none; LEPIC's own derivation ([ADR 0032](../../../docs/adr/0032-store-encrypted-at-rest.md)). The seed is the BIP39 entropy that node `keychain/src/mnemonic.rs` reads from the phrase | The key the wallet database is encrypted under, BLAKE2b-256(key = seed, `lepic-wallet store key v1`), and the key check file `0x01` ‖ salt ‖ BLAKE2b-128(key = store key, `lepic-wallet store check v1` ‖ salt) for the given salt. |

The BLAKE2b is `blake2_rfc`'s, not the RustCrypto code LEPIC uses. LEPIC draws the salt at random;
the vector fixes it.
