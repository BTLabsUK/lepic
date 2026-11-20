# app_data

Written by `conformance/vectors/src/app_data.rs`. The area is deterministic: every file
regenerates byte for byte. The envelope and encoding rules are in [../README.md](../README.md).

| Files | Upstream | What they pin down |
|---|---|---|
| `wfeh_seed_a`, `wfeh_seed_b` | node `keychain/src/keychain.rs`, as wallet `impls/src/backends/lmdb.rs` uses it | The BLAKE2b-256 hash of the root secret `derive_key(0, root_key_id, Regular)` on both networks, and a `WFEH` version 1 file ([docs/compat/wfeh.md](../../../docs/compat/wfeh.md)) sealed under it with the given salt, nonce and payload. |
| `wfeh_seed_a_empty_payload` | same | The same with an empty payload, an all-zero salt and an all-ones nonce. |

The files are sealed with `ring`, the library the app seals them with, by code written from the
format description. LEPIC's code does not seal them. The two seeds give two wallets, so each file
is the other wallet's foreign file.
