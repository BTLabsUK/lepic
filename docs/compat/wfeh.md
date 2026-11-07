# App data files (`WFEH` version 1)

BT Wallet encrypts its history backups (`.wfeh` files) in this format, and LEPIC seals
and opens it so that files written before the app moved to LEPIC still open, with no key crossing
the binding (ADR 0014). The format is frozen: a change is a new version byte, never an edit here.

The root secret is derived as `epic-wallet` `v4.0.2` derives it (`impls/src/backends/lmdb.rs`,
`set_keychain` and `keychain`) with the Epic node `v4.0.4` keychain
(`keychain/src/keychain.rs`). Vectors: `testdata/vectors/app_data`.

## Root secret

- `derive_key(0, root_key_id, Regular)`: the master secret key at `m` (identifier depth 0, all
  components zero), then `blind_switch(0, key)`.
- It depends only on the seed (the BIP39 entropy). The network changes only the extended-key
  version bytes, so a floonet and a mainnet keychain of one seed give the same root secret.
- `epic-wallet` stores the unkeyed BLAKE2b-256 of this key as its master checksum. The vectors
  record only that hash, never the key.

## Layout

All integers are single bytes. The first 50 bytes are the header.

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `WFEH` |
| 4 | 1 | version | `1` |
| 5 | 1 | kdf | `1`: HKDF-SHA256 over the root secret |
| 6 | 16 | salt | fresh random bytes per file |
| 22 | 16 | check | HKDF output, info `wfe-history-export-v1/check` |
| 38 | 12 | nonce | fresh random bytes per file |
| 50 | n | ciphertext | ChaCha20-Poly1305 of the payload |
| 50 + n | 16 | tag | Poly1305 tag |

- HKDF-SHA256 (RFC 5869): PRK = HMAC-SHA256(key = salt, root secret). The cipher key is the
  32-byte expansion with info `wfe-history-export-v1/key`; `check` is the 16-byte expansion with
  info `wfe-history-export-v1/check`. Both are one expand block.
- The whole 50-byte header is the associated data.
- The payload is opaque to LEPIC. The app writes UTF-8 JSON with only public or user-entered data.
  An empty payload is valid.

## Opening

Checks run in this order, each with its own error:

1. Shorter than 50 bytes, or magic not `WFEH`: not an app data file.
2. Version not `1` or kdf not `1`: unsupported version.
3. `check` differs from the one this wallet derives with the file's salt: another wallet's file.
   A changed salt or check byte also lands here.
4. Tag does not verify, or fewer than 16 bytes follow the header: damaged.

LEPIC seals and opens payloads up to 32 MiB, the largest file the app reads. The app's own
implementation uses `ring`; LEPIC uses the RustCrypto `hmac`, `sha2` and `chacha20poly1305`
crates, and the vectors, sealed with `ring` by the conformance generator, show both agree byte
for byte.
