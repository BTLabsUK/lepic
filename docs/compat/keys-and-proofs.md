# Keys, proofs, kernels and the seed file

This page lists how an Epic wallet turns a recovery phrase into keys, outputs and kernels, and
where `lepic-keychain`, `lepic-crypto` and `lepic-primitives` match it. The rules come from the
Epic node `v4.1.0` (`keychain/src/{mnemonic,extkey_bip32,keychain,types}.rs`,
`core/src/libtx/{proof,aggsig,build,mod}.rs`, `core/src/core/transaction.rs`,
`core/src/consensus.rs`, `core/src/global.rs`) and `epic-wallet` `v4.1.0`
(`impls/src/lifecycle/seed.rs`, `libwallet/src/internal/{keys,scan,selection,tx}.rs`,
`libwallet/src/address.rs`). The golden vectors are in `testdata/vectors/keys/`,
`testdata/vectors/primitives/` and `testdata/vectors/aggsig/`.

## From mnemonic to keys

- The wallet seed is the BIP39 entropy, not the BIP39 PBKDF2 seed. A mnemonic of 12, 15, 18, 21
  or 24 English words gives 16, 20, 24, 28 or 32 bytes of entropy, with its checksum checked. The
  entropy is the BIP32 input. Words are split on any run of whitespace and matched exactly against
  the English list, so capitalised or Unicode-normalised variants are refused
  (`lepic-keychain/src/mnemonic.rs`).
- Master key: HMAC-SHA512 with the key `IamVoldemort` over the seed. The left half is the secret
  key and the right half the chain code (`lepic-keychain/src/bip32.rs`).
- Child derivation follows BIP32. HMAC-SHA512 is keyed by the chain code over the compressed
  parent public key (normal child) or `0x00` and the parent secret (hardened child), then the
  index as a big-endian `u32`. The child secret is the left half plus the parent secret. A derived
  key that is zero or not below the curve order is an error.
- The network changes only the extended-key version bytes:

  | Network | Private | Public |
  |---|---|---|
  | Mainnet | `0x033C04A4` | `0x033C08DF` |
  | Floonet | `0x03273A10` | `0x03273E4B` |

  Derived keys are identical on both networks (`derivation_seed*_{mainnet,floonet}.json`).

## Identifiers and paths

- An identifier is 17 bytes: the depth (`u8`), then four big-endian `u32` path components. Only the
  first `depth` components are derived. A depth above 4 is refused.
- The parent of an identifier drops one level and zeroes the dropped component. The root is its
  own parent. Upstream's path text prints a hardened component as its raw `u32`.
- The default account is `m/0/0` (depth 2). Output keys are `m/0/0/<n>` (depth 3), with `n` from
  the stored next-child counter of the account.

## Address key and payment-proof key

- The Epicbox address key of an account is the unkeyed BLAKE2b-256 of the plain key at
  `m/0/1/<index>`. The account path gets its second component set to 1, and the index is appended
  (`Keychain::address_key`). `epic-wallet` always uses index 0. Vectors:
  `address_keys_seed*.json`. [epicbox.md](epicbox.md) uses it for addresses and signatures.
- `epic-wallet` signs payment proofs with an ed25519 key whose 32-byte seed is that address key
  (`Keychain::payment_proof_key`). Its public key is the payment-proof address. Vectors:
  `address_proofs.json`.
- The onion of a LEPIC wallet has a key of its own: the keyed BLAKE2b-256 of the seed over the
  label `lepic-wallet onion key v1` is the ed25519 seed (`lepic-wallet/src/namespace.rs`,
  ADR 0044). A payment proof asked for over the onion names that key as the receiver address and
  is signed with it. Vectors: `onion_key_seed*.json`.

## Switch commitments

- An output blinding factor uses the regular switch commitment: the derived key is replaced by
  `blind_switch(amount, key)` from the secp256k1-zkp wrapper. Type codes: none 0, regular 1.
- The output commitment is `commit(amount, blinding)` with the switched key.

## Range proofs

- New outputs use `ProofBuilder`:
  - `private_hash` is the unkeyed BLAKE2b-256 of the secret key at the root path (no switch).
    `rewind_hash` is the BLAKE2b-256 of the 33-byte compressed master public key.
  - The nonce of an output is BLAKE2b-256 keyed by the 33-byte commitment over the 32-byte hash:
    the rewind nonce from `rewind_hash`, the private nonce from `private_hash`
    (`proofs_builder_seed32.json`).
  - The 20-byte proof message is: byte 0 reserved (0), byte 1 the wallet type (0), byte 2 the
    switch type, bytes 3 to 19 the 17-byte identifier, so byte 3 is its depth. When it rewinds,
    `epic-wallet` clamps a depth above 4 to 4 rather than refusing the message, and
    `lepic-keychain` does the same.
  - A rewound output counts as the wallet's only if the commitment it recomputes from the amount,
    path and switch type equals the output's commitment.
- `LegacyProofBuilder` rewinds outputs made by older wallets. Both nonces are BLAKE2b-256 keyed by
  the commitment over the switch-blinded root key. The message has bytes 0 to 3 zero and bytes 4
  to 19 the 16-byte path without its depth. The depth is taken as 3 and the switch type as regular
  (`proofs_legacy_builder_seed32.json`).
- A restore tries `ProofBuilder` first and then `LegacyProofBuilder`.

## Kernels and fees

- Kernel feature bytes: plain 0, coinbase 1, height-locked 2.
- The kernel signature message is the BLAKE2b-256 of: the feature byte (coinbase); the feature
  byte and the fee as a big-endian `u64` (plain); or the feature byte, the fee and the lock height,
  each a big-endian `u64` (height-locked).
- The kernel hash is the unkeyed BLAKE2b-256 of the protocol version 1 layout (feature `u8`, fee
  `u64`, lock height `u64`, the 33-byte excess and the 64-byte signature), whatever protocol
  version is spoken. Version 2 on the wire omits the fee and lock height where a feature has none.
  Both binary layouts carry the signature in the secp wrapper's internal form, the compact form
  with each 32-byte half byte-reversed. JSON uses the compact form
  (`testdata/vectors/smoke/plain_kernel_hash.json`).
- Fee = transaction weight times the base fee. The base fee is `MILLI_EPIC`, 100,000 base units,
  where 1 EPIC is 100,000,000 base units (`EPIC_BASE`). The weight is `max(4 * outputs + kernels -
  inputs, 1)`, with the subtraction saturating at 0 (`lepic-primitives/src/fee.rs`).
- Block weights: input 1, output 21, kernel 3. The block limit is 40,000. A transaction may use
  39,976, the limit less one coinbase output and kernel, on both networks (`weight_limits.json`).
- A receiver refuses a transaction whose fee is below the weight-based fee for its actual input,
  output and kernel counts.
- Offset: the first party to add data draws a random 32-byte offset and subtracts it from its own
  excess. The final kernel excess is the sum of the excesses minus `commit(0, offset)`.
- Coinbase maturity is 1,440 blocks on mainnet and 30 on floonet
  (`lepic-primitives/src/params.rs`). A restored coinbase output is locked until its height plus
  the maturity.
- Other vectors: `kernel_features.json`, `fee_grid.json`, `chain_params_*.json`.

## Aggregate signatures

`lepic-crypto/src/aggsig.rs` ports `core/src/libtx/aggsig.rs` over the secp256k1-zkp wrapper:
nonce creation, partial signatures and their verification, aggregation, the check of a completed
signature, and the single-signer signature over the BLAKE2b-256 of a message. Vectors:
`testdata/vectors/aggsig/`.

## Seed file `wallet.seed`

LEPIC reads this file to import a wallet and does not write it (ADR 0005). It is pretty-printed
JSON, `{ "encrypted_seed": hex, "salt": hex, "nonce": hex }`.

- Key: PBKDF2-HMAC-SHA512 over the password with the 8-byte salt, 100 iterations, 32 bytes.
- Cipher: ChaCha20-Poly1305 with the 12-byte nonce and empty associated data. `encrypted_seed` is
  the ciphertext followed by the 16-byte tag, and the plaintext is the entropy
  (`lepic-keychain/src/vault/wallet_seed.rs`). Vectors: `wallet_seed_seed*.json`.
