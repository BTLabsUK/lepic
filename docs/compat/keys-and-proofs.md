# Keys, proofs, kernels and the seed file

Derived from the Epic node `v4.0.4` (`keychain/src/{mnemonic,extkey_bip32,keychain,types}.rs`,
`core/src/libtx/{proof,aggsig,build,mod}.rs`, `core/src/core/transaction.rs`, `core/src/consensus.rs`,
`core/src/global.rs`) and `epic-wallet` `v4.0.2` (`impls/src/lifecycle/seed.rs`,
`libwallet/src/internal/{keys,scan,selection,tx}.rs`, `impls/src/backends/lmdb.rs`). Items marked
"confirm" need vectors before code depends on them.

## From mnemonic to keys

- The wallet seed is the BIP39 entropy, not the BIP39 PBKDF2 seed. The mnemonic (12, 15, 18, 21 or
  24 English words) is converted to entropy with its checksum checked, and the entropy is the BIP32
  input. Words are split on any run of whitespace and matched exactly against the English list, so
  capitalised or Unicode-normalised variants are rejected.
- Master key: HMAC-SHA512 with key `"IamVoldemort"` over the seed. Left half is the secret key, right
  half the chain code.
- Child derivation follows BIP32: HMAC-SHA512 keyed by the chain code over the compressed parent
  public key (normal) or `0x00 || secret` (hardened), then the index as u32 big-endian; child secret
  = left half + parent secret.
- Network affects only the extended-key version bytes: floonet `0x03273A10`/`0x03273E4B`, mainnet
  `0x033C04A4`/`0x033C08DF`. Derived keys are identical on both networks
  (`testdata/vectors/keys/derivation_*`).

## Identifiers and paths

- An identifier is 17 bytes: depth (u8) then four u32 big-endian path components. Only the first
  `depth` components are derived; a depth above 4 has no derivation upstream and LEPIC rejects it.
- The parent of an identifier drops one level and zeroes the dropped component; the root is its own
  parent. Upstream's path text prints hardened components as their raw `u32` value.
- The default account is `m/0/0` (depth 2). Output keys are `m/0/0/<n>` (depth 3) with `n` taken from
  the stored next-child counter.
- The Epicbox address key path is in `docs/compat/epicbox.md`.

## Payment-proof key

`epic-wallet` signs payment proofs with an ed25519 key whose 32-byte seed is the Epicbox address
secret key for the account and derivation index (`libwallet/src/address.rs`, `ed25519_keypair`; used
from `libwallet/src/internal/tx.rs` and `api_impl/owner.rs`). Its public key is the payment-proof
address, also shown in onion v3 form. Vectors: `testdata/vectors/keys/address_keys_*`.

## Switch commitments

- Output blinding factors use the "regular" switch commitment: the derived key is replaced by
  `blind_switch(amount, key)` from the secp256k1-zkp wrapper. Type codes: none 0, regular 1.
- The output commitment is `commit(amount, blinding)` with the switched key.

## Range proofs

- New outputs use `ProofBuilder`:
  - `private_hash` = BLAKE2b-256 of the master secret key (unkeyed), `rewind_hash` = BLAKE2b-256 of
    the 33-byte compressed master public key.
  - Nonce for an output = BLAKE2b-256 keyed by the 33-byte commitment over the 32-byte hash (rewind
    nonce from `rewind_hash`, private nonce from `private_hash`); vectors `proofs_builder_seed32`.
  - 20-byte proof message: byte 0 = 0, byte 1 = 0 (wallet type), byte 2 = switch type, bytes 3..20 =
    the 17-byte identifier, so byte 3 is its depth. On rewind upstream clamps a depth above 4 to 4
    rather than rejecting the message.
- `LegacyProofBuilder`, needed to restore old outputs: one nonce = BLAKE2b-256 keyed by the commitment
  over the switch-blinded master key; message bytes 0..4 zero, bytes 4..20 the 16-byte path without
  depth; depth assumed 3 and switch type regular.
- Restore tries `ProofBuilder` first and falls back to `LegacyProofBuilder`.

## Kernels and fees

- Kernel feature bytes: plain 0, coinbase 1, height-locked 2.
- Kernel signature message: BLAKE2b-256 of the feature byte (coinbase), the feature byte then the fee
  as u64 big-endian (plain), or the feature byte, fee and lock height, each u64 big-endian
  (height-locked).
- Kernel hash: unkeyed BLAKE2b-256 of the protocol version 1 layout (feature u8, fee u64 BE, lock
  height u64 BE, 33-byte excess, 64-byte signature), whatever protocol version is spoken; version 2
  drops the unused fee and lock height fields. Both binary layouts carry the signature in the secp
  wrapper's internal form, the compact form with each 32-byte half byte-reversed; JSON uses the
  compact form (`testdata/vectors/smoke/plain_kernel_hash.json`).
- Fee = transaction weight times base fee. Base fee is `MILLI_EPIC` = 100,000 base units, where
  1 EPIC = 100,000,000 base units (`EPIC_BASE`). Weight is `max(4 * outputs + kernels - inputs, 1)`,
  with the subtraction saturating at 0.
- Block weights: input 1, output 21, kernel 3. The block limit is 40,000 and a transaction may use
  39,976, the limit less one coinbase output and kernel, on both networks.
- Vectors: `testdata/vectors/primitives/` (`kernel_features`, `fee_grid`, `chain_params_*`,
  `weight_limits`).
- The receiver rejects a transaction whose fee is below the weight-based fee for its actual input,
  output and kernel counts.
- Offset: the first party to add data generates a random 32-byte offset and subtracts it from its own
  excess; the final kernel excess is the sum minus `commit(0, offset)`.
- Coinbase maturity: 1,440 blocks on mainnet, 30 on floonet. A restored coinbase output is locked until
  its height plus maturity.

## Aggregate signatures

Partial signatures, partial verification, aggregation and single-signer signatures (for message
signatures, over BLAKE2b-256 of the message) come from `core/src/libtx/aggsig.rs` over the
secp256k1-zkp wrapper. Port the call sequence exactly and prove it with vectors.

## Seed file `wallet.seed`

Read-only for LEPIC (ADR 0005):

- Pretty-printed JSON `{ "encrypted_seed": hex, "salt": hex, "nonce": hex }`.
- Key = PBKDF2-HMAC-SHA512(password, 8-byte salt, 100 iterations, 32 bytes).
- ChaCha20-Poly1305 with the 12-byte nonce and empty AAD; `encrypted_seed` is ciphertext then the
  16-byte tag. The plaintext is the entropy.
