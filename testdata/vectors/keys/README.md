# keys

Written by `conformance/vectors/src/keys`. Deterministic: every file regenerates byte for byte,
except `wallet_seed_*`, which records the salt and nonce upstream drew.

| Files | Upstream | What they pin down |
|---|---|---|
| `mnemonic_<n>_words*` | node `keychain/src/mnemonic.rs` | Entropy to English mnemonic, for each allowed length. |
| `mnemonic_parse_*` | same | Phrase to entropy: one accepted whitespace variant and one file per rejection rule, with upstream's message. |
| `derivation_<seed>_<network>` | node `keychain/src/{keychain,extkey_bip32}.rs` | Master key, extended-key version bytes, and the plain BIP32 key, public key, chain code and parent fingerprint at normal, hardened and depth 0 to 4 paths. The keys are equal across the two networks. |
| `commit_raw` | node, secp256k1-zkp wrapper | `commit` and `blind_switch` over given blinding factors and edge amounts. |
| `commit_sums` | same | `blind_sum` and `commit_sum` over positive and negative terms. |
| `commitments_<seed>` | node `Keychain::{derive_key,commit}` | Output blinding factor and commitment per path, amount and switch type. |
| `bulletproof_raw` | secp256k1-zkp wrapper | Bulletproof creation with given blind, nonces, message and optional extra data; rewind output; failures with a wrong nonce or missing extra data. |
| `proofs_builder_seed32` | node `core/src/libtx/proof.rs` | `ProofBuilder` nonces, message and proof per output; rewind by the same builder, by `LegacyProofBuilder` of the same wallet, and by another wallet. |
| `proofs_legacy_builder_seed32` | same | The same for `LegacyProofBuilder`, depth-3 paths and the regular switch type only, as upstream restores them. |
| `wallet_seed_*` | wallet `impls/src/lifecycle/{default,seed}.rs` | The exact `wallet.seed` text written by `create_wallet` from a mnemonic and password, with upstream's salt and nonce. Upstream decrypts it with `password` and rejects `wrong_password`. Kept across runs while the pin and inputs are unchanged. |
| `address_keys_<seed>` | wallet `libwallet/src/address.rs`, `epicbox_address.rs` | Epicbox address key path, plain and hashed key, compressed public key, base58check key and default address on both networks, payment-proof ed25519 key and its onion v3 form. |

An identifier is 17 bytes: depth, then four big-endian `u32` components. `bip32_path` is
upstream's own rendering, which prints hardened components as their raw `u32` value. Every
`null` rewind result is upstream returning `None`.
