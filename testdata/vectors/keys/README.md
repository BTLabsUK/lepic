# keys

Written by `conformance/vectors/src/keys`. The area is deterministic: every file regenerates byte
for byte, except `wallet_seed_*`, which records the salt and nonce upstream drew. The envelope and
encoding rules are in [../README.md](../README.md).

The test seeds are `seed32` (the bytes `00` to `1f`) and `seed16` (`a55ac33c…`). A file name that
ends in a seed name holds that seed's values.

## Keys of the reference node and wallet

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
| `address_keys_<seed>` | wallet `libwallet/src/address.rs`, `epicbox_address.rs` | Epicbox address key path, plain and hashed key, compressed public key, base58check key and default address on both networks, payment-proof Ed25519 key and its onion v3 form. |

An identifier is 17 bytes: depth, then four big-endian `u32` components. `bip32_path` is
upstream's own rendering, which prints hardened components as their raw `u32` value. Every `null`
rewind result is upstream returning `None`.

## Keys and tags of the LEPIC namespace

No upstream wallet has these. The generator writes each from its description with code
independent of LEPIC's: keyed BLAKE2b-256 from `blake2-rfc`, secp256k1 keys, ECDH and ECDSA from
the node's secp256k1-zkp, and SHA-256, HKDF, HMAC and Ed25519 from `ring`. `u32 BE` is a
big-endian `u32`. In the derivations below, `seed` is the BLAKE2b key.

| Files | What they pin down |
|---|---|
| `listing_keys_<seed>` | Listing key: BLAKE2b(key = seed, `lepic-wallet listing key v1` ‖ service key (33) ‖ generation (u32 BE) ‖ counter (u8)). The counter counts from 0 to the first valid secp256k1 key. |
| `listing_signatures` | ECDSA by the listing key over SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ len(domain) (u8) ‖ domain ‖ message), with tag `lepic/listing-signature/v1`, for several domains. |
| `device_link_key_<seed>` | Ed25519 key from BLAKE2b(key = seed, `lepic-wallet device link key v1`). It signs `lepic/device-link/v1` ‖ transcript. |
| `onion_key_<seed>` | Ed25519 key from BLAKE2b(key = seed, `lepic-wallet onion key v1`) and its onion v3 address. |
| `api_tls_key_<seed>` | Ed25519 key from BLAKE2b(key = seed, `lepic-wallet api tls v1`) and the SHA-256 of its RFC 8410 SubjectPublicKeyInfo, the fingerprint a client pins. |
| `epic1_delivery_key_<seed>` | secp256k1 key from BLAKE2b(key = seed, `lepic-wallet epic1 delivery key v1` ‖ account (u32 BE) ‖ network ‖ index (u32 BE) ‖ counter), for indexes 0, 1 and 2^31. The counter counts from 0 to the first valid secp256k1 key. |
| `reply_mailbox_<seed>`, `post_key_<seed>` | BLAKE2b(key = seed, label ‖ account (u32 BE) ‖ network ‖ slate id (16) ‖ counter), each an ordinary Epicbox address. A post key takes the payment id (16) and `role` in place of the slate id. The counter counts from 0 to the first valid secp256k1 key. |
| `seed_check_<seed>` | Seed check: BLAKE2b-256(key = seed, `lepic-wallet seed check v1`). |
| `post_txids` | Transaction id of a post: HMAC-SHA256(key = the post key's 32 secret bytes, `lepic/post-txid/v1` ‖ payment id (16) ‖ stage), the first 16 bytes with the version 4 and RFC 4122 variant bits set, as 32 hex digits. |
| `check_codes` | Check code: the first 4 bytes of SHA-256(`epic-check/1` ‖ public excess (33)), read big-endian, modulo 10,000, as four digits. |
| `address_proofs` | Pairing address proof: K = HKDF-SHA256(salt `lepic/addr-proof/1`, ikm = x of the ECDH point, info = `mac` ‖ network ‖ step). Tag = HMAC-SHA256(K, H(prover card) ‖ H(verifier card) ‖ H(invite)), with 32 zero bytes for a hash a step does not have. |
| `private_pairing_keys` | The keys of a private pairing: the root and, per slot, the encryption, signature, hint and box keys. |
| `private_pairing_tags` | The reply key, the channel key, the words check and the HPKE pre-shared-key id of a private pairing. |
| `pairing_verdicts` | The hash a pairing verdict carries: BLAKE2b-256(`lepic-wallet pairing verdict v1` ‖ sas). |

The private pairing files use the cards, invite and nonces of the first floonet pairing in
[../pairing/cards_invites.json](../pairing/cards_invites.json).

## The epic1 address and link

`epic1_addresses`, `epic1_addresses_refused` and `epic1_links` pin down the `epic1` address and
the `epic1` payment link of RFC 0003 (sections 5.13 and 5.14 and Appendix B). The generator has
its own bech32m and percent-encoding. The keys are published test data: RFC 7748 section 6.1
public keys for the seal half, and the secp256k1 base point G and 2G for the delivery half.
The mailbox keys in `epicbox` entries come from the wallet's address code.

- `epic1_addresses`: a seal key and a delivery key to the address text on each network.
- `epic1_addresses_refused`: texts a reader refuses, with the reason: `mixed_case`, `bad_checksum`,
  `version_00`, `version_02`, `floonet_read_as_mainnet`, `mainnet_read_as_floonet`,
  `small_order_seal_key`, `delivery_key_prefix_04`, `delivery_key_off_curve`, `earlier_length`
  and `one_byte_long`.
- `epic1_links`: each case is `link` or `refused`. A read link lists the `http` and `tor` routes
  it keeps and what it left out: `epicbox` for each `epicbox` entry, which links of earlier
  releases wrote and a reader no longer reads, and `transport_http` or `transport_onion` for a
  value out of form. A link with more than three `http` and `tor` entries is refused with
  `too_many_entries`; an Epicbox link with an `epic1` parameter with `not_an_epic1_link`.
