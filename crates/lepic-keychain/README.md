# lepic-keychain

Everything a wallet derives from its recovery phrase: the BIP39 mnemonic and seed, BIP32 keys as
the Epic keychain derives them, output keys and commitments, the range proof builders, the
Epicbox address and payment-proof keys, and the vault format that keeps the seed under a
password. A pure crate.

## Where it fits

- Depends on `lepic-crypto` and `lepic-primitives`.
- Used by the engine (`lepic-wallet`), the methods, the contacts layer and both hosts.
- Feature `test-kdf`: `KdfParams::for_tests`, the cheapest Argon2 setting, so tests of the crates
  above stay fast. App builds never enable it.
- Does no I/O. The vault reads and writes through a `VaultStorage` the caller supplies, and every
  function that needs randomness takes an RNG.

## Core concepts

- **Seed.** The wallet seed is the BIP39 entropy itself, as `epic-wallet` feeds it to its
  keychain, not the PBKDF2 seed BIP39 defines. `Seed::from_mnemonic` and `Seed::to_mnemonic`
  convert between phrase and seed.
- **Keychain.** `Keychain::from_seed(seed, network)` holds the master key. Output keys are
  addressed by an `Identifier`: a depth and up to four path components. `Keychain::commit`
  builds an output's commitment with the `SwitchCommitment` scheme.
- **Range proofs.** `ProofBuilder` makes the proof every output gets. `LegacyProofBuilder`
  is the scheme of outputs made before the first hard fork; LEPIC only rewinds with it.
  `OutputRewinder` tries both to recognise the wallet's own outputs during a scan.
- **Addresses.** `Keychain::address_key` derives the Epicbox address key as `epic-wallet`'s
  `address_from_derivation_path` does; `PaymentProofKey` is the Ed25519 key built on it.
  `contact_identity_key_id` gives the contact-identity key path of RFC 0002.
- **Vault.** `Vault` keeps named secrets in one file (`LEPICVLT`, version 1), sealed with
  XChaCha20-Poly1305 under an Argon2id key from the password (ADR 0005). `WalletSeedFile` reads,
  but never writes, the `wallet.seed` file of `epic-wallet`.
- **App data.** `app_data::seal` and `app_data::open` read and write the app's `WFEH` backup
  files under a key derived from the wallet's root secret.

## Public API

| Area | Items |
|---|---|
| Phrase and seed | `Seed`, `MnemonicError` |
| Derivation | `Keychain`, `KeychainError`, `SwitchCommitment`, `Identifier`, `bip32::{ExtendedPrivKey, ChildNumber, ChainCode, Fingerprint}` |
| Proofs | `ProofBuilder`, `LegacyProofBuilder`, `OutputRewinder`, `ProofBuild`, `RewoundOutput`, `ProofError` |
| Address keys | `address_key_id`, `PaymentProofKey`, `contact_identity_key_id` |
| Seed storage | `Vault`, `VaultStorage`, `MemoryVaultStorage`, `SecretStore`, `SecretName`, `SecretBytes`, `KdfParams`, `WalletSeedFile` |
| App data | `app_data::{seal, open}`, `AppDataError` |

## Related

- [Architecture](../../docs/architecture.md)
- [ADR 0005: storage](../../docs/adr/0005-storage.md),
  [ADR 0014: secrets at the Flutter boundary](../../docs/adr/0014-secrets-at-the-flutter-boundary.md)
- [Keys and proofs](../../docs/compat/keys-and-proofs.md), [WFEH files](../../docs/compat/wfeh.md)
- [`lepic-crypto`](../lepic-crypto/README.md), [`lepic-wallet`](../lepic-wallet/README.md)
