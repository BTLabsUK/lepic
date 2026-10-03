# 0014 Which secrets may cross the Flutter boundary

Status: accepted
Date: 2026-10-03 (amended the same day to name the PIN variant, to state what the sealed text
protects, and to list the PIN key and the node API secret)
Supersedes: the "no secrets cross the boundary" line of ADR 0007.

## Context

The rule that no secret crosses the FFI boundary cannot be met by any Flutter app. The user types
passwords, PINs and recovery phrases in Dart, and a backup screen has to show the recovery phrase.
Dart strings cannot be wiped, so every crossing must be deliberate and as rare as possible.

## Decision

- Into Rust: secrets the user types (password, PIN, recovery phrase on restore), and the node API
  secret the user configures, in `WalletConfig`. Nothing else.
- Out of Rust: the recovery phrase, only through `EpicWallet::mnemonic(password)` or
  `EpicWallet::mnemonic_with_pin(pin, sealed_password)` after the credential is verified, for display
  on the backup screen. A new wallet is created without a phrase argument;
  the app asks for the phrase afterwards through the same call.
- Out of Rust into the app's `SecretStore` only, and back from it: the PIN key, a random 256-bit
  value written as `lepic.pin-key` when a PIN wallet is created and read at each PIN attempt. The
  binding passes it to the store and to nothing else.
- Never out of Rust: seed bytes, private keys, blinding factors, nonces, the wallet password, vault
  keys. A wallet password generated for PIN unlock is created, sealed and used inside Rust; Dart holds
  only the sealed text.
- The sealed text is sealed under the PIN together with the PIN key, which the app backs with the
  platform keystore. The sealed text alone, or with the vault, does not reveal the PIN. With the
  store's contents the PIN can be guessed offline at the cost of Argon2id per guess, so the store
  must not leave the device. Through the binding, PIN attempts are counted in the store and delayed
  after repeated failures, and a PIN has at least four characters.
- The binding README states exactly which values cross, in which direction.

## Consequences

- `generate_mnemonic`, `generate_wallet_password` and `open_password` are not part of the binding;
  PIN unlock is `create_with_pin` and `open_with_pin`.
- Every binding call that receives a `WalletConfig` moves the node API secret into a buffer that is
  wiped on drop before doing anything else.
- Reviews check every function signature in `lepic-ffi` against this list.
