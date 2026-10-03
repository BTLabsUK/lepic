# 0014 Which secrets may cross the Flutter boundary

Status: accepted
Date: 2026-10-03
Supersedes: the "no secrets cross the boundary" line of ADR 0007.

## Context

The rule that no secret crosses the FFI boundary cannot be met by any Flutter app. The user types
passwords, PINs and recovery phrases in Dart, and a backup screen has to show the recovery phrase.
Dart strings cannot be wiped, so every crossing must be deliberate and as rare as possible.

## Decision

- Into Rust: secrets the user types (password, PIN, recovery phrase on restore). Nothing else.
- Out of Rust: the recovery phrase, only through `EpicWallet::mnemonic(password)` after the password
  is verified, for display on the backup screen. A new wallet is created without a phrase argument;
  the app asks for the phrase afterwards through the same call.
- Never out of Rust: seed bytes, private keys, blinding factors, nonces, the wallet password, vault
  keys. A wallet password generated for PIN unlock is created, sealed and used inside Rust; Dart holds
  only the sealed text.
- The binding README states exactly which values cross, in which direction.

## Consequences

- `generate_mnemonic`, `generate_wallet_password` and `open_password` are not part of the binding;
  PIN unlock is `create_with_pin` and `open_with_pin`.
- Reviews check every function signature in `lepic-ffi` against this list.
