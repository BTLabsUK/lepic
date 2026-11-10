# ADR 0014: Which secrets cross the Flutter boundary

Status: accepted

## Context

An app cannot meet a rule that no secret crosses the FFI boundary. The user types passwords,
PINs and recovery phrases in Dart, and a backup screen shows the recovery phrase. Dart strings
cannot be wiped, so every crossing is deliberate and as rare as possible. This record replaces
the "no secrets cross the boundary" line of ADR 0007.

## Decision

- Into Rust, only what the user types or configures:
  - the wallet password and the PIN;
  - a recovery phrase, in `create` and `create_with_pin` (when restoring), `validate_mnemonic`,
    `wallet_fingerprint` and `reset_password`; `MockChain::fund` also takes one, in builds with
    the `mock` feature, which no app ships;
  - the password of an `epic-wallet` `wallet.seed` file, in `import_wallet_seed`;
  - the node API secret, in `WalletConfig.node_api_secret`.
- Out of Rust, the recovery phrase only, through `EpicWallet::mnemonic(password)` or
  `EpicWallet::mnemonic_with_pin(pin, sealed_password)` after the credential is checked, for the
  backup screen. A new wallet is created without a phrase; the app asks for it afterwards.
- Out of Rust into the app's `SecretStore` only, and back from it: the vault (`lepic.vault`,
  `lepic.vault-next` during a password change), the PIN attempt counter (`lepic.pin-failures`),
  and for a PIN wallet the PIN key, a random 256-bit value (`lepic.pin-key`, and
  `lepic.pin-key-pending` with a digest of the new sealed text until `confirm_pin_change`). The
  binding passes these to the store and to nothing else.
- Both ways, for contact pairing (RFC 0002): an invite link (`epiccash://pair/1/`) and its five
  pairing words. They leave Rust from `pairing_invite` and `pairing_find_words` for display and
  sharing, and enter it, as the user typed, pasted or scanned them, in `pairing_preview`,
  `pairing_accept` and `pairing_find_words`. Whoever holds either can pair as the contact until
  the invite is used or expires. The app does not store or log them, and the binding types that
  hold them leave them out of `Debug`. Reply, confirm and card links are not secrets.
- Never out of Rust: seed bytes, private keys, blinding factors, nonces, the wallet password,
  vault keys. A wallet password generated for PIN unlock is created, sealed and used inside Rust.
  Dart holds only the sealed text.
- The sealed text is the generated password sealed under the PIN together with the PIN key,
  which the app backs with the platform keystore. The sealed text alone, or with the vault,
  does not reveal the PIN. With the store's contents a PIN can be guessed offline at the cost
  of one Argon2id run per guess, so the store must stay on the device and out of backups.
- PIN attempts are counted in the store and delayed after repeated failures: three free
  failures, then 30 seconds, doubling per further failure up to one hour. `create_with_pin`
  and `change_pin` require at least six characters (`PinSettings.min_len`); unlocking does not
  check the length.
- Every binding call that receives a `WalletConfig` moves the node API secret into a buffer
  that is wiped on drop before it does anything else. Secrets that enter as arguments are held
  in `Zeroizing` values.

## Consequences

- The binding has no `generate_mnemonic`, `generate_wallet_password` or `open_password` call.
  PIN unlock is `create_with_pin` and `open_with_pin`.
- A review of the binding checks every function signature in `lepic-ffi` against this list.
- `docs/rules.md` states the rule for contributors.

## Related

- ADR 0007, ADR 0023
