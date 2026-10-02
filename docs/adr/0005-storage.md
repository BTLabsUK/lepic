# 0005 SQLite storage, platform keystore for secrets, legacy seed import

Status: accepted
Date: 2026-10-02

## Context

`epic-wallet` stores wallet data in SQLite (despite a backend named after LMDB) as a key-value table
with byte prefixes, keeps transactions in separate files, and stores the seed in `wallet.seed`
encrypted with ChaCha20-Poly1305 under a PBKDF2-HMAC-SHA512 key (format in
`docs/compat/keys-and-proofs.md`). LEPIC wants a memory-hard password KDF for anything it writes.

Mobile platforms provide hardware-backed key storage. Users moving from `epic-wallet` hold a mnemonic
and possibly a `wallet.seed` file.

## Decision

- `rusqlite` with the bundled SQLite, a real schema (accounts, outputs, transactions, slates by stage
  and codec, private contexts, relay inbox and outbox, settings, schema version) and forward-only
  migrations. WAL journal mode.
- Repository traits in `lepic-store`; the engine sees only the traits.
- Private transaction context (blinding factors, nonces) is encrypted at rest with an AEAD key derived
  from the wallet's root key.
- Seeds go through a `SecretStore` port. On mobile the host app implements it with Android Keystore or
  the iOS Keychain. On desktop, `lepic-keychain` provides a vault file: XChaCha20-Poly1305 under an
  Argon2id key.
- `wallet.seed` from `epic-wallet` can be imported, read-only. LEPIC never writes that format.
- No import of the `epic-wallet` database. Restoring from the seed recovers funds; local history and
  notes are not carried over.

## Consequences

- Schema changes need a migration and a test that opens a database from the previous version.
- The Argon2id parameters must be tuned per platform so unlocking stays fast on low-end phones. Task
  K-03 measures them and records the defaults in `docs/spikes/k-03-argon2.md` and in code.

## Alternatives considered

- `redb`, a pure-Rust embedded database. Fewer C sources, but no SQL migrations and less mobile
  history. Revisit if SQLite causes build trouble.
- Mirror the `epic-wallet` key-value layout. Would make a database import possible, at the cost of
  keeping its design.
