# ADR 0005: SQLite storage, platform keystore for secrets, legacy seed import

Status: accepted. The database-import bullet: see ADR 0019.

## Context

`epic-wallet` stores wallet data in SQLite as a key-value table with byte prefixes, keeps
transactions in separate files, and stores the seed in `wallet.seed`, encrypted with
ChaCha20-Poly1305 under a PBKDF2-HMAC-SHA512 key (`../compat/keys-and-proofs.md`). LEPIC wants a
memory-hard password KDF for anything it writes.

Mobile platforms provide hardware-backed key storage. Users moving from `epic-wallet` hold a
mnemonic and possibly a `wallet.seed` file.

## Decision

- `rusqlite` with the bundled SQLite (SQLite3 Multiple Ciphers, which encrypts the file: ADR 0032).
  The schema has tables for accounts, outputs, transactions, slates by stage and codec, private
  contexts, the relay inbox and outbox, settings, contacts, pairings and pending invoices. A
  `schema_version` table records the version, and migrations only move forward: a database written
  by a newer version is refused. The journal mode is WAL.
- The engine sees only the repository traits in `lepic-store` (`WalletStore` and the repositories
  behind it). `SqliteStore` is the product implementation and `MemoryStore` serves tests of the
  layers above.
- Private transaction context (blinding factors, nonces) is sealed at rest with XChaCha20-Poly1305
  under a key derived from the wallet's root key. The slate id and participant are authenticated as
  associated data.
- An invoice received from a paired contact is parked in its own table until the user pays or
  declines it. Its slate bytes are sealed under the same key, with the slate id and sender key as
  associated data, because they carry a peer's amount and message before the user accepted
  anything. The store caps parked invoices at 100 in total and 10 per sender key
  (`MAX_PARKED_INVOICES`, `MAX_PARKED_INVOICES_PER_SENDER`); parking past a cap fails with
  `InvoiceCapReached`. A parked invoice moves only to paid or declined.
- What a peer's messages showed about its software is keyed by the Epicbox public key alone,
  because the relay authenticates the key and never the domain. A row holds only dates and feature
  bits, sealed under the private context key and found by a keyed hash of the key, so the table
  names no peer. The hash is authenticated with the sealed bytes, so a row copied under another
  peer's hash does not open.
- The invoice address of earlier builds is retired. The store keeps its single index row, which
  is never 0, so older stores read as before; nothing new writes it.
- Seeds go through a `SecretStore` port in `lepic-keychain` (`put`, `get`, `delete` by name). On
  mobile the host app implements it with Android Keystore or the iOS Keychain. On desktop,
  `lepic-keychain` provides a vault, one file of named secrets sealed with XChaCha20-Poly1305
  under an Argon2id key; the caller supplies the file access and the randomness.
- `wallet.seed` from `epic-wallet` can be imported, read-only (`WalletSeedFile`). LEPIC never
  writes that format.
- Import of the `epic-wallet` database: see ADR 0019.

## Consequences

- A schema change needs a migration and a test that opens a database from the previous version.
- Argon2id parameters are chosen per platform so unlocking stays fast on low-end phones.
- The import of a seed file recovers funds. Local history comes from ADR 0019.

## Related

- ADR 0014: which secrets cross the Flutter boundary.
- ADR 0019: import of the `epic-wallet` transaction history.
- ADR 0032: the encrypted database file.
