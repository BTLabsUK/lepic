# lepic-store

Wallet storage behind repository traits. The engine sees only `WalletStore` and the repository
traits. `SqliteStore` is the product implementation: one SQLite database per wallet directory,
encrypted at rest. `MemoryStore` behaves the same without a file, for tests of the layers above.

## Where it fits

- Depends on `lepic-primitives`.
- Used by `lepic-wallet`, `lepic-wallet-contacts`, `lepic-cli`, `lepic-ffi`, the conformance
  suite and the fuzz targets.
- Feature `sqlite` (default) adds `SqliteStore`, the directory lock, the contact backup and the
  `epic-wallet` import. Without it, the traits, record types and `MemoryStore` remain.

## Core concepts

- **One transaction for everything.** `WalletStore::read` runs a closure against a consistent
  snapshot; `WalletStore::write` runs one atomic write across every repository. A closure that
  returns `Err` leaves nothing behind.
- **Repositories.** `Repositories` joins the traits for accounts, outputs, transactions, slates,
  private contexts, the relay inbox and outbox, settings, invoices, peers, peer pins, imported
  history, contacts and transaction records.
- **Encryption at rest.** The database file is encrypted with SQLite3 Multiple Ciphers under a
  `StoreKey` (ADR 0032). A key check file beside it tells a wrong key from a damaged file.
  `open_wallet_dir` opens the encrypted database, or copies a plain one into it, checks the copy
  and switches; `AtRestReport` says which happened.
- **Sealed contexts.** Private transaction contexts (blinding factors and nonces) are sealed with
  XChaCha20-Poly1305 under the `ContextKey` in `StoreKeys`. The slate id and participant are the
  associated data, so a context copied to another row does not open.
- **Directory lock.** Every opener of a wallet directory takes one OS lock (`lock_data_dir`), so
  a CLI command and an app never open one database at once.
- **Owner-only files.** `file::write_owner_only_atomic` writes a file readable by its owner only,
  through a temporary file and a rename, so a crash leaves the old content or the new.
- **Import.** `legacy` reads the transaction history of an `epic-wallet` database from a copy,
  never writing the source folder.
- **Contact backup.** `export_contacts` and `import_contacts` produce and read the JSON payload
  of a contact backup file.

## Public API

| Area | Main items |
|---|---|
| Store | `WalletStore`, `Repositories`, `MemoryStore`, `StoreError`, `DatabaseError`, `Record` |
| SQLite (`sqlite`) | `SqliteStore` (`open`, `open_existing`), `open_wallet_dir`, `open_existing_wallet_dir`, `retire_plain_store`, `DATABASE_FILE`, `ENCRYPTED_DATABASE_FILE`, `SCHEMA_VERSION` |
| At rest | `StoreKey`, `AtRest`, `AtRestReport`, `AtRestState`, `MigrationObserver`, `MigrationProgress` |
| Keys and contexts | `StoreKeys`, `ContextKey`, `ContextRepository`, `PrivateContext`, `ParticipantId`, `PeerTagKey` |
| Wallet records | `AccountRepository`, `OutputRepository` (`OutputRecord`, `OutputStatus`, `KeyId`), `TransactionRepository` (`TxId`, `TxState`), `TxRecordRepository` (`TxWatch`), `SlateRepository`, `SettingsRepository` |
| Messaging records | `RelayRepository` (inbox and outbox), `InvoiceRepository` (`PendingInvoice`, `MAX_PARKED_INVOICES`), `PeerRepository`, `PeerPinRepository` |
| Contacts | `ContactRepository`, `ContactRecord`, `PendingPairing`, `MAX_CONTACTS`, `MAX_PENDING_PAIRINGS`; `export_contacts`, `import_contacts`, `CONTACT_BACKUP_VERSION` (`sqlite`) |
| Import | `ImportedRepository`, `ImportedTransaction`, `ImportedOutput`; `legacy` (`sqlite`) |
| Files (`sqlite` for the lock) | `file::write_owner_only_atomic`, `lock_data_dir`, `try_lock_data_dir`, `DataDirLock`, `LOCK_FILE` |

## Related

- [Architecture: storage at rest](../../docs/architecture.md#storage-at-rest)
- [ADR 0032: store encrypted at rest](../../docs/adr/0032-store-encrypted-at-rest.md)
- [`epic-wallet` database format](../../docs/compat/epic-wallet-db.md)
- [Pairing protocol](../../docs/protocols/pairing.md) for the contact records
- [`lepic-wallet`](../lepic-wallet/README.md)
