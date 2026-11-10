# ADR 0032: Wallet database encrypted at rest with SQLite3 Multiple Ciphers

Status: accepted

## Context

The wallet database holds outputs, amounts, counterparty addresses, slates, relay messages,
contacts and settings. The private transaction contexts are sealed in their column (ADR 0005); the
rest is a plain SQLite file, kept to its owner by file mode or access list. A copied data folder,
a lost laptop disk or a phone read after its first unlock gives all of it away.

LEPIC needs the whole database unreadable without the wallet's seed, with no change to the
repositories and queries, with crash safety under WAL, and without a crypto library it would have
to maintain.

## Decision

The database file and its WAL are encrypted page by page with SQLite3 Multiple Ciphers
(SQLite3MC), keyed from the seed.

- **Build.** rusqlite links `third_party/libsqlite3-sys`, libsqlite3-sys 0.38.2 with a rewritten
  build script. The script compiles the SQLite3MC amalgamation from crates.io `sqlite3mc-src`,
  pinned `=206.1.0`, a byte-for-byte copy of the release amalgamation (checksums in
  `third_party/libsqlite3-sys/PATCHES.md`). The root `Cargo.toml` and `fuzz/Cargo.toml` patch
  crates.io's `libsqlite3-sys` with it. Only the ChaCha20-Poly1305 scheme is compiled
  (`CODEC_TYPE_CHACHA20`, every other scheme off), with `SQLITE_TEMP_STORE=3` and
  `SQLITE3MC_SECURE_MEMORY=1`. The build needs only a C compiler: it refuses pkg-config, a system
  SQLite, SQLCipher and bindgen, and uses no OpenSSL. With C23, glibc before 2.43 lacks
  `memset_explicit`, which the amalgamation calls, so the build asks for `gnu17`.
- **Licences.** SQLite3MC is MIT and public domain; one block of the amalgamation is under the
  Unlicense. `deny.toml` allows that licence for `sqlite3mc-src` alone, as a licence exception.
- **Scheme.** Every 4 KiB page of the database and its WAL is encrypted with ChaCha20 and
  authenticated with Poly1305. A 16-byte nonce, drawn from SQLite3MC's generator for every page
  write, and a 16-byte tag sit at the end of the page. A page's nonce is never derived from its
  page number, so installs that share a key do not repeat a nonce. A wrong key or an altered page
  reads as "not a database".
- **Key.** `store_key = BLAKE2b-256(key = seed, "lepic-wallet store key v1")`
  (`lepic-wallet/src/lifecycle.rs`), derived beside the context key. It is given to SQLite3MC as
  the bytes `raw:` ‖ key through `sqlite3_key_v2` before the first read, never in a SQL text, so
  SQLite3MC runs no key stretching. The connection first sets `PRAGMA memory_security = fill`, so
  SQLite wipes freed memory. `StoreKey` zeroizes on drop and has no `Debug`. A password or PIN
  change needs no re-key, and "Recover with phrase" opens the same file.
- **Key check.** `<database>.check` holds `0x01 ‖ salt(16) ‖ BLAKE2b-128(key = store_key,
  "lepic-wallet store check v1" ‖ salt)`, with a fresh random salt for every write. It is written
  through a temporary file, `fsync`, rename and a folder `fsync`, with mode 0600 on Unix, when an
  encrypted database is created or opened with the right key and no check. A check that refuses
  the key is `StoreError::WrongKey` and nothing is touched. A file is set aside as damaged
  (ADR 0005) only when its check proves the key. Without a check, a file the key cannot open is
  `WrongKey` too. "Not a database" alone never sets an encrypted file aside.
- **Interface.** `SqliteStore::open(path, keys, at_rest)` and `open_existing` take
  `AtRest::Plain` or `AtRest::Encrypted(&StoreKey)`. The `StoreOpener` port
  (`lepic-wallet/src/ports.rs`) takes the store key; `open_reporting` also returns an
  `AtRestReport`: whether the database is encrypted, was migrated by this open or fell back to
  plain (`AtRestState`), and whether an older build's plain file was set aside.
  `EncryptingSqliteStores` is the opener of the app and the CLI. It opens a data directory
  through `lepic_store::open_wallet_dir`. `EncryptedSqliteStores` opens `wallet.enc.sqlite3` only
  and `SqliteStores` the plain `wallet.sqlite3`, for tests and tools.
- **Migration.** A plain `wallet.sqlite3` is copied, checked and switched under the data
  directory's claim (`.lepic.lock`), in `lepic-store/src/sqlite/migrate_encrypted.rs`.
  1. With `wallet.enc.sqlite3` present, it opens.
  2. Else, with a plain `wallet.sqlite3`: remove a `wallet.enc.sqlite3.tmp` left by an earlier
     run and make it again, empty; open the plain file read-only and run `quick_check` (a damaged
     file is set aside, a file of a newer schema is refused and left unchanged); `VACUUM INTO` the
     keyed `.tmp`; flush it, open it with the key and compare `quick_check`, schema version,
     `user_version` and the rows of every table with the plain file; store `store.migrated_from`
     (schema, size and SHA-256 of the plain file and its log, row counts, time) in it; write the
     key check; rename `.tmp` to `wallet.enc.sqlite3` (the switch) and flush the folder; move the
     plain file and its log to `wallet.sqlite3.pre-encryption` and remove its `-shm`.
  3. Else, a new encrypted database is made.

  The schema migrations run after the switch, on the encrypted file only, so the plain file's
  bytes never change. An interruption before the switch leaves only the `.tmp`, and the next open
  starts over. After the switch, the next open sets aside a plain file whose bytes match the
  `store.migrated_from` record. A failure before the switch, such as a full disk, removes the
  `.tmp` and runs the session on the plain file (`AtRestState::FellBackToPlain`); the next open
  tries again. Any other plain file beside the encrypted one is an older build's after a
  rollback: the open stores `store.rollback_scan_required`, moves the file to
  `wallet.sqlite3.after-rollback-<unix>`, and the wallet turns the flag into its restore-scan
  requirement in the same transaction.

  A check of a recovery phrase (`open_existing_wallet_dir`) moves nothing: without an encrypted
  file it reads a throwaway encrypted copy, removed when the store drops. A second opener that
  finds the claim held while a copy is in progress waits up to ten minutes (`MIGRATION_WAIT` in
  the FFI runtime and the CLI) instead of failing at once. `retire_plain_store` deletes the
  `pre-encryption` files and the `after-rollback-*` files older than a given age, and only while
  the encrypted database exists. `EpicWallet::retire_plain_store` exposes it to the app.
- **Unsafe code.** The key call is the only hand-written `unsafe` in LEPIC: one block in
  `lepic-store/src/sqlite/cipher.rs` under `#[expect(unsafe_code)]`. The workspace denies
  `unsafe_code`, and `xtask`'s `repo-lint` allows one relaxation there and the generated FFI
  module.
- **Temporary files.** SQLite3MC seals the database and its WAL, not temporary files. The build
  keeps them in memory (`SQLITE_TEMP_STORE=3`), and `temp_store = MEMORY` is set on each
  connection as well.

## Consequences

- A data folder copied without the seed holds no readable wallet records. Anyone with the
  recovery phrase reads them, as they can spend the funds.
- File sizes and change times are still visible.
- A C source and the Unlicense are part of the dependency graph. An SQLite3MC upgrade is a new
  `sqlite3mc-src` pin and a re-check of `PATCHES.md`. A rusqlite upgrade re-applies the build
  changes to the matching libsqlite3-sys.
- Older builds cannot read `wallet.enc.sqlite3`. The name is new, so they never mistake it for a
  damaged `wallet.sqlite3`.
- The wallet keeps one `.check` file per database and a plain copy aside after a migration until
  `retire_plain_store` removes it.

## Alternatives considered

- SQLCipher through rusqlite's `bundled-sqlcipher`: needs OpenSSL, which ADR 0010 excludes, or a
  crypto provider build LEPIC would maintain.
- Every column sealed in Rust, as the contexts are: every repository and query changes, lookups
  by address or slate id break, and row counts and structure stay visible.
- A Rust VFS over `chacha20poly1305`: LEPIC would own WAL, shared-memory and locking correctness
  of a money database.
- Encrypting the file on close: not crash-safe with WAL, and plaintext while open.

## Related

- ADR 0005: storage, damaged-file rule, sealed contexts.
- ADR 0010: dependency policy.
