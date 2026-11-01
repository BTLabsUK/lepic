# 0032 Wallet database encrypted at rest with SQLite3 Multiple Ciphers

Status: accepted
Date: 2026-11-01

Amends 0005 (storage) and 0010 (dependency policy).

## Context

The wallet database holds outputs, amounts, counterparty addresses, slates, relay messages,
contacts and settings. Only the private transaction contexts are sealed (0005); the rest is a plain
SQLite file, kept to its owner by file mode or access list. A copied data folder, a lost laptop
disk or a phone read after its first unlock gives all of it away.

Options:

| Option | Verdict |
|---|---|
| SQLCipher (rusqlite's `bundled-sqlcipher`) | No: needs OpenSSL, banned by 0010, or a crypto provider build LEPIC would maintain |
| Every column sealed in Rust, as contexts are | No: every repository and query changes, lookups by address or slate id break, row counts and structure still show |
| A Rust VFS over `chacha20poly1305` | No: LEPIC would own WAL, shared-memory and locking correctness in a money database |
| Encrypt the file on close | No: not crash-safe with WAL, plaintext while open |
| SQLite3 Multiple Ciphers (SQLite3MC) page encryption | Chosen |

SQLite3MC is an amalgamation of SQLite with page-level encryption and its own C crypto, so it needs
only a C compiler, as LEPIC's other C (secp256k1-zkp) does.

## Decision

- **Build.** rusqlite links `third_party/libsqlite3-sys`, libsqlite3-sys 0.38.2 with its build
  script rewritten to compile SQLite3MC 2.6.1 (SQLite 3.54.0) from crates.io `sqlite3mc-src`
  206.1.0, pinned exactly, a byte-for-byte copy of the release amalgamation (checksums in
  `third_party/libsqlite3-sys/PATCHES.md`). Root `Cargo.toml` and `fuzz/Cargo.toml` patch
  crates.io's `libsqlite3-sys` with it. Only the ChaCha20-Poly1305 scheme is compiled
  (`CODEC_TYPE_CHACHA20`, every other scheme off), with `SQLITE_TEMP_STORE=3`. The build refuses
  pkg-config, system SQLite, SQLCipher and bindgen. No OpenSSL, no CMake, no bindgen.
- **Licences.** SQLite3MC is MIT and public domain; one block is under the Unlicense, which
  `deny.toml` now allows; the rest (CC0-1.0, Apache-2.0) was allowed already.
- **Scheme.** Every 4 KiB page of the database and its WAL is encrypted with ChaCha20 and
  authenticated with Poly1305 (sqleet's construction): a 16-byte nonce drawn from SQLite3MC's
  ChaCha20 generator for every page write and a 16-byte tag at the end of the page (32 reserved
  bytes per page, 0.8 %). The generator reseeds from the OS (`getrandom`, `/dev/urandom`,
  `rand_s` on Windows) and after a fork. Page nonces never derive from the page number, so
  linked installs and restores of one seed, which share the key, never repeat a nonce. A wrong
  key or altered page reads as "not a database".
- **Key.** `store_key = BLAKE2b-256(key = seed, "lepic-wallet store key v1")`, beside the context
  key (`lepic-wallet/src/lifecycle.rs`, `lepic_wallet::store_key`). It is given to SQLite3MC raw
  with `sqlite3_key_v2` as the bytes `raw:` ‖ key before the first read, never in a SQL text,
  so SQLite3MC runs no PBKDF2. `StoreKey` zeroizes and has no `Debug`. The key never leaves
  Rust. A password or PIN change needs no re-key; "Recover with phrase" opens the same file.
- **Key check.** `<database>.check` beside the file: `0x01 ‖ salt(16) ‖ BLAKE2b-128(key =
  store_key, "lepic-wallet store check v1" ‖ salt)`, the salt random per write, so copies of one
  wallet's folder do not match each other. Written (temporary file, fsync, rename, folder fsync)
  when an encrypted database is created, or opened with the right key and no check. A check that
  refuses the key is `StoreError::WrongKey` and nothing is touched. A file is set aside as
  damaged (0005's rule, the check moving with it) only when its check proves the key; without
  a check, a file the key cannot open is `WrongKey` too. "Not a database" alone never sets an
  encrypted file aside.
- **Interface.** `SqliteStore::open(path, key, at_rest: AtRest)` and `open_existing`, with
  `AtRest::Plain` or `AtRest::Encrypted(&StoreKey)`. `StoreOpener::open` and `open_existing` take
  the store key; `SqliteStores` keeps the plain `wallet.sqlite3` and ignores it,
  `EncryptedSqliteStores` opens `wallet.enc.sqlite3`. The app's opener stays on `SqliteStores`
  until the copy-then-switch migration (task N-02, after schema v13) moves it; until then nothing
  the app does changes. The CLI opens `wallet.enc.sqlite3` when the data directory has one.
- **Unsafe code.** The key call is the only hand-written `unsafe` in LEPIC: one block in
  `lepic-store/src/sqlite/cipher.rs` under `#[expect(unsafe_code)]`, which the repository lint
  allows there once and nowhere else.
- **Temporary files.** SQLite3MC seals the database and its WAL, not temporary files; the build
  keeps them in memory and `configure` sets `temp_store = MEMORY` as well.
- **Copy.** `VACUUM INTO 'file:<target>?cipher=chacha20&key=raw:<hex>'` from a read-only
  connection makes an encrypted copy of a plain database, its WAL included, and changes neither
  the plain file nor its WAL (bytes and mtime). The migration task uses it.

## Findings (task N-02, 2026-11-01)

| Target | How | Result |
|---|---|---|
| `x86_64-unknown-linux-gnu` | `cargo test -p lepic-store` | builds; every check below passes |
| `x86_64-pc-windows-msvc` | epicrig rig, Rust 1.99.0, MSVC | builds; cipher, `encrypted` and `sqlite` tests pass |
| `x86_64-linux-android` | `cargo ndk`, API 24, run on the API 36 emulator | builds; cipher and `encrypted` tests pass |
| `aarch64-linux-android` | `cargo ndk`, API 24 | builds; not run (no arm64 device was attached) |

Checked on each target that ran: a raw 32-byte key with the ChaCha20 scheme (`PRAGMA cipher` is
`chacha20`); WAL mode; neither the file nor its WAL holds a written value or `SQLite format 3`;
the wrong key reads as "not a database"; a plain database opens plain in the same build;
`VACUUM INTO` a keyed target leaves the plain file and WAL byte-identical with the same mtime; two
files of one key with the same writes have different nonces on every page, and a rewritten page
gets a new nonce. With C23, glibc before 2.43 lacks `memset_explicit`, which the amalgamation
calls, so the build compiles it as `gnu17`.

Cost, 2,000 transactions written in commits of 100, refreshed and reopened
(`lepic-store/tests/at_rest_probe.rs`, median of 7, encrypted ÷ plain): Linux x86_64 total 1.02,
Android x86_64 emulator 0.97 to 0.99, Windows 1.06. Opening a new database costs about 1.2 times
plain, a few milliseconds.

Outside LEPIC, the desktop app on Linux without a Secret Service starts on its "No keyring found"
screen with Retry and writes nothing but its log; it reaches no wallet, so no database opens.

## Consequences

- A data folder copied without the seed holds no readable wallet records. Anyone with the
  recovery phrase reads them, as they can spend the funds.
- A new C source and the Unlicense in the graph. An SQLite3MC upgrade is a new `sqlite3mc-src`
  pin and a re-check of `PATCHES.md`; an rusqlite upgrade re-applies the build changes to the
  matching libsqlite3-sys.
- Older builds cannot read `wallet.enc.sqlite3`. They never see it: it has a new name, so they
  never mistake it for a damaged `wallet.sqlite3`.
- File sizes and change times still show.
