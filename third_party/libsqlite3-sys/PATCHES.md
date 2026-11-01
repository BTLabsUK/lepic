# Vendored libsqlite3-sys, built from SQLite3 Multiple Ciphers

LEPIC's rusqlite links this crate instead of crates.io's `libsqlite3-sys` (root `Cargo.toml`
`[patch.crates-io]`, ADR 0032). It compiles the SQLite3 Multiple Ciphers (SQLite3MC) amalgamation
in place of SQLite's, so every wallet database can be sealed page by page.

## Origin

- Rust bindings: crates.io `libsqlite3-sys` 0.38.2 (rusqlite 0.40.2's), MIT. Kept as published:
  `LICENSE`, `src/error.rs`, `sqlite3/bindgen_bundled_version.rs` and `_ext.rs` (generated for
  SQLite 3.53.2).
- C source: crates.io `sqlite3mc-src` 206.1.0+sqlite3mc-2.6.1-sqlite-3.54.0, a byte-for-byte copy
  of the SQLite3MC 2.6.1 release amalgamation. The `.c`, `.h` and `sqlite3ext.h` files match the
  release archive `sqlite3mc-2.6.1-sqlite-3.54.0-amalgamation.zip` (sha256
  `3f25af603566a23c821d8e581778b5ece2a541d2435776de57b8d845c176815a`):
  - `sqlite3mc_amalgamation.c` `9b129d1ceb2c7d5dbf374b833eb29a640ecfa8e4a5af6d48508b429019c707b0`
  - `sqlite3mc_amalgamation.h` `99b3e6997aa5fc604d9ea2352e6ae89dfd4d0af8d5bd7cbfe7293d959779e6eb`
  - `sqlite3ext.h` `48963abfefb41ac329ef9d706acb5eadba952a99a748285c9ded6b5e0942721b`

The 3.53.2 bindings serve SQLite 3.54.0: SQLite only adds to its C API, and rusqlite checks at run
time that the library is not older than its bindings.

## Changes against libsqlite3-sys 0.38.2

- `build.rs` is rewritten. It compiles `sqlite3mc_amalgamation.c` with every option 0.38.2 gives
  its bundled SQLite, plus:
  - `HAVE_CIPHER_CHACHA20=1`, `CODEC_TYPE=CODEC_TYPE_CHACHA20` and every other scheme set to 0
    (AES-128-CBC, AES-256-CBC, SQLCipher, RC4, Ascon-128, AEGIS);
  - `SQLITE_TEMP_STORE=3`: temporary tables, indices and sorts stay in memory on every target.
  It refuses the features that would link or build anything else (system SQLite, SQLCipher,
  bindgen, loadable extensions, sessions).
- `Cargo.toml` is rewritten: the same feature names (rusqlite refers to all of them), build
  dependencies `cc` and `sqlite3mc-src` only. No OpenSSL, no bindgen.
- `src/lib.rs`: the `openssl-sys` link is removed, and `sqlite3_key_v2` and `sqlite3_rekey_v2`
  are declared, as SQLite3MC's header declares them.
- Removed: `sqlcipher/`, SQLite's own `sqlite3.c`, `sqlite3.h` and `sqlite3ext.h`, the bindgen
  wrappers, the 3.34.1 prebuilt bindings, `README.md`, `Upgrade.md`.

## Upgrading

Move rusqlite, then take the matching libsqlite3-sys release, re-apply the changes above, and pin
the newest `sqlite3mc-src` whose SQLite is not older than the bindings' version.
