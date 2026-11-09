# Legacy wallet databases

This directory holds `epic-wallet` SQLite databases (`wallet_data/db/sqlite/epic.db`) as fixtures
for the legacy history reader in `crates/lepic-store/src/legacy/`. The format is in
[docs/compat/epic-wallet-db.md](../../docs/compat/epic-wallet-db.md).

The test `reads_every_fixture_without_skipping` in `crates/lepic-store/tests/legacy.rs` reads every
`*.db` file here, with its `*.db-wal` file if present, from a temporary copy. It requires at least
one account and no skipped row. It does nothing when the directory is missing.

Only databases of throwaway wallets on a local or test chain belong here, because a database also
holds private transaction contexts. Record for each file which `epic-wallet` version wrote it and
what history it holds.
