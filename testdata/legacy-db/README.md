# Legacy wallet databases

`epic-wallet` SQLite databases (`wallet_data/db/sqlite/epic.db`) used as fixtures for the legacy
history reader in `crates/lepic-store/src/legacy/`. The format is in
[`docs/compat/epic-wallet-db.md`](../../docs/compat/epic-wallet-db.md).

`crates/lepic-store/tests/legacy.rs` (`reads_every_fixture_without_skipping`) reads every `*.db`
here, with its `*.db-wal` if present, from a temporary copy, and requires at least one account and
no skipped row.

Only databases of throwaway wallets on a local or test chain belong here: a database also holds
private transaction contexts. Record for each file which `epic-wallet` version wrote it and what
history it holds.
