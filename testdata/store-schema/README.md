# Frozen store schemas

Each `vN.sql` is a `sqlite3 .dump` of a store at schema version N, with a few rows in every table that version has. The tests in `crates/lepic-store/src/sqlite/tests.rs` load a file, run the current migrations over it and check the schema and the rows.

- `v14.sql` is the last version before the V15 `touched` column (outputs have no `touched`).
- `v18.sql` to `v22.sql` are the schemas added since 0.5.0. 22 is the shipped one.

The files were made with `migrate_to(N)` from the migrations at the commit that added them, then seeded by hand. They are not captures from released builds. The released-build wallets in `testdata/upgrade` (encrypted) cover schemas 13, 16 and 17.

Add a file when a new schema version ships: dump a store built at that version with rows in every table, add the number to `FROZEN_SCHEMAS` and give the upgrade test the checks for the new rows. Never regenerate an existing file: it is the point of the fixture that it does not follow edits to old migrations.

Total size: about 99 KB for six files.
