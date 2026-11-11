# Upgrade fixtures

Wallets made by released builds. The tests open each one with the current code and check that it
reaches the current store schema (`SCHEMA_VERSION` in `crates/lepic-store/src/sqlite/schema.rs`),
lists the history it listed before, syncs against a node that mined its pending send, and opens a
second time unchanged.

| Fixture | Made by | Schema | Opened by |
|---|---|---|---|
| [`cli-0.4.0`](cli-0.4.0/README.md) | LEPIC 0.4.0, `31609bd8`, the CLI | 16 | `crates/lepic-cli/tests/upgrade.rs` |
| [`app-26.11.3-desktop`](app-26.11.3-desktop/README.md) | LEPIC `b6f5003f` (app release 26.11.3), FFI `create(password)` | 13 | `crates/lepic-ffi/src/tests/upgrade.rs` |
| [`app-26.11.3-mobile`](app-26.11.3-mobile/README.md) | LEPIC `b6f5003f` (app release 26.11.3), FFI `createWithPin` | 13 | `crates/lepic-ffi/src/tests/upgrade.rs` |
| [`ffi-0.4.0`](ffi-0.4.0/README.md) | LEPIC 0.4.0, `31609bd8`, FFI `createWithPin` | 16 | `crates/lepic-ffi/src/tests/upgrade.rs` |

Each directory holds the wallet's files, `chain.json` (the scripted node's chain and the
transactions it was sent), `expected.json` (what the old build itself listed), a README (the
commit, the keys, the history, the cargo features, what was left out) and `generator/`, the ignored
test that made it. `chain.json` is loaded by `RecordedChain` in `lepic-node` (`mock`).

Only throwaway wallets on a scripted floonet belong here, with their phrase and password written
in their README. The wallets use the cheap test key derivation (`test-kdf`), so they open only in
test builds.

## The rule

**A release that changes the store schema adds a fixture made by the previous release.** The
fixture shows the new migration on a database that build wrote, which the synthetic `UPGRADES`
test in `crates/lepic-store/src/sqlite/tests.rs` cannot. Keep the older fixtures: they cover the
chain of migrations.

To add one:

1. Make a detached worktree of the previous release's commit (`git worktree add --detach
   <path> <commit>`). Do not change that commit's code except for what its fixture README names.
2. Copy a generator from an existing fixture's `generator/` into that worktree and adapt it to the
   harness of that commit (`crates/lepic-cli/tests/support` for the CLI, `crates/lepic-ffi` with
   the `mock` feature for the FFI). It makes the same history: two funding outputs, a send that is
   mined, a send that is pushed and not mined, a cancelled send, a contact. It writes the wallet
   directory, `chain.json`, `expected.json` and, for the FFI, `secrets.json` and `mnemonic.txt`
   into the directory named by `LEPIC_UPGRADE_OUT`.
3. Run it in that worktree with `CARGO_INCREMENTAL=0 cargo test ... -- --ignored`.
4. Copy the output to `testdata/upgrade/<path>-<version>/`, with the generator and any patch it
   needed under `generator/`, and write the README as the existing ones do. Keep the fixture
   under 1 MB.
5. Add the fixture to the tests: one more `Fixture` and `upgrade_tests!` line in the FFI tests,
   or a copy of the CLI test's constants. A field of the old listing whose meaning the new build
   changed is named in the fixture's README ("Meaning changes"), and the test compares it
   differently.
6. Remove the worktree.

When a fixture cannot be listed again with the same values, the release changed what a user sees
of an old wallet: fix the code or document the change in the README; do not edit `expected.json`
to match.
