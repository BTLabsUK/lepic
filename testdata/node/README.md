# Node fixtures

Answers of a public floonet node to LEPIC's node client. The opt-in live test
`crates/lepic-node/tests/live.rs` records them. `crates/lepic-node/tests/fixtures.rs` replays them
offline through `MockNode` and over a local HTTP server
(`fixtures_replay_through_the_mock_and_over_http`). These are fixtures, not golden vectors: they
show that the client accepts what a deployed node sends, not what upstream computes.

Each file holds `schema` (`1`), `description`, `network`, `recorded_by`, the `node_version` the
node reported, and `exchanges`. Exchanges use the format of
[Recorded node exchanges](../vectors/README.md#recorded-node-exchanges), and `MockNode` serves a
fixture with the replay rules of [LEPIC replay](../vectors/README.md#lepic-replay).

To record again, point the test at a floonet node:

```bash
LEPIC_LIVE_TESTS=1 LEPIC_TEST_NODE_URL=<floonet node url> LEPIC_RECORD_NODE_FIXTURES=1 \
  cargo test -p lepic-node --test live
```

The test makes six read calls over the last three blocks. Do not point it at a mainnet node.

| File | Calls |
|---|---|
| `floonet_reads.json` | `get_version`, `get_tip`, `get_pmmr_indices` and `get_unspent_outputs` over the last three blocks, `get_outputs` for two listed outputs and one unknown commitment, `get_kernel` for an unknown excess (`NotFound`). |
