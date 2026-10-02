# Node fixtures

Answers of a public floonet node to LEPIC's node client, recorded once by the opt-in live test
`crates/lepic-node/tests/live.rs` and replayed offline by `crates/lepic-node/tests/fixtures.rs`,
through `MockNode` and over a local HTTP server. These are fixtures, not golden vectors: they show
that the client accepts what a deployed node sends, not what upstream computes.

Each file holds `schema` (currently `1`), `description`, `network`, `recorded_by`, the node's
`node_version` and `exchanges`. Exchanges use the format of
[Recorded node exchanges](../vectors/README.md#recorded-node-exchanges), so `MockNode` serves a
fixture with the same LEPIC replay rules as a G-05 session.

To record again, with a floonet node:

```
LEPIC_LIVE_TESTS=1 LEPIC_TEST_NODE_URL=<floonet node url> LEPIC_RECORD_NODE_FIXTURES=1 \
  cargo test -p lepic-node --test live
```

The test makes six read calls over the last three blocks. Never point it at mainnet.

| File | Calls |
|---|---|
| `floonet_reads.json` | `get_version`, `get_tip`, `get_pmmr_indices` and `get_unspent_outputs` over the last three blocks, `get_outputs` for two listed outputs and one unknown commitment, `get_kernel` for an unknown excess (`NotFound`). |
