# Node API used by the wallet

Derived from `epic-wallet` `v4.0.2` (`impls/src/node_clients/http.rs`, `libwallet/src/internal/{scan,updater}.rs`,
`libwallet/src/api_impl/owner.rs`) and the node `v4.0.4` foreign API. LEPIC uses the foreign JSON-RPC
API at `/v2/foreign` only: no owner API, no Tor path.

Upstream also calls the owner API's `get_status` before every refresh to check that the node is
synced (the G-05 recordings start with that exchange). LEPIC does not: public nodes do not expose the
owner API, so LEPIC judges node progress from `get_tip` and `get_version`, and replays of the
recordings skip the owner exchange.

## Calls

| Method | Params | Result fields used |
|---|---|---|
| `get_version` | none | `node_version`, `block_header_version` |
| `get_tip` | none | `height`, `last_block_pushed` |
| `get_kernel` | `[excess_hex, min_height or null, max_height or null]` | `tx_kernel`, `height`, `mmr_index`; error `NotFound` means none |
| `get_outputs` | `[commits_hex[], null, null, false, false]` | `commit`, `block_height`, `mmr_index` |
| `get_unspent_outputs` | `[start_index, end_index or null, max, true]` | `highest_index`, `last_retrieved_index`, `outputs[]` with `commit`, `range_proof`, `output_type`, `spent`, `block_height`, `mmr_index` |
| `get_pmmr_indices` | `[start_height, end_height or null]` | `last_retrieved_index`, `highest_index` |
| `push_transaction` | `[tx, fluff]` | none |

Requests are JSON-RPC 2.0. The reference client sends `get_outputs` in chunks of 500 commitments in
parallel. A node may require HTTP Basic auth on the foreign API; LEPIC supports an optional secret.

## Restore and scan

1. Convert the height range to output index range with `get_pmmr_indices`.
2. Page through `get_unspent_outputs` from the start index in batches of 1,000, continuing from
   `last_retrieved_index + 1` until `highest_index <= last_retrieved_index`. Skip spent entries.
3. For each output, try to rewind its range proof with `ProofBuilder`, then `LegacyProofBuilder`
   (`docs/compat/keys-and-proofs.md`). A match yields amount, identifier and switch type.
4. Reconcile with stored outputs: correct indices, revive outputs marked spent that are still unspent,
   add missing ones with a transaction log entry, and lock restored coinbase outputs by maturity.
5. A regular update rescans from the last scanned height minus 100 blocks to the tip.

## Refresh

1. `get_tip`.
2. `get_outputs` for every commitment the wallet tracks.
3. Found: mark unspent and confirm the related transaction; for coinbase, look up the kernel. Missing
   and previously unspent: mark spent.
4. Store the confirmed height. Skip applying results if the tip is below the stored confirmed height.

## Hardening LEPIC adds

Response size limits, timeouts on connect and on each request, retries only for idempotent reads,
strict validation of every hex field and range proof size, and no trust in heights or indices beyond
bounding the next request.
