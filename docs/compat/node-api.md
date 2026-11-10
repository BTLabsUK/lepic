# Node API used by the wallet

LEPIC calls the foreign JSON-RPC API of an Epic node at `/v2/foreign` and nothing else: no owner
API, no REST. The calls follow `epic-wallet` `v4.1.0` (`impls/src/node_clients/http.rs`,
`libwallet/src/internal/{scan,updater}.rs`, `libwallet/src/api_impl/owner.rs`) and the node's
foreign API at `v4.1.2` (`api/src/foreign_rpc.rs`). The client is `lepic-node`
(`crates/lepic-node/src/client.rs`).

The reference wallet calls the owner API's `get_status` before a refresh to check that the node is
synced. Public nodes do not expose the owner API, so LEPIC judges node progress from `get_tip`,
`get_version` and `ready_for_txs`.

## Calls

| Method | Params | Result fields used |
|---|---|---|
| `get_version` | none | `node_version`, `block_header_version` |
| `get_tip` | none | `height`, `last_block_pushed` |
| `ready_for_txs` | none | `ready_for_txs`; a node that does not know the method answers error `-32601` and the wallet records no answer |
| `get_header` | `[height, null, null]` | `height`, `hash`, `timestamp` (RFC 3339); a `NotFound` rejection means the node has no block at that height |
| `get_kernel` | `[excess_hex, min_height or null, max_height or null]` | `tx_kernel`, `height`, `mmr_index`; a `NotFound` rejection means none |
| `get_outputs` | `[commits_hex[], null, null, false, false]` | `commit`, `block_height`, `mmr_index`; only the outputs found are answered |
| `get_unspent_outputs` | `[start_index, end_index or null, max, true]` | `highest_index`, `last_retrieved_index`, `outputs[]` with `commit`, `proof`, `output_type` (`Coinbase` or `Transaction`), `spent`, `block_height`, `mmr_index` |
| `get_pmmr_indices` | `[start_height, end_height or null]` | `last_retrieved_index` (the first index of the range), `highest_index` (the last) |
| `push_transaction` | `[tx, fluff]` | none |
| `get_unconfirmed_transactions` | `[]` | `tx.body.kernels[]` with `excess`, `excess_sig`, `features`; the transaction pool only, not the Dandelion stem pool |

`get_header` answers a `BlockHeaderPrintable`. The node maps every failure of
`get_header_by_height`, a height above its chain included, to a `NotFound` error; LEPIC returns
`None` for it and keeps every other error. LEPIC refuses a header whose hash is not 32 hex bytes,
whose height is not the one asked for, whose timestamp is not RFC 3339 or is dated before
2019-01-01, or whose height is above the tip it has seen.

## Transport

Requests are JSON-RPC 2.0 over HTTP/1.1. `HttpTransport` (`crates/lepic-node/src/http.rs`)
applies these rules:

- A node URL is `https`, or `http` to a loopback host (`localhost` or a loopback IP). Plain
  `http` to an onion address is accepted when the caller supplies a dialer that connects through
  Tor. A URL with user info, a query or a fragment is refused.
- A node may require HTTP Basic auth on the foreign API; LEPIC takes an optional secret in the
  settings, never in the URL. On a phone another app may serve a loopback port, so a mobile app
  should default to `https` or send no secret.
- A response is read up to `MAX_RESPONSE_BYTES` (8 MiB, room for a full `get_unspent_outputs`
  page). The connect and the request each have a timeout in `HttpSettings`.
- Reads that fail in a way repeating may fix are retried with a doubling backoff
  (`RetryPolicy`). `push_transaction` is never retried.
- `get_outputs` goes in chunks of `outputs_per_request` commitments, several requests in flight
  (`CallPolicy`). The reference client sends 500 per request.

The client remembers the highest tip it accepted. A later tip implausibly far above it is refused,
and so are outputs or kernels in blocks above the tip it knows.

## Restore and scan

1. Convert the height range to an output index range with `get_pmmr_indices`.
2. Page through `get_unspent_outputs` from the start index in pages of 1,000
   (`DEFAULT_PAGE_SIZE`), continuing from `last_retrieved_index + 1` until `highest_index <=
   last_retrieved_index`. Skip spent entries.
3. For each output, try to rewind its range proof with `ProofBuilder`, then `LegacyProofBuilder`
   ([keys and proofs](keys-and-proofs.md)). A match yields amount, identifier and switch type.
4. Reconcile with stored outputs: correct indices, revive outputs marked spent that are still
   unspent, add missing ones with a transaction log entry, and lock restored coinbase outputs by
   maturity.
5. A regular update rescans from the last scanned height minus 100 blocks (`UPDATE_RESCAN_BLOCKS`)
   to the tip.

## Refresh

1. `get_tip`.
2. `get_outputs` for every commitment the wallet tracks.
3. Found: mark unconfirmed outputs unspent and confirm their transaction. Missing and previously
   unspent or locked: mark spent.
4. Confirm open transactions without a change output by `get_kernel` on their excess; an invoice
   payer takes the excess from its I2. The reference wallet also builds a confirmed coinbase entry
   for an unconfirmed coinbase output found on chain.
5. Expire transactions at or past their TTL cutoff. A finalized or posted transaction is never
   expired.
6. Store the confirmed height. When the tip is below the stored confirmed height, the whole
   refresh is skipped, nothing is stored and the node is reported as behind (`NodeBehind`).
7. For each finalized or posted send at or above 1,440 blocks after the height it was finalized
   at (`RELEASE_AFTER_BLOCKS`), counted from the highest confirmed tip, look up its kernel. A
   kernel found confirms the send; a missing one makes it releasable ([states](states.md)). The
   reference wallet has no release.
8. For each released send, look up its kernel for 10,080 blocks after the release
   (`RELEASED_WATCH_BLOCKS`), up to the tip and not past that window. A kernel found moves the
   send from `cancelled` to `confirmed` and stores its change `unspent`. After the window the
   refresh looks for the send's change outputs instead.
9. For a receive that ended unconfirmed, look up its kernel for 1,440 blocks
   (`ENDED_RECEIVE_WATCH_BLOCKS`), and after that ask the node for the payment's own output with
   no end.

Steps 7 to 9 are LEPIC's own ([states](states.md)).

## Checks LEPIC adds

Every hex field and the range proof size are validated. Heights and indices are trusted only to
bound the next request. Sizes and timeouts are bounded by the transport, and only idempotent reads
are retried.
