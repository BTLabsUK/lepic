# Wallet foreign API over HTTP

LEPIC sends and answers the wallet foreign API at `/v2/foreign`, as `epic-wallet` v4.1.0 does
(`impls/src/adapters/http.rs`, `api/src/foreign_rpc.rs`). The code is in the `lepic-legacy-rpc`
crate (`client.rs`, `server.rs`, `rpc.rs`, `url.rs`) and, for the wallet side of a received
payment, `lepic-methods/src/http/receiver.rs`. ADR 0017 records the design.

## Sending

1. The address is `http://` or `https://`, a host, an optional port and an optional path. A
   missing scheme is refused. A missing port is 3415 for `http` and 443 for `https`. A path is
   kept, and `/v2/foreign` is appended unless the path already ends with it. User info, a query,
   a fragment and white space are refused. A `.onion` host is not taken here; it goes through
   Tor.
2. `check_version`:

   ```json
   {"jsonrpc":"2.0","method":"check_version","id":1,"params":[]}
   ```

   `result.Ok` holds `foreign_api_version` and `supported_slate_versions`. A foreign API version
   below 2 is refused as incompatible, and so is a list of more than 16 slate versions. A 404
   answer means the other wallet has no `/v2/foreign` endpoint. Keys that LEPIC does not know are
   ignored.
3. `receive_tx`:

   ```json
   {"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[<S1>,null,null,null]}
   ```

   The parameters after the slate are the destination account, a message and the sender's
   address; they are sent as `null`. `result.Ok` is the S2.
4. A wallet error comes back as `result.Err`, a JSON-RPC error as `error`. Both mean the payment
   was refused.

The S1 goes out in the V2 shape, as over Epicbox. The S2 is finalized like any other.

The client reads at most `ClientSettings::max_response_bytes` of an answer and gives up on a
request after `send_request_timeout_s` (see [Limits](#limits)). A status other than success or
404 is a failed call.

## Listening

- Only `POST /v2/foreign` is served. Another path answers 404, another method 405.
- `check_version` answers foreign API version 2 with `["V3","V2"]`. A listener that also serves
  the LEPIC native endpoint adds a `lepic` key with its advert.
- `receive_tx` takes the slate and up to three more parameters. The extra parameters must be
  `null` or strings and are not used; the wallet receives into its default account. The S2 goes
  back in the shape of the S1. A slate received before returns the same S2.
- Other methods answer the JSON-RPC error `-32601`. A body that is not JSON answers `-32700`, a
  request that is not a JSON-RPC 2.0 call `-32600`, and wrong parameters `-32602`. A request
  `id` is at most 64 characters, and `params` at most four entries.
- `finalize_invoice_tx` is not served.
- `build_coinbase` is for a mining node that pays its block rewards to this wallet (ADR 0046,
  ADR 0048). The host chooses who it is served to with `ListenSettings::with_coinbase`:

  | `CoinbaseAccess` | Served to |
  |---|---|
  | `Off` | nobody; the call answers `-32601` (default) |
  | `LocalOnly` | peers on loopback; others get the `Off` answer |
  | `Remote` | every peer, under the listener's limits |

  On a listener that serves it, loopback connections have their own slots and a `build_coinbase`
  from one spends no budget.
- A refusal is `result.Err` with `{"GenericError":"slate refused"}` or
  `{"GenericError":"wallet not ready"}`. "Slate refused" is given when the same slate would fail
  again. "Wallet not ready" is given for anything about the wallet, its node or the process that
  may pass, so the sender may retry. It covers a locked wallet, an unreachable node, the
  `receives_per_minute` budget and the `max_open_receipts` policy, which is 100 received
  payments that wait for their senders to finalize.

### Exposure

The listener binds IPv4 only: `127.0.0.1` for `LocalOnly`, `0.0.0.0` for `Internet`.

### Limits

A body over `MAX_BODY_LEN` (the largest wire slate plus 64 KiB) answers 413. A header, body or
request that is not complete in time answers 408. A request over the per-minute budget answers
503, as does a call other than a payment once the budget is reached. A remote address that
already holds `max_connections_per_address` connections has further ones closed unanswered.

These are settings. The defaults are in `crates/lepic-cli/lepic-config.toml` under `[http]`:

| Setting | Default |
|---|---|
| `header_timeout_s` | 10 |
| `body_timeout_s` | 15 |
| `request_timeout_s` | 60 |
| `answer_timeout_s` | 10 |
| `max_connections` | 16 |
| `max_connections_per_address` | 4 |
| `requests_per_minute` | 120 |
| `receives_per_minute` | 30 |
| `send_connect_timeout_s` | 10 |
| `send_request_timeout_s` | 60 |
