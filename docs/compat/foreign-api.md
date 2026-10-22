# Wallet foreign API over HTTP

What LEPIC sends and answers at `/v2/foreign`, matching `epic-wallet` `v4.1.0`
(`impls/src/adapters/http.rs`, `api/src/foreign_rpc.rs`). ADR 0017 records the design.

## Sending (`send -m http`)

1. The address is `http(s)://host[:port][/path]`. `epic-wallet` appends `v2/foreign` to it;
   LEPIC does the same unless the path already ends with it. Port 3415 is the listener default.
2. `check_version`: `{"jsonrpc":"2.0","method":"check_version","id":1,"params":[]}`. The answer's
   `result.Ok` holds `foreign_api_version` (at least 2) and `supported_slate_versions`
   (`["V3","V2"]` for every 3.x and 4.x wallet). A 404 means the other wallet predates the
   foreign API v2.
3. `receive_tx`: `{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[<S1>,null,null,null]}`.
   The parameters after the slate are the destination account, a message and the sender's
   address; `epic-wallet` sends them `null`. The answer's `result.Ok` is the S2, in the version
   of the S1.
4. A wallet error comes back as `result.Err`; a JSON-RPC error as `error`. Both mean refused.

LEPIC sends the S1 in the V2 shape, as over Epicbox, and finalizes the S2 like any other.

## Listening (`listen -m http`)

- `POST /v2/foreign` only; other paths answer 404 and other methods 405.
- `check_version` answers version 2 with `["V3","V2"]`.
- `receive_tx` takes one to four parameters (4.0 sends three extras, 4.1 four) and uses only the
  slate; the extras must be `null` or strings. The S2 goes back in the shape of the S1. A slate
  received before returns the same S2.
- Every other method answers JSON-RPC error `-32601`. `finalize_invoice_tx` and
  `build_coinbase` are not served.
- A refusal is `result.Err` with `{"GenericError":"slate refused"}` or
  `{"GenericError":"wallet not ready"}`. "Wallet not ready" may be retried later: the wallet is
  locked or its node unreachable, the listener took its 30 payments of the minute, or 100
  payments received over HTTP still wait for their senders to finalize.
- LEPIC's own limits: a body over the size limit answers 413, a
  body not complete 15 s after the headers 408, more than 120 requests a minute 503, and a
  remote address with 4 connections open has further ones closed unanswered. The listener binds
  IPv4 only (`127.0.0.1`, or `0.0.0.0` from the internet).
