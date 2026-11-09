# lepic-node

The client for the Epic node's foreign JSON-RPC API. It defines `NodeApi`, the port the wallet
engine reads the chain through, and implements it over HTTP or HTTPS. Every answer is decoded
strictly and checked against the request that was made before the engine sees it.

## Where it fits

- Depends on `lepic-crypto` and `lepic-primitives`, and on hyper, rustls (ring provider) and
  Tokio for the HTTP transport (ADR 0006).
- Used by `lepic-wallet`, `lepic-methods`, `lepic-wallet-contacts`, `lepic-cli` and `lepic-ffi`.
- Feature `mock`: `MockNode`, an in-memory node for engine, CLI and binding tests.
- Has no defaults of its own. The app passes timeouts, retries and the node URL; the CLI reads
  them from `settings.toml`.

## Core concepts

- **The port.** `NodeApi` has one method per call the wallet makes: version, tip, kernel,
  outputs by commitment, unspent outputs by PMMR index, PMMR indices, header, the transaction
  pool, and `push_transaction` with `Propagation::Stem` or `Fluff`.
- **Client and transport.** `NodeClient<T>` implements `NodeApi` over any `RpcTransport`.
  `HttpTransport` is the real one; `HttpNodeClient` names the pair.
- **Strict decoding.** The `decode` module frames JSON-RPC 2.0 and checks every answer against
  its request: no missing, duplicate, unrequested or out-of-range items. Answers are capped at
  `max_response_bytes`; `MAX_RESPONSE_BYTES` (8 MiB) fits a full unspent-outputs page.
- **Plausible tips.** The client remembers the highest tip it accepted. A later tip implausibly
  far above it fails with `NodeError::ImplausibleTip`, so one false answer cannot move the
  wallet's view of the chain arbitrarily far.
- **Retries.** `CallPolicy` sets retries with backoff and how `get_outputs` requests are split
  and run in parallel. Reads retry; `push_transaction` does not, because a repeated post of an
  accepted transaction is answered with an error.
- **Plain HTTP only to loopback.** `HttpTransport` refuses an `http://` URL to a remote host
  (`NodeError::PlainHttpToRemoteHost`), so the API secret never crosses a network unencrypted.
- **Dialers.** A `NodeDialer` given to `HttpTransport::with_dialer` opens the byte streams, so a
  host can route node traffic through Tor. TLS and the `Host` header follow the node URL
  whatever the dialer connects to.

## Public API

| Area | Items |
|---|---|
| Port | `NodeApi`, `Tip`, `NodeVersion`, `BlockHeaderInfo`, `LocatedKernel`, `OutputLocation`, `UnspentOutput`, `UnspentOutputs`, `PmmrIndices`, `PoolTransaction`, `Propagation`, `MAX_POOL_KERNELS` |
| Client | `NodeClient` (`new`, `with_known_tip`, `ready_for_txs`), `CallPolicy`, `RetryPolicy`, `RpcTransport`, `HttpNodeClient` |
| HTTP | `HttpTransport` (`new`, `with_dialer`), `HttpSettings`, `webpki_tls_config`, `is_loopback_host`, `MAX_RESPONSE_BYTES` |
| Dialing | `NodeDialer`, `NodeStream`, `DialFuture` |
| Errors | `NodeError`, `NodeRejection`, `RejectionKind`, `FieldProblem`, `JsonProblem` |
| Tests | `decode` (also for fuzz targets); `mock` and `testing` behind the `mock` feature |

## Example

Ask a local node for its tip:

```rust
use std::time::Duration;

use lepic_node::{
    CallPolicy, HttpNodeClient, HttpSettings, HttpTransport, MAX_RESPONSE_BYTES, NodeApi,
    RetryPolicy, webpki_tls_config,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = HttpSettings {
        connect_timeout: Duration::from_secs(15),
        request_timeout: Duration::from_secs(90),
        max_response_bytes: MAX_RESPONSE_BYTES,
        pool_idle_timeout: Duration::from_secs(10),
        api_secret: None,
    };
    let policy = CallPolicy {
        retry: RetryPolicy::NONE,
        outputs_per_request: 500,
        max_concurrent_requests: 4,
    };
    let transport = HttpTransport::new("http://127.0.0.1:3413", &settings, webpki_tls_config()?)?;
    let node: HttpNodeClient = HttpNodeClient::new(transport, policy);

    let tip = node.get_tip().await?;
    println!("tip at height {}", tip.height.value());
    Ok(())
}
```

## Related

- [Architecture: ports](../../docs/architecture.md#ports)
- [Node API compatibility](../../docs/compat/node-api.md)
- [ADR 0006: TLS and HTTP](../../docs/adr/0006-tls-and-http.md)
- [Configuration](../../docs/configuration.md)
