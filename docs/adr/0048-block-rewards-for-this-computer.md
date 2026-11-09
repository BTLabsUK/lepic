# ADR 0048: Block rewards are for this computer unless the host opens them

Status: accepted

## Context

A host that wants payments from the internet and block rewards for its own mining node needs the
method `build_coinbase` (ADR 0046) to answer the node and not everyone who reaches the port. The
method shares the listener's limits with every other caller, and each call stores a row, while
`docs/rules.md` allows untrusted input only bounded work.

A mining node does not take no for an answer. When the wallet does not answer, the node retries until
it does and gets no new job meanwhile. No limit on the node's calls may refuse it.

## Decision

### Who is served

`CoinbaseAccess` (`lepic-legacy-rpc`) says who is served: `Off`, `LocalOnly` or `Remote`.
`ListenSettings::with_coinbase` takes it. The binding's `start_http_listener` takes the matching
`HttpCoinbase`. In the CLI, `http listen --coinbase` is `LocalOnly`; `--coinbase-remote`, which needs
`--coinbase` and `--internet`, is `Remote`.

- `Off`: the method is answered as unknown.
- `LocalOnly`: loopback peers on the listener's own port are served. Any other caller gets the answer
  of `Off`, whatever the exposure, so payments from the internet keep working.
- `Remote`: every peer is served. Peers beyond loopback stay under the listener's limits.
- A connection on a Unix socket is never a loopback peer. Tor's listeners do not turn the method on.

### Connections

On a listener that serves the method, loopback peers have their own pool of connections, the same
size as the shared one. Their `build_coinbase` spends no request budget. Their other calls spend it
as anyone's do.

### The cap

A wallet keeps at most `MAX_CANDIDATES` (4,096) candidates (`lepic-wallet/src/coinbase.rs`). A build
that passes it deletes the candidate touched longest ago. A build is never refused for this, and the
number is not configurable. Building an output touches it, so a template the node keeps asking for
stays. The store keeps the order in the `touched` column of `outputs`.

## Consequences

- A node on the same computer is served. A node elsewhere uses a tunnel, which reaches the listener as
  loopback, or the host opts in with `Remote`.
- A reverse proxy on the same computer looks like loopback, so `--coinbase` serves every caller the
  proxy forwards. A node in a container on a bridge network does not look like loopback and needs
  `Remote` or host networking.
- A candidate deleted at the cap whose block was found is recorded by a scan, as a reward always can
  be. The CLI listener does not refresh, so a long run leaves more candidates for the cap than the app
  does.

## Alternatives considered

- A second port for rewards: a second listener's lifecycle and binding work, and nothing gained over
  the peer check.
- A secret in the URL: the node sends no authentication, and plain HTTP would carry the secret.
- Refusing at the cap or by rate: both stop the miner.
- Dropping the lowest height at the cap: heights come from the caller.
- A cap per height: it would drop job versions that are still valid.
- Two flags, one for rewards and one for remote: they allow a state that means nothing.

## Related

- ADR 0046: a wallet for a mining node.
