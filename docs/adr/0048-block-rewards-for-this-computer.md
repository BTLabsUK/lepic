# 0048 Block rewards are for this computer unless the host opens them

Status: accepted
Date: 2026-11-06

Supersedes: the line of 0046 that core does not stop a host from serving `build_coinbase` beyond
this computer, its statement that no store migration is needed, and its rejection of a limit in
core. The rest of 0046 stands. Tor never serves rewards, as 0046 says.

## Context

0046 left it to the host who reaches `build_coinbase`. A host that wants payments from the
internet and rewards for its own node had to choose: the method is on for everyone who reaches
the port or for no one. It also shares the listener's limits with every other caller, and each
call stores a row, while `docs/rules.md` says untrusted input may cause only bounded work.

A mining node does not take no for an answer. When the wallet does not answer, the node retries
until it does and gets no new job meanwhile. So no limit here may refuse it.

## Decision

- `CoinbaseAccess` says who is served: `Off`, `LocalOnly` or `Remote`.
  `ListenSettings::with_coinbase` takes it, and the FFI's `start_http_listener` takes the matching
  `HttpCoinbase`. The CLI's `http listen --coinbase` is `LocalOnly`; `--coinbase-remote`, which
  needs `--coinbase` and `--internet`, is `Remote`.
- `LocalOnly` answers loopback peers on the listener's own port. Any other caller gets the same
  answer as with the method off, whatever the exposure, so payments keep working over the
  internet.
- `Remote` answers every peer. Peers beyond loopback stay under the listener's limits.
- On a listener that serves the method, loopback peers have their own pool of connections, the
  same size as the shared one, and their `build_coinbase` spends no request budget. Their other
  calls spend it as anyone's do.
- A connection on a Unix socket is never a loopback peer. Tor's listeners do not turn the method
  on.
- A wallet keeps at most `MAX_CANDIDATES` (4,096) candidates. A build that goes past it deletes
  the candidate built longest ago. A build is never refused for this and the number is not
  configurable. Building an output touches it, so a template the node keeps
  asking for stays. The store keeps the order in a `touched` column (schema 15).

## Consequences

- A node on the same computer works as before. A node elsewhere uses a tunnel, which reaches the
  listener as loopback, or the host opts in with `Remote`.
- A reverse proxy on the same computer looks like loopback. A node in a container on a bridge
  network does not, and needs `Remote` or host networking.
- A candidate deleted at the cap whose block was in fact found is recorded by a scan, as a reward
  always can be. The CLI listener does not refresh, so a long run leaves more candidates to the
  cap than the app does.
- Hosts upgrading from schema 14 migrate once. Rows from before it are the oldest.

## Alternatives considered

- A second port for rewards. A clean split, with a second listener's lifecycle and FFI work, and
  nothing gained over the peer check.
- A secret in the URL. The node sends no authentication, and plain HTTP would carry the secret.
- Refusing at the cap or by rate. Both stop the miner.
- Dropping the lowest height at the cap. Heights come from the caller.
- A cap per height. It would drop job versions that are still valid.
- Keeping the `coinbase` flag and adding a second one. Two flags allow a state that means nothing.
