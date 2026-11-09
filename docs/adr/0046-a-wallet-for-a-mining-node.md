# ADR 0046: A wallet for a mining node

Status: accepted; who is served and how many candidates are kept: see ADR 0048

## Context

A mining node does not hold keys. When it builds a block template it asks a wallet for the coinbase:
it POSTs `build_coinbase` with `block_fees {fees, height, key_id}` to `wallet_listener_url` +
`/v2/foreign` (`[server.stratum_mining_config]` in `epic-server.toml`). `epic-wallet` answers with an
output, a kernel and the key it used, and records the output so that a refresh finds it once a block
is mined.

An owner who mines needs the same from LEPIC: block rewards that land in the wallet and come back
from the recovery phrase. LEPIC does not mine and runs no node. It only builds the coinbase a node
asks for (`docs/rules.md`, scope).

## Decision

### Building

`Wallet::build_coinbase` (`lepic-wallet/src/coinbase.rs`) takes the fees, the height and the key the
node passed back.

- The value is `ChainParams::coinbase_value`: the miner's reward at the height after the foundation
  levy, plus the fees.
- The output and kernel come from the wallet's keychain on the default account, with the same keys
  `epic-wallet` derives, so a restore from the phrase finds the output. The kernel is checked against
  its excess before it is returned.
- The output is stored as an unconfirmed coinbase output with no transaction, a candidate, locked
  until `ChainParams::coinbase_lock_height`.
- A node that passes back the key of a candidate gets that key again, and the earlier candidate
  stays, since a block can still be found on the older template. A key that blinds anything else, or
  nothing, is not reused; the account's next output key is taken.

### Confirming and cleaning

- A refresh or a scan that finds a candidate on chain confirms it and records an incoming, confirmed
  transaction. `TransactionDetails::coinbase` marks it: incoming, with no slate and a coinbase
  output.
- A refresh deletes a candidate built for height 0, more than `STALE_AFTER` (50) blocks below the
  tip, or more than 50 blocks above it. A scan records a reward whose candidate was deleted.

### Serving

`lepic-legacy-rpc` serves `build_coinbase` on the HTTP listener only when the host turns it on
(`ListenSettings::with_coinbase`). Off, the method is answered as unknown (`METHOD_NOT_FOUND`). The
CLI turns it on with `lepic http listen --coinbase`. The binding's `start_http_listener` takes an
`HttpCoinbase`. Tor's listeners never turn it on. Who is served, and the cap on candidates: see
ADR 0048.

## Consequences

- A mining node can pay a LEPIC wallet. A host that does not turn the method on is unchanged.
- No chain or proof-of-work crate enters the dependency graph.
- A candidate is an ordinary output row, so the store has no table for it.

## Alternatives considered

- Keep mining out of scope: an owner who mines needs a second wallet.
- Serve the method always, as `epic-wallet` does: it changes what an existing listener answers, and
  every caller would write candidates.

## Related

- ADR 0017: direct transactions over HTTP.
- ADR 0048: block rewards for this computer.
