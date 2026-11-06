# 0046 A wallet for a mining node

Status: accepted
Date: 2026-11-06

Extends 0017 (the foreign API over HTTP). Changes the "Mining" non-goal in `docs/rules.md`.
0048 supersedes the line that core does not stop a host from serving it beyond this computer, and
the statement that no store migration is needed.

## Context

A mining node does not hold keys. When it builds a block template it asks a wallet for the
coinbase: it POSTs `build_coinbase` with `block_fees {fees, height, key_id}` to
`wallet_listener_url` + `/v2/foreign` (`[server.stratum_mining_config]` in `epic-server.toml`;
`servers/src/mining/mine_block.rs`, `config/src/comments.rs`, epic `bd3a8c8`). `epic-wallet`
`v4.1.0` answers with an output, a kernel and the key it used, and records the output so a
refresh finds it once a block is mined (`libwallet/src/internal/updater.rs`, `build_coinbase` and
`clean_old_unconfirmed`).

LEPIC answered the method with `METHOD_NOT_FOUND`, so a node pointed at a LEPIC wallet could not
pay it. The 1.0 non-goals listed "Mining". A wallet that cannot take its owner's block rewards
falls short of `epic-wallet`, and the parity rule wins.

## Decision

- The wallet builds a coinbase on request. `Wallet::build_coinbase` takes the fees, the height
  and the key the node passed back. The value is `ChainParams::coinbase_value`: the miner's
  reward at the height after the foundation levy (upstream `reward_at_height`), plus the fees.
  The output and kernel come from the wallet's keychain on the default account, the same keys
  `epic-wallet` derives, so a restore from the phrase finds the output. It is stored as an
  unconfirmed coinbase output with no transaction (a candidate), locked until
  `ChainParams::coinbase_lock_height`.
- A refresh that finds a candidate on chain records an incoming, confirmed transaction for it.
  `TransactionDetails::coinbase` marks it, and marks a coinbase output found by scan.
- A node that passes back the key of a candidate gets that key again, and the old candidate
  stays, as a block can still be found on the older template. A key that blinds anything else,
  or nothing, is not reused. A refresh deletes a candidate more than 50 blocks below the tip, as
  upstream's `clean_old_unconfirmed` does, and one at height 0 or more than 50 blocks above the
  tip. Candidates leave no other way.
- `lepic-foreign` serves `build_coinbase` only when the host turns it on
  (`ListenSettings::with_coinbase`). It is off by default. Off, the method answers
  `METHOD_NOT_FOUND` as before. The CLI turns it on with `http listen --coinbase`. The FFI
  passes a `coinbase` flag to `start_http_listener`. Tor never serves it.
- Core does not stop a host from serving it beyond this computer. That is the host's policy.

## Consequences

- A mining node can pay a LEPIC wallet. The CLI and the app can expose it; nothing changes for a
  wallet that does not.
- The listener builds a reward for anyone who reaches the port. A reward is worthless unless
  that party's node mines a block with it, but each request writes a candidate. Hosts should
  keep the listener on this computer when the method is on.
- No store migration: a candidate is an ordinary output row. An older LEPIC that opens the
  database sees an unconfirmed output with no transaction, which it neither spends nor counts.
- LEPIC still mines nothing and runs no node: no proof of work and no chain crates enter the
  graph.

## Alternatives considered

- Keep the non-goal. Owners who mine would need a second wallet.
- Serve the method always, as `epic-wallet` does. That would change what an existing listener
  answers. Off by default keeps existing hosts as they are.
- Refuse `--coinbase` with `--internet` in the CLI. That is policy, and the CLI holds none.
