# ADR 0027: Minimum confirmations is a per-wallet setting, default 6

Status: accepted; the upper bound of 30: see ADR 0036

## Context

An unspent output counts as spendable, and may be selected for a send, only once it has a number
of confirmations. The number trades speed against the risk of a reorg removing the output a send
spent. Reference `epic-wallet` defaults its `InitTxArgs` to 10. A wallet user may want a lower
number on a test network or a higher one for large amounts, so the number is the wallet's, not a
constant.

## Decision

- An output received, or returned as change, counts as spendable and may be selected after 6
  confirmations unless the wallet stores another number (`DEFAULT_MINIMUM_CONFIRMATIONS`,
  `crates/lepic-wallet/src/refresh.rs`). A host may choose another default for wallets that
  store none (`WalletPolicy::default_minimum_confirmations`, ADR 0036).
- The number is one per-wallet setting, `wallet.minimum_confirmations`, in the store's `settings`
  table. The balance split (`Wallet::balance`, `Wallet::outputs`, balance events, the FFI
  summary) and the sends the app makes read the same value, so a send can spend exactly what the
  balance calls spendable. A send never uses fewer confirmations than the stored value, whatever
  its request asks for, and never fewer than 1.
- `Wallet::minimum_confirmations` reads the number. `Wallet::set_minimum_confirmations` stores
  it and emits a `Balance` event per account, re-split at the stored tip without asking the node.
  It fails with `WalletError::MinimumConfirmationsOutOfRange` for 0, which would spend
  unconfirmed outputs. An absent, unreadable or zero stored value reads as the default.
- The FFI offers `minimum_confirmations()` and `set_minimum_confirmations(count)`; the range error
  maps to `InvalidArgument`. Each CLI spend command takes `--min-confirmations`, defaulting to 6
  (`SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS`).
- The upper bound of the setting: see ADR 0036.

Why 6: Epic Cash blocks come about once a minute, so 6 confirmations take a few minutes. 10 makes
an everyday wallet wait longer for its change, and a lower number leaves a thin margin against a
reorg. 6 is a common "deep enough" compromise.

Coinbase maturity (`lock_height`, immature outputs) is consensus and unrelated: it applies
whatever number is set.

## Consequences

- A lower setting trusts a shallower chain: a send may spend an output that a reorg then removes.
- A number above what the chain has makes nothing spendable.
- `Balance` carries the count it was split with.

## Related

- ADR 0036
