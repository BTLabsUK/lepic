# 0027 Minimum confirmations is a per-wallet setting, default 6

Status: accepted
Date: 2026-10-27

## Context

An unspent output counts as spendable, and may be selected for a send, only once it has a number
of confirmations. LEPIC fixed that number at 3 (`BALANCE_MINIMUM_CONFIRMATIONS`), following the old
GUI wallet (decision D1), while upstream `epic-wallet`'s `InitTxArgs` defaults to 10. The
2026-10-27 security audit's upstream-comparison row "Default minimum confirmations for spending"
flagged the difference and asked for the reason. This ADR answers it.

## Decision

- An output received, or returned as change, counts as spendable and may be selected after **6
  confirmations** by default.
- The number is one per-wallet setting, `wallet.minimum_confirmations` in the store's settings
  table, 1 to 30 inclusive (`MINIMUM_CONFIRMATIONS_RANGE`). The balance split
  (`Wallet::balance`, `Wallet::outputs`, balance events, the FFI summary) and the sends the app
  makes read the same value, so a send can always spend exactly what the balance calls spendable.
  Sends, estimates and self-sends keep a plain `minimum_confirmations` parameter; a host passes
  the wallet's value.
- `Wallet::minimum_confirmations` reads it, `Wallet::set_minimum_confirmations` validates the
  range (`WalletError::MinimumConfirmationsOutOfRange`), stores it, and emits a `Balance` event
  per account re-split at the stored tip, without the node. `Balance` carries the count it was
  split with.
- The FFI offers `minimum_confirmations()` and `set_minimum_confirmations(count)`; the error maps
  to `InvalidArgument`. The CLI keeps a `--min-confirmations` option per command, defaulting to 6.

Why 6: Epic Cash blocks come about once a minute, so 6 confirmations take a few minutes. Reorgs
seen in practice are 1 or 2 blocks deep. 3 was the GUI wallet's choice and leaves a thin margin;
10 is upstream's CLI default and makes an everyday wallet wait ten minutes for its change. 6 is
the usual "deep enough" compromise, also common in Bitcoin practice.

Range: 1 is the fastest, for test networks and for people who accept the reorg risk. 30 keeps a
control sane, and a deeper wait is pointless on Epic.

Not covered: coinbase maturity (`lock_height`, Immature) is consensus and unchanged; the
finalization TTLs and the release watch are unrelated.

## Consequences

- A lower setting trusts a shallower chain: a send may spend an output a reorg then removes.
- Wallets that never set it simply move from 3 to 6, because the setting is absent; there are no
  users to migrate. An unreadable or out-of-range stored value also reads as 6.
- `BALANCE_MINIMUM_CONFIRMATIONS` is removed; `DEFAULT_MINIMUM_CONFIRMATIONS` replaces it, and
  `Balance` gains a field (breaking for code that builds one).

## Alternatives considered

- Keep 3: matches the GUI, but the audit's depth argument stands.
- Use upstream's 10: slow for everyday change, with no matching evidence of deeper reorgs.
- A constant only: the people who want 1 (test networks) or more would have to fork.
