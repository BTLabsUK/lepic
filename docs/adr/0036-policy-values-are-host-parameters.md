# 0036 Policy values are host parameters

Status: accepted
Date: 2026-11-04

## Context

LEPIC held a number of limits and presets as constants: the default selection strategy, the
send and invoice TTLs, the change and exclusion limits, the Epicbox invoice window, the open
receipt caps, the default minimum confirmations, the PIN length and delays. Each is a choice
of the app, not of the engine, and two of them were checks that a host may want stricter or
looser: the length of a new password and the cap of 30 on minimum confirmations. the owner decided
on 2026-11-04 that policy values are host parameters.

## Decision

- A value that is policy becomes a parameter the host may pass. Its default is the value LEPIC
  had, so a host that passes nothing sees no change. `lepic-wallet` takes `WalletPolicy` in
  `WalletConfig`; `lepic-ffi` takes `HostPolicy` in `WalletConfig` and `PinSettings` in
  `LepicRuntime::with_pin_settings`, every field an `Option`. An out-of-range value fails with
  `InvalidArgument` when the wallet is created, restored or opened.
- Two checks leave the library, because the hosts enforce them: the minimum length of a new
  password (8) and the upper bound of 30 on minimum confirmations. `lepic-cli` sets no
  password length rule and no cap on the invoice expiry (the owner, 2026-11-04). Core keeps only that the confirmation count is at least 1. This
  supersedes ADR 0027 for the cap; its default of 6 and the per-wallet setting stand.
- Constants that guard the engine stay in core: the payer's lag cap (525,600 blocks), the
  ceiling on the invoice TTL lead (525,600 blocks), and the 1 minimum.
- The payer's invoice TTL lead cap is its own parameter, no longer tied to the invoice TTL.

## Consequences

- An app that wants the old password rule checks 8 characters, and one that wants the old
  confirmation bound checks 30, before it calls the library.
- A confirmation count above what the chain has makes nothing spendable.
- `WalletConfig.transports` is removed: it only checked that each id was registered.

## Alternatives considered

- Keep the two checks in core with a host-set minimum: the engine would still enforce a policy.
- A parameter for every constant, including the lag cap: it guards the payer, not the app.
