# ADR 0036: Policy values are host parameters

Status: accepted

## Context

The engine has limits and presets that are choices of the app, not of the engine: the default
selection strategy, the send and invoice TTLs, the change and exclusion limits, the Epicbox
invoice window, the open-receipt caps, the default minimum confirmations, the PIN length and
delays. Two of them are checks that a host may want stricter or looser: the length of a new
password and an upper bound on minimum confirmations. LEPIC is minimal and unopinionated
(`docs/rules.md`): a value that is policy belongs to the host.

## Decision

- A value that is policy is a parameter the host may pass, with a default. `lepic-wallet` takes
  `WalletPolicy` in `WalletConfig` (`WalletPolicy::DEFAULT` holds the defaults). `lepic-ffi` takes
  `HostPolicy` in `WalletConfig` and `PinSettings` in `LepicRuntime::with_pin_settings`, every
  field an `Option` where `None` selects the default. An out-of-range value fails with
  `InvalidArgument` when the wallet is created, restored or opened.
- The library checks no password length and no upper bound on minimum confirmations. The host
  enforces them. The core keeps one lower bound: a confirmation count is at least 1. A count
  above what the chain has makes nothing spendable. `lepic-cli` sets no password length rule and
  no cap on the invoice expiry.
- Constants that guard the engine stay in the core: the payer's lag cap, the ceiling on the
  invoice TTL lead (`MAX_INVOICE_TTL_LEAD_CEILING_BLOCKS`, 525,600 blocks), and the minimum of 1
  where a value must be positive.
- The payer's invoice TTL lead cap (`max_invoice_ttl_lead_blocks`) is its own parameter, not tied
  to the invoice TTL.

## Consequences

- An app that wants a password rule or an upper bound on confirmations checks it before it calls
  the library.
- A host that passes nothing gets the defaults in `WalletPolicy::DEFAULT` and the `HostPolicy`
  field docs.
- `WalletConfig` carries no list of transports.

## Alternatives considered

- Keep the two checks in the core with a host-set minimum: the engine would still enforce a
  policy.
- A parameter for every constant, including the lag cap: it guards the payer, not the app.

## Related

- ADR 0027, ADR 0031
