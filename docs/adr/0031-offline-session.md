# 0031 An offline session for cold wallets

Status: accepted
Date: 2026-10-30

## Context

A cold wallet keeps its keys on a device that never goes online. It still makes, signs and
finalizes payments, carried as slate files or QR codes, and another device posts the finished
transaction. The app decides when a wallet is cold and what its screens offer, but it cannot
stop LEPIC from calling the node itself: every payment stage asks the node for the chain tip, a
finalize pushes the transaction, and a refresh, a scan or the Epicbox listener open connections
of their own. Only LEPIC can make those calls not happen. A process-wide network mode inside
LEPIC would do it, at the price of global state (ADR 0011) and app policy in the library.

## Decision

- `WalletConfig::offline` in `lepic-wallet`, and the same field in `lepic-ffi`'s config, set when
  the session opens and fixed for it.
- The host builds the ports of an offline session to refuse: in `lepic-ffi` the node backend
  answers every request with `NodeError::Offline` and the Epicbox connector fails every
  connection, before any name lookup or connect. No check sits anywhere else.
- In the engine, the payment stages (send and its estimate, receive, finalize, and the invoice
  stages issue, pay and finalize) take the highest tip a refresh confirmed instead of asking the
  node, and skip the plausibility check, which needs the node's answer. Without a confirmed tip
  they fail with `NodeError::Offline`. Finalizing stores the transaction `finalized` and does
  not push it.
- `Wallet::finished_payment` returns the stored S3, or the I3 of an issued invoice, as legacy V3
  JSON, which `epic-wallet post -i` reads; the app saves it or shows it as an `ur:epic-slate`
  code. Posting it is the app's: any wallet's node accepts the transaction, and the cold
  wallet's next online refresh confirms it from the kernel on chain.
- `lepic-ffi` maps every refusal to one new `WalletErrorKind::Offline` (78) and reports
  `FinalizedTx::posted` false.

## Consequences

- No process-wide state and no mode in LEPIC: two wallets in one process can be one offline and
  one online. Which methods an app offers in a cold mode, and when it is cold, stay app policy.
- A mode change means opening the wallet again. `set_servers` and `node_tip_for` refuse a config
  whose `offline` differs from the session's.
- Offline, a payment stage trusts the stored tip. A tip far behind the chain makes slates with
  stale heights, which the online side checks as it checks any peer's slate.
- HTTP and Tor sends and listeners are not ports of the session's node or relay; an offline app
  does not start them.
- `lepic-ffi`'s `WalletConfig` and `FinalizedTx` gain a field, so code that builds either by
  hand must set it.

## Alternatives considered

- A process-wide network mode checked under every socket LEPIC opens: complete, but global state
  and app policy in the library, with a source scan to keep it complete.
- Leaving it to the app: it cannot stop the engine's own node calls in payment stages.
