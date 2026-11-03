# Architecture decision records

Each record states one decision, why it was made, and what it costs. Status is `accepted`,
`proposed` (needs a decision or a spike), or `superseded by NNNN`. Change a decision by writing a new
record that supersedes the old one; accepted records are not rewritten.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-port-not-depend.md) | Port the node and wallet logic; no Epic crates in the product graph | accepted |
| [0002](0002-slate-domain-and-codecs.md) | One version-free slate model, one codec per wire format | accepted |
| [0003](0003-transport-format-policy.md) | Transports declare the slate formats they speak | accepted, file row superseded by 0015 |
| [0004](0004-epicbox-client.md) | Async Epicbox client with listen and drain modes, acknowledge after store | accepted |
| [0005](0005-storage.md) | SQLite storage, platform keystore for secrets, legacy seed import | accepted, database-import bullet superseded by 0019 |
| [0006](0006-tls-and-http.md) | rustls with ring, hyper for HTTP, tokio-tungstenite for websockets | accepted |
| [0007](0007-mobile-bindings.md) | flutter_rust_bridge bindings for the existing Flutter frontend | accepted, secrets line superseded by 0014, delivery bullet superseded by 0023 |
| [0008](0008-logging-and-errors.md) | tracing everywhere, host-installed subscribers, typed errors | accepted |
| [0009](0009-conformance.md) | Separate conformance workspace on public pins, golden vectors | accepted, version table superseded by 0020 |
| [0010](0010-dependency-policy.md) | Latest stable crates and toolchain, banned list, update bots | accepted |
| [0011](0011-no-global-state.md) | No process-global state; network and settings are parameters | accepted, `ChainParams` contents superseded by 0013 |
| [0012](0012-native-slate-format.md) | A compact native slate format for LEPIC-to-LEPIC methods | proposed |
| [0013](0013-network-parameters.md) | Network parameters live with the format that uses them | accepted |
| [0014](0014-secrets-at-the-flutter-boundary.md) | Which secrets may cross the Flutter boundary | accepted |
| [0015](0015-file-method-writes-v3.md) | The file method writes V3; Epicbox stays V2 for S1, V3 for invoice stages | accepted |
| [0016](0016-epicbox-notices.md) | LEPIC notices over Epicbox, sent only to proven peers | accepted |
| [0017](0017-foreign-api-over-http.md) | The wallet foreign API over HTTP in its own crate | accepted |
| [0018](0018-tor-on-desktop.md) | Tor on desktop through a bundled tor child process | accepted |
| [0019](0019-import-epic-wallet-history.md) | Import the transaction history of an epic-wallet wallet, reconciled with the scan | accepted |
| [0020](0020-reference-epic-wallet-4-1.md) | Reference wallet and node move to epic-wallet v4.1.0 | accepted |
| [0021](0021-epicbox-over-tor.md) | Epicbox over Tor | accepted |
| [0022](0022-node-over-tor.md) | Node over Tor | accepted |
| [0023](0023-binding-in-its-own-repository.md) | The Flutter binding lives in its own repository | accepted |
| [0024](0024-contact-pairing-and-invoice-trust.md) | Contact pairing, sealed slates, and invoice trust on paired contacts | proposed |
| [0025](0025-animated-qr-slates.md) | Slates as animated QR codes in `ur:epic-slate` | accepted |
| [0026](0026-tor-as-a-build-feature.md) | Tor is a build feature of the binding | accepted |
| [0027](0027-minimum-confirmations.md) | Minimum confirmations is a per-wallet setting, default 6 | accepted |
| [0028](0028-transaction-records-in-tables.md) | Per-transaction state lives in tables that cascade with the transaction | accepted |
| [0029](0029-contacts-on-the-engine.md) | Contacts are a crate on top of the engine | accepted |
| [0030](0030-all-configuration-in-settings-toml.md) | All configuration in settings.toml (no hardcoded configuration) | accepted |
| [0031](0031-offline-session.md) | An offline session for cold wallets | accepted |
| [0032](0032-store-encrypted-at-rest.md) | Wallet database encrypted at rest with SQLite3 Multiple Ciphers | accepted |
| [0033](0033-key-and-domain-registry.md) | One registry of seed-derived keys and signature domains | proposed |
| [0034](0034-trust-versioning-and-probing.md) | Trust, versioning and probing between Epic wallets | proposed |
| [0035](0035-restore-from-a-start-height.md) | Restore from a start height | accepted |

Template:

```
# NNNN Title

Status: proposed | accepted | superseded by NNNN
Date: YYYY-MM-DD

## Context
## Decision
## Consequences
## Alternatives considered
```
