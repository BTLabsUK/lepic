# Architecture decision records

An architecture decision record (ADR) states one decision about LEPIC, the reason for it and what
it costs. Each record describes the decision as it holds in the code.

Status is one of:

- `accepted`: the decision is in effect.
- `proposed`: the decision is written but still needs an answer.
- `superseded by NNNN`: a later record replaced it. A record that is replaced in part says which
  part, in one line with a pointer.

A decision changes by a new record that supersedes the old one. Records are numbered in the order
they were written, and the file names do not change.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-port-not-depend.md) | Port the node and wallet logic; no Epic crates in the product graph | accepted |
| [0002](0002-slate-domain-and-codecs.md) | One version-free slate model, one codec per wire format | accepted |
| [0003](0003-transport-format-policy.md) | Transports declare the slate formats they speak | accepted; file row superseded by 0015 |
| [0004](0004-epicbox-client.md) | Async Epicbox client with listen and drain modes, acknowledge after store | accepted |
| [0005](0005-storage.md) | SQLite storage, platform keystore for secrets, legacy seed import | accepted; database-import bullet superseded by 0019 |
| [0006](0006-tls-and-http.md) | rustls with ring, hyper for HTTP, tokio-tungstenite for websockets | accepted |
| [0007](0007-mobile-bindings.md) | Mobile bindings with flutter_rust_bridge for the Flutter frontend | accepted; secrets line superseded by 0014, delivery by 0023 |
| [0008](0008-logging-and-errors.md) | tracing everywhere, host-installed subscribers, typed errors | accepted |
| [0009](0009-conformance.md) | Conformance workspace and golden vectors | accepted; version table superseded by 0020 |
| [0010](0010-dependency-policy.md) | Dependency and toolchain policy | accepted |
| [0011](0011-no-global-state.md) | No process-global state | accepted; `ChainParams` contents superseded by 0013 |
| [0012](0012-native-slate-format.md) | A compact native slate format, `lepic.v1`, for LEPIC-to-LEPIC methods | proposed |
| [0013](0013-network-parameters.md) | Network parameters live with the format that uses them | accepted |
| [0014](0014-secrets-at-the-flutter-boundary.md) | Which secrets cross the Flutter boundary | accepted |
| [0015](0015-file-method-writes-v3.md) | The file method writes V3 | accepted |
| [0016](0016-epicbox-notices.md) | LEPIC notices over Epicbox | accepted |
| [0017](0017-foreign-api-over-http.md) | The wallet foreign API over HTTP in its own crate | accepted |
| [0018](0018-tor-on-desktop.md) | Tor through a bundled tor child process | accepted; onion key superseded by 0044 |
| [0019](0019-import-epic-wallet-history.md) | Import the transaction history of an epic-wallet wallet | accepted |
| [0020](0020-reference-epic-wallet-4-1.md) | Reference wallet and node at epic-wallet v4.1.0 | accepted; node pin of the interop images and `upstream.toml` superseded by 0038 |
| [0021](0021-epicbox-over-tor.md) | Epicbox over Tor | accepted |
| [0022](0022-node-over-tor.md) | Node over Tor | accepted |
| [0023](0023-binding-in-its-own-repository.md) | The Flutter binding lives in its own repository | accepted |
| [0024](0024-contact-pairing-and-invoice-trust.md) | Contact pairing, sealed slates and invoice trust on paired contacts | proposed |
| [0025](0025-animated-qr-slates.md) | Slates as animated QR codes in `ur:epic-slate` | accepted |
| [0026](0026-tor-as-a-build-feature.md) | Tor is a build feature of the binding | accepted |
| [0027](0027-minimum-confirmations.md) | Minimum confirmations is a per-wallet setting, 1 to 30, default 6 | accepted |
| [0028](0028-transaction-records-in-tables.md) | Per-transaction state lives in tables that cascade with the transaction | accepted |
| [0029](0029-contacts-on-the-engine.md) | Contacts are a crate, `lepic-wallet-contacts`, on top of the engine | accepted |
| [0030](0030-all-configuration-in-settings-toml.md) | All configuration is in `settings.toml` and a shipped config, none in code | accepted |
| [0031](0031-offline-session.md) | An offline session for cold wallets refuses all network access | accepted |
| [0032](0032-store-encrypted-at-rest.md) | The wallet database is encrypted at rest with SQLite3 Multiple Ciphers | accepted |
| [0033](0033-key-and-domain-registry.md) | One registry of seed-derived keys and signature domains | proposed |
| [0034](0034-trust-versioning-and-probing.md) | Trust, versioning and probing between Epic wallets | proposed |
| [0035](0035-restore-from-a-start-height.md) | A restore may start its scan at a height the caller picks | accepted |
| [0036](0036-policy-values-are-host-parameters.md) | Policy values are host parameters | accepted |
| [0037](0037-one-send-to-self.md) | One send-to-self primitive | accepted |
| [0038](0038-reference-node-4-1-2.md) | Reference node moves to epic v4.1.2 | accepted |
| [0039](0039-the-host-applies-a-relay-move.md) | The host applies a contact's relay move | accepted |
| [0040](0040-contact-check-and-own-relay-move.md) | The contact check, and moving one's own home relay | accepted |
| [0041](0041-the-owners-profile-in-the-feature-word.md) | The owner's profile is the upper half of the feature word | accepted |
| [0042](0042-draining-the-old-home-after-moving-ones-own.md) | The old home relay is drained for a set time after moving one's own | accepted |
| [0043](0043-domain-proof-for-paired-contacts.md) | Domain proof for paired contacts | accepted |
| [0044](0044-the-onion-has-its-own-key.md) | The onion has its own key | accepted |
| [0045](0045-refusing-slates-nobody-asked-for.md) | Refusing slates nobody asked for | proposed |
| [0046](0046-a-wallet-for-a-mining-node.md) | A wallet for a mining node | accepted |
| [0047](0047-the-mailbox-is-the-default-between-paired-contacts.md) | The mailbox is the default route between paired contacts | accepted |
| [0048](0048-block-rewards-for-this-computer.md) | Block rewards are served to this computer unless the host opens them | accepted |
| [0049](0049-keeping-messages-that-cannot-be-taken-yet.md) | Keeping messages that cannot be taken yet | accepted |
| [0050](0050-one-wallet-api.md) | One wallet API, served by `lepic serve` | proposed |
| [0051](0051-transaction-methods-in-one-crate.md) | Transaction methods live in one crate, outside the engine | accepted |
| [0052](0052-legacy-at-the-edge-native-between-lepic-wallets.md) | Epic compatibility at the edge, a native protocol between LEPIC wallets | accepted |
