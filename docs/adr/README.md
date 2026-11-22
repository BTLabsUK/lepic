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
| [0016](0016-epicbox-notices.md) | LEPIC notices over Epicbox | accepted; payments-address notices and the marker superseded by 0062; unmatched-notice forwarding and cancels on a notice by 0067 |
| [0017](0017-foreign-api-over-http.md) | The wallet foreign API over HTTP in its own crate | accepted |
| [0018](0018-tor-on-desktop.md) | Tor through a bundled tor child process | accepted; onion key superseded by 0044 |
| [0019](0019-import-epic-wallet-history.md) | Import the transaction history of an epic-wallet wallet | accepted |
| [0020](0020-reference-epic-wallet-4-1.md) | Reference wallet and node at epic-wallet v4.1.0 | accepted; node pin of the interop images and `upstream.toml` superseded by 0038 |
| [0021](0021-epicbox-over-tor.md) | Epicbox over Tor | accepted |
| [0022](0022-node-over-tor.md) | Node over Tor | accepted |
| [0023](0023-binding-in-its-own-repository.md) | The Flutter binding lives in its own repository | accepted |
| [0024](0024-contact-pairing-and-invoice-trust.md) | Contact pairing, sealed slates and invoice trust on paired contacts | proposed; pair request by address, marker reply key and one-off drains superseded by 0062 |
| [0025](0025-animated-qr-slates.md) | Slates as animated QR codes in `ur:epic-slate` | accepted |
| [0026](0026-tor-as-a-build-feature.md) | Tor is a build feature of the binding | accepted |
| [0027](0027-minimum-confirmations.md) | Minimum confirmations is a per-wallet setting, default 6 | accepted; upper bound superseded by 0036 |
| [0028](0028-transaction-records-in-tables.md) | Per-transaction state lives in tables that cascade with the transaction | accepted |
| [0029](0029-contacts-on-the-engine.md) | Contacts are a crate, `lepic-wallet-contacts`, on top of the engine | accepted |
| [0030](0030-all-configuration-in-settings-toml.md) | All configuration is in `settings.toml` and a shipped config, none in code | accepted |
| [0031](0031-offline-session.md) | An offline session for cold wallets refuses all network access | accepted |
| [0032](0032-store-encrypted-at-rest.md) | The wallet database is encrypted at rest with SQLite3 Multiple Ciphers | accepted |
| [0033](0033-key-and-domain-registry.md) | One registry of seed-derived keys and signature domains | proposed |
| [0034](0034-trust-versioning-and-probing.md) | Trust, versioning and probing between Epic wallets | proposed; marker, its feature word and the learning loop superseded by 0062 |
| [0035](0035-restore-from-a-start-height.md) | A restore may start its scan at a height the caller picks | accepted |
| [0036](0036-policy-values-are-host-parameters.md) | Policy values are host parameters | accepted |
| [0037](0037-one-send-to-self.md) | One send-to-self primitive | accepted |
| [0038](0038-reference-node-4-1-2.md) | The interop stacks run the Epic node at v4.1.2 | accepted; conformance line superseded by 0059 |
| [0039](0039-the-host-applies-a-relay-move.md) | The host applies a contact's mailbox move | accepted |
| [0040](0040-contact-check-and-own-relay-move.md) | The contact check, and moving one's own home mailbox | accepted |
| [0041](0041-the-owners-profile-in-the-feature-word.md) | The owner's profile is the upper half of the feature word | accepted |
| [0042](0042-draining-the-old-home-after-moving-ones-own.md) | The old home mailbox is drained for a set time after moving one's own | accepted; how a previous home is read superseded in part by 0062 |
| [0043](0043-domain-proof-for-paired-contacts.md) | Domain proof for paired contacts | accepted |
| [0044](0044-the-onion-has-its-own-key.md) | The onion has its own key | accepted |
| [0045](0045-refusing-slates-nobody-asked-for.md) | Refusing slates nobody asked for | accepted; "declined" on a payments address superseded by 0062; the cancel on "declined" by 0067 |
| [0046](0046-a-wallet-for-a-mining-node.md) | A wallet for a mining node | accepted; who is served and how many candidates are kept superseded by 0048 |
| [0047](0047-the-mailbox-is-the-default-between-paired-contacts.md) | The mailbox is the default route between paired contacts | accepted; plain fallback superseded by 0062 |
| [0048](0048-block-rewards-for-this-computer.md) | Block rewards are served to this computer unless the host opens them | accepted |
| [0049](0049-keeping-messages-that-cannot-be-taken-yet.md) | Keeping messages that cannot be taken yet | accepted |
| [0050](0050-one-wallet-api.md) | One wallet API, served by `lepic serve` | proposed; paths, generated document, bodies and TLS clients superseded by 0055 |
| [0051](0051-transaction-methods-in-one-crate.md) | Transaction methods live in one crate, outside the engine | accepted; the `lepic-methods` edge to `lepic-peer` superseded by 0062 |
| [0052](0052-legacy-at-the-edge-native-between-lepic-wallets.md) | Epic compatibility at the edge, a native protocol between LEPIC wallets | accepted; marker, `check_version` advert, origin pins and sealed slates on the payments address superseded by 0062; proof key, link slots and the mailbox in a link by 0063 |
| [0053](0053-cli-commands-through-a-running-serve.md) | CLI commands reach a running `lepic serve` through its socket | accepted; route mapping superseded by 0055 |
| [0054](0054-epic1-over-carriers-derived-mailboxes-short-links.md) | epic1 over carriers: derived slots and a short link | proposed; mailbox pool, pool bits, mailbox list and drain schedule superseded by 0062; the proof key, derived link slots, link fields and the reply route (sections 1 to 6) by 0063 |
| [0055](0055-the-wallet-api-v1.md) | The wallet API v1, served from one hand-written document | accepted; pair requests and peers removed by 0062 and 0063; address creates and link ids by 0066 |
| [0056](0056-payment-files-in-qr-as-native-slates.md) | Payment files in QR codes as native slates | superseded by 0057 |
| [0057](0057-payment-qr-codes-as-deflated-text.md) | Payment QR codes carry deflated slate text only | accepted |
| [0058](0058-service-wallet-api.md) | Serve for service wallets: boost, webhooks, and payment fields | accepted; `Relays` poller for native mailboxes superseded by 0062; link ids and per-request addresses by 0063, then 0066 |
| [0059](0059-conformance-node-4-1-2.md) | Conformance and vectors on epic v4.1.2 | accepted |
| [0060](0060-epicbox-310-cancel.md) | Epicbox 3.1.0 transaction cancel and the txcancel/1 mux extension | accepted; local-only API cancel superseded by 0062 |
| [0061](0061-cancel-domain-separation.md) | A domain-separated cancel signature, epicbox-cancel/1 | accepted |
| [0062](0062-the-address-decides-the-protocol.md) | The address decides the protocol, and native mail arrives by push | accepted; `epicbox` link entries, link bounds and two tests superseded by 0063; invoices and pair requests to an epic1 address by 0063; the native mailbox setting and the mux/1 refusal by 0065; kept addresses and the migration by 0063 and 0066; the new openapi version by 0066 |
| [0063](0063-the-epic1-address-carries-its-own-mailbox.md) | The epic1 address carries its own slot: a seal key and a delivery key, and no mailbox in a link | accepted; numbered addresses, a link per address, link ids and the restore gap superseded by 0066; the posting rule, the single answering mailbox and pairing mail by 0065; the cancel on `declined` by 0067; §8 amended by 0068 |
| [0064](0064-mailboxes-by-default.md) | Mailboxes by default; the Epicbox switch governs only the classic address | accepted; mailbox health, failover and the list decided in 0065 |
| [0065](0065-mail-goes-where-the-receiver-reads.md) | Mail goes where the receiver reads: one mailbox list, one posting rule, health per mailbox | accepted |
| [0066](0066-one-address-per-account.md) | One epic1 address per account; a request link only fills in the Send screen | accepted |
| [0067](0067-one-notice-path.md) | One notice path: one kind set, one send path, one intake; no notice but `declined` affects the engine | accepted |
| [0068](0068-invoices-the-payer-opens-need-no-pairing.md) | Invoices the payer opens need no pairing: the invoice rule, checkout requests, links need a checked domain | accepted |
