# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Entries are generated from
Conventional Commit messages at release time.

## [Unreleased]

### Changed

- The legacy formats have crates of their own (ADR 0052). `lepic-foreign` is renamed
  `lepic-legacy-rpc`; the V2 and V3 JSON codecs move from `lepic-slate`'s `codec::legacy` to
  the new `lepic-legacy-slate`, with the slate marker codecs from `lepic-transport::marker`,
  which re-exports them. `lepic-transport` and `lepic-methods` gain a default `legacy` feature;
  without it they build with no legacy crate and the default codecs decode nothing, which
  `cargo xtask no-legacy` checks, also as a step of `cargo xtask check`. The OpenAPI document
  lists `/v2/foreign` under a `legacy` tag. Codec ids, transport ids, paths and method names do
  not change.
- `lepic serve` answers the wallet API, HTTP/1.1 on its socket (ADR 0050): status, events as
  server-sent events, wallet info, address, outputs and password, node status, transactions,
  Epicbox sends, and slate receive and finalize. Bodies are the commands' JSON reports, errors
  RFC 9457 problem details. `docs/api/openapi.json` describes it, with the payment endpoint.
  `lepic --service`, its line protocol and the `service_unavailable` error kind are removed;
  `GET /v1/status` replaces `lepic --service serve status`.
- The wallet's onion has a key of its own, the namespace key `lepic-wallet onion key v1`, and is
  no longer the payment-proof address in onion form (ADR 0044). Updated installs show a new
  onion; a restore from the phrase gives the same one. Epicbox and payment-proof addresses do
  not change. A payment proof asked for over the onion names the onion's key and is signed with
  it; `ReceiveRequest` takes the key as `proof_key` (`ProofKey::Payments` by default), and a
  proof for the other key's address is refused with `ForeignProofAddress`.
- The FFI's `start_http_listener` takes a `coinbase` flag; pass `false` to keep the old
  behaviour.

### Added

- `lepic-epic1`: the epic1 address (bech32m, hrp `epic` and `tepic`, proof key and seal key) and
  the epic1 payment link with up to three Epicbox transport entries, amount, message and label
  (RFC 0003 §5.13, §5.14). An Epicbox link is not read as an epic1 link. A link with no usable
  transport reads and reports that it cannot be paid.
- `lepic_transport::host_rule`: classifies a relay host from untrusted input as public or on
  the local network and refuses loopback and unspecified hosts, by name before resolving and by
  address for each resolved address.
- `ur:epic-slate` payload version 2 (RFC 0003 §5.18): `encode_ur_binary` and `decode_ur_parts`
  carry a native slate or an envelope as bytes, uncompressed. Version 1 codes are unchanged.
- Golden vectors for the epic1 address and link (`testdata/vectors/keys/epic1_*`) from an
  independent bech32m, and the `epic1_link` fuzz target.
- `lepic-native-slate`, the native slate codec `lepic.v1` of EPICTX: a binary slate with the
  network and block header version in its header, a TLV tail for reply records, a JSON view, and
  `NativeV1Codec` for the codec registry (media type `application/vnd.lepic.slate`). The wallet
  does not use it yet. Golden vectors in `testdata/vectors/slates_native` and a `slate_native`
  fuzz target cover it.
- `lepic-seal`, the sealed envelope format in a crate of its own (RFC 0003, ADR 0052).
  `lepic-contact` re-exports the envelope, its armor and contact cards at their former paths.
  New in it, not yet used by the engine: envelope type `0A` with a reply mailbox (tag `09`);
  slate envelopes padded to at least 768 bytes (tag `FE`), which readers of RFC 0002 open as
  before; the seal, epic1 and listener key classes (`KeyClass`, `seal_tx`, `open_tx`); the
  `BEGINEPICTX.` armor beside `BEGINEPICSEALED.` (`armor_tx`, `dearmor_marked`); and `classify`
  for payment files. A body over 65,535 bytes is refused with `EncodeError::BodyTooLarge`, which
  carries the limit and the size and replaces `FieldTooLong` for the body.
- Local quarantine and an early-notice buffer, both off by default (ADR 0049).
  `quarantine_max_bytes` keeps contact messages that opened and could not be taken, with
  `contact_quarantine`, `contact_quarantine_retry`, `contact_quarantine_discard` and
  `lepic contact quarantine`. `early_notice_max_count` with `early_notice_max_age_s` keeps a
  notice that came before its slate and applies it when the slate arrives. The inbox and contact
  reports count `buffered`, and the contact report `quarantined` and `quarantine_dropped`.
- `Wallet::previous_onion_key`, `lepic tor address --previous` and the binding's
  `previous_onion_address`: the onion of LEPIC 0.3.1 and earlier, the one `epic-wallet` and the
  GUI wallet publish.
- `lepic tor listen --previous-onion` and `HostPolicy::publish_previous_onion` (default off)
  publish the previous onion too, on a listener of its own whose proofs are signed with the
  payment-proof key, so senders that saved it still reach the wallet.
- `lepic_tor::TorProcess::add_onion_to` adds a further onion to a running tor.
- Two wallet policy switches, off by default (ADR 0045): `refuse_unsolicited_payments` refuses an
  S1 nobody asked for over Epicbox, HTTP, Tor or a contact's mailbox, and
  `refuse_unsolicited_invoices` refuses a contact's I1. A refused slate is answered with the
  `declined` notice where the sender can take one; over HTTP and Tor the request fails. The CLI
  takes them as settings (`LEPIC_REFUSE_UNSOLICITED_PAYMENTS`,
  `LEPIC_REFUSE_UNSOLICITED_INVOICES`) and the binding's `HostPolicy` as two optional fields.
- A send whose receiver declines it is cancelled, which frees its inputs, and raises
  `PaymentDeclined`. `TransactionDetails` gains `receiver_declined_at` (the binding
  `receiver_declined_at_ms`), and `lepic tx show` prints it.
- Block rewards for a mining node, ADR 0046: `Wallet::build_coinbase` builds the coinbase output
  and kernel from the wallet's keys, and a refresh records a mined one as an incoming
  transaction. `lepic-foreign` answers `build_coinbase` when the host turns it on with
  `ListenSettings::with_coinbase`, `lepic http listen --coinbase` does, and the FFI's
  `start_http_listener` takes `coinbase` (`HttpCoinbase`). Only loopback callers are served,
  with `CoinbaseAccess::Remote` (`--coinbase-remote`) every caller (ADR 0048). A candidate stays
  until a refresh finds it more than 50 blocks from the tip, or built for height 0, and deletes
  it; past 4,096 the one built longest ago goes. Store schema 15.
- `TransactionDetails::coinbase` (engine and FFI) marks an incoming transaction whose output is
  a coinbase output; `lepic tx show` prints it as `Kind mining reward`.
- `WalletPolicy::listener_held_rounds` and `HostPolicy::listener_held_rounds` (1 to 64, default
  none): a listener moves to a fresh socket after this many rounds that began with a message
  held, counted per socket and not reset by an acknowledgement. The held message is taken up
  again on the new socket. Drains are not affected. `EpicboxClient::listen_with_held_rounds`
  takes the limit.
- `CollectReport` and the FFI's `ContactCollectReport` count mailboxes by how their drain ended:
  `capped`, `kept`, `refused`, `timed_out` and `not_reached`. `lepic contact collect` prints
  them.
- `ChainParams::block_total_reward`, `foundation_levy`, `mining_reward` and `coinbase_value`,
  with vectors for the reward schedule.

### Fixed

- `lepic wallet info` reports the height its balances are at, and says `catching_up` with
  `node_height` when the chain outgrew it.
- The FFI builds the previous onion lookup without the `tor` feature.

## [0.3.1] - 2026-11-06

### Added

- `lepic-wallet-contacts` re-exports `DomainName`, `VerifyingKey` and the contact `Network` (as
  `ContactNetwork`), so the CLI no longer depends on `lepic-contact` directly.

### Changed

- `lepic profile domain file` takes the file's path as `--path PATH`, not `--out`: `--out`
  elsewhere means "write to this file instead of printing".

### Fixed

- The in-memory store refuses a contact's domain proof over 4,096 bytes, as SQLite already did.

## [0.3.0] - 2026-11-06

### Added

- The domain claim, ADR 0043: envelope extension `0x83` carries a domain and an Ed25519
  signature by a domain key over the pairing's signing key, in a reply, a confirm and a contact
  update. `lepic-contact` gains `DomainClaim`, `DomainName` and `DomainKey`;
  `lepic-wallet-contacts` derives the key from the contact root (`epic-domain/1`) and gains the
  pure `ContactBook::domain_verify`, which takes the file bytes the host fetched and answers
  `Proven` or `Refused` with a reason, and `contacts_tell_domain`, which sends paired contacts the
  claim. `WalletConfig.domain` sets the domain. Schema 14 adds `peer_domain` and
  `peer_domain_attestation` to contacts, stored as received; backups carry them as optional
  fields, so schema 13 stores and v1 backups still load. `ContactView.peer_domain` and
  `peer_domain_attestation` give the contact's claim. Vectors: `pairing/domain.json`. Core does
  no fetching and keeps no verification state; a wallet that predates the extension ignores it.
- `lepic` domain settings: `domain` in the config file, `LEPIC_DOMAIN` and `--domain`, and
  `lepic profile domain show|file|attach`, which print the domain key, write the
  `epic-wallet.json` file and send the claim to paired contacts.
- `lepic-ffi` gains `contact_domain_verify`, `DomainVerdict`, `WalletConfig.domain` and the
  claim on `ContactView`.
- Draining the old home after moving one's own, ADR 0042: `ContactBook::contacts_move_home`
  takes a `drain` (at most `MAX_HOME_DRAIN`, a year), and for that long every collect still
  reads the old mailboxes and answers contact checks there with the new card. FFI
  `contacts_move_home(relay, drain_days)`; CLI `lepic contact move-home HOST --drain-days N`
  (0 to 365, default 0), with `drain_until` in the report.
- `ContactView.peer_enc_key` (`lepic-wallet-contacts` and `lepic-ffi`): the contact's card
  encryption key (tag 05), so a host can recognise a service by its key.

### Changed

- `PairingExtras` (`lepic-contact`) is `Clone` and no longer `Copy`.

### Fixed

- A collect with more than 50 pairings in progress on one relay no longer drains nothing on that
  relay: pairings in progress now take turns across cycles as contacts do, and while they are
  more than fit, contacts keep up to half of a cycle's 50 mailboxes.
- On more than three relays, a foreground collect no longer drops the previous home of a quiet
  contact while its drain lasts.

## [0.2.0] - 2026-11-06

### Added

- The owner's profile, ADR 0041: bits 16 to 31 of the envelope feature word (tag `0x82`,
  `HOST_PROFILE` and `PROFILE_SHIFT` in `lepic-epicbox`) carry a host-defined profile to every
  paired contact. `WalletConfig.profile` (`lepic-wallet` and `lepic-ffi`) sets it, with
  `WalletConfig::pairing_features`; `ContactBook::contacts_set_own_profile` sends paired contacts
  a card update when it changes; `ContactView.peer_profile` (`lepic-wallet-contacts` and
  `lepic-ffi`) gives the contact's. Core gives the bits no meaning. A wallet that predates it
  reads zero.
- `lepic` profile settings: `profile = "no-payments,automated"` in the config file,
  `LEPIC_PROFILE`, `--profile <NAMES>` and `--profile-bits <N>`, `lepic profile show` and
  `lepic profile set`, also through `--service`. The CLI names bit 0 `no-payments` and bit 1
  `automated`; contact views show the contact's profile.
- Policy values as host parameters, ADR 0036: `WalletPolicy` in `lepic-wallet`'s
  `WalletConfig`, `HostPolicy` in `lepic-ffi`'s `WalletConfig` and `PinSettings` with
  `LepicRuntime::with_pin_settings`. They cover the default strategy, the send and invoice
  TTLs, the change and exclusion limits, the Epicbox invoice window, the payer's TTL lead
  cap, the open receipt caps, the default minimum confirmations and the PIN rules. Every
  default is the value used before.
- One send to self, ADR 0037: `Wallet::send_to_self` and `Wallet::estimate_send_to_self`
  take a `SelfSendRequest` of inputs (`All`, `Smallest`, `Named`) and outputs (`Count`,
  `Amounts`, the rest as one more output), 1 to 10 outputs; the estimate's fee equals the
  send's. `lepic-ffi` gains `EpicWallet::send_to_self` and `EpicWallet::estimate_send_to_self`
  with `SelfSendRequest`, `SelfInputs` and `SelfOutputs`.
- `lepic-ffi`'s `node_tip` takes a `NodeRoute`: directly, or through the host's SOCKS5 proxy
  with no fallback to a direct connection.

- Restore from a start height, ADR 0035: `Wallet::restore_from_height` scans from a chosen
  height, and the wallet creates outputs once a scan from that height or below completes; its
  key counters move past the keys that scan found. `Wallet::restore_scan_start` tells where a
  pending restore scan starts. `lepic-cli` gains `lepic wallet restore --from-height`.
- `InvitePreview::own` (`lepic-wallet-contacts` and `lepic-ffi`): the invite is one this
  wallet made, standing, waiting or cancelled, so an app refuses its own invite before asking
  "Pair with …?", also after a restart. `ContactBook::pairing_preview` is now async and reads
  the store, so it needs an open session.
- `lepic-ffi` gains `EpicWallet::set_http_over_tor` and `EpicWallet::http_over_tor`: HTTP
  sends can reach the other wallet directly while the wallet's tor runs, as the node and the
  relay already can (`set_node_over_tor`, `set_epicbox_over_tor`), for an app that runs tor
  only to be paid at its onion and to send to onions. On by default: nothing changes until
  the app turns it off.
- The wallet database moves to encryption at rest at its first open (ADR 0032): a plain
  `wallet.sqlite3` is copied into `wallet.enc.sqlite3`, checked, switched to and kept aside as
  `wallet.sqlite3.pre-encryption`; a failed copy runs the session on the plain file and is tried
  again. `lepic-ffi` gains `EpicWallet::store_at_rest`, `EpicWallet::retire_plain_store`,
  `LepicRuntime::store_migration_progress` and `WalletErrorKind::WrongKey` (code 90).

- Repository setup: licence, architecture and build settings.
- `lepic-cli` reads its servers from `settings.toml` (`--settings`, `LEPIC_SETTINGS`,
  `settings_file`), in the layout of the Epic Cash wallet app's user file (`[node] servers`,
  `[epicbox] servers`), and writes the shipped default to `~/.lepic/settings.toml` on first
  use. Timeouts, ports, limits, the default address server and the onions come from its
  built-in `lepic-config.toml`.
- An offline session for cold wallets, ADR 0031: `WalletConfig::offline` makes the session's
  node and relay ports refuse every call (`NodeError::Offline`, `lepic-ffi`'s
  `WalletErrorKind::Offline`), the payment stages work on the last confirmed tip, and finalizing
  stores the transaction without posting it (`FinalizedTx::posted` false).
  `finished_payment` returns its final slate as legacy V3 JSON.
- `lepic-ffi`'s `start_tor` takes `publish_onion`: false starts tor for its SOCKS routes only,
  without publishing the wallet's onion or running the listener behind it.
- A refused post whose inputs are gone says whose they were: `FinalizeError` and
  `InvoiceError` gain `InputsSpentByOwnTransaction` (another transaction of this wallet, such
  as a cancelled payment mined before its coins were moved back, spent them; no other wallet is
  recorded) and `PeerInputsSpent` (the other party's inputs are spent). `lepic-ffi`'s
  `WalletErrorKind` gains both (codes 79 and 80). The transaction is cancelled and its kernel
  stays watched.
- A refresh ends a finalized or posted transaction that can never be mined: an input it spends
  is gone in two answers and neither the node's pool nor its chain holds its kernel. It is
  cancelled with its kernel watched, so a refused move back to the wallet is no longer posted
  again forever. An invoice this wallet issued and finalized expires at its cutoff.
- `Event::NotPosted` (`lepic-wallet`) and `WalletEventKind::NotPosted` (`lepic-ffi`, with
  `tx_id`, `slate_id` and `message`): a finalized transaction the node refused or could not be
  reached for, also on the Epicbox answer and invoice paths that only logged it. The
  transaction stays finalized; core retries nothing, and the host calls `repost_transaction`
  when it chooses.
- `PairingFailure::KindDiffers`, `ContactError::KindDiffers`, `PairingFailureReason::KindDiffers`
  and `WalletErrorKind::PairingKindDiffers` (code 91): a pairing whose invite and card name
  different contact kinds is refused when the confirm arrives, and nothing is stored.
- `WalletError.tx_id` (`lepic-ffi`) and `ContactError::NotCancelled` (`lepic-wallet-contacts`):
  a paste-slate send or a contact send that stored a transaction and then failed is cancelled;
  when the cancel fails too, the error names the transaction, which stays stored with its
  inputs locked, and the failed cancel. A stored-but-undelivered send also sets `tx_id`.

- The contact check, ADR 0040: envelope type `09` asks a paired contact for its current card,
  and the contact answers with a contact update through its outbox. `ContactBook::contact_check`,
  `EpicWallet::contact_check` and `lepic contact check <CONTACT>` send one. Answers are paced per
  contact by `contact_check_answers_per_hour` (default 1) and `contact_check_answers_per_day`
  (default 3, at most 24) in `WalletPolicy` and `HostPolicy`; checks beyond them are taken and
  dropped. A wallet that predates type `09` drops the check as malformed and does not answer.
- A move of the wallet's own home relay, ADR 0040: `ContactBook::contacts_move_home`,
  `EpicWallet::contacts_move_home` and `lepic contact move-home <HOST>` send every paired contact
  our card naming our mailbox on the new relay once, in a contact update, and move our mailboxes
  there at once. The old mailboxes are not read again; there is no drain.
- `lepic --service serve status` shows, for serve's wallet refresh and contact collect, the
  failures since the last success, the last error and the time of the last success.

### Deprecated

- The contact kind, ADR 0041: new invites and cards write person whatever the request names,
  so an invite and its cards always agree; existing pairings keep their kind. The `kind`
  fields stay in the card, the invite, the requests and the views, and are not to be read for
  meaning. `lepic contact invite --kind` and `lepic contact show-card --kind` are hidden and
  ignored, with a note.

### Removed

- `lepic-cli`'s minimum of 8 characters for a new wallet password (an empty one is still
  refused) and its cap of 48 hours on `invoice_expiry_hours`: limits belong to the consumer,
  not the CLI. `lepic contact move --apply` stays.
- `Password::MIN_NEW_LEN` and `Password::is_long_enough_to_set` (`lepic-wallet`), the password
  length check of `lepic-ffi`, `MINIMUM_CONFIRMATIONS_RANGE` and its upper bound of 30, and
  `WalletConfig.transports` (ADR 0036). The host checks the password length and the depth it
  allows.
- `Wallet::self_send`, `Wallet::spend_outputs_to_self`, `Wallet::estimate_self_send`,
  `SelfSendShape` and `SplitCount` in `lepic-wallet`, and `estimate_split`, `split_outputs`,
  `estimate_consolidate`, `consolidate_outputs` and `spend_outputs_to_self` in `lepic-ffi`:
  `send_to_self` replaces them (ADR 0037).

### Changed

- Shared helpers replace copies in the core crates; behaviour is unchanged. `lepic-store`
  gains `file::write_owner_only_atomic` (owner-only temp file, sync, rename, folder sync),
  which the CLI now uses for the vault, slate files and contact backups, and an async
  `lock_data_dir` with `try_lock_data_dir`, `DataDirLock` and `DataDirLockError`, which the
  CLI and the binding both use for the data-directory claim. `lepic-primitives` gains
  `error_chain::ErrorChain`, and the wallet, relay, node and contact crates use it.
  `lepic_crypto::hex` replaces the local hex readers and writers in the contact and relay
  crates. The PIN and password code in `lepic-ffi` shares one `blocking()` and `rng()`, and
  `lepic-wallet` calls `codecs::legacy` directly.
- **Breaking:** a contact's move to another relay is the host's choice, ADR 0039. The
  collector no longer reads a contact's kind: an update whose card names a mailbox on the same
  relay applies as before, and one naming another relay stores the newer card, keeps the
  mailbox in use and raises `Event::ContactRelayMoveRequested` (contact id and `domain:port`)
  once per card. `ContactBook::apply_relay_move` applies the move, and is refused with
  `ContactError::RelayMoveNotRequested` for any other relay or when no move waits;
  `ContactView::requested_relay` shows a waiting move. The rule that let only services move,
  and only to a meeting relay or a named host on the default port, is gone. Existing contacts'
  mailboxes are not touched. `lepic-ffi` gains `WalletEventKind::ContactRelayMoveRequested`
  (`contact_id`, `relay`), `EpicWallet::contact_apply_relay_move`,
  `ContactView::requested_relay` and `WalletErrorKind::RelayMoveNotRequested` (code 92).
  The CLI's contact list shows a waiting move, and `lepic contact move <ID> --apply <HOST>`
  applies it.
- A contact mailbox message held on a passing error (the store, a relay or the node did not
  answer, or the wallet is locked) is kept and its tries are not counted; only messages that fail for other reasons are
  dropped after `contact_hold_attempts` tries (default 3, at most 10) over
  `contact_hold_patience` (default 180 s, at most a day), now host parameters in `WalletPolicy`
  and `HostPolicy` (`contact_hold_patience_s`).
- `lepic serve` no longer drops requests still running at shutdown: it interrupts each one as
  Ctrl-C would, so a `tx send` that stored its transaction answers with its `tx_id`, and it waits
  for every reply.
- A contact mailbox message's hold count is forgotten a day after it was first held, also when
  the message never comes back. `SettingsRepository` gains `settings_with_prefix`.
- A contact payment whose receive was stored but not linked to its contact is linked when the
  sender repeats it, instead of being dropped and acknowledged. A mailbox message the handler
  holds with `Later` is held at most 3 times or 3 minutes, as the payments inbox bounds its
  holds; errors the collector dropped at debug level are logged at warn.
- `delete_wallet` also removes scratch slate files, `tor-expected` and the `tor/` directory.
  Pasted slates are decoded in memory instead of through a scratch file.
- `lepic-ffi`'s `EpicWallet::create` and `EpicWallet::create_with_pin` take
  `restore_from_height: Option<u64>` after the mnemonic; `None` or 0 restores from genesis, and a
  height without a mnemonic is refused with `InvalidArgument`. `scan` without a start, while a
  restore is pending, starts where that restore starts, and `lepic wallet scan` does the same.
- The library crates hold no host name, onion or URL: the default Epicbox domain, the meeting
  relays for pairing words and the onion routes all come from the caller. An Epicbox address
  without `@domain` is refused unless a default domain is given. In `lepic-ffi`,
  `WalletConfig` gains `onion_routes`, `meeting_relays` is a required list, and
  `built_in_pairing_relays` is gone.
- All configuration in settings.toml (no hardcoded configuration), ADR 0030: the library crates
  hold no timeout, retry, port or server limit either. The settings types of `lepic-node`,
  `lepic-epicbox`, `lepic-foreign` and `lepic-tor` lost their defaults and take every value from
  the caller; in `lepic-ffi`, `WalletConfig` gains `tuning: NetTuning`.
- A posted send to the wallet itself counts its coins once, as awaiting confirmation, instead of
  its inputs as locked and its output as awaiting finalization.
- `lepic-cli` exits with the rejected code (7) for a post refused because its inputs were
  spent, instead of the internal one.
