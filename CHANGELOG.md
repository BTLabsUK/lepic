# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Entries are generated from
Conventional Commit messages at release time.

## [Unreleased]

### Added

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

### Removed

- `Wallet::self_send`, `Wallet::spend_outputs_to_self`, `Wallet::estimate_self_send`,
  `SelfSendShape` and `SplitCount` in `lepic-wallet`, and `estimate_split`, `split_outputs`,
  `estimate_consolidate`, `consolidate_outputs` and `spend_outputs_to_self` in `lepic-ffi`:
  `send_to_self` replaces them (ADR 0037).

### Changed

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
