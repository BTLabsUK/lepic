# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Entries are generated from
Conventional Commit messages at release time.

## [Unreleased]

### Added

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

### Changed

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
