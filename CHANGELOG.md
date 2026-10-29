# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Entries are generated from
Conventional Commit messages at release time.

## [Unreleased]

### Added

- Repository setup: licence, architecture and build settings.
- `lepic-cli` reads its servers from `settings.toml` (`--settings`, `LEPIC_SETTINGS`,
  `settings_file`), in the layout of the Epic Cash wallet app's file, and writes the shipped
  default to `~/.lepic/settings.toml` on first use.

### Changed

- The library crates hold no host name, onion or URL: the default Epicbox domain, the meeting
  relays for pairing words and the onion routes all come from the caller. An Epicbox address
  without `@domain` is refused unless a default domain is given. In `lepic-ffi`,
  `WalletConfig` gains `onion_routes`, `meeting_relays` is a required list, and
  `built_in_pairing_relays` is gone.
