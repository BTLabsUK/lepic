# 0030 All configuration in settings.toml (no hardcoded configuration)

Status: accepted
Date: 2026-10-29

## Context

On 2026-10-29 the BT Labs Epicbox relay was renamed `epicbox.btlabs.uk`. The rename touched 58
files of the app and 9 of LEPIC: relay lists, onion maps, report scrubbing, Help in six languages,
mocks and tests. A host in code is a change in code, a release and a review for what is a fact
about a service, not about the wallet.

## Decision

- No hardcoded configuration. No host name, URL, IP address, onion address, port, service
  endpoint or path, and no server-related timeout or interval is written in the code of the app,
  LEPIC or lepic-flutter. All of them live in `settings.toml`.
- The file is `settings.toml` in the wallet's data folder, never `epic-wallet.toml`. The app
  ships a default and writes it on the first start. The user's values win; a newer default only
  adds what is missing. On desktop it can be edited while the app runs.
- The library crates take every such value from the caller and hold no default. The CLI ships its
  own default file (`crates/lepic-cli/settings.toml`) and reads `--config` as before.
- The Node and Epicbox server in use are shared by all wallets of a data folder and live in the
  file.
- The file's layout, the first-start and version merge, and the sync rules between app and file
  are in `docs/settings-file.md` of wallet-for-epic. This ADR does not restate them.
- Tests use example hosts (`*.example.invalid`, RFC 5737 addresses). A guard in the check script
  fails the build when a host, URL or IPv4 literal appears in source. Loopback, the Android
  emulator host and RFC 2606 / RFC 5737 names are allowed.
- Hidden development networks (Floonet, Usernet) have their own settings files outside the
  product.

## Consequences

- A rename or a new server is one line in the shipped default.
- Users and operators can change servers without a build.
- A bad hand edit has to be handled: the last good value stays in use and the app reports the line.
- Older ADRs and RFCs that name hosts describe the state when they were written. This one governs
  from 2026-10-29.

## Alternatives considered

- Keep hosts in code in one constants file: still a code change per rename, and tests and Help
  copy them.
- Use `epic-wallet.toml`: it would be mistaken for, and could overwrite, another wallet's config.
