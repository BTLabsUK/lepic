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
  endpoint or path, and no server-related timeout, interval or limit is written in the code of
  the app, LEPIC or lepic-flutter.
- Two files, in the wallet app and in the CLI alike:
  - the user's `settings.toml` in the data folder, written on the first start from a shipped
    `settings.default.toml`: the Node list, the Epicbox list (the first entry of each is the one
    in use) and a few on/off switches. On desktop it can be edited while the app runs.
  - the built-in, read-only configuration shipped with the program (`app-config.toml` in the
    app, `lepic-config.toml` compiled into the CLI): operators, onions, service URLs, timeouts,
    intervals, ports and limits. Changing it needs a new build.
  The file is never `epic-wallet.toml`.
- The library crates take every such value from the caller and hold no default. The servers come
  as before; the tuning comes as `WalletConfig.tuning` (`NetTuning`: `node`, `epicbox`, `http`
  and `tor` groups, units in the field names, every field required; a zero, or a minimum above
  its maximum, is `InvalidArgument`). The settings types of `lepic-node`, `lepic-epicbox`,
  `lepic-foreign` and `lepic-tor` have no `Default`; tests take the shipped values from one
  `testing` helper per crate.
- What stays in code, because both sides of a protocol must agree or because changing it is a
  safety decision and not a setting: what an address or URL without a port means (443 for an
  Epicbox address, 3415 for a peer's `http://` URL), the onion service port, wire-format and size
  limits, crypto parameters, consensus values, the Epic node's API paths, the bounds against a
  hostile relay or node, the release window of locked outputs, the contact-pairing windows and
  the waits for the local tor process.
- The app's layout, first start and sync rules are in `docs/settings-file.md` of wallet-for-epic;
  the CLI's in `docs/cli.md`. This ADR does not restate them.
- A guard in the check script fails the build when a host, URL, IPv4 literal, port or API path
  appears in source. Loopback and RFC 2606 / RFC 5737 names are allowed. Tests use example hosts.
- Hidden development networks (Floonet, Usernet) have their own files outside the product.

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
