# ADR 0030: All configuration in settings.toml, no hardcoded configuration

Status: accepted

## Context

Facts about services change independently of the wallet: a relay gets a new host name, a node is
added, a timeout needs tuning. If hosts, URLs, onion addresses, ports and server timeouts are
written in code, each such change is a code change, a release and a review, and copies of the
same host spread over relay lists, tests and help text.

## Decision

- No host name, URL, IP address, onion address, port, service endpoint or path, and no
  server-related timeout, interval or limit is written in the code of LEPIC, lepic-flutter or an
  app that embeds them.
- Two files hold that configuration, in the wallet app and in the CLI alike:
  - The user's `settings.toml`, written on the first start from a shipped
    `settings.default.toml` (`crates/lepic-cli/settings.default.toml` for the CLI). It holds the
    node list, the Epicbox server list (the first entry of each is the one in use) and a few
    switches.
  - The built-in, read-only configuration shipped with the program (`lepic-config.toml`,
    compiled into the CLI; the app has its own file of the same layout): operators, onions,
    service URLs, timeouts, intervals, ports and limits. Changing it needs a new build.
- The library crates take every such value from the caller and hold no default. A host passes the
  servers and, for the tuning, `NetTuning` in `lepic-ffi`'s `WalletConfig.tuning`: groups `node`,
  `epicbox`, `http` and `tor`, units in the field names, every field required. A zero, or a
  minimum above its maximum, fails with `InvalidArgument`. The settings types of `lepic-node`,
  `lepic-epicbox`, `lepic-legacy-rpc` and `lepic-tor` carry no tuning defaults; tests take values
  from a `testing` helper in each crate.
- What stays in code, because both sides of a protocol must agree or because changing it is a
  safety decision and not a setting: what an address or URL without a port means (443 for an
  Epicbox address, `DEFAULT_LISTEN_PORT` 3415 for a peer's `http://` URL), the onion service
  port, wire-format and size limits, crypto parameters, consensus values, the Epic node's API
  paths, the bounds against a misbehaving relay or node, the release window of locked outputs, the
  contact-pairing windows and the waits for the local tor process.
- Tests use example hosts: loopback addresses and the reserved example names.

The CLI's two files and their keys are described in [`docs/cli.md`](../cli.md).

## Consequences

- A new server or a renamed host is one line in a shipped default.
- Users and operators can change servers without a build.
- A host that edits `settings.toml` by hand has to handle a bad edit: the host decides which value
  stays in use and what it reports.

## Alternatives considered

- Keep hosts in code in one constants file: still a code change per rename, and tests and help
  copy them.
- Use `epic-wallet.toml`: it would be mistaken for, and could overwrite, another wallet's file.

## Related

- ADR 0021, ADR 0036
