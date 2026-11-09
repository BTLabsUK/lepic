# lepic-cli

The `lepic` command-line wallet. It parses the command line, resolves the settings from flags,
`LEPIC_*` variables and the settings files, opens the wallet with the LEPIC engine and prints a
report as text or JSON with a fixed exit code. It is also a library, so tests run whole commands
in-process against a mock node and a mock relay. [docs/cli.md](../../docs/cli.md) is the user
guide and command reference.

## Where it fits

- Builds the binary `lepic` from `src/main.rs`; the library is `lepic_cli`.
- Sits at the top of the workspace, beside `lepic-ffi`. It uses `lepic-wallet` and
  `lepic-wallet-contacts` for the wallet, `lepic-store` for the database, `lepic-keychain` for
  the vault, `lepic-node`, `lepic-epicbox`, `lepic-transport` and `lepic-methods` for the
  network, and `lepic-telemetry` for logs.
- Holds the two files every server address and timeout comes from: `settings.default.toml`, the
  first copy of the user's `~/.lepic/settings.toml`, and `lepic-config.toml`, compiled into the
  binary.
- No features. The API of `lepic serve` is built on Unix only.

## Core concepts

- **One run, one command.** `run` parses the arguments, resolves the settings once, installs
  logging for the command only, runs the command on its own Tokio runtime and returns the exit
  code.
- **No global state.** The environment, the standard streams, the node, the relay and the
  interrupt signal come in through `Host` and `Console`. `ProcessHost` is the real process;
  tests pass their own.
- **Layered settings.** A flag beats its variable, which beats `config.toml`, which beats the
  default. Servers come from `settings.toml`; timeouts, ports and limits from the built-in
  `lepic-config.toml`. [docs/configuration.md](../../docs/configuration.md) lists every key.
- **Typed exits.** Every failure maps to an `exit::ErrorKind` with a code from 1 to 12, which the
  JSON output names in its `error.kind` field.
- **Secrets off the command line.** Passwords and recovery phrases come from a file, a variable,
  a hidden prompt or standard input (`secret::SecretInput`), never from arguments.

## Public API

| Area | Items |
|---|---|
| Entry point | `run`, `Console`, `Host`, `ProcessHost` |
| Command line | `cli::Cli` and its argument types |
| Settings | `settings::{Settings, Env, SETTINGS, CONFIG_ENV}`, `settings_file`, `app_config` |
| Results | `exit::ErrorKind`, `output`, `hint` |
| Secrets and storage | `secret::SecretInput`, `vault`, `stores` |

## Related

- [docs/cli.md](../../docs/cli.md): commands, files and exit codes
- [docs/configuration.md](../../docs/configuration.md): config.toml, settings.toml and the
  built-in values
- [ADR 0030: all configuration in settings.toml](../../docs/adr/0030-all-configuration-in-settings-toml.md)
- [ADR 0050: one wallet API](../../docs/adr/0050-one-wallet-api.md)
- [`lepic-ffi`](../lepic-ffi/README.md): the same engine for the Flutter app
