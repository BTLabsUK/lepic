# lepic-cli configuration files

- `settings.default.toml`: the first-start copy of the user's `~/.lepic/settings.toml` (`--settings`): which node and Epicbox servers to use.
- `lepic-config.toml`: the CLI's built-in configuration, compiled into the binary and read-only: timeouts, ports, limits, the default address server and the servers' onions.
- Neither the library crates nor the CLI's code hold such a value; see `docs/cli.md` and ADR 0030.
