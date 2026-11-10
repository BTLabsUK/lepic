# 0053 CLI commands reach a running `lepic serve` through its socket

Status: proposed
Date: 2026-11-10

## Context

Every opener of a wallet's data directory takes the directory lock (`.lepic.lock`): the CLI, the
FFI runtime and `lepic serve`. Two openers of one SQLite database at once would race on the
wallet's state, so the lock stays.

`lepic serve` holds the lock for as long as it runs. Every other `lepic` command on that wallet
failed with exit code 5 (`another lepic process is using the data directory`), so an operator, a
script or a test suite had to stop serve to run `lepic wallet info`, and lose its Epicbox
connection, its HTTP listener and its event stream meanwhile. ADR 0050 removed the old line
protocol that let a CLI command reach the running wallet, and decided that serve holds one
wallet.

The app (Epic Wallet) opens one wallet at a time through the FFI runtime. Its claim on a busy
directory waits a moment and then answers `WalletBusy`, which the app shows as "wallet busy, try
again in a moment". Nothing in this record changes the FFI.

## Decision

A CLI command that has a route in the wallet API reaches the wallet serve holds through serve's
socket, and prints what it prints when it runs on its own.

- Before it opens the wallet, `lepic` connects to serve's socket. Serve writes the absolute path
  of the socket it listens on to `<data dir>/serve-socket` (owner-only, removed when serve exits),
  and `lepic` tries that path first and `<data dir>/lepic.sock` second. A socket counts only when
  its peer is the CLI's own OS user. When serve answers and the command has a route, the command
  becomes that route's request: the same fields, with the defaults the CLI would apply. The
  wallet password is not asked for: serve holds the wallet unlocked, and the socket admits only
  serve's own OS user (ADR 0050).
- The response body is the command's report. With `--output json` it is printed as it comes,
  which is what the command prints on its own. For human output the request asks for
  `Accept: text/plain` and serve answers with the text the command prints. An error comes back
  as a problem; its `code`, `detail`, `causes`, `tx_id` and `hint` become the CLI error, with the
  kind and exit code the command has when it runs on its own, and the hint is printed under it as
  it is for a direct run. The hint is built only when the request asks for `text/plain`.
- The contact, in-person, epic1, `epictx open` and `profile domain` families go through serve as
  well as the wallet, transaction, Epicbox and profile commands. A file a command reads (a
  payload, a code, an answer, a contact backup) is read by `lepic` after it has connected and sent
  in the request body, which is held in zeroizing memory. A file a command writes (`contact
  export`, `profile domain file`) is written by `lepic` from the answer, with the checks of a
  direct run. Serve never opens a path the client names.
- The command runs with serve's settings, as every API request does. Options that have no field in
  the route (`--to-file`, `--tor-binary`, `--ttl-blocks`, `--offline`, ...) make the command one
  with no route.
- A command with no route, and every command that must not run beside an open wallet (`wallet
  init`, `restore`, `serve`, the listeners, `epicbox drain`), takes the lock as before and fails
  with exit code 5. The message names the running serve and its socket and says to stop serve or
  use its API.
- A serve whose socket cannot be reached (a stale pointer file, a socket removed) is not found;
  the command takes the lock and fails with exit code 5 as before.
- The problem document gains `causes` (the causes in `detail`, outermost first) and `hint`, and the
  owner routes answer `text/plain` when asked. All three are additions to `/v1`.

The forwarded commands are listed in `docs/cli.md` ("Commands while serve runs"). The same page lists
the commands that still exit 5 and why. A new route is added to the list when it covers a CLI
command one to one.

## Consequences

- Operators and scripts run `lepic` commands while serve runs, without stopping it.
- One more place maps CLI arguments to routes, the reverse of `api/routes.rs`. Tests compare
  each forwarded command's output with the direct run.
- Lines a command prints on stderr while it runs on its own (progress, invoice events, notes about
  the peer) are not forwarded; the report and the hint are.
- Interrupting a forwarded command closes the connection; serve finishes the request, as it does
  for any client that goes away.
- The lock, the FFI and the single-wallet serve are unchanged.

## Alternatives considered

- **Wait for the lock.** The CLI would wait until serve stops: a script blocks forever, and an
  interactive user sees nothing happen. Serve does not stop on its own.
- **Multi-wallet serve, or the CLI as a thin client of serve for every command.** ADR 0050
  dropped multi-wallet management for now. A CLI that always needs serve breaks the one-shot use
  every script and the acceptance suite relies on.
- **Bring back a line protocol for CLI command lines.** ADR 0050 removed it: no schema, and every
  option, the tor binary and relative paths included, reached the running wallet. Forwarding
  through the routes sends only the fields their schema lists.
- **Release the lock between serve's requests.** The engine's background work (refresh, Epicbox,
  the HTTP listener) needs the database all the time; a CLI command between two requests would
  still race with it.
