# End-to-end cases on floonet

`interop/e2e` drives the `lepic` CLI and the wallet API of `lepic serve` on **floonet**, against a
real node and a real Epicbox relay, the way a user or a service uses them. It holds named wallets
that keep their funds between runs and covers every payment method, epic1 links, in-person
codes, invoices, pairing and contacts, sealed text and files, the errors a service has to handle,
and a service sending and receiving at once.

## Why a suite next to `acceptance`

`interop/acceptance` runs every command against a local stack on a test-mode chain. The epic1 flows
cannot run there: epic1 links and in-person reply mailboxes need a relay reachable over TLS at a
non-loopback host, which the local stack does not have (see `acceptance/native.sh`). This suite
runs those flows, and the rest, against real floonet servers.

## What it needs

- **A `lepic` binary.** The default is `target/release/lepic` of this repository
  (`cargo build --release -p lepic-cli`). `--lepic <path>` or `LEPIC_E2E_BIN` names another.
- **Tools.** `bash`, `jq`, `flock`, `curl`, `python3` and `pm2`. `run.sh` refuses to start without
  `jq`, `flock`, `pm2` and `python3`, even with `--no-mine`.
- **A floonet node and an Epicbox relay that serve floonet.** The defaults are BT Labs servers.
  A second relay is needed by the cases that name two relays or move a contact between relays.
- **A way to fund the bank wallet with floonet coins.** See [Funds](#funds).
- **A way to move blocks.** Cases wait for confirmations, so floonet must keep producing blocks
  while they run. See [Blocks](#blocks).
- **A CLI settings file.** The first run copies one into the state folder, so it reads
  `LEPIC_E2E_SETTINGS`, default `~/.lepic/settings.toml`. Run any `lepic` command for floonet once
  to create it, or point the variable at a copy.
- **A tor binary and its library folder** for `send.tor` only (`LEPIC_E2E_TOR_BIN` and
  `LEPIC_E2E_TOR_DIR`).

The suite uses its own state folder, never `~/.lepic`: each command runs with a clean environment
(`env -i`) and the suite's own `HOME`, config, settings and password file.

## Environment variables

| Variable | Meaning | Default |
|---|---|---|
| `LEPIC_E2E_BIN` | The `lepic` binary to test; `--lepic` overrides it | `target/release/lepic` |
| `LEPIC_E2E_STATE` | The state folder: wallets, the shared config, the password file, locks and logs of the bank and the miner | A folder in the maintainers' home directory; set it to a folder of your own |
| `LEPIC_E2E_NODE` | The floonet node URL, written to the shared config as `node_url` | `https://floo-node.btlabs.uk` |
| `LEPIC_E2E_RELAY` | The Epicbox relay of every wallet, written as `epicbox_relay` | `epicbox.btlabs.uk` |
| `LEPIC_E2E_RELAY2` | A second relay, for links that name two relays and for relay moves | A second BT Labs relay |
| `LEPIC_E2E_MINCONF` | Confirmations a send needs on its inputs, passed as `--min-confirmations` | `1` |
| `LEPIC_E2E_SETTINGS` | The settings file copied into the state folder on first use | `~/.lepic/settings.toml` |
| `LEPIC_E2E_FUNDER` | The funding script. It is run as `<script> <HTTP listener URL> <amount>` and must pay that amount to the listener | A path that exists only on the maintainers' machine; set it |
| `LEPIC_E2E_BANK_FLOOR` | EPIC the bank must hold spendable; `bank.ready` asks the funding script for a refill below it | `10` |
| `LEPIC_E2E_BANK_REFILL` | EPIC the funding script is asked for when the bank is below the floor or runs low mid-run | `30` |
| `LEPIC_E2E_MINER_ALLOW` | A file to write while the miner runs and remove after, for hosts that guard miners. Unset writes nothing | unset |
| `LEPIC_E2E_TOR_BIN` | The tor binary of `send.tor` | `tor` inside `LEPIC_E2E_TOR_DIR` |
| `LEPIC_E2E_TOR_DIR` | The folder with tor and its libraries, passed to `tor listen` as `--lib-dir` (and the tor binary is passed as `--tor-binary`) | A folder that exists only on the maintainers' machine; set it |
| `E2E_MINE` | `false` does the same as `--no-mine` | `true` |

## Running

```sh
cd interop/e2e
./run.sh --list                          # the cases and the paths that select them
./run.sh                                 # every case
./run.sh --only epic1                    # one area
./run.sh --only epic1.link-pay,ip.ttl    # some cases
./run.sh --from send.tor                 # this case and every one after it
./run.sh --affected main..HEAD           # cases whose code changed in a git range
./run.sh --lepic path/to/lepic           # test this binary
./run.sh --no-mine                       # do not start the miner
```

One case, with the settings it needs:

```sh
LEPIC_E2E_STATE="$PWD/../../.work/e2e/state" \
LEPIC_E2E_FUNDER=/path/to/fund.sh \
./run.sh --only epic1.link-pay
```

The area of a case is the part of its id before the dot. `--only` takes areas and case ids.
`--list` prints the case ids; they run in file order, and `bank.ready` comes first. A run that
selects other cases still creates and funds the wallets they use.

Every run writes a folder `runs/<UTC time>-<pid>` next to the state folder (inside it, when the
state folder is not named `state`). It holds `run.log`, `results.txt` and a folder per case with
its background logs, API calls and saved JSON. One line per case is appended to `NOTES.md` in
the same place. The exit status is 0 when every selected case passed.

## State and funds

### Warm state

Wallets live under `<state>/wallets/<name>` and keep their coins, so a rerun does not fund or
restore a wallet it already has. Names start with `e1s-`, for example `e1s-bank`. When a wallet
is created, its `wallet init` output, with the recovery phrase, is saved as
`<state>/wallets/<name>.init.json` (owner-only). A helper then tries to record the phrase in an
optional test database, and does nothing when none is set up. The password of every wallet is in
`<state>/pw`, made with a random value on first use.

The wallets hold test coins on floonet only. A case must rerun on the same wallets and run alone.

### Funds

All coins come from one wallet, `e1s-bank`, which the funding script fills:

- `ensure_funds <wallet> <epic> [outputs]` sends from the bank over HTTP until the wallet has that
  much it can spend with `LEPIC_E2E_MINCONF` confirmations, under a lock, and waits for it.
- When the bank holds too little, `fund_bank` calls the funding script for `LEPIC_E2E_BANK_REFILL`
  EPIC. It retries up to 15 times, 20 seconds apart, while the script prints `Not enough funds`
  (its own change is not confirmed yet). Calls are serialised by a lock file in the cache folder.

To use your own source, fund the bank wallet with floonet coins and write a script that takes the
URL of a running HTTP listener and an amount, and sends that amount to the listener. Without a
script, fund `e1s-bank` by hand with floonet coins to at least `LEPIC_E2E_BANK_FLOOR` before the
run. A run that needs more than the bank holds fails at that step.

### Blocks

Unless `--no-mine` is given, the runner starts a miner through `pm2` (an app named `floo-miner`,
from a fixed folder named in `miner_start` in `lib.sh`), shares it between parallel runs, and
stops it when the last run ends. Its rewards go to the node's own wallet, never to a test wallet.
With `--no-mine`, something else must move floonet blocks while the cases run, or cases that wait
for a confirmation time out.

## Writing a case

A case file in `cases/` appends `"<area>.<case>|<function>|<path prefixes>"` to `CASES`. The path
prefixes are what `--affected` matches. The function runs in a subshell without `set -e`: chain
each step with `|| fail "<why>" || return 1`, and use `note "<detail>"` for what a pass found.

- `w <wallet> <args>` runs `lepic` with `--output json`. `wx <exit> <wallet> <args>` asserts the
  exit status; the error JSON is in `LAST_JSON`.
- `wbg <wallet> <tag> <args>` runs `lepic` in the background; `epicbox_listen` and `http_listen`
  wrap the listeners. Background processes stop at the end of the case.
- A listener or `serve` holds the wallet's data directory: another command on it exits 5 at once,
  except that a command with an API route runs through a running `serve` (see
  [Commands while serve runs](../../docs/cli.md)).
- `ensure_wallet`, `ensure_funds`, `wait_until`, `wait_blocks`, `tx_by_slate`, `slate_state_is`,
  `expect_eq`, `expect_match` and `expect_json`.

A wallet can have its own config: `wconfig_set <wallet> <key = value>...` writes one, and
`wconfig_reset <wallet>` removes it.

## Areas

| Area | File | Covers |
|---|---|---|
| `bank` | `00-bank.sh` | The bank wallet is funded |
| `life` | `10-lifecycle.sh` | Create, address, info and refresh, restore from the phrase with and without a scan, the outputs list |
| `send`, `peer` | `20-sends.sh` | Payments over Epicbox (online and offline receiver), HTTP and Tor; native and legacy slates; files, `.epictx`, messages; repeated and idempotent sends; cancel and resend; peer pins; refusing unsolicited payments |
| `inv` | `30-invoices.sh` | Invoices over Epicbox and files: issue, pay, decline, expiry, and a peer invoice |
| `epic1` | `40-epic1.sh` | The epic1 address and links, on-screen and printed; paying and collecting; link relays; restore; concurrent payers; refusals |
| `ip` | `50-in-person.sh` | In-person invoice and send codes, the answer by relay or by hand, TTL limits, the payer with no relay |
| `pair`, `ct` | `60-pairing.sh` | Pairing by invite, by hand and by request; contact management, export and import, key check, relay moves, payments, invoices, payloads, profiles, offline contacts |
| `seal` | `70-sealed.sh` | Sealed text, slates and files between paired contacts, send-slate through the mailbox, plain slates |
| `err` | `80-errors.sh` | The exit status and error kind for low balance, bad input, unreachable servers, double spend, cancel after post, declined or expired invoices and a locked wallet |
| `svc` | `90-service.sh` | `lepic serve` and its API: status, the CLI running through serve, withdrawals and deposits in bursts over HTTP and Epicbox |
