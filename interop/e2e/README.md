# End-to-end cases on floonet

`interop/e2e` drives the `lepic` CLI and `lepic serve`'s wallet API on **floonet**, against BT Labs'
node and Epicbox relay, the way a user or a service uses them: named wallets that keep their funds
between runs, every payment method, epic1 links, in-person codes, invoices, pairing and contacts,
sealed text and files, the errors a service has to handle, and a service sending and receiving at
once.

## Why a suite next to `acceptance`

`interop/acceptance` runs every command against a local stack on a test-mode chain, and stays the
gate for a release. It cannot run the epic1 flows: epic1 links and in-person reply mailboxes need
a relay reachable over TLS at a non-loopback host, which the local stack does not have (see
`acceptance/native.sh`). This suite runs those flows, and the rest, on the real floonet servers.

## Running

```sh
cd interop/e2e
./run.sh --list                          # the cases, by area
./run.sh                                 # every case
./run.sh --only epic1                    # one area
./run.sh --only epic1.link-pay,ip.ttl    # some cases
./run.sh --from send.tor                 # resume at a case
./run.sh --affected main..HEAD           # cases whose code changed in a git range
./run.sh --lepic path/to/lepic           # test this binary (default: target/release/lepic)
```

It needs `jq`, `flock`, `curl`, `python3` and `pm2`, the QA funder at `~/epic/qa-funder/fund.sh`
and the floonet miner at `~/epic/floo-miner`.

Each run writes `~/epic-build/epic1-suite/runs/<time>/`: `run.log`, `results.txt` and a directory
per case with its background logs, API calls and saved JSON. One line per case goes to
`~/epic-build/epic1-suite/NOTES.md`.

## Warm state and funds

Wallets live under `~/epic-build/epic1-suite/state/wallets/<name>` and keep their funds, so a rerun
of one case does not fund or restore anything it already has. Names are `e1s-<area>-<role>`. Each
wallet is recorded in the test database (`tools/rellib/testdb`) when it is created, with its phrase.

Funds come only from the QA funder, through one bank wallet (`e1s-bank`):

- `ensure_funds <wallet> <epic> [outputs]` sends from the bank over HTTP until the wallet has that
  much spendable, under a lock, and waits for it to confirm.
- Below the floor the bank refills itself from the QA funder (30 EPIC, `LEPIC_E2E_BANK_REFILL`).
  The funder needs 10 confirmations on its own change, so a refill retries until it can send.

The runner starts the floonet miner to move blocks while cases run, shares it between parallel
runs, and stops it when the last one ends; blocks are never mined to fund a wallet. Sends use
`--min-confirmations 1`. Where a host guard asks for a time-boxed allow file before a miner runs,
`LEPIC_E2E_MINER_ALLOW` names it: the runner writes it while the miner runs and removes it after.

## Writing a case

A case file in `cases/` appends `"<area>.<case>|<function>|<path prefixes>"` to `CASES`. The path
prefixes are what `--affected` matches. The function runs in a subshell without `set -e`: chain each
step with `|| fail "<why>" || return 1`, and `note "<detail>"` for what a pass found.

- `w <wallet> <args>`: lepic with `--output json`. `wx <exit> <wallet> <args>` asserts the exit
  status; the error JSON is on stdout, in `LAST_JSON`.
- `wbg <wallet> <tag> <args>` runs lepic in the background; `epicbox_listen`, `http_listen` wrap the
  listeners. Background processes stop at the end of the case.
- A listener or `serve` holds the wallet's data directory: another command on it exits 5 at once,
  except that a command with an API route runs through a running `serve` (docs/cli.md, "Commands
  while serve runs").
- `ensure_wallet`, `ensure_funds`, `wait_until`, `wait_blocks`, `tx_by_slate`, `slate_state_is`,
  `expect_eq`, `expect_match`, `expect_json`.

A case must rerun on the same wallets and run alone.

## Areas

| Area | File | What |
|------|------|------|
| bank | 00-bank.sh | the bank wallet funded |
| life | 10-lifecycle.sh | create, restore, scan, outputs |
| send, peer | 20-sends.sh | Epicbox, HTTP, Tor, native and legacy, files, slate ids, cancel, resend, peer pins, refusing unsolicited |
| inv | 30-invoices.sh | invoices: issue, pay, decline, expiry |
| epic1 | 40-epic1.sh | epic1 address and links, pay, collect, relays, refusals |
| ip | 50-in-person.sh | in-person codes and their TTL |
| pair, ct | 60-pairing.sh | pairing, contacts, moves, contact invoices, payloads, profile |
| seal | 70-sealed.sh | sealed text, slates and files |
| err | 80-errors.sh | the errors a service handles, by exit status and kind |
| svc | 90-service.sh | `lepic serve` and its API: withdrawals and deposits at once |
