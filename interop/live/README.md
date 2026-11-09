# Live floonet test

`run.sh` sends EPIC between `lepic` and `epic-wallet` v4.1.0 on the public floonet chain: both
ways over slate files and both ways over a local Epicbox relay. It waits for each transaction to
confirm and prints a table with every kernel excess. No node runs locally. The wallets and the
miner use the foreign API of a public floonet node, so transactions confirm in blocks the stack
mines itself.

The run does nothing unless `LEPIC_LIVE_TESTS=1`. It is not part of CI.

```bash
LEPIC_LIVE_TESTS=1 interop/live/run.sh               # build, start or reuse the stack, fund, test
LEPIC_LIVE_TESTS=1 interop/live/run.sh --no-build    # reuse the images and binaries already built
LEPIC_LIVE_TESTS=1 interop/live/run.sh --down        # stop the stack afterwards
LEPIC_LIVE_TESTS=1 interop/live/run.sh --mine-funds  # fund by mining coinbase
```

It needs what [the interop README](../README.md#requirements) lists and HTTPS access to the
floonet node. `LIVE_NODE_URL` sets the node; its default is in `run.sh`. The stack takes the
host-wide Docker stack lock, like the other runners.

## What runs

| Service | What it is |
|---|---|
| `nodeproxy` | `docker/node-proxy.py` on `127.0.0.1:33413`. Forwards `/v2/foreign` to the node, answers the owner call `get_status` from the node's public `/v1/status`, and limits and counts the requests |
| `miner` | `miner/`, a RandomX miner on the node's foreign API. Starts only while blocks are needed |
| `mongodb`, `epicbox` | The relay, run locally with domain `localhost` on `127.0.0.1:33423`, plain `ws://` |
| `funder` | `epic-wallet` serving its foreign API on `127.0.0.1:33415`. The miner takes every coinbase from it |
| `peer` | `epic-wallet`, the counterparty |
| `lepic` | `lepic --network floonet`, driven with `docker compose exec` |

Every service runs in the host's network namespace and listens on `127.0.0.1` only. `lepic` uses
`LEPIC_TEST_NODE_URL` (default the proxy, `http://127.0.0.1:33413`) and `LEPIC_TEST_RELAY`
(default the local relay, `ws://localhost:33423`).

`epic-wallet` asks its node's owner API for `get_status` at start and keeps its listeners paused
until the answer says `no_sync`. A public node does not serve its owner API, so the proxy answers
that one call from the node's public status.

## Request rates

The proxy keeps the stack's load on the public node low. It sends at most 4 reads per second, and
one write (`push_transaction`, `submit_block` or `finalize_block_template`) every 2 seconds, for
`lepic`, both wallets and the miner together. It counts every request it sends upstream in
`.work/live/proxy/calls.json`, which survives proxy restarts.

- The miner leaves 2 seconds between its own requests.
- `run.sh` polls the wallets every 15 seconds (`LIVE_POLL_INTERVAL`). Its own foreign API reads
  (`get_tip`, `get_kernel`) are at least 5 seconds apart.
- The proxy, the miner and `run.sh` retry a 429 answer after a pause that starts at 10 seconds
  and doubles.
- The run ends with the total of public node calls, split between the proxy and `run.sh`, and
  the number of 429 answers.

## Funds and mining

The funder wallet needs coins before the wallets can be funded. There are two sources.

An outside floonet wallet pays it. `LEPIC_LIVE_FUNDER` names a command that sends with
`<command> <http-url> <amount>` and prints an `epic-wallet info` table with `<command> info`.
`run.sh` checks the outside wallet's spendable balance, pays the funder's foreign listener
(`http://127.0.0.1:33415`) what the top-ups need plus one EPIC, and mines until that payment has
one confirmation. Setting the variable to an empty value disables the command.

Mining is the other source. It is used with `--mine-funds`, with no command, or when the outside
wallet holds too little. The funder then mines its own coinbase, which matures after 30 blocks.

Floonet accepts RandomX blocks only, and the reward is 16 EPIC. The miner follows the node's
stratum flow through the foreign API:

1. `get_block_template` gives the next height, the mineable transactions, the next difficulty and
   the header fields the chain decides.
2. The funder's `build_coinbase` builds the reward output and kernel.
3. `finalize_block_template` returns the header with the roots for that body.
4. The miner sets the total difficulty to the previous total plus the next difficulty and validates
   the block locally with the node's own code before hashing.
5. A solution goes to `submit_block`, which validates the block in full.

The miner refuses foundation heights, whose block needs an output only a node can add. It pauses 10
seconds after each block. `LIVE_MINER_THREADS` sets the thread count (default 4).

The miner runs only when blocks are needed:

1. Funding. When `lepic` or the peer holds less than `LIVE_FUND_MINIMUM` spendable EPIC (default
   8), `run.sh` first makes sure the funder holds enough. It then sends `LIVE_FUND_OUTPUTS`
   slate files (default 3) of `LIVE_FUND_AMOUNT` EPIC each (default 5) to each short wallet, one
   at a time, until each is confirmed.
2. Each test transaction. The miner mines until both wallets show it confirmed, up to
   `LIVE_CONFIRM_TIMEOUT` seconds (default 1800).

## Persistent wallets

The wallets are bind mounts under `data/`, which git ignores, so funds carry over from run to
run. Stopping the stack with `run.sh --down`, or with `docker compose --profile mining down`
without `-v`, keeps them.

| Directory | Contents | Password |
|---|---|---|
| `data/funder` | `epic-wallet` floonet wallet in `.epic/floo` | `live-funder-password` |
| `data/peer` | `epic-wallet` floonet wallet in `.epic/floo`, the counterparty | `live-peer-password` |
| `data/lepic` | `lepic` floonet wallet in `lepic/` | `live-lepic-password` |
| `data/exchange` | slate files of every file transaction | |

These are throwaway floonet wallets whose coins have no value, so the passwords are in
`compose.yaml`. Recovery phrases are not printed. `run.sh` writes the compose variables to `.env`
in this directory, so after one run `docker compose` works here by hand:

```bash
cd interop/live
docker compose exec lepic lepic wallet info
docker compose exec peer ew info
```

Delete `data/` to start over with new wallets.

## Output

```text
Step                                   Result   Time  Kernel excess   Detail
floonet node                           PASS      ...  -               floonet node at height ...
wallets                                PASS      ...  -               ...
funding                                PASS      ...  -               ...
lepic sends to epic-wallet, file       PASS      ...  09...           slate ... confirmed on both sides, kernel in block ...
epic-wallet sends to lepic, file       PASS      ...  08...           ...
lepic sends to epic-wallet, epicbox    PASS      ...  09...           ...
epic-wallet sends to lepic, epicbox    PASS      ...  08...           ...

Public node calls: ... in total (... through the proxy for lepic, epic-wallet and the miner,
... by run.sh); the proxy got 0 answers of 429; run time ... Logs: ...
exit status: 0
```

A transaction passes when `lepic tx show` and `epic-wallet txs` both report it confirmed, the
total of `lepic` changed by exactly the amount (plus the fee when it sent), and the node reports
the kernel `epic-wallet` recorded in a block. The exit status is the last line of every run.

Each run writes `.work/live/logs/<time>/` under `interop/`:

| File | Content |
|---|---|
| `run.log` | every command's stderr |
| `compose.log` | the logs of every container; the proxy logs each forwarded call |
| `proxy-calls.json` | the proxy's cumulative counters by method |
| `public-calls.log` | the requests `run.sh` sent itself |
