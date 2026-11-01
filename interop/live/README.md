# Live floonet smoke test

## TL;DR

`run.sh` sends EPIC between `lepic` and `epic-wallet` `v4.0.2` on the public floonet chain, both ways
over slate files and both ways over a local Epicbox relay, waits for each transaction to confirm and
prints a table with every kernel excess. No node runs locally: the wallets use the public floonet
node's foreign API. An outside floonet wallet (`LEPIC_LIVE_FUNDER`, see below) pays the funder, and the
miner mines floonet blocks through that same API so transactions confirm. It runs
only with `LEPIC_LIVE_TESTS=1` and never in CI.

```
LEPIC_LIVE_TESTS=1 interop/live/run.sh            # build, start or reuse the stack, fund, test
LEPIC_LIVE_TESTS=1 interop/live/run.sh --no-build # reuse the images and binaries already built
LEPIC_LIVE_TESTS=1 interop/live/run.sh --down     # stop the stack afterwards
LEPIC_LIVE_TESTS=1 interop/live/run.sh --mine-funds  # fund by mining coinbase, not LEPIC_LIVE_FUNDER
```

Needs what `../run.sh` needs (Docker with Compose, `git`, `jq`, `bash`) and HTTPS to the floonet node,
`https://floo-node.btlabs.uk` by default (`LIVE_NODE_URL`).

## What runs

| Service | What it is |
|---|---|
| `nodeproxy` | `docker/node-proxy.py` on 127.0.0.1:33413: forwards `/v2/foreign` to the floonet node, answers owner `get_status` from the node's public `/v1/status`, limits and counts the requests |
| `miner` | `miner/`, a RandomX miner on the node's foreign mining API; started only while blocks are needed |
| `mongodb`, `epicbox` | The public relay code, run locally with domain `localhost` on 127.0.0.1:33423, plain `ws://` |
| `funder` | `epic-wallet` serving its foreign API on 127.0.0.1:33415; `LEPIC_LIVE_FUNDER` pays it there, and the miner gets every coinbase from it |
| `peer` | `epic-wallet`, the counterparty |
| `lepic` | `lepic --network floonet` through the proxy, driven with `docker compose exec` |

Every service runs in the host's network namespace and listens on 127.0.0.1 only.

`lepic` uses `LEPIC_TEST_NODE_URL` (default the proxy, `http://127.0.0.1:33413`) and
`LEPIC_TEST_RELAY` (default the local relay, `ws://localhost:33423`).

`epic-wallet` also reaches the node through `nodeproxy`. It asks its node's owner API for `get_status` at
start, and keeps its HTTP and Epicbox listeners paused until that says `no_sync`. A public node does
not serve its owner API, so the proxy answers that one call from the same node's public status.

## Request rates

The public node allows 20 reads and 2 writes per second. The proxy sends at most 4 reads per second
and one write (`push_transaction`, `finalize_block_template`, `submit_block`) every 2 seconds, for
`lepic`, both `epic-wallet` wallets and the miner, and counts every request it sends upstream in
`../.work/live/proxy/calls.json`, kept across restarts of the proxy. The miner leaves 2 seconds between its own requests. `run.sh`
polls wallets every 15 seconds (`LIVE_POLL_INTERVAL`) and spaces its own foreign API reads (`get_tip`, `get_kernel`) at
least 5 seconds apart. The run ends by printing one total of public node calls, the proxy's and its
own, and the number of 429 answers. The proxy, the miner and `run.sh`
retry a 429 answer
after a pause that doubles from 10 seconds.

## Funds and mining

The funder gets its coins from an outside floonet wallet, `LEPIC_LIVE_FUNDER`: a command that sends
with `<command> <http-url> <amount>` and prints an `epic-wallet info` table with `<command> info`.
When the variable is unset and `$HOME/epic/qa-funder/fund.sh` exists, that QA funder is used; set
it empty to mine instead. `run.sh` checks the wallet's spendable balance, pays the funder's foreign
listener (`http://127.0.0.1:33415`) what the top-ups need plus one EPIC, and mines only until that
payment has one confirmation. With `--mine-funds`, with no command, or when the wallet holds too
little, the funder mines its own coinbase instead, which takes 30 blocks to mature.

Floonet blocks are RandomX only, the reward is 16 EPIC and coinbase matures after 30 blocks. The miner
follows the reference node's own stratum flow, through the foreign API:

1. `get_block_template` gives the next height, the mineable transactions, the next difficulty and the
   chain-chosen header fields (RandomX seed, secondary scaling, policy, bottles).
2. The funder's `build_coinbase` builds the reward output and kernel, as it does for a node's stratum
   server.
3. `finalize_block_template` returns the header with the roots for that body.
4. The header takes the template's chain fields and a total difficulty of the previous total plus the
   next difficulty, as the stratum server sets it. The block is validated locally with the node's own
   code before hashing.
5. A solution goes to `submit_block`, which validates the block in full before it joins the chain.

The miner refuses foundation heights (every 1,440 blocks on floonet), whose block needs an output only
a node can add, and pauses 10 seconds after each block. `LIVE_MINER_THREADS` (4) sets the thread
count; each thread needs about 256 MB. It runs only while it is needed:

1. Funding, when `lepic` or the peer holds less than `LIVE_FUND_MINIMUM` (8) spendable EPIC: when the
   funder holds too little, get it paid by `LEPIC_LIVE_FUNDER` and mine until that confirms (or mine
   until it has enough mature coinbase), then send `LIVE_FUND_OUTPUTS` (3) slate files of
   `LIVE_FUND_AMOUNT` (5) EPIC to each wallet that is short, one at a time, until each is confirmed.
2. Each test transaction: mine until both wallets show it confirmed.

## Persistent wallets

Wallets are bind mounts under `data/`, which git ignores, so funds carry over from run to run and later
tasks can reuse them. Stopping the stack (`run.sh --down`, or `docker compose --profile mining down`
without `-v`) keeps them.

| Directory | Contents | Unlock |
|---|---|---|
| `data/funder` | `epic-wallet` floonet wallet in `.epic/floo`, paid by `LEPIC_LIVE_FUNDER` or coinbase recipient | password `live-funder-password` |
| `data/peer` | `epic-wallet` floonet wallet in `.epic/floo`, the counterparty | password `live-peer-password` |
| `data/lepic` | `lepic` floonet wallet in `lepic/` | password `live-lepic-password` |
| `data/exchange` | slate files of every file transaction, named by run | |

These are throwaway floonet wallets whose coins have no value; the passwords are in `compose.yaml` on
purpose. Recovery phrases are not printed. `run.sh` writes the compose variables to `.env` here, so
after one run `docker compose` works in this directory by hand. With the stack up:

```
cd interop/live
docker compose exec lepic lepic wallet info
docker compose exec peer ew info
```

Delete `data/` to start over with new wallets; funding then mines again.

## Output

```
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

Each transaction passes when `lepic tx show` and `epic-wallet txs` both report it confirmed, `lepic`'s
total changed by exactly the amount (and its fee when it sent), and the floonet node reports the
kernel `epic-wallet` recorded in a block. Logs are in `../.work/live/logs/<time>/`: `run.log` with every
command's stderr, `compose.log` with the containers' logs (the proxy logs each forwarded call),
`proxy-calls.json` with the proxy's cumulative counters by method,
`public-calls.log` with `run.sh`'s own requests.
