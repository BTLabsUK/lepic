# Live floonet smoke test

## TL;DR

`run.sh` sends EPIC between `lepic` and `epic-wallet` `v4.0.2` on the public floonet chain, both ways
over slate files and both ways over a local Epicbox relay, waits for each transaction to confirm and
prints a table with every kernel excess. It runs only with `LEPIC_LIVE_TESTS=1` and never in CI.

```
LEPIC_LIVE_TESTS=1 interop/live/run.sh            # build, start or reuse the stack, sync, fund, test
LEPIC_LIVE_TESTS=1 interop/live/run.sh --no-build # reuse the images and binaries already built
LEPIC_LIVE_TESTS=1 interop/live/run.sh --down     # stop the stack afterwards
```

The stack stays up after a run unless `--down` is given, so the node keeps its connection to the
seed instead of re-dialling it every run.

Needs what `../run.sh` needs (Docker with Compose, `git`, `jq`, `bash`) plus outbound TCP to the
floonet seed on port 13414 and HTTPS to the public floonet API.

## What runs

| Service | What it is |
|---|---|
| `node` | `epic` `v4.0.4` on floonet, `only_randomx`, peered only with the seed, stratum on 127.0.0.1:13416 |
| `miner` | `miner/`, a multi-threaded RandomX stratum client; started only while blocks are needed |
| `mongodb`, `epicbox` | The public relay code, run locally with domain `localhost`, port 3423, plain `ws://` |
| `funder` | `epic-wallet` serving its foreign API on 13415; the node pays every coinbase to it |
| `peer` | `epic-wallet`, the counterparty |
| `lepic` | `lepic --network floonet`, driven with `docker compose exec` and `--output json` |

Only the node joins a Docker network with a route out, and it connects only to the seed. Every other
service shares the node's network namespace and reaches the others on 127.0.0.1. No port is
published on the host.

The node accepts seeds only as `IP:port`, so `run.sh` resolves `floo-node.btlabs.uk` (override with
`LIVE_SEED_HOST`, or set `LIVE_SEED=IP:port`). Public reads go to `https://floo-node.btlabs.uk`
(`LIVE_PUBLIC_API`): the tip, to know when the local node has synced, and each kernel, to check that
it is on the public chain at the height the local node reports. They are GET requests at least ten
seconds apart, logged with a count at the end of the run. Pushes, mining and everything else use the
local node.

`lepic` talks to `LEPIC_TEST_NODE_URL` (default the local node, `http://127.0.0.1:13413`) and
`LEPIC_TEST_RELAY` (default the local relay, `ws://localhost:3423`). Both must accept writes: the
public floonet API is read-only.

## Funds and mining

Floonet blocks are RandomX only, the reward is 16 EPIC and coinbase matures after 30 blocks. The miner
runs only while it is needed and stops as soon as the condition holds:

1. Funding, when `lepic` or the peer holds less than `LIVE_FUND_MINIMUM` (8) spendable EPIC: mine
   until the funder has enough mature coinbase, send `LIVE_FUND_OUTPUTS` (3) slate files of
   `LIVE_FUND_AMOUNT` (5) EPIC to each wallet that is short, one at a time, until each is confirmed.
2. Each test transaction: mine until both wallets show it confirmed.

The miner submits through the local node, which validates every block before relaying it, so only
valid blocks reach floonet. `LIVE_MINER_THREADS` (4) sets the thread count; each thread needs about
256 MB.

## Persistent wallets

Wallets and the node's chain are bind mounts under `data/`, which git ignores, so funds carry over
from run to run and later tasks can reuse them. Stopping the stack (`run.sh --down`, or
`docker compose --profile mining down` without `-v`) keeps them.

| Directory | Contents | Unlock |
|---|---|---|
| `data/node` | floonet chain, `epic-server.toml`, API secrets (`.api_secret`, `.foreign_api_secret`) | |
| `data/funder` | `epic-wallet` floonet wallet in `.epic/floo`, coinbase recipient | password `live-funder-password` |
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

Delete `data/` to start over with new wallets; the node then resyncs and funding mines again.

## Output

```
Step                                   Result   Time  Kernel excess   Detail
sync with floonet                      PASS      ...  -               local node synced at height ...
wallets                                PASS      ...  -               ...
funding                                PASS      ...  -               ...
lepic sends to epic-wallet, file       PASS      ...  09...           slate ... confirmed on both sides, kernel at height ...
epic-wallet sends to lepic, file       PASS      ...  08...           ...
lepic sends to epic-wallet, epicbox    PASS      ...  09...           ...
epic-wallet sends to lepic, epicbox    PASS      ...  08...           ...
```

Each transaction passes when `lepic tx show` and `epic-wallet txs` both report it confirmed, `lepic`'s
total changed by exactly the amount (and its fee when it sent), and the kernel `epic-wallet` recorded
is on the local chain and on the public floonet node at the same height. Logs are in
`../.work/live/logs/<time>/`: `run.log` with every command's stderr, `compose.log` with the containers'
logs, `public-calls.log` with every public request.
