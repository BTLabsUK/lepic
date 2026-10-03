# Epicbox interop with real binaries

## TL;DR

`interop/run.sh` builds the public Epicbox relay, the reference node `v4.0.4`, `epic-wallet` `v4.0.2`
and `lepic`, starts them on a private Docker network with a local test-mode chain, funds both wallets,
runs every scenario below and prints a pass or fail table. It exits 0 only when every scenario
passed. The compose network is internal, with no route out, so nothing in the stack can reach a
public relay or node; `run.sh` refuses to run if it is not.

```
interop/run.sh            # build what changed, start a clean stack, run, tear it down
interop/run.sh --keep     # leave the stack running afterwards
interop/run.sh --no-build # reuse the binaries already in .work/bin
```

Needs Docker with Compose 2.17 or later, `git`, `jq` and `bash`. The first build compiles the node,
the wallet and the relay's checker from source and takes 20 to 30 minutes; later runs take about six
minutes. Builds use `CARGO_BUILD_JOBS` (default 4).

## What runs

| Service | What it is |
|---|---|
| `mongodb` | MongoDB 6.0 with the relay's own `mongo-init.js` |
| `epicbox` | The relay from `EpicCash/epic-epicbox-docker`, domain `localhost`, port 3423, plain `ws://` |
| `node` | `epic` `v4.0.4` on usernet: no peers, no seeds, RandomX blocks only, stratum on 23416 |
| `miner` | `miner/`, a stratum client that mines with the reference node's RandomX code |
| `funder` | `epic-wallet` serving its foreign API; the node pays every coinbase to it |
| `peer` | `epic-wallet`, the counterparty; the scenarios start and stop its Epicbox listener |
| `lepic` | `lepic`, driven with `docker compose exec` and `--output json` |

Only the node joins the internal compose network; every other service runs in the node's network
namespace and reaches the others on 127.0.0.1. lepic speaks plain HTTP and WebSocket only to a
loopback host, so the node is `http://127.0.0.1:23413` and the relay `ws://localhost:3423`, and every
Epicbox address in the stack ends in `@localhost:3423`.

Pins live in `pins.env`. Sources, the Cargo home, build directories, binaries and run logs live in
`.work/`, which git ignores. `build.sh` compiles in a container from `docker/builder.Dockerfile` with
those directories mounted, so build caches never land in Docker's image store. The pinned upstream
binaries are compiled once and their build directories removed.

## The local chain

The node runs with `--usernet`. Two facts shape the setup:

- On usernet `epic-wallet` derives Epicbox addresses with the mainnet version bytes, because only
  floonet switches them. `lepic` therefore runs with `--network mainnet`. The mainnet parameters that
  differ from usernet do not matter here: `lepic` holds no coinbase outputs, so coinbase maturity never
  applies, and it writes block header version 6 into its slates where the usernet chain is already at
  version 7, which `epic-wallet` and the node accept.
- The node's built-in test miner solves only Cuckatoo, but the node's proof-of-work policy also asks
  for RandomX and ProgPoW blocks, which the test miner cannot produce, so the chain stalls. The node
  therefore runs with `only_randomx = true` and its stratum server enabled. `miner/` asks for jobs,
  hashes them with `epic_core`'s own RandomX context and submits blocks every couple of seconds.

The node's API secrets are generated on first start and shared read-only with the wallets and `lepic`.
`epic-wallet` sends its one node secret to both the owner and the foreign API, so both files hold the
same secret.

## Funding recipe

`run.sh` does this in its setup step. By hand, with the stack up (`run.sh --keep`, or
`docker compose up -d --wait` after `build.sh`):

```
cd interop
# 1. Wait until the funder has mature coinbase (three blocks on usernet).
docker compose exec funder ew info
# 2. The funder sends to a slate file; the receiver answers it; the funder finalizes and posts.
docker compose exec funder ew send -m file -d /exchange/lepic.slate -c 1 -s smallest 20
docker compose exec lepic lepic tx receive /exchange/lepic.slate
docker compose exec funder ew finalize -i /exchange/lepic.slate.response
# The same for the peer wallet:
docker compose exec funder ew send -m file -d /exchange/peer.slate -c 1 -s smallest 20
docker compose exec peer ew receive -i /exchange/peer.slate
docker compose exec funder ew finalize -i /exchange/peer.slate.response
# 3. Ten blocks later the funds are spendable.
docker compose exec lepic lepic wallet info
```

`ew` is `epic-wallet --usernet` with the container's test password. Send one funding transaction at a
time and wait until it is mined before the next.

## Scenarios

Every scenario checks the transaction on both sides (`lepic tx show` and `epic-wallet txs`) and that
`lepic`'s total equals what it was funded with plus everything received, minus everything sent and
the fees, so a lost or doubled effect fails the run.

| Scenario | What happens |
|---|---|
| lepic sends to epic-wallet | S1 over the relay, the listening `epic-wallet` answers, `lepic epicbox drain` finalizes and posts |
| epic-wallet sends to lepic | `epic-wallet send -m epicbox`, `lepic` drains and answers, `epic-wallet` finalizes and posts |
| relay restart mid-transaction | the relay restarts with S1 waiting in its database, and again with S2 waiting |
| lepic offline, then one drain | `epic-wallet` sends twice while `lepic` is not connected; one drain answers both |
| duplicates of open transactions | an S1 and an S2 already acknowledged are queued again under new relay message ids while their transactions are open; each counts as repeated |
| duplicates of settled slates | every message `lepic` acknowledged is queued again after all transactions confirmed; none may create, change or hold anything, and all must be acknowledged |

Redeliveries are injected into the relay's MongoDB queue under a new message id, so `lepic` can only
recognise them by slate id and stage. In the settled case `lepic` currently counts a copy of an S2
whose transaction is already confirmed as rejected instead of repeated; it has no effect and is
acknowledged. The scenario requires exactly that split: every S1 copy repeated, every S2 copy
rejected.

## When a run fails

The table names the scenario and the failed check. `.work/logs/<time>/run.log` has every command's
stderr and failure status, and `compose.log` the logs of every container. `run.sh --keep` leaves the
stack up for inspection; `docker compose down -v` in this directory removes it.

Not in scope: public relays and nodes, which task V-03 covers.
