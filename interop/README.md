# Epicbox and file interop with real binaries

## TL;DR

`interop/run.sh` builds the public Epicbox relay, the reference node `v4.1.2`, `epic-wallet` `v4.1.0`
and `lepic`, starts them on a private Docker network with a local test-mode chain, funds both wallets,
runs every scenario below and prints a pass or fail table. It exits 0 only when every scenario
passed. The compose network is internal, with no route out, so nothing in the stack can reach a
public relay or node; `run.sh` refuses to run if it is not.

```
interop/run.sh            # build what changed, start a clean stack, run, tear it down
interop/run.sh --keep     # leave the stack running afterwards
interop/run.sh --no-build # reuse the binaries already in .work/bin
```

Every Docker stack runner (`run.sh`, `acceptance/run.sh`, `live/run.sh`) takes one host-wide lock, `~/.cache/lepic-docker-stack.lock`, before it starts a stack and holds it until teardown; a second runner prints `waiting for <holder>` and starts when the first ends.

Needs Docker with Compose 2.17 or later, `git`, `jq`, `bash` and `python3` (with its standard
`sqlite3` module, which the acceptance run uses). The first build compiles the node, the wallet
and the relay's checker from source and takes 20 to 30 minutes; later runs take about six minutes.
Builds use `CARGO_BUILD_JOBS` (default 4).

## What runs

| Service | What it is |
|---|---|
| `mongodb` | MongoDB 6.0 with the relay's own `mongo-init.js` |
| `epicbox` | The relay from `EpicCash/epic-epicbox-docker`, domain `localhost`, port 3423, plain `ws://` |
| `node` | `epic` `v4.1.2` on usernet: no peers, no seeds, RandomX blocks only, stratum on 23416 |
| `miner` | `miner/`, a stratum client that mines with the reference node's RandomX code |
| `funder` | `epic-wallet` serving its foreign API; the node pays every coinbase to it |
| `peer` | `epic-wallet`, the counterparty; the scenarios start and stop its Epicbox listener |
| `lepic` | `lepic`, driven with `docker compose exec` and `--output json` |

Only the node joins the internal compose network; every other service runs in the node's network
namespace and reaches the others on 127.0.0.1. lepic speaks plain HTTP and WebSocket only to a
loopback host, so the node is `http://127.0.0.1:23413` and the relay `ws://localhost:3423`, and every
Epicbox address in the stack ends in `@localhost:3423`. Every service listens on 127.0.0.1 only;
the relay's listen call is patched to loopback when its image is built.

Base images are pinned by digest in the Dockerfiles and `compose.yaml`, and every container runs
as a non-root user: the runtime and relay images set one, and MongoDB runs as its image's
`mongodb` user. `cargo xtask repo-lint` fails on an unpinned image, a root container or a
`0.0.0.0` bind anywhere under `interop/`. To move to a newer base image, replace its digest with
the one `docker buildx imagetools inspect <image>:<tag>` prints.

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

The node's owner API secret is generated on first start. The foreign API has no secret, as on a
node with the default configuration: `epic-wallet` `v4.1.0` sends its node secret to owner calls
only. `.foreign_api_secret` is a copy of the owner secret, kept under the path the scenarios use
and shared read-only with the wallets and `lepic`.

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
| lepic sends to epic-wallet by file | `lepic tx send --to-file --ttl-blocks`, `epic-wallet receive -i`, `lepic tx finalize` on the reply |
| epic-wallet sends to lepic by file | `epic-wallet send -m file`, `lepic tx receive`, `epic-wallet finalize -i` on the reply |
| lepic invoices epic-wallet by file | `lepic invoice issue --to-file`, `epic-wallet pay -i`, `lepic tx finalize` on the reply |
| epic-wallet invoices lepic by file | `epic-wallet invoice -d`, `lepic invoice pay --ttl-blocks`, `epic-wallet finalize -i` on the reply |
| lepic sends over http | `epic-wallet listen -m http -l 23500` on loopback; `lepic tx send --to http://127.0.0.1:23500` reports `posted` in one command |
| epic-wallet sends over http | `lepic http listen --port 23510`; `epic-wallet send -m http`; the listener's report counts one received payment |
| same S1 twice over http | one S1 posted twice to `lepic http listen`: identical S2, one transaction, report counts one received and one repeated |
| receiver cancels an unseen receipt | `epic-wallet` pays over Epicbox and does not finalize; `lepic tx cancel` succeeds and the amount leaves `wallet info`; `epic-wallet` then finalizes anyway, and once mined `lepic` confirms the transaction and the output comes back |
| receiver cancel of a posted receipt | with the miner paused, `epic-wallet` finalizes and posts; `lepic tx cancel` is refused with exit 7 as in the node's pool, then, after the block, as on chain; state and balance stay |
| spendable at minimum confirmations | with the miner paused and blocks mined one at a time, a receipt awaits confirmation below LEPIC's default minimum confirmations (6), a send that needs it exits 8 one block before, and it is spendable at exactly 6 |

`SCENARIO_FILTER='import epic-wallet history' ./run.sh` runs the last scenario alone (`history.sh`,
`history_compare.py`). It builds a history in a fresh `epic-wallet` wallet: receipts over Epicbox and
by file with messages, a send with fee and change, a cancelled send and a cancelled receipt, an
invoice each way, a second account and a send left unfinished. It copies the stopped wallet's folder
and records `epic-wallet`'s own `export_tx`, `info` and `outputs`, then imports the copy into two
`lepic` wallets (history before the scan, and scan before the history) and compares every
transaction, the account labels and the balances. A second `import-history` must report
`already-imported` and change nothing, the copy's file hashes must not change, and the folders of
two other wallets must report `other-wallet` and store nothing. The report with both tables goes to
`.work/history/<time>/report.md`.

`lepic` writes every slate file in the V3 shape with header `3/3/<b>` (ADR 0015), while `epic-wallet`
writes V2 unless the slate carries a TTL or payment proof. Each file scenario checks that the file
`lepic` wrote is V3 at 3/3, with the TTL where one was asked for, and that a reply keeps the block
header version of the file it answers. `epic-wallet pay` asks for the invoice amount on a terminal
prompt, so the scenario runs it under `script` and types the amount in. Setup also funds `lepic` by
file, so `epic-wallet finalize` reads a `lepic` V3 reply there too.

Redeliveries are injected into the relay's MongoDB queue under a new message id, so `lepic` can only
recognise them by slate id and stage. Every copy, including an S2 whose transaction is already
confirmed, must count as repeated.

`lepic http listen` holds the wallet open, so the scenarios stop it (as Ctrl-C does) before they
run other `lepic` commands; those exit 5 ("in use") while it runs. `SCENARIO_FILTER=<regex> ./run.sh
--no-build` runs only the scenarios whose names match; setup always runs.

## When a run fails

The table names the scenario and the failed check. `.work/logs/<time>/run.log` has every command's
stderr and failure status, and `compose.log` the logs of every container. `run.sh --keep` leaves the
stack up for inspection; `docker compose down -v` in this directory removes it.

Not in scope: public relays and nodes, which task V-03 covers.
