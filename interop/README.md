# Interop with real binaries

`interop/run.sh` builds the public Epicbox relay, the reference node, `epic-wallet` and `lepic`
from pinned sources. It starts them on a private Docker network with a local test-mode chain,
funds two wallets, runs every scenario below and prints a table of results. It exits 0 only when
every scenario passed.

```bash
interop/run.sh             # build what changed, start a clean stack, run, tear it down
interop/run.sh --keep      # leave the stack running afterwards
interop/run.sh --no-build  # reuse the binaries already in .work/bin
```

The compose network is internal and has no route out, so nothing in the stack can reach a public
relay or node. `run.sh` refuses to run if the network is not internal.

## Running tests fast

Three things are shared or saved, so a second run costs far less than the first.

- **One build per source state, for the whole machine.** `build.sh` keeps every binary in
  `~/.cache/lepic-build` (`LEPIC_BUILD_CACHE`), keyed by what it is built from: a pinned upstream
  binary by its commit and toolchain, `lepic` by the content of the files it compiles (so a commit
  that changes only docs or `interop/` rebuilds nothing). A new worktree copies the binaries into
  `.work/bin` and compiles only what its sources changed. The newest 3 entries per kind stay
  (`LEPIC_BUILD_KEEP`); `./build.sh --status` lists the cache and what this checkout uses, and
  `./build.sh --prune` cleans it. The same `tools/lepic.sh smoke` and `interop/run.sh` use it.
- **A funded chain.** The acceptance run mines the private chain to coinbase maturity and funds the
  peer wallet once per stack version, saves the node and wallet volumes under
  `~/.cache/lepic-build/snapshots`, and starts later runs from a copy. A run stays hermetic: it
  works on its own volumes. The snapshot is keyed by the pinned binaries and the scripts that
  configure the stack, so a changed image rebuilds it on the next run. `./run.sh --from-genesis`
  mines from a new chain; `./run.sh --rebuild-snapshot` replaces the saved one. `tools/lepic.sh
  smoke` passes both flags through. (`acceptance/README.md` has the details.)
- **Targeted runs.** `ACCEPTANCE_ONLY=step_wallet_init,step_address_and_status acceptance/run.sh
  --no-build --lepic .work/bin/lepic` runs setup and the listed steps only.

- **Which relay.** The acceptance stack runs the Epicmail mailbox, the one we ship, with the full
  step set; its image is built from `~/.cache/wfe-lepic/mux-relay/src` (`ACCEPTANCE_MUX_RELAY_SRC`).
  `--stock-relay` is an opt-in lane on the stock Node relay with only the Legacy Epicbox address and
  stock epic-wallet steps; run it rarely. `tools/lepic.sh smoke` takes the same flag.

- **The Mac.** `interop/on-mac.sh` copies a commit to the Mac over ssh, builds the arm64 stack
  binaries there (`build.sh --no-lepic`, the Mac's own cache), builds `lepic` natively and runs the
  acceptance stack: `interop/on-mac.sh`, or `interop/on-mac.sh -- --from-genesis`, or
  `interop/on-mac.sh --commit <ref> --sync-only` to only copy. `MAC_HOST` (required, an ssh
  target such as `user@mac.example`) and `MAC_DIR` name the target; the header of the script lists what the Mac needs. A second run reuses the Mac's cache,
  build directories and saved chain. The Mac cannot clone the relay's private repository, so the
  script copies its source from this machine and builds the image there for arm64; `--stock-relay`
  skips that.

The floonet suite (`e2e/`) fetches the pinned Tor bundle for `send.tor` into the same cache
(`e2e/fetch-tor.sh`, checked by SHA-256, no network when the tarball is cached).

## Requirements

- Docker with the Compose plugin, `git`, `jq`, `bash` and `python3` with its `sqlite3` module.
- `flock`, for the stack lock. Without it (macOS) a run prints a warning and starts without the lock;
  `build.sh` then locks with a directory (`portable.sh`).

`build.sh` compiles the node, the wallet, the legacy wallet and the relay's signature checker from source, then
`lepic` and the miner. Cargo uses `CARGO_BUILD_JOBS` jobs (default 4). Rerunning it is
incremental.

One host-wide lock, `~/.cache/lepic-docker-stack.lock` (or the path in `LEPIC_DOCKER_STACK_LOCK`),
allows one Docker stack at a time. `run.sh`, `acceptance/run.sh` and `live/run.sh` take it before
they start a stack and hold it until teardown. A second runner prints `waiting for <holder>` and
starts when the first ends.

## Pins

`pins.env` holds the pinned inputs: the repository and commit of the reference node
(`epic` v4.1.2), `epic-wallet` (v4.1.0), the legacy `epic-wallet` (v4.0.2) and the Epicbox relay (`EpicCash/epic-epicbox-docker`),
and the Rust toolchains. `REFERENCE_RUST` builds the upstream sources, `NODE_RUST` the node and
the miner, and `LEPIC_RUST` `lepic`.

Sources, the Cargo home, build directories, binaries and run logs live in `.work/`, which git
ignores. `build.sh` compiles in a container built from `docker/builder.Dockerfile`, with those
directories mounted, so build caches stay out of Docker's image store.

Base images are pinned by digest in the Dockerfiles and in `compose.yaml`, and every container
runs as a non-root user. `cargo xtask repo-lint` fails on an unpinned image, a root container or
a `0.0.0.0` bind under `interop/`. To move to a newer base image, replace its digest with the one
`docker buildx imagetools inspect <image>:<tag>` prints.

## Services

| Service | What it is |
|---|---|
| `mongodb` | MongoDB 6.0 with the relay's `mongo-init.js` |
| `epicbox` | The relay, domain `localhost`, port 3423, plain `ws://` |
| `node` | The reference node on usernet: no peers, no seeds, RandomX blocks only, stratum on 23416 |
| `miner` | `miner/`, a stratum client that mines with the reference node's RandomX code |
| `funder` | `epic-wallet` serving its foreign API; the node pays every coinbase to it |
| `peer` | `epic-wallet`, the counterparty. The scenarios start and stop its Epicbox listener |
| `lepic` | `lepic`, driven with `docker compose exec` and `--output json` |

Only `node` joins the internal network. Every other service runs in the node's network namespace
and reaches the others on `127.0.0.1`. `lepic` uses plain HTTP and WebSocket only for a loopback
host, so the node is `http://127.0.0.1:23413`, the relay is `ws://localhost:3423`, and every
Epicbox address in the stack ends in `@localhost:3423`. Every service listens on `127.0.0.1`. The
relay image patches the relay's listen call to loopback.

## The local chain

The node runs with `--usernet`.

- On usernet `epic-wallet` derives Epicbox addresses with the mainnet version bytes, because only
  floonet switches them. `lepic` runs with `LEPIC_NETWORK=mainnet`.
- The node's built-in test miner solves only Cuckatoo, and the chain's proof-of-work policy also
  asks for RandomX and ProgPoW blocks. The node therefore runs with `only_randomx = true` and its
  stratum server on. `miner/` asks the stratum server for jobs, hashes them with `epic_core`'s
  RandomX context and submits a block every couple of seconds.
- The node's owner API secret is generated on first start. The foreign API has no secret.
  `.foreign_api_secret` is a copy of the owner secret, kept under the path the scenarios use and
  shared read-only with the wallets and `lepic`.

## Funding by hand

`run.sh` funds both wallets in its setup step. To do it by hand, start the stack with `run.sh
--keep`, then run these in `interop/`. `ew` is `epic-wallet --usernet` with the container's test
password.

```bash
# 1. Wait until the funder has mature coinbase.
docker compose exec funder ew info
# 2. The funder sends to a slate file, the receiver answers it, the funder finalizes and posts.
docker compose exec funder ew send -m file -d /exchange/lepic.slate -c 1 -s smallest 20
docker compose exec lepic lepic tx receive /exchange/lepic.slate
docker compose exec funder ew finalize -i /exchange/lepic.slate.response
# The same for the peer wallet.
docker compose exec funder ew send -m file -d /exchange/peer.slate -c 1 -s smallest 20
docker compose exec peer ew receive -i /exchange/peer.slate
docker compose exec funder ew finalize -i /exchange/peer.slate.response
# 3. After enough blocks the funds are spendable.
docker compose exec lepic lepic wallet info
```

Send one funding transaction at a time and wait until it is mined before the next.

## Scenarios

Every scenario checks the transaction on both sides (`lepic tx show` and `epic-wallet txs`). It
also checks that `lepic`'s total equals what it was funded with plus everything received, minus
everything sent and the fees, so a lost or doubled effect fails the run.

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
| lepic sends over http | `epic-wallet listen -m http -l 23500`; `lepic tx send --to http://127.0.0.1:23500` reports `posted` in one command |
| epic-wallet sends over http | `lepic http listen --port 23510`; `epic-wallet send -m http`; the listener's report counts one received payment |
| epic-wallet sends over http to serve | `lepic serve --http --port 23510`; `epic-wallet send -m http`; the report counts one received payment under `http` |
| same S1 twice over http | one S1 posted twice to `lepic http listen`: identical S2, one transaction, one received and one repeated in the report |
| receiver cancels an unseen receipt | `epic-wallet` pays over Epicbox and does not finalize; `lepic tx cancel` succeeds and the amount leaves `wallet info`; `epic-wallet` then finalizes anyway, and once mined `lepic` confirms the transaction and the output comes back |
| receiver cancel of a posted receipt | with the miner paused, `epic-wallet` finalizes and posts; `lepic tx cancel` is refused with exit code 7, first with the transaction in the node's pool and again once it is on chain; state and balance stay |
| spendable at minimum confirmations | with the miner paused and blocks mined one at a time, a receipt waits for confirmations below the default minimum of 6; a send that needs it exits with code 8 one block before, and succeeds at exactly 6 |
| import epic-wallet history | see below |

Details that apply to several scenarios:

- A file scenario checks that the slate file `lepic` wrote is V3 with header `3/3/<b>`
  ([ADR 0015](../docs/adr/0015-file-method-writes-v3.md)), with the TTL where one was asked for, and
  that a reply keeps the block header version of the file it answers. Setup funds `lepic` by file,
  so `epic-wallet finalize` reads a `lepic` V3 reply there too.
- `epic-wallet pay` asks for the invoice amount on a terminal prompt, so the scenario runs it
  under `script` and types the amount.
- Redeliveries are injected into the relay's MongoDB queue under a new message id, so `lepic`
  can recognise them only by slate id and stage. Every copy, including an S2 whose transaction is
  already confirmed, must count as repeated.
- `lepic http listen` holds the wallet open. The scenarios stop it before they run other `lepic`
  commands, which exit with code 5 while it runs.

### History import

The last scenario (`history.sh`, `history_compare.py`) builds a history in a fresh `epic-wallet`
wallet: receipts over Epicbox and by file with messages, a send with fee and change, a cancelled
send and a cancelled receipt, an invoice each way, a second account and a send left unfinished.
It copies the stopped wallet's folder and records `epic-wallet`'s own `export_tx`, `info` and
`outputs`. It imports the copy into two `lepic` wallets, one importing the history before the
scan and one the scan before the history, and compares every transaction, the account labels and
the balances.

A second `wallet import-history` must report `already-imported` and change nothing. The copy's
file hashes must not change, and the folders of two other wallets must report `other-wallet` and
store nothing. The report with both tables goes to `.work/history/<time>/report.md`.

## Running a subset

`SCENARIO_FILTER` is an extended regular expression matched against the scenario names above.
Setup always runs.

```bash
SCENARIO_FILTER='import epic-wallet history' interop/run.sh --no-build
```

A filter that matches no name runs setup only and exits 0.

## Legacy wallet cases

Users still run the previous classic wallet, `epic-wallet` v4.0.2 (`EPIC_WALLET_LEGACY_TAG` in
`pins.env`). `build.sh` compiles it as `epic-wallet-legacy`, and `PEER_WALLET=legacy` makes it the
peer in place of v4.1.0. That run uses the `legacy` scenarios, which reuse the Epicbox and file
scenario functions: `lepic` sends to it and receives from it over Epicbox, and both directions
over slate files, for sends and for invoices. Setup and the funder stay on the pinned release.

```bash
PEER_WALLET=legacy interop/run.sh --no-build
```

`SCENARIO_FILTER` narrows the legacy run the same way. A normal run does not include these cases.

## The legacy gate

`gate.sh` is the gate for changes that touch what lepic sends to a classic wallet. It runs the
stock 4.x send and receive cases in both directions over Epicbox, HTTP and file:

```sh
./gate.sh             # build, then both passes, each on a fresh stack
./gate.sh --no-build  # reuse .work/bin and .work/capture-target
```

- Pass 1 runs nine scenarios against the pinned epic-wallet release: the two Epicbox cases, the
  four file cases and the three HTTP cases.
- Pass 2 runs the six legacy scenarios against the previous classic release. That release parses
  slates, Epicbox frames and hex fields more loosely than the pinned one (it skips the Epicbox
  challenge check and the participant data checks, and decodes hex without bounds), so the two
  releases can disagree about the same frame. It has no HTTP cases: the pinned release is the
  stricter HTTP client.
- The gate fails unless exactly `GATE_CASES` (15) cases ran and passed, and prints the count. It
  refuses `SCENARIO_FILTER` and `PEER_WALLET`. In `run.sh`, a filter that matches no scenario
  fails the run.
- Tor is a named gap, `TOR_GAP` (2 cases: stock sends over Tor, stock receives over Tor). The
  stack's network is internal and has no Tor network to reach; the gate does not open one.
- Every frame lepic writes is recorded: `INTEROP_CAPTURE=1` starts the `capture` service, which
  runs tcpdump on loopback for the relay port and both HTTP listener ports. `capture/frames.py`
  reassembles the streams and keeps the Epicbox client frames lepic sent, the HTTP bodies lepic
  sent or answered, and the slate files lepic wrote. `capture/` also holds `open-frames`, which
  opens the Epicbox messages lepic sent with the peer's key from its seed file.
- A frame with a `lepic` key is printed with the key's value and fails the gate: lepic writes no
  such key on the classic lane. Too few frames of a kind, or an Epicbox message that does not
  open, fails the gate as a broken capture.

## When a run fails

The table names the scenario and the failed check. `.work/logs/<time>/run.log` has every
command's stderr and failure status, and `compose.log` has the logs of every container.
`run.sh --keep` leaves the stack up for inspection. `docker compose down -v` in this directory
removes it.

## Related

- [acceptance/README.md](acceptance/README.md): the acceptance run on the same kind of stack.
- [live/README.md](live/README.md): runs against public services.
