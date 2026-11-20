# CLI acceptance

`run.sh` installs `lepic` with `cargo xtask install` and drives the installed binary through the
commands a user runs from a shell. It runs against the local stack of [interop/](../README.md):
the Epicbox relay, the reference node on a test-mode chain and two `epic-wallet` wallets. It
prints a table of steps and exits 0 only when every step passed.

```bash
interop/acceptance/run.sh               # build, install, start a clean stack, run, tear down
interop/acceptance/run.sh --no-build    # reuse the built binaries and the installed lepic
interop/acceptance/run.sh --keep        # leave the stack running afterwards
interop/acceptance/run.sh --lepic PATH  # test another lepic binary
interop/acceptance/run.sh --stack-only  # start a clean stack and keep it until Ctrl-C
interop/acceptance/run.sh --probes      # probe the relay and a stock listener instead
interop/acceptance/run.sh --trust       # run the stock-queue checks instead
```

The checks need what [the interop README](../README.md#requirements) lists, plus a Rust toolchain
for `cargo xtask install`.

## What a run does

Every run starts from nothing: a new chain, new wallets, and a `lepic` home, config file and data
directory under `.work/state`. `lepic` runs with a cleared environment (`env -i`) apart from
`PATH`, that home and that config file, so nothing from the invoking shell or `~/.lepic` leaks in.
The chain is usernet, where `epic-wallet` derives mainnet Epicbox addresses, so the config file
says `network = mainnet`. `epic-wallet` prints its address without the relay port, and the steps
add `:3423`.

`run.sh` starts the stack, funds the wallets in a setup step and runs the steps in `steps.sh`
in order. The steps cover:

- both directions over Epicbox and over slate files, and invoices both ways;
- a failed delivery and `tx resend`, `tx cancel`, `tx list`, `tx show` and `tx post`;
- `wallet restore`, a restore with `--no-scan` followed by `wallet scan`, and `wallet import-seed`
  of an `epic-wallet` `wallet.seed`;
- the exit codes of common mistakes: a wrong password (4), a bad address (2), an overspend (8), no
  wallet (5) and no node (9);
- an `epic-wallet` payment to a `lepic` listing address, drained and answered from the listing;
- a second `lepic` wallet funded by file, paired by invite, with an invoice through the contact
  mailboxes, and `lepic serve` answering a contact check;
- no CLI limits: a two-letter password makes a wallet and a 72-hour invoice expiry is taken. Only
  an empty password (exit code 7) and an expiry of 0 hours (exit code 3) are refused;
- the EPICTX steps in `native.sh`, between two `lepic` wallets: contact payments, `.epictx`
  files, in-person codes offline, the code TTL, `epic1` links and cancelling.

The stack sets `local_mailbox`, so its relay is the wallets' whole mailbox list. A payment to an
`epic1` link goes through it, and the step checks that the payment completes. A relay on a
non-loopback host is still needed for an in-person reply mailbox; that step checks that the code
from the local relay names no mailbox.

`ACCEPTANCE_ONLY=<function>[,...]` runs setup and only the listed steps, for developing one.
List `step_wallet_init`, `step_receive_by_file` and `step_fund_payer` first, because the later
steps need funds. A name that matches no step stops the run before it starts the stack.

Each run writes `.work/logs/<time>/`:

| File | Content |
|---|---|
| `results.txt` | the table, the `lepic` version and the git tree it ran from |
| `run.log` | every failed command and its JSON error |
| `compose.log` | the logs of every container |

### The saved funded chain

Mining to coinbase maturity and funding the peer wallet takes minutes and gives the same result
every run, so `run.sh` does it once per stack version. `fund_stack` in `steps.sh` mines and funds;
`snapshot.sh` then stops the stack, saves the `node-data`, `funder-data` and `peer-data` volumes
as gzipped tar files in `~/.cache/lepic-build/snapshots/acceptance-<key>/` and records the chain
height in `meta.json`. The run then removes that stack and starts the usual fresh one, restoring
the saved volumes into its empty ones, so the first run of a version is hermetic as well. The relay's
MongoDB, the lepic state and the exchange folder are never saved.

The key is a hash of the binaries `epic`, `epic-wallet` and `miner`, `pins.env`, the Dockerfile
of the runtime image, `docker/node.sh`, `wallet.sh` and `ew.sh`, `lib.sh`, `compose.yaml`,
`snapshot.sh` and the text of `fund_stack`. `lepic` is not in it. Changing any of those makes the
next run build a new snapshot; the newest 2 stay (`SNAPSHOT_KEEP`). The saved files are never
written to.

| Flag | Effect |
|---|---|
| `--from-genesis` | ignore the snapshot: mine and fund in this run, save nothing |
| `--rebuild-snapshot` | mine and fund, replace the saved chain, then run from it |

`--probes`, `--trust` and `--stack-only` always start from genesis.

## The stack

The stack is `compose.yaml` here, under the project name `lepic-acceptance`: the services of
[`../compose.yaml`](../compose.yaml) without the `lepic` container. Its services have no route
out and listen on loopback. Two TCP forwarders (`forward.js`, each listening on its own interface
addresses and never on a wildcard) carry the node API to `127.0.0.1:43413` (or the port
`ACCEPTANCE_NODE_PORT` names) and the relay to
`127.0.0.1:3423` on the host, and nothing else:

- `node-port` runs in the node's network namespace and exposes both ports on the internal network.
- `gateway` sits on the internal network and a host bridge, because Docker publishes ports only
  from a container on a non-internal network.

The relay keeps port 3423 because Epicbox addresses name it. `run.sh` refuses to start when either
host port is taken, and when the internal network has a route out. Slate files go through
`.work/exchange`, mounted into the wallets as `/exchange`. It has mode 1777 because the wallet
containers run as their own uid.

### Which relay

The default relay is the Epicmail mailbox, the software we ship, and the full step set runs on it.
`run.sh` builds its image with `../mux-relay-image.sh` from a checkout of the relay
(`ACCEPTANCE_MUX_RELAY_SRC`, else `LEPIC_MUX_RELAY_SRC`, else `~/.cache/wfe-lepic/mux-relay/src`, the
clone `tools/lepic.sh smoke` keeps) and merges `compose.mux.yaml`: that image runs as the `epicbox`
service and the stock relay's MongoDB does not start. An image built elsewhere goes in
`ACCEPTANCE_MUX_RELAY_IMAGE` with its config in `ACCEPTANCE_MUX_RELAY_CONFIG`. The config makes the
relay listen on `127.0.0.1:3423` with plain ws (it shares the node's network namespace, and the
forwarders carry the port out as before) and write the domain `localhost` and the port 3423 in
addresses. The image has `bash` (the health check, a TCP connect to port 3423, and the read of the
metrics page) and `sqlite3` (the read of the store).

The steps that look inside the relay go through one adapter in `steps.sh`, so each works on both
relays:

- `relay_messages_for <key>`: messages waiting in a queue;
- `relay_unmade_for <key>`: messages nobody acknowledged (Epicmail deletes a message when its
  recipient acknowledges it, so these are all the rows of the queue; the stock relay flags them);
- `relay_posts_total`: slates the relay has accepted (Epicmail: the `stored` posts on its metrics
  page; stock: the documents in its collection).

Epicmail's store is only read, never changed.

**The stock lane.** `run.sh --stock-relay` (`tools/lepic.sh smoke --stock-relay`) starts the stock
Node relay and MongoDB instead, and runs setup and the `STOCK_STEPS` of `steps.sh` only: node status,
wallet init, address and status, a slate file from epic-wallet, and lepic's payments by Epicbox with
the stock epic-wallet in both directions and to a listing. Public stock relays such as
epicbox.epiccash.com still carry that traffic, so the lane checks that our wallet keeps working with
them. Run it rarely. `--probes`, `--trust` and `--stack-only` test the stock relay itself and always
use it.

## Probes

`--probes` runs `probes.sh` instead of the steps. The probes check how the relay and a stock
listener behave:

- how the relay serves two addresses on its sessions;
- how one socket drains several mailboxes in turn;
- that a stock listener never acknowledges a payload that is not a slate, so the relay hands it
  out again.

The probe client is [`../probe`](../probe), built into `.work/probe-target`. The raw output of
each probe goes to `probes/` in the run's log directory. [docs/compat/epicbox.md](../../docs/compat/epicbox.md)
describes the relay behaviour the probes check.

## Trust checks

`--trust` runs `trust.sh` instead of the steps. It checks what `lepic` sends to a stock wallet's
payments address.

`lepic` pays the stock wallet, a probe posts a slate to it while `lepic` finalizes, and `lepic`
pays it three more times while its listener is off. The step passes when:

- the stock wallet answered all four payments and the probe's slate;
- its log shows no `Unable to parse slate`;
- nothing for it is left unacknowledged on the relay.

A last step reads the relay's log: every `ClientDetails` names `wallet_version` `4.1.0`. Pass
`--lepic` to run the same checks against another build.

## Using the stack from outside

`--stack-only` funds nothing and runs no step. It prints the node URL, the node API secret file,
the relay and the exchange directory, then holds the stack and its lock until stopped. Use it for
a `lepic` outside this script, such as the tests of the Flutter binding
([BTLabsUK/lepic-flutter](https://github.com/BTLabsUK/lepic-flutter)).

`chain.sh` drives that stack:

| Command | Effect |
|---|---|
| `chain.sh env` | prints the `LEPIC_INTEROP_*` settings as `KEY=value` lines |
| `chain.sh height` | prints the node's tip height |
| `chain.sh mine <blocks>` | waits until the miner has added that many blocks |
| `chain.sh fund <address> <epic>` | the funder sends that amount over Epicbox; the receiving wallet drains or listens to answer |
| `chain.sh receive <file>` | the funder answers an S1 file in the exchange directory and writes `<file>.response` beside it |
