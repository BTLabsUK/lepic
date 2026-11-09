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
- `lepic` sending to that wallet over Epicbox while it listens: both slates carry the LEPIC
  marker and the listener reports the payment as posted by its sender before it confirms;
- a stock `epic-wallet` listener that sends back an Epicbox invoice unpaid: `lepic` counts it as
  bounced and sends that peer no notice;
- no CLI limits: a two-letter password makes a wallet and a 72-hour invoice expiry is taken. Only
  an empty password (exit code 7) and an expiry of 0 hours (exit code 3) are refused;
- the EPICTX steps in `native.sh`, between two `lepic` wallets with native slates on: Epicbox
  payments, contact payments, `.epictx` files, in-person codes offline, the code TTL, `epic1`
  links, cancelling, and the direct HTTP endpoint.

Details of the EPICTX steps:

- Every LEPIC contact claims native slates, so the sender's `native_direct` switch drives the V3
  case between the two wallets.
- The product accepts a private address for a direct send but refuses loopback. The HTTP step
  reaches its listener through a small forwarder on the docker0 address `172.17.0.1`, never on a
  wildcard.
- A relay on a non-loopback host is needed for an in-person reply mailbox and for an `epic1` link,
  and the product allows plain websocket only to loopback. Those two steps check what the local
  relay gives: a code with no mailbox, and an `epic1` link refused with exit code 7.

`ACCEPTANCE_ONLY=<function>[,...]` runs setup and only the listed steps, for developing one.
List `step_wallet_init`, `step_receive_by_file` and `step_fund_payer` first, because the later
steps need funds. A name that matches no step stops the run before it starts the stack.

Each run writes `.work/logs/<time>/`:

| File | Content |
|---|---|
| `results.txt` | the table, the `lepic` version and the git tree it ran from |
| `run.log` | every failed command and its JSON error |
| `compose.log` | the logs of every container |

## The stack

The stack is `compose.yaml` here, under the project name `lepic-acceptance`: the services of
[`../compose.yaml`](../compose.yaml) without the `lepic` container. Its services have no route
out and listen on loopback. Two TCP forwarders (`forward.js`, each listening on its own interface
addresses and never on a wildcard) carry the node API to `127.0.0.1:43413` and the relay to
`127.0.0.1:3423` on the host, and nothing else:

- `node-port` runs in the node's network namespace and exposes both ports on the internal network.
- `gateway` sits on the internal network and a host bridge, because Docker publishes ports only
  from a container on a non-internal network.

The relay keeps port 3423 because Epicbox addresses name it. `run.sh` refuses to start when either
host port is taken, and when the internal network has a route out. Slate files go through
`.work/exchange`, mounted into the wallets as `/exchange`. It has mode 1777 because the wallet
containers run as their own uid.

## Probes

`--probes` runs `probes.sh` instead of the steps. The probes check what invoices and notices over
Epicbox build on:

- how a stock listener treats a V3 I1, a marker key and a payload that is not a slate;
- how the relay serves two addresses, and how one socket drains mailboxes in turn;
- how `lepic`'s Epicbox policy reads a marked V3 invoice;
- that no pairing request goes to an unproven or stale key.

The probe client is [`../probe`](../probe), built into `.work/probe-target`. The raw output of
each probe goes to `probes/` in the run's log directory. [docs/compat/epicbox.md](../../docs/compat/epicbox.md)
describes the relay behaviour the probes check.

## Trust checks

`--trust` runs `trust.sh` instead of the steps. It checks what `lepic` sends to a stock wallet's
payments address once another install on that wallet's recovery phrase ran LEPIC, against
[ADR 0016](../../docs/adr/0016-epicbox-notices.md).

A `lepic` "twin", imported from the stock wallet's `wallet.seed`, pays `lepic` with the marker, so
`lepic` sees that key run LEPIC. Then `lepic` pays the stock wallet, a probe posts a slate to it
while `lepic` finalizes, and `lepic` pays it three more times while its listener is off. The step
passes when:

- the stock wallet answered all four payments and the probe's slate;
- its log shows no `Unable to parse slate`;
- nothing for it is left unacknowledged on the relay;
- `lepic epicbox peer` shows the key as another wallet's again.

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
