# The lepic command-line wallet

## TL;DR

`lepic` is a light Epic Cash wallet for the terminal. It keeps keys and history on your machine,
asks an Epic node for chain data, and exchanges transactions with other wallets, `epic-wallet`
included, through slate files or an Epicbox relay. It does not mine or store the chain.

```
cargo xtask install                   # build and install to ~/.local/bin/lepic
lepic --network floonet wallet init   # create a test wallet, write down the phrase
lepic --network floonet wallet info   # balances, from the node at 127.0.0.1:13413
```

Status: pre-alpha. Use floonet. Do not put real funds in it.

## Install

You need Rust (the repository pins the version in `rust-toolchain.toml`; `rustup` installs it on
first use) and a C compiler. From the repository root:

```
cargo xtask install
```

This builds the release binary from `Cargo.lock` and installs it as `~/.local/bin/lepic`. Give
`--dir <directory>` to install elsewhere. If the directory is not on your `PATH`, the command says
so; add it, for example with `export PATH="$HOME/.local/bin:$PATH"` in your shell profile. Check
the result with `lepic --version`. Run the same command again to upgrade; a running `lepic` keeps
working while the file is replaced.

## Before the first wallet: network, node and relay

Every command runs on one chain, chosen with `--network mainnet` (the default) or
`--network floonet`. A wallet belongs to one chain, and a command refuses a wallet of the other.

`lepic` reads chain data from an Epic node's foreign API. It does not ship one. By default it asks
`http://127.0.0.1:3413` on mainnet and `http://127.0.0.1:13413` on floonet, the ports an `epic`
node uses. A node that protects its foreign API with a secret keeps it in `.foreign_api_secret`
next to its config, for example `~/.epic/floo/.foreign_api_secret` for a floonet node; point
`node_api_secret_file` at that file. `lepic node status` shows what the node reports:

```
$ lepic --network floonet node status
Node     127.0.0.1 (version 4.0.4)
Height   1052
Block    cb68c9daf1289d121b49e5e9d32e1a00b4c38763ec813f0384460a895575e11a
Header   version 6
```

The node should be synced. A node that is behind shows old balances, and `wallet info` says so.

For Epicbox, `lepic` uses the relay `wss://epicbox.epiccash.com` unless you set another.

### Settings

Each setting comes from, in order: a flag, its environment variable, the config file, the default.

| Config key | Variable | Flag | Default |
|---|---|---|---|
| `network` | `LEPIC_NETWORK` | `--network` | `mainnet` |
| `data_dir` | `LEPIC_DATA_DIR` | `--data-dir` | `~/.lepic/<network>` |
| `node_url` | `LEPIC_NODE_URL` | | `http://127.0.0.1:3413`, floonet `:13413` |
| `node_api_secret_file` | `LEPIC_NODE_API_SECRET_FILE` | | none |
| `epicbox_relay` | `LEPIC_EPICBOX_RELAY` | | `wss://epicbox.epiccash.com` |
| `output` | `LEPIC_OUTPUT` | `--output` | `human` |
| `log_level` | `LEPIC_LOG_LEVEL` | `--log-level` | `warn` |
| `log_format` | `LEPIC_LOG_FORMAT` | `--log-format` | `compact` |

The config file is `~/.lepic/config.toml` when it exists, or the file `--config` or `LEPIC_CONFIG`
names. It holds `key = value` lines; values are bare words or double-quoted strings, `#` starts a
comment, and an unknown or repeated key is an error, so a typo never falls back to a default
silently. Relative paths in it are relative to the file's directory. A floonet setup:

```
# ~/.lepic/config.toml
network = floonet
node_url = "http://127.0.0.1:13413"
node_api_secret_file = "/home/me/.epic/floo/.foreign_api_secret"
epicbox_relay = "wss://epicbox.epiccash.com"
```

Without a node of your own, point `node_url` at any floonet node whose foreign API is served
over `https://`, and leave `node_api_secret_file` out unless that node asks for one.

`node_url` is the API root, without `/v2/foreign`. Plain `http://` and `ws://` are accepted only
for a loopback host, because the node secret and the relay traffic would otherwise cross the
network in the clear; use `https://` and `wss://` for anything else. An `epicbox_relay` without a
scheme means `wss://`.

## Passwords and the recovery phrase

Secrets are never taken from arguments, which other users can see in the process list and your
shell keeps in its history. A command that opens the wallet reads the password from
`LEPIC_PASSWORD` if it is set, else from a hidden prompt, else from one line of standard input. A
new password is asked for twice at a prompt. `LEPIC_PASSWORD` is meant for scripts; while a
command runs, other processes of the same user can read it.

The recovery phrase is shown once, by `wallet init`. Write it down. It is the only way to get the
funds back if the data directory is lost, and anyone who has it can spend them.

## Create a wallet

```
$ lepic --network floonet wallet init
Wallet password:
Repeat the wallet password:
Wallet created on floonet in /home/me/.lepic/floonet.
Write down the recovery phrase. It is not shown again:

    elite over era wagon open excite favorite over convince ...

To receive, give the sender the address `lepic wallet address` prints, or
answer their slate file with `lepic tx receive <FILE>`.
```

`--words 12|15|18|21|24` picks the phrase length (24 by default). The examples below assume
`network = floonet` is in the config file; otherwise add `--network floonet` to each command.

`wallet info` refreshes from the node and shows each account:

```
$ lepic wallet info
Network floonet, chain height 1052.

Account default (0)
  Total                  0.00000000
  Spendable              0.00000000
  Awaiting confirmation  0.00000000
  Awaiting finalization  0.00000000
  Immature               0.00000000
  Locked                 0.00000000
```

Awaiting confirmation is received but not yet buried under `--min-confirmations` blocks (10 by
default); awaiting finalization is a receive the sender has not posted yet; locked is spent by a
transaction that is not confirmed yet, change included.

## Restore

From the recovery phrase:

```
lepic wallet restore
```

It asks for the phrase, then a new password, creates the wallet and scans the chain for its
outputs, printing progress on stderr. From an `epic-wallet` `wallet.seed` file and its password:

```
lepic wallet import-seed ~/.epic/floo/wallet_data/wallet.seed
```

Both refuse a data directory that already holds a wallet; give `--data-dir` for a new one. Ctrl-C
stops the scan and keeps what it found. `--no-scan` skips the scan, for a wallet you know is
empty. The history is not restored: each output found appears in `tx list` as one confirmed
incoming transaction with no slate.

## How a transaction travels

A payment is a slate that goes from sender to receiver and back: the sender writes S1, the
receiver answers with S2, and the sender finalizes S3 and posts it to the node. An invoice runs
the other way: the receiver issues I1, the payer answers with I2, the issuer finalizes. `lepic`
moves slates in one of two ways:

- Slate files, which you carry to the other party yourself. `lepic` writes V3 slate JSON and reads
  V2 and V3, so `epic-wallet` `v4.0.2` reads its files and it reads `epic-wallet`'s.
- An Epicbox relay, which holds encrypted slates for an address until its wallet fetches them.
  Over Epicbox `lepic` sends V2 slates, as `epic-wallet` does.

## Receive and send with slate files

Receive. The sender gives you a file; you answer it and give back the `.response` file:

```
$ lepic tx receive payment.slate
Transaction 1 receives 20.00000000 EPIC. Return payment.slate.response to the sender.
Slate c3160940-aa63-461b-963b-3cda6d320cf9.
```

`--reply-file <FILE>` writes the answer elsewhere. The amount shows under awaiting finalization
until the sender posts, then under awaiting confirmation until it is mined.

Send. Write S1 to a file, give it to the receiver, and finalize their answer:

```
$ lepic tx send 1.5 --to-file pay-alice.slate -m "for lunch"
Transaction 3 sent 1.50000000 EPIC (fee 0.00800000) by file to pay-alice.slate.
Slate d4217e26-f23c-46f0-9944-84b406dd16a6.
$ lepic tx finalize pay-alice.slate.response
Transaction 3 finalized and posted.
Slate d4217e26-f23c-46f0-9944-84b406dd16a6.
```

The inputs stay locked from the send until the transaction confirms or is cancelled. Options:
`--min-confirmations` (10), `--selection all|smallest` (`all`, as `epic-wallet`, spends every
eligible output and so locks all of them until it confirms; `smallest` spends as few as cover the
amount), `--change-outputs`, `--ttl-blocks` (the receiver must refuse the slate after that many
blocks), `-a <account>`, `--fluff` on finalize to skip the stem phase.

## Epicbox

Your address names your key and the relay:

```
$ lepic wallet address
esZ6qDQ1mQ98sYP1k3APEdzfw4NK7LEtwPqyAscN2sH3zKurRXGM@epicbox.epiccash.com
```

When the relay listens on a port other than 443, the address ends in `:<port>`, and a sender must
include it. `epic-wallet` leaves the port out of the address it prints, so add it when you copy
an `epic-wallet` address on such a relay.

Send to an address:

```
lepic tx send 1.5 --to <address>
```

The receiving wallet answers when it next connects. Your wallet picks the answer up and finalizes
it the next time it connects, with either of:

- `lepic epicbox drain` handles everything waiting on the relay once and exits. It prints what it
  did: `Received 0, finalized 1, repeated 0, rejected 0, held for retry 0.`
- `lepic epicbox listen` stays connected, answers incoming payments and finalizes answers as they
  arrive, printing each change on stderr, until Ctrl-C. Then it prints the same summary.

Receiving over Epicbox needs no command beyond these two: the sender's S1 waits on the relay
until you drain or listen. `epic-wallet` on the other side handles your answer only while it
runs `epic-wallet listen -m epicbox`, so a payment from it is finalized once that listener is
up; until then your side shows the transaction as `received`. `epicbox status` shows the relay, your address and how many of your
slates the relay has not taken yet.

If a send stores the transaction but the relay does not take the slate, `lepic` exits with code
11 and the inputs stay locked. Deliver the same slate again, to the same address or another way,
or give up:

```
lepic tx resend 3 --to <address>
lepic tx resend 3 --to-file pay-alice.slate
lepic tx cancel 3
```

## Invoices

Ask for a payment:

```
$ lepic invoice issue 0.8 --to-file invoice.slate
Transaction 5 asks for 0.80000000 EPIC. Give invoice.slate to the payer.
```

The payer answers it; then finalize their answer with `lepic tx finalize invoice.slate.response`.
To pay an invoice, type the amount it asks for again, so a changed file cannot charge you more:

```
lepic invoice pay invoice.slate 0.8
```

It writes `invoice.slate.response` for the issuer, and takes the spending options of `tx send`.
Invoices travel by file only.

## Transactions

```
$ lepic tx list
   ID  DIR       STATE                   AMOUNT          FEE  TRANSPORT  CREATED (UTC)
    1  incoming  confirmed          20.00000000            -  file       2026-10-03 11:24:52
    3  outgoing  posted             -1.50000000   0.00800000  epicbox    2026-10-03 11:28:32
```

States: `sent` (S1 or I2 handed over), `received` (S2 or I1 answered, waiting for the other side),
`finalized`, `posted` (with the node), `confirmed` (in a block), `cancelled`, `expired`.
`lepic tx show <ID>` adds the slate id, timestamps and the slate stages stored.

`lepic tx cancel <ID>` gives up a transaction that is not posted and unlocks its inputs.
`lepic tx post <ID>` sends a finalized transaction to the node again, for one the node dropped; a
node refuses a transaction it already holds.

## Data and logs

The data directory, `~/.lepic/<network>` unless `data_dir` says otherwise, holds:

- `wallet.vault`, the seed, encrypted with your password through Argon2;
- `wallet.sqlite3`, outputs and transaction history, with private transaction data encrypted;
- `.lepic.lock`, which keeps two `lepic` commands, or `lepic` and a mobile app, from opening the
  wallet at once.

The directory must be private to you (mode 700); `lepic` creates it that way and refuses one that
other users can enter. Back up the recovery phrase, not the directory: a copy of the directory is
as good as the phrase plus the password to whoever holds it.

Logs go to stderr, never to stdout, at level `warn` unless `--log-level` says otherwise
(`info`, `debug`, or tracing directives such as `lepic_epicbox=debug`). To keep them, redirect:
`lepic --log-level info epicbox listen 2>>lepic.log`. Logs never contain the password, the
phrase or keys; amounts and addresses appear only at `debug` and below.

## Scripts: JSON output and exit codes

`--output json` makes every command print exactly one JSON document on stdout, errors included:

```
$ lepic --output json tx send 1000 --to-file x.slate
{"error":{"kind":"insufficient_funds","exit_code":8,"message":"send failed","causes":["output selection failed: not enough funds"]}}
```

Amounts are strings with eight decimals. The exit code says what kind of failure it was:

| Code | Kind | Meaning |
|---|---|---|
| 0 | | success |
| 1 | `internal` | an unexpected failure, see the log |
| 2 | `usage` | invalid arguments or missing input |
| 3 | `config` | invalid settings or config file |
| 4 | `wrong_password` | the password did not unlock the wallet |
| 5 | `wallet_state` | no wallet, a wallet already exists, it is in use, or it belongs to another network |
| 6 | `not_found` | no such transaction, slate or account |
| 7 | `rejected` | the slate or request was refused; nothing was stored |
| 8 | `insufficient_funds` | not enough spendable funds |
| 9 | `node` | the node could not be reached or answered badly |
| 10 | `transport` | the slate file or relay failed |
| 11 | `incomplete` | stored, but not delivered or not posted; retry |
| 12 | `interrupted` | stopped before it finished |

## Common errors

With human output, an error ends with a `hint:` line that names what to try next.

| You see | What it means |
|---|---|
| `no wallet exists`, hint `no floonet wallet in ...` | Wrong data directory or network, or no wallet yet: `wallet init` or `wallet restore`. |
| `wallet database belongs to a mainnet wallet, the configuration says floonet` | The data directory holds a wallet of the other chain; pass the matching `--network`. |
| `password did not unlock the wallet` | Wrong password, or `LEPIC_PASSWORD` is set to an old one. |
| `another lepic process is using the data directory` | A `lepic epicbox listen` or other command has the wallet open; stop it first. |
| `other users can access the data directory` | Run `chmod 700` on it. |
| `could not connect to the node` (exit 9) | The node is not running at `node_url`, or listens elsewhere. |
| `node rejected the api secret` | Set `node_api_secret_file` to the node's `.foreign_api_secret`. |
| `not enough funds` (exit 8) | The hint shows what is spendable. Recent receives and change need `--min-confirmations` blocks, and `--selection all` locks every output until its transaction confirms. |
| `epicbox address rejected` (exit 2) | The address is mistyped or belongs to the other network. Nothing was stored. |
| `stored but was not delivered` (exit 11) | The relay did not take the slate; check the address and its port, then `tx resend` or `tx cancel`. |
| `epicbox subscription failed` | The relay at `epicbox_relay` is unreachable. |
| `invoice amount differs from the approved amount` | The amount you typed is not the one in the invoice; nothing was paid. |
| `was already received as transaction N` | That slate was answered before; give the sender the existing `.response` file. |
| `finalized but the node did not accept it` (exit 11) | The node refused the transaction. If it was posted before, the node already holds it; watch `wallet info`. |
