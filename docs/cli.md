# The lepic command-line wallet

## TL;DR

`lepic` is a light Epic Cash wallet for the terminal. It keeps keys and history on your machine,
asks an Epic node for chain data, and exchanges transactions with other wallets, `epic-wallet`
included, through slate files, an Epicbox relay or straight over HTTP or Tor. It does not mine or
store the chain.

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
| `invoice_expiry_hours` | `LEPIC_INVOICE_EXPIRY_HOURS` | | `24`, at most `48` |

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
stops the scan and keeps what it found. `--no-scan` skips the scan; the wallet then refuses to
create outputs, so to receive or to send with change, until `lepic wallet scan` has scanned the
chain from genesis. The history is not restored: each output found appears in `tx list` as one
confirmed incoming transaction with no slate.

## Scan

`lepic wallet scan` looks for the wallet's outputs on chain, from a start height to the node's
tip, and brings the wallet in line with what it finds: outputs it did not know are restored with
a confirmed incoming transaction each, and outputs it took for spent that are still unspent are
revived.

```
$ lepic wallet scan
Scanned heights 952 to 1052: 1 outputs found, 0 restored, 0 revived.
```

Without options it starts 100 blocks before the end of the last completed scan, so outputs of a
short reorganisation are found again. It starts at genesis when no scan has completed, or when the
wallet was restored with `--no-scan` and has not scanned from genesis since. Progress goes to
stderr. Ctrl-C stops it and keeps what it found (exit 12); the next scan with the same options
continues where it stopped, and says `Continued an interrupted scan.`

- `--start-height <HEIGHT>` starts there instead; `0` scans the whole chain. A height above the
  node's tip is refused with exit 2. Only a scan from 0 ends the wait after a `--no-scan`
  restore.
- `--delete-unconfirmed` also repairs what unfinished transactions hold, as `epic-wallet scan
  --delete_unconfirmed` does: locked outputs found on chain are unlocked and unconfirmed outputs
  not found are deleted, and their transactions are cancelled. The report adds the outputs
  unlocked and deleted.
- `--reset-chain` forgets the chain heights the wallet stored and scans from genesis. Use it when
  `wallet info` says the node is behind the wallet although the node is synced: the wallet
  stored a height that this chain does not have, after a node reported a false tip or a test
  network was restarted. It cannot be combined with `--start-height`; with
  `--delete-unconfirmed` it runs the repair too.

The JSON document has `start_height`, `end_height`, `resumed`, `found`, `restored`, `revived`,
`unlocked` and `deleted`.

## How a transaction travels

A payment is a slate that goes from sender to receiver and back: the sender writes S1, the
receiver answers with S2, and the sender finalizes S3 and posts it to the node. An invoice runs
the other way: the receiver issues I1, the payer answers with I2, the issuer finalizes. `lepic`
moves slates in one of three ways:

- Slate files, which you carry to the other party yourself. `lepic` writes V3 slate JSON and reads
  V2 and V3, so `epic-wallet` `v4.0.2` reads its files and it reads `epic-wallet`'s.
- An Epicbox relay, which holds encrypted slates for an address until its wallet fetches them.
  Over Epicbox `lepic` sends payments as V2 slates, as `epic-wallet` does, and invoices as V3
  slates, which carry the payment's TTL.
- HTTP, straight to a wallet that listens for payments, which answers in the same exchange. Only
  payments travel this way, not invoices.
- Tor, the same exchange as HTTP with a wallet that listens at its onion address, through a
  `tor` the wallet runs for itself.

## Receive and send with slate files

Receive. The sender gives you a file; you answer it and give back the `.response` file:

```
$ lepic tx receive payment.slate
Transaction 1 receives 20.00000000 EPIC. Return payment.slate.response to the sender.
Slate c3160940-aa63-461b-963b-3cda6d320cf9.
```

`--reply-file <FILE>` writes the answer elsewhere. The amount shows under awaiting finalization
until the sender posts, then under awaiting confirmation until it is mined.

Receiving the same slate file again, for example after the reply file was lost, writes the reply
stored the first time again, byte for byte, and stores nothing new; the JSON report has
`"repeated": true`. `--message` and `--account` are ignored on a repeat, because the stored
reply already carries the first ones. A different slate that reuses the slate id is refused, and
so is the same slate once its transaction was cancelled or expired.

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
blocks), `-m, --message <TEXT>` (a message to the other party, signed with the slate; `tx
receive`, `invoice issue` and `invoice pay` take it too), `--fluff` on finalize to skip the stem
phase.

`-a, --account <LABEL>` on `tx send`, `tx receive`, `tx list`, `invoice issue` and `invoice pay`
picks the account, `default` unless given. No command creates accounts yet: a new wallet has
only `default`, and a restore adds `account_<n>` for each other account it finds outputs in, as
`wallet info` lists them.

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
  did: `Received 0, finalized 1, repeated 0, rejected 0, held for retry 0, parked 0, bounced 0,
  dropped 0, notices 0.`
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

`tx cancel` of a transaction the other party can still complete on its own (a finalized send, an
invoice you paid, a payment you received and answered) first asks the node, and is refused with
exit code 7 while its pool or chain already holds it. After a cancel, the next week of refreshes
still looks for it, and if it is mined after all, the transaction becomes `confirmed` and its
outputs come back. A received payment that carries no TTL ends by itself a week of blocks after
the wallet first saw it, under the same check.

## Direct over HTTP

A wallet that runs `epic-wallet listen -m http`, or `lepic http listen`, answers a payment as it
arrives, so the send is finalized and posted in the same command:

```
$ lepic tx send 1.5 --to https://wallet.example.org
Transaction 4 sent 1.50000000 EPIC (fee 0.00800000) by http to https://wallet.example.org:443/v2/foreign, finalized and posted.
```

A missing port is 3415 for `http` and 443 for `https`, and `/v2/foreign` is appended. Plain
`http` goes only to this computer unless you add `--allow-plain-http`: the slate then travels
unencrypted, and anyone on the way can read the amount. `--fluff` posts without the stem phase,
as for `tx post`. If the other wallet cannot be reached or refuses, `lepic` exits with code 11
and the inputs stay locked; `lepic tx resend <ID> --to <URL>` delivers the same slate again,
and a wallet that answered it before answers the same way.

To take payments this way:

```
$ lepic http listen
Listening for payments over HTTP on port 3415 (local). Ctrl-C stops.
```

It listens on `127.0.0.1` only. `--internet` listens on every IPv4 interface, for a port you
forward from your router: anyone who reaches the port can send you payments. Payments that wait
for their senders to finalize are capped at 100; at the cap a new payment is refused for now,
and none already taken is cancelled. The listener
also takes at most 30 payments a minute. `--port` picks another
port; 0 lets the system choose. Each payment prints a line on stderr, and Ctrl-C prints how many
were received, repeated and refused. Invoices are never answered over HTTP.

## Direct over Tor

Every wallet has an onion address: its payment-proof address in onion form, the one
`epic-wallet address` prints too, so it survives a restore from the recovery phrase.

```
$ lepic tor address
gpuxiaswl37rjqfunltyo57h7ubqvmyf4yoyomyh6zs5btdbbzymfeid.onion
```

`lepic` does not bundle tor. Give it the `tor` binary of the Tor Expert Bundle with
`--tor-binary`, and on Linux the bundle's directory with `--lib-dir` for the libraries it ships.
Each wallet runs its own tor, with its files in `tor/` inside the data directory.

To take payments at the onion address:

```
$ lepic tor listen --tor-binary ~/tor/tor --lib-dir ~/tor
Connecting to the Tor network: 95%
Publishing the wallet's onion address.
Listening for payments at gpuxiaswl37rjqfunltyo57h7ubqvmyf4yoyomyh6zs5btdbbzymfeid.onion over Tor. Ctrl-C stops.
```

Tor forwards the onion's port 80 to a listener on `127.0.0.1` that nothing else reaches. Only
payments are answered, never invoices, with the same caps as `http listen`. Ctrl-C stops tor and
prints how many payments were received, repeated and refused.

To pay a wallet that receives over Tor, `lepic tor listen` or any wallet with a published onion:

```
$ lepic tx send 1.5 --to gpuxiaswl37rjqfunltyo57h7ubqvmyf4yoyomyh6zs5btdbbzymfeid.onion --tor-binary ~/tor/tor --lib-dir ~/tor
```

The address may carry `http://`, a port or a path; the other wallet is always reached at port 80.
The send starts tor, waits until it is connected, sends, finalizes and posts, and stops tor. A
wallet that is not online takes up to about two and a half minutes to fail; the send then exits
with code 11 and the inputs stay locked, so `lepic tx resend <ID> --to <ONION> --tor-binary ...`
tries again later, or `lepic tx cancel <ID>` gives up.

## Invoices

An invoice asks the payer for an amount: the issuer builds I1, the payer answers with I2 and the
issuer finalizes and posts. A service that runs `lepic` all the time can invoice a user over
Epicbox, so the user answers once and never has to come back to finalize.

### Over Epicbox

The payer receives invoices on an invoice address of its own, apart from the payments address
`wallet address` prints. It accepts invoices only from senders the payer allowed, and drops
everything else unread:

```
$ lepic epicbox invoice-address
esABC...@epicbox.epiccash.com
$ lepic epicbox allow add esShop...@epicbox.epiccash.com --label "bike shop"
Invoices from esShop...@epicbox.epiccash.com are accepted.
```

The payer gives the service its invoice address and allows the address the service shows, its
`wallet address`. Senders are matched on the key, the part before `@`, because the relay vouches
for the key of a message and never for its domain; payments always go to the address given to
`allow add`. `epicbox allow list` shows the allowed senders, `epicbox allow remove <ADDRESS>`
removes one, and invoices already parked from it stay. The invoice address is derived from the
recovery phrase at index 1 or higher; `epicbox invoice-address --rotate` moves to the next index
and abandons the old address. A restored wallet starts again at index 1.

The service issues the invoice to the payer's invoice address:

```
$ lepic invoice issue 0.8 --to esABC...@epicbox.epiccash.com -m "order 42"
Transaction 5 asks for 0.80000000 EPIC; the invoice went by epicbox to esABC...@epicbox.epiccash.com.
```

The payer fetches it, looks at it, and pays or declines it. Nothing is paid until the payer runs
`invoice pay` and types the amount again:

```
$ lepic epicbox drain --invoices
Received 0, finalized 0, repeated 0, rejected 0, held for retry 0, parked 1, bounced 0, dropped 0, notices 0.
$ lepic invoice list
2f4a6c1e-5b3d-4e8f-9a0b-1c2d3e4f5a6b  0.80000000 EPIC from esShop...@epicbox.epiccash.com
    received 2026-10-05 09:12:40, expires 2026-10-06 09:12:40 (UTC)
    message: order 42
$ lepic invoice pay 2f4a6c1e-5b3d-4e8f-9a0b-1c2d3e4f5a6b 0.8
Transaction 4 pays 0.80000000 EPIC (fee 0.00800000); the payment went by epicbox to esShop...@epicbox.epiccash.com.
```

`lepic invoice decline <SLATE_ID>` declines a parked invoice instead; it is never paid. The
payment carries a TTL of 1440 blocks, about a day, unless `--ttl-blocks` says otherwise, and
takes the other spending options of `tx send`. If the relay does not take it, `lepic` exits with
code 11 and the inputs stay locked; `lepic tx resend <ID> --to <ADDRESS>` delivers it again, to
the sender's allowed address only.

The service's `epicbox listen` or `epicbox drain` finalizes and posts the payment when it
arrives. An invoice that comes back unpaid from a wallet that does not pay invoices over Epicbox,
as `epic-wallet` does, counts as `bounced`, and with human output a line on stderr names the
invoice, its transaction and the payer; `lepic tx cancel <ID>` withdraws it, and a slate file
reaches that payer instead.

Before invoicing a payer, `lepic epicbox peer <ADDRESS>` shows what the wallet learned from that
payer's own messages, matched on the key: `lepic` once a payment or notice from it carried the
LEPIC marker, `no_invoices` once it sent an invoice back, `unknown` before either. It reads
only the wallet and sends nothing:

```
$ lepic epicbox peer esABC...@epicbox.epiccash.com
esABC...@epicbox.epiccash.com runs LEPIC: it pays invoices and is sent notices.
```

Its JSON document has `address` and `capability`.

Two LEPIC wallets also tell each other what happened to an invoice, with short notices that
never move funds. The payer's next `epicbox drain --invoices` hears that the service posted the
payment. When the service cancels an invoice with `lepic tx cancel`, or it expires, the payer's
drain deletes it if it was not paid yet, and names the payment if it was, so the payer can give
up on it with `tx cancel`; nothing is cancelled for the payer. `invoice decline` tells the
service, whose next drain or listen names the invoice to withdraw. Notices go only to a wallet
that has shown it runs LEPIC, because `epic-wallet` cannot read them; they are counted as
`notices` and, with human output, shown on stderr.

Unpaid invoices expire after `invoice_expiry_hours`, 24 unless set, at most 48. Each `epicbox
drain`, and `epicbox listen` when it starts and every few minutes while it runs, deletes parked
invoices that were not paid in time, and cancels invoices this wallet issued that nobody paid,
which drops the output and keys they reserved, so a late payment is refused. A payment of an
invoice that was not posted within its TTL is never cancelled on its own; the drain names it,
and `lepic tx cancel <ID>` gives up on it. The JSON document of a drain or listen has `parked`,
`bounced`, `dropped`, `notices` and `expired`, which lists the `deleted` slate ids and the
`cancelled` and `cancellable` transaction ids, or is `null` when the expiry could not run.

### Through slate files

```
$ lepic invoice issue 0.8 --to-file invoice.slate
Transaction 5 asks for 0.80000000 EPIC. Give invoice.slate to the payer.
```

The payer answers it; then finalize their answer with `lepic tx finalize invoice.slate.response`.
To pay an invoice file, type the amount it asks for again, so a changed file cannot charge you
more:

```
lepic invoice pay invoice.slate 0.8
```

It writes `invoice.slate.response` for the issuer, and takes the spending options of `tx send`.
`invoice pay` reads its first argument as a parked invoice's slate id when it is one, so a file
whose name is a slate id is given with its directory, as in `./<SLATE_ID>`.

## Transactions

```
$ lepic tx list
   ID  DIR       STATE                   AMOUNT          FEE  TRANSPORT  CREATED (UTC)
    1  incoming  confirmed          20.00000000            -  file       2026-10-03 11:24:52
    3  outgoing  posted             -1.50000000   0.00800000  epicbox    2026-10-03 11:28:32
```

States: `sent` (S1 or I2 handed over), `received` (S2 or I1 answered, waiting for the other side),
`finalized`, `posted` (with the node), `confirmed` (in a block), `cancelled`, `expired`.
`lepic tx show <ID>` adds the slate id, timestamps, the slate stages stored, the final kernel's
excess (`Kernel`, JSON `kernel_excess`, in hex) and the block height the transaction was
confirmed at (`Confirmed at`, JSON `confirmed_height`). The kernel is known once this wallet has
finalized the transaction or paid the invoice, so not for a payment taken by `tx receive` or one
restored from the chain. The height is known once a refresh or scan confirms the transaction.
When a reorganisation mines a confirming output at another height, the next refresh moves the
height with it. A transaction with no change output is confirmed by its kernel instead, and
keeps the height of that first confirmation: a reorganisation is not followed. Human output
prints `-` for what is unknown; the JSON document leaves the key out.

`tx show` also lists the parties' messages, one `Message` line each, `sender:` or `receiver:` of
the money before the text (JSON `messages`, an array of `role` and `text`), from the latest slate
stage stored: a send shows its own message, a receive the sender's and its own, a finalized send
both. Only a message whose signature verifies is listed, and control characters in it are
escaped in human output. A message of more than 256 bytes is cut on a character boundary before
it is signed, as `epic-wallet` keeps it. A transaction restored from the chain has none.

`lepic tx cancel <ID>` gives up a transaction that is not posted and unlocks its inputs. A
finalized one is refused (exit 7, `rejected`) while the node's chain or its transaction pool holds
its kernel.
`lepic tx release <ID>` gives up a finalized or posted send the network never took, and unlocks
its inputs too. A send becomes releasable once a refresh (`lepic wallet info`) at a height 1440
blocks, about a day, or more after it was finalized still finds its kernel nowhere on chain.
`lepic tx show` says when: `Release` reads `now`, or the height a refresh must reach first (JSON
`releasable` and `releasable_from`, for finalized and posted sends only). The release asks the
node once more and is refused (exit 7, `rejected`) while the node's chain or its transaction pool
holds the transaction. What it can cost: if another node still holds the transaction and mines it
later, the inputs are spent by it after all, and a new send that spends the same inputs fails.
A refresh within 10080 blocks, about a week, of the release then finds the kernel: the
transaction shows `confirmed` and its change is back in the balance. A transaction mined later
than that keeps showing `cancelled`, and its change is missing from the balance until
`lepic wallet scan` finds it on chain again.
`lepic tx post <ID>` sends a finalized transaction to the node again, for one the node dropped. A
node whose pool already holds it counts as having taken it. When the node refuses it and its chain
already holds the transaction's kernel, lepic records the transaction as posted and the next `lepic wallet info`
confirms it. Human output then reads `Transaction <ID> is posted; its kernel is already on chain at
height <n>.` The JSON document keeps `"state": "posted"` and adds `"already_on_chain": true` and
`"height": <n>`; for a normal accept `already_on_chain` is `false` and there is no `height`.

## Data and logs

The data directory, `~/.lepic/<network>` unless `data_dir` says otherwise, holds:

- `wallet.vault`, the seed, encrypted with your password through Argon2;
- `wallet.sqlite3`, outputs and transaction history, with private transaction data encrypted;
- `tor/`, the files of the wallet's tor, once `tor listen` or a send over Tor ran: its state and
  the cookie that authenticates to it, never the onion key;
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
| 10 | `transport` | the slate file, the relay, the http listener or tor failed |
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
| `http address rejected` (exit 2) | The `--to` URL is not `http(s)://host[:port][/path]`, or is plain `http` to another computer without `--allow-plain-http`. Nothing was stored. |
| `invoices go over epicbox or through a slate file, not over http` (exit 2) | `invoice issue --to` was given an address with a scheme (`://`). |
| `the http listener could not start` (exit 10) | Another program holds the port, or the port needs privileges; pick another with `--port`. |
| `give --tor-binary to use tor` (exit 2) | `tor listen`, or a send to an onion address, needs the path of the tor binary. Nothing was stored. |
| `onion address rejected` (exit 2) | The `--to` address names an onion that is not a valid onion v3 address, or has a typo. Nothing was stored. |
| `tor is not working: tor failed (missing)` (exit 3) | No tor binary at the `--tor-binary` path. Nothing was stored. |
| `tor is not working: tor failed (network)` (exit 10) | Tor could not connect to the Tor network: no internet, or a network that blocks Tor. `(clock)` means the computer's clock is wrong. |
| `invoice amount differs from the approved amount` | The amount you typed is not the one in the invoice; nothing was paid. |
| `invoice ... is not waiting to be paid` (exit 6) | The slate id is not a parked invoice: it was paid, declined or expired. `lepic invoice list` shows the ones waiting. |
| `goes only to the allowed address of its invoice` (exit 7) | `tx resend` of an invoice payment names another key than the sender's allowed address; `epicbox allow list` shows it. |
| `was already received as transaction N` | The file is a different slate under the id of one received before, or that transaction was cancelled or expired. The same slate again would have rewritten its reply. |
| `transaction N cannot be released` (exit 7) | The send is not finalized or posted, or no refresh at the height `lepic tx show` names has missed its kernel yet. |
| `transaction N is in the node's pool` (exit 7) | The node may still mine it; refresh later instead of releasing it. |
| `finalized but the node did not accept it` (exit 11) | The node neither took the transaction nor holds its kernel. Check the node, then `lepic tx post <ID>`. |
| `a restore scan must complete before new outputs are created` (exit 5) | The wallet was restored with `--no-scan`, or its database was rebuilt, and has not scanned the chain from genesis since. Run `lepic wallet scan`. |
| `The node is behind the last refresh; balances not updated.` from `wallet info` | The node is still syncing, or the wallet stored a height this chain does not have. Once the node is synced, `lepic wallet scan --reset-chain` recovers. |
