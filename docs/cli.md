# The lepic command-line wallet

`lepic` is the command-line wallet built on LEPIC. It creates and restores Epic Cash wallets,
sends and receives over Epicbox, HTTP, Tor and slate files, pairs with contacts, and runs as a
service with a local REST API. Every command takes its settings from flags, `LEPIC_*` variables
and two optional files, and reports on stdout as text or JSON with a documented exit code.

This page covers installing it, where it keeps its files, how it reads the password, each group
of commands, the API of `lepic serve`, and the exit codes. Every option is also in
`lepic <command> --help`. The settings files are described in full in
[configuration.md](configuration.md).

## Install

`lepic` is the binary of the `lepic-cli` crate. Build it from the workspace root:

```sh
cargo build --release -p lepic-cli
./target/release/lepic --version
```

```text
lepic 0.3.1
```

The workspace needs Rust 1.99 or later (`rust-version` in `Cargo.toml`).

## Data directory and files

Each wallet lives in its own data directory. Without `--data-dir`, the directory is
`~/.lepic/<network>`, so `~/.lepic/mainnet` or `~/.lepic/floonet`. On Windows `~` is
`USERPROFILE`.

| File | What it holds |
|---|---|
| `wallet.vault` | The seed, encrypted under the wallet password |
| `wallet.enc.sqlite3` | The wallet database, encrypted; `-wal`, `-shm` and `.check` files sit next to it |
| `.lepic.lock` | The lock one running `lepic` holds on the directory |
| `lepic.sock` | The API socket, while `lepic serve` runs |
| `api-clients` | The clients `serve --owner-tls` accepts |
| `api-tls.pem` | The certificate `serve --owner-tls` presents |
| `tor/` | The files of the tor that `tor listen` runs |
| `tor-epicbox/` | The files of the tor that reaches the relay, with `epicbox_tor_binary` set |

The last four appear only once the matching command has run. A fresh wallet holds the first
three:

```text
.lepic.lock  wallet.enc.sqlite3  wallet.enc.sqlite3.check  wallet.vault
```

Two `lepic` processes cannot open the same data directory at once; the second fails with exit
code 5.

Two files sit outside the data directory, in `~/.lepic`:

- `config.toml`, the CLI's own settings. It is read only when it exists.
- `settings.toml`, the node and Epicbox servers. It is written from the shipped copy the first
  time a command needs it, and never changed after.

[configuration.md](configuration.md) lists every key of both.

## Password and other secrets

A command that opens the wallet reads the password from, in order:

1. the file `LEPIC_PASSWORD_FILE` (or `password_file` in config.toml) names, which must be
   readable by its owner only;
2. the `LEPIC_PASSWORD` variable;
3. a hidden prompt, when standard input is a terminal;
4. one line of standard input.

Secrets are never taken from arguments. `LEPIC_PASSWORD` stays in the process environment while
the command runs, where processes of the same user can read it; the file, the prompt and standard
input leave nothing there.

`wallet init`, `wallet restore` and `wallet import-seed` set the password from the same
sources, and the prompt asks for it twice. `wallet password` reads the current password the same
way, then the new one from the file `LEPIC_NEW_PASSWORD_FILE` names, else `LEPIC_NEW_PASSWORD`,
else the prompt or standard input. A new password cannot be empty.

`wallet restore` reads the recovery phrase from a hidden prompt or one line of standard input.

A secret longer than 4096 bytes is refused.

## Global options

These go before or after the command group, and each has a variable and a config.toml key.

| Option | Variable | Meaning |
|---|---|---|
| `--data-dir DIR` | `LEPIC_DATA_DIR` | The wallet directory |
| `--network mainnet\|floonet` | `LEPIC_NETWORK` | The chain; default `mainnet` |
| `--config FILE` | `LEPIC_CONFIG` | The config file; it must exist when named |
| `--settings FILE` | `LEPIC_SETTINGS` | The settings file; it must exist when named |
| `--log-level FILTER` | `LEPIC_LOG_LEVEL` | A level or tracing directives; default `warn` |
| `--log-format pretty\|compact\|json` | `LEPIC_LOG_FORMAT` | Log lines on stderr; default `compact` |
| `--output human\|json` | `LEPIC_OUTPUT` | Reports on stdout; default `human` |
| `--profile NAMES` | `LEPIC_PROFILE` | Profile bits told to paired contacts: `no-payments`, `automated` |
| `--profile-bits N` | `LEPIC_PROFILE` | The same bits as a number, 0 to 65535 or `0x` hex |
| `--domain DOMAIN` | `LEPIC_DOMAIN` | A domain to claim to paired contacts |

A flag beats its variable, the variable beats config.toml, and config.toml beats the default.

A throwaway floonet wallet for trying the commands on this page:

```sh
mkdir -p ./try && printf 'example-password-1\n' > ./try/password && chmod 600 ./try/password
export LEPIC_PASSWORD_FILE=$PWD/try/password
lepic --network floonet --data-dir ./try/wallet wallet init
```

The examples below leave out `--network` and `--data-dir`.

## Wallet lifecycle

| Command | What it does |
|---|---|
| `wallet init [--words N]` | Creates a wallet and prints its recovery phrase once; 12, 15, 18, 21 or 24 words, default 24 |
| `wallet restore [--from-height H] [--no-scan]` | Recreates a wallet from its phrase and scans the chain |
| `wallet import-seed FILE [--no-scan]` | Recreates a wallet from an `epic-wallet` `wallet.seed` file |
| `wallet import-history DIR` | Imports the transaction history of the `epic-wallet` wallet it was made from |
| `wallet info` | Refreshes against the node and shows accounts and balances |
| `wallet address` | Shows the Epicbox address |
| `wallet outputs [-a LABEL]` | Lists the outputs, spent ones included |
| `wallet password` | Changes the password |
| `wallet scan` | Scans the chain and brings the wallet in line with it |

`wallet init` prints:

```text
Wallet created on floonet in /home/user/try/wallet.
Write down the recovery phrase. It is not shown again:

    <24 words>

To receive, give the sender the address `lepic wallet address` prints, or
answer their slate file with `lepic tx receive <FILE>`.
```

A restore without a scan, with the phrase on standard input:

```sh
printf '%s\n' "$PHRASE" | lepic --data-dir ./try/restored wallet restore --no-scan
```

```text
Wallet restored on floonet in /home/user/try/restored.
Chain not scanned.
```

`wallet scan` options:

- `--start-height H` starts at a height; 0 scans the whole chain.
- `--delete-unconfirmed` also unlocks locked outputs found on chain and deletes unconfirmed
  outputs it does not find, cancelling their transactions.
- `--reset-chain` forgets the stored chain heights and scans from genesis, for a wallet ahead of
  its node. It cannot be combined with `--start-height`.

Commands that read the chain need a node: `node_url`, or on mainnet the first of `[node] servers`
in settings.toml. Floonet uses `http://127.0.0.1:13413` unless `node_url` is set. `lepic node
status` shows the node's version and tip.

## Receive

A wallet receives in four ways:

- **Epicbox.** Give the sender the address from `lepic wallet address`. Then `lepic epicbox
  listen` stays connected and answers slates as they arrive, or `lepic epicbox drain` handles
  what is waiting once and exits.
- **Slate file.** `lepic tx receive FILE` reads a V2 or V3 slate and writes the reply to
  `FILE.response`, or to `--reply-file`. A file from a LEPIC wallet carries a one-time reply
  key, and the reply is sealed to it: armoured text that only the sender's `tx finalize` opens.
  A file without one, such as a stock wallet's, gets a plain V3 reply.
- **HTTP.** `lepic http listen` answers payments at `/v2/foreign`.
- **Tor.** `lepic tor listen` publishes the onion address from `lepic tor address` and answers
  payments sent to it.

Those listeners answer payments only, never invoices.

```sh
lepic wallet address
```

```text
zzexampleexampleexampleexampleexampleexampleexample@epicbox.epiccash.com
```

The host after `@` is the relay this wallet uses: `epicbox_relay`, else the first of
`[epicbox] servers` in settings.toml.

```sh
lepic epicbox status
```

`epicbox status` shows the relay, the address and the deliveries still pending. `epicbox peer
ADDRESS` shows whether a peer is known to pay invoices.

With `refuse_unsolicited_payments = true` in config.toml, payments nobody asked for are refused,
and a LEPIC sender is told they were declined.

Receiving the same slate again, for example after the reply file was lost, gives the same answer
and stores nothing new; the JSON report has `"repeated": true`, and `--message` and `--account`
are ignored. A repeat is answered only over the transport and to the address that took the slate
the first time; the same slate sent to another listener or address of the wallet is refused as
already received, so the answer never shows that two addresses belong to one wallet. A different
slate under the same slate id is refused, and so is the same slate once its transaction was
cancelled or expired.

### HTTP listener

```sh
lepic http listen --port 3415
```

Without `--internet` it listens on 127.0.0.1 only. `--internet` listens on every interface, for
a port forwarded from the internet; anyone who reaches the port can then send the wallet
payments. `--port 0` lets the system pick a port; without `--port` the port is 3415.

The listener's limits come from the built-in `[http]` table: 16 connections at once, 4 per
address, 120 requests and 30 payments a minute.

`--coinbase` also answers `build_coinbase` for a mining node on this computer, so block rewards
go to the `default` account. Point the node's `wallet_listener_url` in
`[server.stratum_mining_config]` at `http://127.0.0.1:<port>`. `--coinbase-remote` with
`--internet` answers every caller. Behind a local reverse proxy every caller is loopback, so
`--coinbase` alone then serves whatever the proxy forwards.

### Tor listener

```sh
lepic tor address
lepic tor listen --tor-binary /opt/tor/tor --lib-dir /opt/tor
```

`tor address` prints the onion address without starting Tor. `tor listen` runs the given tor
binary (as the Tor Expert Bundle ships it) with its files in `tor/` in the data directory, and
forwards the onion to a listener on 127.0.0.1. It prints the address once others can reach it.
`--previous-onion` also publishes the wallet's previous onion address on its own listener;
`tor address --previous` prints it.

The HTTP and onion listeners open payments sealed to the wallet's epic1 addresses only with
`epic1_web_listener = true` or `epic1_onion_listener = true` in config.toml. Both are off by
default: the listener then answers such a payment as one sealed to a key it does not hold, so
whoever has one of the wallet's epic1 addresses cannot tell that the listener is the same wallet.

## Send

`lepic tx send AMOUNT` takes exactly one destination:

| Destination | How the slate travels |
|---|---|
| `--to ADDRESS@HOST` | Through Epicbox; the payee answers when it next connects |
| `--to http://HOST[:PORT]` or `https://` | Straight to a listening wallet, which answers at once |
| `--to NAME.onion` | Over Tor to a listening wallet, which answers at once |
| `--to-file FILE` | Written as V3 slate JSON for the payee to receive by hand |
| `--to-contact ID` | Sealed to a paired contact and queued in its mailbox |

Amounts are in EPIC, for example `1.5`.

```sh
lepic tx send 1.5 --to zzexampleexampleexampleexampleexampleexampleexample@epicbox.epiccash.com
lepic tx send 1.5 --to http://127.0.0.1:3415
lepic tx send 1.5 --to exampleexampleexampleexampleexampleexampleexampleexampl.onion \
  --tor-binary /opt/tor/tor --lib-dir /opt/tor
lepic tx send 1.5 --to-file ./payment.slate
```

Over HTTP and Tor the transaction is finalized and posted in the same command:

- A missing port is 3415 for `http://` and 443 for `https://`.
- Plain `http://` goes only to this computer unless `--allow-plain-http` is given, since the
  slate then travels unencrypted.
- For an onion, the tor binary is started for the send and stopped after it.
- `--legacy` sends a V2 or V3 slate to a listener that offers native slates.
- A native send to a listener on this computer is refused with exit code 7 and stores nothing;
  `--legacy` sends the V2 or V3 slate there.

Over Epicbox the payee's answer is finalized and posted by the next `epicbox listen` or `epicbox
drain`. With a file, the payer runs `lepic tx finalize FILE.response` on the reply, plain V3 or
sealed.

| Option | Meaning |
|---|---|
| `-a, --account LABEL` | The account to spend from; default `default` |
| `-m, --message TEXT` | A message to the other party, signed with the slate |
| `--min-confirmations N` | Confirmations an output needs to be spent; default 6 |
| `--change-outputs N` | Outputs the change is split into; default 1 |
| `--selection smallest\|all` | Fewest small outputs that cover the amount, or every eligible output; default `smallest` |
| `--ttl-blocks N` | Blocks after which the payee must refuse the slate |
| `--purpose P` | `payment`, `deposit`, `withdrawal`, `refund` or `request`; only with `--to-contact` |
| `--fluff` | Broadcast to all peers at once instead of through the stem phase |
| `--slate-id UUID` | A version-4 UUID the caller stores before sending |

`--slate-id` makes a send safe to repeat. A send made again under the same id sends nothing: it
reports the first send with `repeated: true` and exit code 0, or fails with code 7 when the
account, amount, destination or transport differ. `lepic tx show --slate-id UUID` finds it.

### After the send

| Command | Use |
|---|---|
| `tx resend TX_ID --to ... \| --to-file ...` | Delivers the first slate again after exit code 11 |
| `tx finalize FILE [--fluff]` | Finalizes a reply slate file and posts the transaction |
| `tx post TX_ID [--fluff]` | Posts a finalized transaction again |
| `tx cancel TX_ID` | Cancels a transaction that is not posted |
| `tx release TX_ID` | Releases the inputs of a send the network never took |
| `tx list [-a LABEL] [--refresh]` | Lists an account's transactions |
| `tx show TX_ID` or `tx show --slate-id UUID` | Shows one transaction |

`tx list` and `tx show` read the states the last refresh stored. `--refresh` refreshes from the
node first, as `wallet info` does, so the listing shows current confirmations.

`tx release` works once a refresh at least 1440 blocks after the send was finalized finds its
kernel nowhere on chain; `tx show` says when. The node is asked once more first, and the release is
refused while the node's chain or pool holds the transaction. If another node mines it later, a
refresh within 10080 blocks of the release finds it and shows it `confirmed`.

`peer pins` lists the keys this wallet pinned for the LEPIC wallets it paid directly, and `peer forget ORIGIN` drops one so the next send pins the key the payee shows.

## Invoices

An invoice asks a payer for an amount; the payer adds the fee.

```sh
lepic invoice issue 2 --to-file ./invoice.slate
```

The payer pays the file and the issuer finalizes the reply:

```sh
lepic invoice pay ./invoice.slate 2          # payer: writes ./invoice.slate.response
lepic tx finalize ./invoice.slate.response   # issuer
```

| Command | What it does |
|---|---|
| `invoice issue AMOUNT --to ADDRESS \| --to-file FILE` | Asks for a payment over Epicbox or in a file |
| `invoice pay INVOICE AMOUNT` | Pays a parked invoice by slate id, or an invoice file |
| `invoice list` | Lists the parked invoices |
| `invoice decline SLATE_ID` | Declines a parked invoice so it is never paid |

The payer types the amount again, and an invoice for any other amount is refused. A file whose
name looks like a slate id is given with a directory, as in `./<SLATE_ID>`.

When the payer declines an invoice, the issuer's `tx show` of it shows when (`Payer  declined by
the payer at …`, `payer_declined_at` in JSON); the invoice stays `received` until the issuer
cancels it with `tx cancel`.

Over Epicbox a LEPIC payer takes invoices only from a paired contact it allowed to send them.
Invoice such a contact with `lepic contact invoice`. An unpaid invoice is cancelled after
`invoice_expiry_hours` (default 24) by the next `epicbox listen` or `epicbox drain`.

## Contacts and pairing

The `contact` commands pair this wallet with another and then exchange invoices, slates and
app payloads through each side's mailbox. [protocols/pairing.md](protocols/pairing.md)
describes the protocol.

Two flags apply to every `contact`, `in-person` and `epic1` command:

- `--offline` reaches no relay at all. Pairing by hand or in person and sealed files still work.
- `--epicbox-off` treats Epicbox as switched off: no relay connections, and contact mailboxes
  pause.

### Pairing

1. One side makes an invite:

   ```sh
   lepic contact invite --name Shop --expiry 24h
   ```

   ```text
   Share this invite: epiccash://pair/1/AQAB...example
   It expires at 2026-01-02 12:00:00. Contact 00000000000000000000000000000000.
   ```

   `--expiry` is `1h`, `24h` or `7d`; default `24h`. `--pairing-words` also prints five words
   that find the invite.

2. The other side reads it with `contact open LINK`, then answers it with `contact accept LINK`.
   The reply goes to the inviter's relay, or with `--by-hand` it is printed as a link to send by
   other means. `contact enter` takes such a reply link, a confirm link, or the five pairing
   words.
3. Both sides run `contact collect` to fetch pairing messages and send what waits.
4. Both compare the four SAS words on the two screens, and each records the result with
   `contact sas CONTACT match|mismatch|skip`.

In person, one phone runs `contact show-card` and the other `contact scan-card CONTACT LINK`.
`contact request ADDRESS` asks a wallet that paid or was paid lately to pair, at its payments
address. The request waits up to 7 days for the answer, listed under `sent_requests` in `contact
list`; a second request to that address is refused while it waits, and `contact request-cancel
CONTACT` withdraws it, so a late answer is refused.

`contact requests` lists the pair requests this wallet received, each with a `request_id` of 16
hex digits. `contact request-accept REQUEST [--name NAME]` pairs through it, verified against the
address that asked; `contact request-dismiss REQUEST` drops it without an answer. An unknown
request id exits with code 6.

### Using a contact

| Command | What it does |
|---|---|
| `contact list`, `remove`, `label` | Lists, removes (without telling the contact) or renames contacts; an unknown id exits with code 6 |
| `contact allow-invoices CONTACT on\|off` | Allows or stops invoices from a verified contact |
| `contact invoice CONTACT AMOUNT` | Invoices a contact through its mailbox |
| `contact invoices`, `pay-invoice`, `decline` | Lists, pays or declines invoices parked from contacts |
| `contact send-slate` | Sends a transaction's slate sealed through the contact's mailbox |
| `contact seal CONTACT TX_ID [--out FILE]` | Seals a slate to a contact as text for a file or a paste |
| `contact open-sealed FILE\|-` | Opens sealed text and acts on its slate; the answer is sealed back |
| `contact plain TX_ID [--out FILE]` | Writes a slate plain, for a contact that cannot open sealed text |
| `contact payload post\|list\|ack` | Sends, lists and acknowledges the host app's payloads |
| `contact quarantine` | Lists contact messages kept in quarantine |
| `contact check CONTACT` | Asks a contact to answer with its current card |
| `contact key-check`, `keys` | Checks and settles a pairing whose keys changed |
| `contact move CONTACT --apply HOST` | Moves to the relay a contact asked for |
| `contact move-home HOST [--drain-days N]` | Moves this wallet's home relay for every contact |
| `contact export FILE`, `import FILE` | Backs up and restores the pairing records; through the API on the socket only |

`tx send --to-contact ID` pays a contact; `contact collect` posts what is still queued and takes
the answer. A send the contact cannot take locks nothing.

`move-home` tells each contact once, and reads the old mailboxes for `--drain-days`, 0 to 365.

## In-person codes

The `in-person` commands make or answer a payment through one code, shown on a screen and
scanned once. The answer goes to the relay the code names, or is shown back by hand.

| Side | Commands |
|---|---|
| The one showing the code | `in-person invoice AMOUNT` or `in-person send AMOUNT`, then `answers SLATE_ID`, `take ANSWER`, `finalize SLATE_ID ANSWER` |
| The one scanning | `in-person read --hex HEX \| --file FILE`, then `pay AMOUNT` or `receive`, then `post SLATE_ID` |

`read` shows what the code asks and where its answer goes, before anything is paid. `post`
prints the answer's check code, four digits of the payer's public excess; `pay` does not, so the
payer's screen shows it only once the answer is posted. The side showing the code finalizes the
answer whose check code the other screen shows.

## epic1 links

An epic1 address takes payments through links; each link has its own mailbox on a relay.
[protocols/epic1.md](protocols/epic1.md) describes the format.

```sh
lepic epic1 address
```

```text
tepic1qqqqexampleexampleexampleexampleexampleexampleexampleexampleexample
```

Floonet addresses start with `tepic1`, mainnet ones with `epic1`.

An account has many epic1 addresses, each a number. Number 0 always exists, and `epic1
new-address` issues the next one, for a shop, an invoice or one payment. Payments to every
address come to the same account, a received transaction shows the number its address had, and
two addresses of one account do not show that they belong together.

| Command | What it does |
|---|---|
| `epic1 address [--index N]` | Shows address 0, or an issued or paid one; a higher number is refused |
| `epic1 new-address` | Issues the account's next address |
| `epic1 addresses [--from N] [--limit N]` | Lists the issued addresses, with `highest`, the highest number issued or paid |
| `epic1 issue-here` | Makes a restored install the one that issues addresses |
| `epic1 link [AMOUNT] [--index N] [--printed] [--epicbox HOST]` | Makes a link; `--epicbox` names up to three relays |
| `epic1 links`, `retire N` | Lists link mailboxes in use; frees a printed link's mailbox |
| `epic1 answers`, `post-answer SLATE_ID` | Lists answers to payments taken; posts one to a relay outside the relay list |
| `epic1 read LINK` | Shows what a link asks and the relays a payment would go to |
| `epic1 pay LINK [AMOUNT] [--hosts-ok] [--proof]` | Pays a link |
| `epic1 post-next SLATE_ID` | Posts the same payment to the link's next relay |
| `epic1 restore` | After a restore, reads every link mailbox on the wallet's relay once |

An on-screen link takes the next of 50 mailboxes, which wrap. A printed link takes the first of
32 not in use, until `epic1 retire`. Without `--epicbox` a link names the wallet's relay.

`contact collect` takes the payments at the link mailboxes and answers each. A payment whose
amount is not the one the link asked is refused and creates no transaction. The answer is
posted to the payer's reply mailbox when that relay is in the relay list (the wallet's own relay
or a meeting relay); `epic1 post-answer SLATE_ID --relay-ok` posts it elsewhere, and posting
again is safe. The payer's `contact collect` takes the answer and finalizes it.

`epic1 pay` pays the amount the link asks and refuses another; a link that asks none takes the
amount after it. It takes the spending options of `tx send`. `--hosts-ok` confirms relays outside
the relay list, after `epic1 read` showed them. `--proof` asks for a payment proof signed with
the payee's epic1 proof key. The payment goes to the link's first relay, and `post-next` tries
the next when a post fails, at most three. In JSON, `posted` is the index of the relay it went
to, `posted_ok` says whether any post went through, and `uncertain` is the first relay that did
not answer after the payment was sent: it may hold the payment, so do not pay again. A second
`pay` to the same link is refused while a payment to it waits for its answer. `--slate-id` works
as for `tx send`: a repeat to the same address, from the same account and for the same amount
posts nothing and reports the first payment with `"repeated": true`; anything else under that id
exits with code 7.

The wallet records the numbers it issued and the ones paid. A restore from the phrase tries 50
numbers past the highest it knows; a payment to an address more than 50 past it is not found.
Another install on the same phrase may still be issuing addresses, and two installs that both
issue give the same number to two payers. So a restored wallet refuses `epic1 new-address` (exit
code 5) until `epic1 issue-here`; run that once the other install no longer issues. Until then it
keeps trying 50 numbers past the highest one paid. A wallet made with `wallet init` issues from
the start. `epic1 restore` finds only links named on the wallet's own relay.

## EPICTX files

```sh
lepic epictx open ./payment.epictx
```

`epictx open FILE` (or `-` for standard input) opens an `.epictx` file with this wallet's keys
and prints its slate as JSON. Nothing is stored. [protocols/epictx.md](protocols/epictx.md)
describes the format.

## Profile and domain

`profile show` prints the profile bits this wallet tells its contacts; `profile set NAMES` or
`profile set --bits N` tells every contact a new one.

```text
Profile 0
```

`profile domain show|file|attach` handles a domain claim. `profile domain file` writes
`./epic-wallet.json` (or `--path`), which the domain serves at
`https://<domain>/.well-known/epic-wallet.json` over HTTPS, with no redirect, under 4 KiB.
`--relay HOST:PORT` names a relay in the file and can repeat. The key comes from the recovery
phrase, so a restored wallet keeps it. `profile domain attach` tells every contact the domain.

## Tor for the relay and the node

Two config.toml keys route Epicbox through Tor:

- `epicbox_tor_socks = "127.0.0.1:9050"` uses a running tor's SOCKS5 proxy on a loopback
  address.
- `epicbox_tor_binary` runs a tor from that binary, with its files in `tor-epicbox/`;
  `epicbox_tor_lib_dir` names its libraries.

Only one of the two can be set. `node_over_tor = true` sends node calls through the same tor.
[protocols/tor.md](protocols/tor.md) covers the onion routes and the timeouts.

## lepic serve and the wallet API

`lepic serve` opens the wallet once and holds the data directory until Ctrl-C or SIGTERM. While
it runs it listens on Epicbox, expires unpaid invoices, collects contact mailboxes, refreshes the
wallet and answers the wallet API: HTTP with JSON bodies on a Unix socket, `lepic.sock` in the
data directory unless `--socket` says otherwise. Only the user that runs it can use the socket.

```sh
lepic serve &
curl --unix-socket ./try/wallet/lepic.sock http://lepic/v1/status
```

```json
{"socket":"/home/user/try/wallet/lepic.sock","uptime_s":1,"requests":{"served":0,"in_flight":1,"refused":0},"epicbox":"connecting","height":null,"node_tip":null,"refresh":{"consecutive_failures":0,"last_error":null,"last_success":null},"collect":{"consecutive_failures":0,"last_error":null,"last_success":null}}
```

`GET /v1/openapi.json` returns the OpenAPI document of every route; the same document is in
[api/openapi.json](api/openapi.json). Response bodies are the JSON `lepic --output json` prints,
and amounts are decimal strings in EPIC. The routes follow the commands:

| Routes | Commands |
|---|---|
| `/v1/wallet`, `/v1/wallet/address`, `/v1/wallet/password`, `/v1/wallet/scan`, `/v1/outputs` | `wallet` |
| `/v1/transactions`, `/v1/transactions/{tx_id}/…`, `/v1/slates/receive`, `/v1/slates/finalize` | `tx` |
| `/v1/contacts/…`, `/v1/contact-invoices`, `/v1/payloads` | `contact` |
| `/v1/in-person/…`, `/v1/epic1/…`, `/v1/epictx/open` | `in-person`, `epic1`, `epictx` |
| `/v1/epicbox`, `/v1/node`, `/v1/profile/…`, `/v1/peer-pins` | `epicbox`, `node`, `profile`, `peer` |
| `/v1/status`, `/v1/methods`, `/v1/events` | The running service and its events |

`GET /v1/methods` says per method whether this serve `listens` on it: `epicbox` always, `http`
with `--http`. `GET /v1/transactions` and `GET /v1/transactions/{tx_id}` take `refresh=true`, as
`--refresh`. `POST /v1/epic1/pay` takes a `slate_id`, and a repeat under it posts nothing and
reports `repeated: true`; the owner TLS listener requires it.

`serve --http` also answers payments at `/v2/foreign` as `http listen` does, and takes the same
`--port`, `--internet`, `--coinbase` and `--coinbase-remote` options.

### Commands while serve runs

While `serve` holds a wallet, a `lepic` command on that wallet with a route in the API runs on
serve's wallet through its socket ([ADR 0053](adr/0053-cli-commands-through-a-running-serve.md)).
`lepic` tries the socket the data directory's `serve-socket` file names (`serve --socket` writes
it and removes it on exit), then `lepic.sock`. The command prints what it would print on its own,
with the same error, kind and exit code. It asks for no password, runs with serve's settings and
prints no progress lines. Files it reads are read by `lepic` and sent in the request; files it
writes (`contact export`, `profile domain file`) are written by `lepic` with the same checks as a
direct run.

A forwarded `tx send` or `epic1 pay` always carries a slate id, the one given with `--slate-id` or
one `lepic` draws. If serve takes it and does not answer, `lepic` exits with code 11 and names the
id; `tx show --slate-id UUID` shows whether the payment was made, and the same command with
`--slate-id UUID` pays nothing twice.

A forwarded command tells serve its `lepic` version, data directory, network, `native_direct`,
`relay_tor` and `node_over_tor` as `x-lepic-*` headers. Serve refuses one that differs in any of
them with HTTP 409 (kind `config`, exit code 3) and names it; a client that sends none, such as
`curl`, is not checked. Serve answers every request with its version in `x-lepic-version`. A
`--socket` another serve answers on is refused.

A command given an option its route has no field for runs on its own and meets the lock. These
keep a command off serve: `--to-file`, `--to-contact`, `--purpose`, `--allow-plain-http`,
`--tor-binary`, `--lib-dir`, `--fluff` and `--ttl-blocks` on `tx send` (`--ttl-blocks` also on
`in-person read`, `in-person pay` and `epic1 pay`), a non-default `--selection`, `--offline` and
`--epicbox-off`, `--kind` on `contact invite` and `contact show-card`, `--out` on the in-person
commands, `contact payload ack` with several ids, and `epictx open` with text on the command
line. `tx send` to an onion, `tx show --slate-id` and `epicbox status --listing` do not go
through serve either.

These commands exit with code 5 while serve runs:

| Command | Reason |
|---|---|
| `wallet init`, `restore`, `import-seed`, `import-history` | They create or replace the wallet serve holds |
| `wallet password` | It asks for both passwords on the terminal; run it with serve stopped |
| `serve`, `epicbox listen`, `epicbox drain`, `http listen`, `tor listen`, `tor address` | They are listeners or take the wallet for their own run |
| `api client add`, `list`, `remove` | They edit the file serve reads at start |
| `invoice issue`, `pay`, `list`, `decline` | No route covers them |
| `tx receive`, `tx finalize`, `tx resend` | They read or write slate files, or have options no route takes |
| `contact seal`, `open-sealed`, `send-slate`, `plain`, `invoice`, `pay-invoice`, `decline` | No route covers them |

The error reads `lepic serve is running on this wallet (socket PATH) and this command does not go
through its API`. A serve whose socket cannot be reached is not found, and the command meets the
lock.

### Owner API over TLS

`serve --owner-tls` also answers the owner routes over mutual TLS, on the `ip:port` that
`[api] owner_tls` sets in settings.toml. It writes its certificate to `api-tls.pem` in the data
directory, issued to `lepic-wallet`; clients trust that file and present their own certificate.
Routes marked `x-socket-only` in the OpenAPI document stay on the socket: changing the password,
`POST /v1/contacts/export` and `POST /v1/contacts/import`. Over TLS each is a 403 problem with
code `usage`.

The TLS listener has its own `max_connections`, so TLS clients cannot take the socket's
connections. A TLS connection takes one once its handshake ends; up to `max_connections`
handshakes run at a time besides, and more are refused. A handshake that fails, or does not end
within 5 seconds or the header time when that is shorter, counts as refused.

`lepic api client` chooses the clients:

```sh
lepic api client add laptop ./laptop-cert.pem
lepic api client list
lepic api client remove laptop
```

A client is accepted by its Ed25519 key: `add` stores the SHA-256 of the certificate's public
key in `api-clients`. Names use letters, digits, `.`, `-` and `_`.

## Output formats

`--output human` prints short sentences meant for a person. `--output json` prints one JSON
object per command on stdout:

```sh
lepic --output json wallet address
lepic --output json tx list
```

```json
{"address":"zzexampleexampleexampleexampleexampleexampleexample@epicbox.epiccash.com"}
{"account":"default","transactions":[]}
```

A failure prints an `error` object, with `kind` named as in the exit code table:

```json
{"error":{"kind":"wrong_password","exit_code":4,"message":"wallet operation failed","causes":["password did not unlock the wallet"]}}
```

A command line that does not parse is a `usage` error too: with `--output json` it prints the
same object (exit code 2, the parser's message as `message`) and nothing on stderr. A command
group without a subcommand, such as `lepic tx`, names the group and lists its subcommands; in
text mode it prints the group's help on stderr. `--help` and `--version` still print text.

An error about one stored transaction carries its `tx_id`. Exit code 11 also carries `recovery`,
the commands that finish or give up that transaction, in the order to try them; the serve API's
problem document carries the same list:

```json
{"error":{"kind":"incomplete","exit_code":11,"message":"finalize failed","causes":["transaction 3 is finalized but the node did not accept it"],"tx_id":3,"recovery":["lepic tx post 3","lepic tx cancel 3"]}}
```

When a native send's listener answered that it is not ready or takes no more payments for now,
and said how long to wait, the error carries `retry_after_s`, the seconds to wait before `tx
resend`; in text mode it is a line under the error.

In human output a failure is a line on stderr, sometimes a hint, and the code:

```text
error: wallet operation failed: password did not unlock the wallet
exit code 4 (wrong_password)
```

Logs go to stderr, at `--log-level` and in `--log-format`. [logging.md](logging.md) describes
the fields.

## Exit codes

| Code | Kind | Meaning |
|---|---|---|
| 0 | | Success |
| 1 | `internal` | An unexpected failure; see the log |
| 2 | `usage` | Invalid arguments or missing input |
| 3 | `config` | Invalid settings or config file |
| 4 | `wrong_password` | The password did not unlock the wallet |
| 5 | `wallet_state` | No wallet, a wallet already exists, it is in use, or it belongs elsewhere |
| 6 | `not_found` | No such transaction, slate or account |
| 7 | `rejected` | The slate or request was refused; nothing was stored |
| 8 | `insufficient_funds` | Not enough spendable funds |
| 9 | `node` | The node could not be reached or answered badly |
| 10 | `transport` | The slate file, the relay or the HTTP listener failed |
| 11 | `incomplete` | Stored, but not delivered or not posted; retry |
| 12 | `interrupted` | Stopped before it finished |

Code 11 means the transaction exists: deliver it with `tx resend` or post it with `tx post`
rather than sending again.

## Related

- [configuration.md](configuration.md): config.toml, settings.toml and the built-in values
- [crates/lepic-cli/README.md](../crates/lepic-cli/README.md): the crate
- [protocols/README.md](protocols/README.md): Epicbox, EPICTX, epic1, pairing, Tor and HTTP
- [ffi.md](ffi.md): the same wallet from a Flutter app
