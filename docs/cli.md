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
  `FILE.response`, or to `--reply-file`.
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

Over Epicbox the payee's answer is finalized and posted by the next `epicbox listen` or `epicbox
drain`. With a file, the payer runs `lepic tx finalize FILE.response` on the reply.

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
| `tx list [-a LABEL]` | Lists an account's transactions |
| `tx show TX_ID` or `tx show --slate-id UUID` | Shows one transaction |

`tx release` works once a refresh 1440 blocks after the send was finalized still finds its kernel
nowhere on chain; `tx show` says when. The node is asked once more first, and the release is
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
address.

### Using a contact

| Command | What it does |
|---|---|
| `contact list`, `remove`, `label` | Lists, removes (without telling the contact) or renames contacts |
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
| `contact export FILE`, `import FILE` | Backs up and restores the pairing records |

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

`read` shows what the code asks and where its answer goes, before anything is paid.

## epic1 links

An epic1 address takes payments through links; each link has its own mailbox on the wallet's
relay. [protocols/epic1.md](protocols/epic1.md) describes the format.

```sh
lepic epic1 address
```

```text
tepic1qqqqexampleexampleexampleexampleexampleexampleexampleexampleexample
```

Floonet addresses start with `tepic1`, mainnet ones with `epic1`.

| Command | What it does |
|---|---|
| `epic1 link [AMOUNT] [--printed] [--epicbox HOST]` | Makes a link; `--epicbox` names up to three relays |
| `epic1 links`, `retire N` | Lists link mailboxes in use; frees a printed link's mailbox |
| `epic1 answers`, `post-answer SLATE_ID` | Lists answers to payments taken; posts one to the payer |
| `epic1 read LINK` | Shows what a link asks and the relays a payment would go to |
| `epic1 pay LINK [AMOUNT] --hosts-ok [--proof]` | Pays a link after its relays were checked |
| `epic1 post-next SLATE_ID` | Posts the same payment to the link's next relay |
| `epic1 restore` | After a restore, reads every link mailbox once |

An on-screen link takes the next of 50 mailboxes, which wrap. A printed link takes the first of
32 not in use, until `epic1 retire`. `contact collect` takes payments at links and the answers to
payments made.

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

`serve --http` also answers payments at `/v2/foreign` as `http listen` does, and takes the same
`--port`, `--internet`, `--coinbase` and `--coinbase-remote` options.

### Owner API over TLS

`serve --owner-tls` also answers the owner routes over mutual TLS, on the `ip:port` that
`[api] owner_tls` sets in settings.toml. It writes its certificate to `api-tls.pem` in the data
directory, issued to `lepic-wallet`; clients trust that file and present their own certificate.
Routes marked `x-socket-only` in the OpenAPI document, such as changing the password, stay on the
socket.

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

In human output the same failure is a line on stderr, sometimes a hint, and the code:

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
