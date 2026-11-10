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

Status: beta. Its commands may still change before 1.0.

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

For Epicbox, `lepic` uses the first relay of `[epicbox] servers` in the settings file
(`wss://epicbox.epiccash.com` in the shipped file) unless you set another.

### Settings

Each setting comes from, in order: a flag, its environment variable, the config file, the default.

| Config key | Variable | Flag | Default |
|---|---|---|---|
| `network` | `LEPIC_NETWORK` | `--network` | `mainnet` |
| `data_dir` | `LEPIC_DATA_DIR` | `--data-dir` | `~/.lepic/<network>` |
| `node_url` | `LEPIC_NODE_URL` | | the first of `[node] servers` in the settings file (`http://127.0.0.1:3413` shipped); floonet `[floonet] node` of the built-in configuration (`http://127.0.0.1:13413`) |
| `node_api_secret_file` | `LEPIC_NODE_API_SECRET_FILE` | | none |
| `password_file` | `LEPIC_PASSWORD_FILE` | | none |
| `epicbox_relay` | `LEPIC_EPICBOX_RELAY` | | the first of `[epicbox] servers` in the settings file, over `wss://` |
| `epicbox_tor_socks` | `LEPIC_EPICBOX_TOR_SOCKS` | | none: the relay is reached directly |
| `epicbox_tor_binary` | `LEPIC_EPICBOX_TOR_BINARY` | | none |
| `epicbox_tor_lib_dir` | `LEPIC_EPICBOX_TOR_LIB_DIR` | | none |
| `node_over_tor` | `LEPIC_NODE_OVER_TOR` | | `false` |
| `output` | `LEPIC_OUTPUT` | `--output` | `human` |
| `log_level` | `LEPIC_LOG_LEVEL` | `--log-level` | `warn` |
| `log_format` | `LEPIC_LOG_FORMAT` | `--log-format` | `compact` |
| `refuse_unsolicited_payments` | `LEPIC_REFUSE_UNSOLICITED_PAYMENTS` | | `false` |
| `refuse_unsolicited_invoices` | `LEPIC_REFUSE_UNSOLICITED_INVOICES` | | `false` |
| `native_direct` | `LEPIC_NATIVE_DIRECT` | | `false` |
| `invoice_expiry_hours` | `LEPIC_INVOICE_EXPIRY_HOURS` | | `24` |
| `host_features` | `LEPIC_HOST_FEATURES` | | none |
| `profile` | `LEPIC_PROFILE` | `--profile`, `--profile-bits` | `0` |
| `domain` | `LEPIC_DOMAIN` | `--domain` | none |
| `settings_file` | `LEPIC_SETTINGS` | `--settings` | `~/.lepic/settings.toml` |

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

A wallet that a service runs claims the host bits of that service in its marker (ADR 0034) with
`host_features`: bit names, comma-separated, of `device-forwarding` (4) and `name-service` (5),
for example `host_features = "name-service"`. An unknown name is an error. Without it the wallet
claims none.

The profile (ADR 0041) is what the wallet tells its paired contacts about the host, in bits 16-31 of
the feature word: 16 bits, never in the marker. `--profile <NAMES>` takes `no-payments` (bit 0, 1)
and `automated` (bit 1, 2), comma-separated; `--profile-bits <N>` takes a number 0 to 65535,
decimal or `0x` hex, for bits the CLI has no name for. The two flags exclude each other. The
config file and `LEPIC_PROFILE` take names or a number. An unknown name or a number above 65535
is a usage error. The flag wins over the variable, the variable over the config file.

#### Refusing slates nobody asked for

`refuse_unsolicited_payments = true` makes the wallet refuse every payment it did not ask for
(ADR 0045): an S1 that comes over Epicbox, over HTTP or Tor, or from a contact. Nothing is
received. `refuse_unsolicited_invoices = true` makes it refuse invoices from contacts instead of
keeping them to pay; a plain Epicbox invoice is refused already. Both are `true` or `false`, off
by default and independent of each other and of the profile: `--profile no-payments` only tells
contacts, it refuses nothing.

The wallet's own sends and invoices, and their answers, go through as before. So do a payment
for one of the wallet's own listings, a slate taken from a file or a paste, and an S1 the wallet
answered before, whose answer goes back again.

A refused sender learns of it where it can:

- Over Epicbox, a `lepic` sender gets the `declined` notice, cancels the send, frees its inputs,
  prints `payment … declined by the receiver` and shows `Receiver  declined at …` in `tx show`.
  An older `lepic` or another wallet gets nothing and keeps the send until its user cancels it.
- Over HTTP or Tor, the sender's request fails with `slate refused`.
- A contact gets the `declined` notice in its mailbox.

A self-send to the wallet's own address is refused too while the switch is on.

#### Native slates to contacts

`native_direct = true` makes the wallet send `lepic.v1` slates (envelope type `0A`, ADR 0052) to
the paired contacts whose pairing features claim native slates (bit 7), through their mailboxes.
It is `true` or `false`, off by default: the wallet then sends V3 JSON (type `01`), as before. A
contact without the claim always gets V3 JSON. Sealed text for a file or a paste follows the
same rule: `BEGINEPICTX.` (`.epictx`) with the switch on and the claim, `BEGINEPICSEALED.`
otherwise.

The wallet takes native slates from its contacts whatever the switch says, and answers a slate
in the format it came in.

The switch also sends native slates to HTTP and Tor listeners that offer them; see Pinned keys
under Direct over Tor.

Over Epicbox payments addresses the same switch claims native slates in the LEPIC marker of every
slate the wallet sends (bit 7, with its seal key for them in `reply`), and sends an S1 as a
native slate, armored `BEGINEPICTX.`, to a peer that runs LEPIC and whose latest marked slate
claimed them with a valid key (RFC 0003 11.1). Any other S1 goes as V2 or V3 JSON, so the first
payment to a peer always does. The `tx send` JSON names the format in `format`: `legacy` or
`native` (null for a repeat). The wallet opens a native slate at its payments address whatever
the switch says, answers it natively, and refuses a native invoice there.

#### Domain

`domain` (`--domain <DOMAIN>`, `LEPIC_DOMAIN`, `domain = "example.com"`) is the domain the wallet
claims to its paired contacts. It is lowercased and loses one trailing dot; a value that is not a
domain name (labels of letters, digits and hyphens, at least one dot) is a usage error. Pairings
made while it is set carry the claim by themselves. The claim is proven by a file the domain
serves (see `lepic profile domain` below), signed for by the wallet's domain key. That key derives
from the recovery phrase (account 0), so a restored wallet keeps it.

### The settings file and the built-in configuration

The rule is "All configuration in settings.toml (no hardcoded configuration)" (ADR 0030): no
library crate holds a server address, port, timeout, retry or server limit, and the CLI's code
holds none either. As in BT Wallet, they live in two files:

- **`settings.toml`, the user's file.** Which servers to use. Without `--settings`,
  `LEPIC_SETTINGS` or `settings_file` it is `~/.lepic/settings.toml`; when that does not exist,
  `lepic` writes it from the copy it ships (`crates/lepic-cli/settings.default.toml`) and never
  changes it after that. A file named explicitly must exist. It has the layout of the app's user
  file, so a copy of the app's file works too; `lepic` reads only these keys:

  | Key | What it sets |
  |---|---|
  | `[node] servers` | the nodes known; the first is the mainnet node unless `node_url` names another |
  | `[epicbox] servers` | the Epicbox servers known, each `host` or `host:port` over TLS, at most 16; the first is the relay unless `epicbox_relay` names another, and pairing words go to the first `pairing_servers` of them |
  | `[api] owner_tls` | the address `ip:port` `lepic serve --owner-tls` listens on; no default, and `--owner-tls` refuses to start without it |

  `[online]` and every other key and section are ignored.

- **`lepic-config.toml`, the built-in configuration.** Shipped read-only with LEPIC: it is
  compiled into the binary (`crates/lepic-cli/lepic-config.toml`), is not a user setting and
  cannot be overridden. Every key is required and none may be zero; units are in the key names.

  | Section | Keys |
  |---|---|
  | `[node]` | `connect_timeout_s`, `request_timeout_s`, `idle_timeout_s`, `retry_attempts`, `retry_backoff_min_ms`, `retry_backoff_max_ms`, `outputs_per_request`, `concurrent_requests` |
  | `[floonet]` | `node`: the node of a floonet wallet that names none |
  | `[epicbox]` | `address_default` (the server of an address written without `@server`), `pairing_servers`, `connect_timeout_s`, `response_timeout_s`, `ping_interval_s`, `reconnect_min_s`, `reconnect_max_s`, `drain_timeout_s`, `tor_connect_timeout_s`, `onion_discovery_timeout_s`, `onion_discovery_retry_s` |
  | `[http]` | `listen_port` (of `http listen` without `--port`), `header_timeout_s`, `body_timeout_s`, `request_timeout_s`, `answer_timeout_s`, `max_connections`, `max_connections_per_address`, `requests_per_minute`, `receives_per_minute`, `send_connect_timeout_s`, `send_request_timeout_s` |
  | `[tor]` | `bootstrap_timeout_s`, `cold_bootstrap_timeout_s`, `stall_timeout_s`, `cold_stall_timeout_s`, `publish_timeout_s`, `connect_timeout_s`, `request_timeout_s`, `onion_only_domains`, and `[[tor.onions]]` with `host`, `port`, `onion`, `onion_port`, `tls`: while the relay or node is reached through tor, `host:port` is dialled at its onion, still with TLS for `host`; routes with `tls = false` are skipped |

Protocol values stay in code: what an address or URL without a port means (443 for an Epicbox
address, 3415 for a peer's `http://` URL), the onion service port, wire-format and size limits,
consensus values and the wallet's release window.

`node_url` is the API root, without `/v2/foreign`. Plain `http://` and `ws://` are accepted only
for a loopback host, because the node secret and the relay traffic would otherwise cross the
network in the clear; use `https://` and `wss://` for anything else. An `epicbox_relay` without a
scheme means `wss://`.

### Epicbox over Tor

Set one of these to take the connection to the relay through tor (ADR 0021):

- `epicbox_tor_socks`: the SOCKS5 address of a tor already running on this computer, such as
  `127.0.0.1:9050`. Only a loopback address is accepted.
- `epicbox_tor_binary`: a tor binary the command runs when it first reaches the relay, with its
  files in `tor-epicbox/` inside the data directory; `epicbox_tor_lib_dir` names the directory of
  the libraries the Tor Expert Bundle ships, as `--lib-dir` does.

The relay `epicbox.btlabs.uk` is then reached at its onion; any other relay at the onion its
`/.well-known/epicbox.json` names, else through the Tor network. TLS still checks the relay
domain's certificate, and the wallet's address does not change. While one is set, the relay is
never reached directly: a tor that is not ready makes the connection wait and, for
`epicbox listen`, retry. `--log-level lepic_epicbox=debug` shows `epicbox relay through tor`.

### Node over Tor

`node_over_tor = true` takes the node requests through the same tor as the relay (ADR 0022), so
it needs `epicbox_tor_socks` or `epicbox_tor_binary`. `node.btlabs.uk` is reached at its onion;
any other node by name through the Tor network, which resolves the name. A loopback node stays
direct. `http://` is refused for any other host, so nothing leaves a Tor exit unencrypted. While
set, the node is never reached directly.

## Passwords and the recovery phrase

Secrets are never taken from arguments, which other users can see in the process list and your
shell keeps in its history. A command that opens the wallet reads the password from the first
line of `password_file` if it is set, else from `LEPIC_PASSWORD`, else from a hidden prompt, else
from one line of standard input. A new password is asked for twice at a prompt.

`password_file` is meant for services: point it at a file only its owner can read (mode `0600`).
A file root owns may also be readable by its group or by the users an access list names, as a
systemd credential (`LoadCredential=`) is. Any other mode is refused. `LEPIC_PASSWORD` is meant for scripts; while
a command runs, other processes of the same user can read it. Neither is passed on to the tor the
CLI starts.

The recovery phrase is shown once, by `wallet init`. Write it down. It is the only way to get the
funds back if the data directory is lost, and anyone who has it can spend them.

### Change the password

`lepic wallet password` re-encrypts the vault file under a new password. The current password
comes as above. The new one comes from the first line of the file `LEPIC_NEW_PASSWORD_FILE` names
(owner-only, like `password_file`), else from `LEPIC_NEW_PASSWORD`, else from a hidden prompt
asked twice, else from the next line of standard input. An empty new password is refused (exit
7), as is a wrong current one (exit 4, `wrong_password`); the vault is then unchanged. The new
key uses the KDF cost of the build. The recovery phrase and the wallet database do not change:
the database key comes from the phrase, not from the password. The command needs the data
directory to itself, so stop `lepic serve` first; `wallet password` is refused through `serve`.
Its JSON is `{"changed": true}`.

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

Awaiting confirmation is received but not yet buried under 3 blocks, as the Epic GUI wallet
counts; awaiting finalization is a receive the sender has not posted yet; locked is spent by a
transaction that is not confirmed yet, change included.

The chain height is the one the balances are at. A wallet more than 60 blocks behind its node
takes the node's tip only once a second answer agrees, so `wallet info` refreshes again until
it does. If the chain still outgrows it, the report adds `Catching up to the node's tip <n>;
balances are at height <m>.` (JSON: `"catching_up": true` and `"node_height"`), and the next
`wallet info` catches up.

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
chain from genesis. The scan alone does not restore the history: each output found appears in
`tx list` as one confirmed incoming transaction with no slate, dated by its block.

`lepic wallet restore --from-height <HEIGHT>` scans from that block height instead of genesis,
which is much faster on mainnet. Give a height below the first transaction of the phrase: outputs
below it are not found, and their funds do not show until a scan from below them, such as
`lepic wallet scan --start-height 0`. Once the scan from the height completes the wallet receives,
sends and makes invoices; its key counters are moved past the keys that scan found, so it does not
reuse a key the phrase used before. With `--no-scan` too, the next `lepic wallet scan` starts at
the height.

## Import history

```
lepic wallet import-history ~/.epic/floo
```

brings across the transaction history of the epic-wallet wallet (CLI or GUI) the wallet was made
from: give its folder, or its `wallet_data` folder. Its database is copied into the data directory
and read from the copy, and nothing in the old folder changes. Run it after `import-seed` or
`restore` with the same seed, before or after the scan. Each old transaction keeps its dates, type,
amounts, fee, slate id, messages and kernel; `tx show` marks it `Origin imported` with the old id
and how the chain judged it. Funds and balances still come from the scan: an output the scan finds
is linked to the old transaction that made it. The report's status says why nothing was imported:
`no-history`, `old-format` (epic-wallet before 3.3), `unreadable`, `source-busy` (close the old
wallet), `too-large`, `other-wallet` (no output it holds is one this seed makes) or `other-history`. Running it again with the
same folder reports `already-imported` and only links and dates what later scans found.

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
wallet was restored with `--no-scan` and its restore scan has not completed since; then it starts
where that scan does, at genesis or at the restore's `--from-height`. Progress goes to
stderr. Ctrl-C stops it and keeps what it found (exit 12); the next scan with the same options
continues where it stopped, and says `Continued an interrupted scan.`

- `--start-height <HEIGHT>` starts there instead; `0` scans the whole chain. A height above the
  node's tip is refused with exit 2. Only a scan from 0, or for a restore with `--from-height`
  from that height or below, ends the wait after a `--no-scan` restore.
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
  V2 and V3, so `epic-wallet` `v4.1.0` reads its files and it reads `epic-wallet`'s.
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

`--reply-file <FILE>` writes the answer elsewhere. A file from a LEPIC wallet carries a one-time
reply key, and the answer is sealed to it: the `.response` file is armoured text, not V3 JSON,
and only the sender's `tx finalize` opens it. A file without a reply key, such as one from a
stock wallet, gets a plain V3 answer. The amount shows under awaiting finalization
until the sender posts, then under awaiting confirmation until it is mined.

Receiving the same slate file again, for example after the reply file was lost, writes the reply
stored the first time again, as the same answer, and stores nothing new; the JSON report has
`"repeated": true`. `--message` and `--account` are ignored on a repeat, because the stored
reply already carries the first ones. A different slate that reuses the slate id is refused, and
so is the same slate once its transaction was cancelled or expired.

Send. Write S1 to a file, give it to the receiver, and finalize their answer; `tx finalize` takes a
plain V3 answer and a sealed one alike:

```
$ lepic tx send 1.5 --to-file pay-alice.slate -m "for lunch"
Transaction 3 sent 1.50000000 EPIC (fee 0.00800000) by file to pay-alice.slate.
Slate d4217e26-f23c-46f0-9944-84b406dd16a6.
$ lepic tx finalize pay-alice.slate.response
Transaction 3 finalized and posted.
Slate d4217e26-f23c-46f0-9944-84b406dd16a6.
```

The inputs stay locked from the send until the transaction confirms or is cancelled. Options:
`--min-confirmations` (6 by default, the confirmations the balance counts), `--selection all|smallest`
(`smallest`, the default, spends as few as cover the amount; `all`, as `epic-wallet`, spends every
eligible output and so locks all of them until it confirms), `--change-outputs`, `--ttl-blocks`
(the receiver must refuse the slate after that many blocks), `-m, --message <TEXT>` (a message to
the other party, signed with the slate; `tx receive`, `invoice issue` and `invoice pay` take it
too), `--fluff` on finalize to skip the stem phase.

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
  dropped 0, notices 0.` A further line counts early notices kept, if any (`buffered` in JSON).
- `lepic epicbox listen` stays connected, answers incoming payments and finalizes answers as they
  arrive, printing each change on stderr, until Ctrl-C or SIGTERM. It then settles the message
  in hand (at most 30 seconds) and prints the same summary.

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

A program that pays, such as a faucet, can make a send safe to repeat: it draws a random
version-4 UUID, stores it with its own record of the payment, and passes it as `--slate-id`. If
the program does not learn how the send ended, it runs the same command again. A send already
made under that id is not made again: `lepic` exits 0 with the first send's `tx_id`, amount, fee
and current `state`, `"repeated": true`, and `"delivered"`, which is `false` while the slate
still has to be resent. The same id with another account, amount, destination or transport is
refused with exit code 7. A slate id stays taken after the send is cancelled or expires.
`lepic tx show --slate-id <UUID>` shows the send made under an id (exit 6 when there is none).
The slate id travels in the slate, so never derive it from a user or order id.

`tx cancel` of a transaction the other party can still complete on its own (a finalized send, an
invoice you paid, a payment you received and answered) first asks the node, and is refused with
exit code 7 while its pool or chain already holds it. After a cancel, refreshes still look for
it: by its kernel for a day of blocks (a received payment) or a week (a send), then by the
outputs it would give this wallet, with no end. If it is mined after all, the transaction becomes
`confirmed` and its outputs come back. A received payment that carries no TTL ends by itself a week of blocks after
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

`http listen` and `lepic serve` both hold `.lepic.lock`, so they cannot run on one wallet. To
take payments over HTTP and use `serve`, run `lepic serve --http` (see Service).

### Block rewards for a mining node

A node that mines asks a wallet for each block's coinbase. `--coinbase` makes the listener
answer a node on this computer:

```
$ lepic http listen --coinbase
Listening for payments and block rewards over HTTP on port 3415 (local). Ctrl-C stops.
```

Point the node at it in `epic-server.toml`:

```
[server.stratum_mining_config]
wallet_listener_url = "http://127.0.0.1:3415"
```

Rewards go to the default account. A mined reward shows as an incoming transaction after the
next refresh, and can be spent once 1,440 blocks have passed on mainnet (30 on floonet). A
reward built for a block that was not mined is deleted 50 blocks later, and a wallet keeps at
most 4,096 of them.

Payments still work over `--internet`: only loopback callers get a reward built, and anyone else
is told the method does not exist. A node on another computer can reach the wallet through a
tunnel, or with `--coinbase --coinbase-remote --internet`. The listener then builds a reward for
anyone who reaches the port, within its limits.

## Direct over Tor

Every wallet has an onion address with a key of its own, derived from the recovery phrase, so
it survives a restore (ADR 0044). It is not the payment-proof address: a payment proof asked for
over the onion names the onion's key as the receiver address and is signed with it, and a proof
asked for over Epicbox, HTTP or a file is signed with the payment-proof key as before.

```
$ lepic tor address
mv5s7skb6dq2rhxouxdz4ibnd2c3zgvmmewe4cnho6irgt35tcwnmqqd.onion
```

LEPIC 0.3.1 and earlier, the Epic GUI wallet and `epic-wallet` publish another onion: the
payment-proof address in onion form, the one `epic-wallet address` prints. `--previous` shows it:

```
$ lepic tor address --previous
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

`--previous-onion` publishes the previous onion as well, for senders that still have it. It gets
a listener of its own, and a payment proof asked for there is signed with the payment-proof key,
so a sender never sees one key answer for both addresses. The lines then name both onions:

```
$ lepic tor listen --previous-onion --tor-binary ~/tor/tor --lib-dir ~/tor
...
Listening for payments at mv5s7skb6dq2rhxouxdz4ibnd2c3zgvmmewe4cnho6irgt35tcwnmqqd.onion and gpuxiaswl37rjqfunltyo57h7ubqvmyf4yoyomyh6zs5btdbbzymfeid.onion over Tor. Ctrl-C stops.
```

Tor forwards the onion's port 80 to a listener on `127.0.0.1`, at a port picked when it starts.
Only payments are answered, never invoices, with the caps of `http listen` but one: tor connects
every sender from `127.0.0.1`, so instead of a share per address, tor closes a sender's circuit
that opens more than 4 connections at once. Receipts are recorded as `tor` and have their own
open-receipt cap. Ctrl-C stops tor and prints how many payments were received, repeated and
refused.

To pay a wallet that receives over Tor, `lepic tor listen` or any wallet with a published onion:

```
$ lepic tx send 1.5 --to gpuxiaswl37rjqfunltyo57h7ubqvmyf4yoyomyh6zs5btdbbzymfeid.onion --tor-binary ~/tor/tor --lib-dir ~/tor
```

The address may carry `http://`, a port or a path; the other wallet is always reached at port 80.
The send starts tor, waits until it is connected, sends, finalizes and posts, and stops tor. A
wallet that is not online takes up to about two and a half minutes to fail; the send then exits
with code 11 and the inputs stay locked, so `lepic tx resend <ID> --to <ONION> --tor-binary ...`
tries again later, or `lepic tx cancel <ID>` gives up.

### Pinned keys

With `native_direct` on, a LEPIC wallet listening over HTTP or Tor also offers its native
endpoint, `/v1/peer`, with a seal key the wallet derives from its seed: one for the onion on
the onion, another for the web listener over HTTP. With the switch off it answers `check_version` without the `lepic` key and serves no
native routes. With `native_direct` on, a send to a wallet that offers the endpoint goes there as a `lepic.v1` slate in a sealed envelope, and the first one
that succeeds pins the key under the address's origin: `http://host:port`, `https://host:port`,
or the onion name alone. A payment proof asked for over the endpoint names the listener's proof
address, the onion's key on the onion and the payment-proof address over HTTP. With the switch
off, or to a listener that offers no endpoint and is not pinned, the send goes as before and
pins nothing. `--output json` reports `dialect`, `native` or `legacy`, for a send or resend to a
listener.

A send to a pinned origin never falls back to the V2 or V3 slate by itself. It stops, with
nothing stored, when the wallet there shows another key (the hint names both keys), when it no
longer offers the endpoint, or when it cannot be asked. A native exchange that fails after the
slate was stored exits with code 11 and the inputs stay locked, as for any send. A native post
goes to other computers only: a host that resolves to this computer fails to connect.

`--legacy` on `tx send` or `tx resend` sends the V2 or V3 slate whatever the listener offers,
and neither checks nor pins its key. Once a key change is confirmed with the payee, forget the
pin; the next send pins the key it is shown.

```
$ lepic peer pins
https://wallet.example:443  4f1c...9a2e  pinned 2026-11-09T10:12:03Z, last seen 2026-11-09T10:12:03Z
$ lepic peer forget https://wallet.example:443
Forgot the key of https://wallet.example:443.
```

## Invoices

An invoice asks the payer for an amount: the issuer builds I1, the payer answers with I2 and the
issuer finalizes and posts. A service that runs `lepic` all the time can invoice a user over
Epicbox, so the user answers once and never has to come back to finalize.

### Over Epicbox

A LEPIC payer takes invoices over Epicbox only from a paired contact it allowed to send them
(RFC 0002; see [Contacts](#contacts)); the invoice address and its allowlist of earlier builds
are gone. Pair with the payer, and once it ran `contact allow-invoices <ID> on`, invoice it:

```
$ lepic contact invoice 3f1c... 0.8 --reference order-42
```

The invoice reaches the payer's contact mailbox at its next `contact collect`. Nothing is paid
until the payer pays it and types the amount again:

```
$ lepic contact invoices
$ lepic contact pay-invoice 2f4a6c1e-5b3d-4e8f-9a0b-1c2d3e4f5a6b 0.8
```

The payment goes back sealed through the mailboxes; the service's `contact collect` finalizes and
posts it, and the payer's next `contact collect` shows that it was posted. `lepic invoice issue
--to <ADDRESS>` still sends an invoice to an Epicbox address, the payer's payments address, where
only a wallet that pays such invoices pays it.

`lepic invoice decline <SLATE_ID>` declines a parked invoice instead; it is never paid. The
payment carries a TTL of 1440 blocks, about a day, unless `--ttl-blocks` says otherwise, and
takes the other spending options of `tx send`. If the relay does not take it, `lepic` exits with
code 11 and the inputs stay locked; `lepic tx resend <ID> --to <ADDRESS>` delivers it again, to
the invoice's sender only.

The service's `epicbox listen` or `epicbox drain` finalizes and posts the payment when it
arrives. An invoice that comes back unpaid from a wallet that does not pay invoices over Epicbox,
as `epic-wallet` does, counts as `bounced`, and with human output a line on stderr names the
invoice, its transaction and the payer; `lepic tx cancel <ID>` withdraws it, and a slate file
reaches that payer instead.

Before invoicing a payer, `lepic epicbox peer <ADDRESS>` shows what the wallet learned from that
payer's own messages over Epicbox, matched on the key: `lepic` while its last payment or notice
carried the LEPIC marker, `no_invoices` once a slate from it came without the marker or it sent
an invoice back, `unknown` before either. It reads only the wallet and sends nothing:

```
$ lepic epicbox peer esABC...@epicbox.epiccash.com
esABC...@epicbox.epiccash.com runs LEPIC: it pays invoices and is sent notices.
```

Its JSON document has `address`, `capability`, `last_marked_at` and `last_unmarked_at` (RFC
3339, or null) and `notices`, whether the peer is told of the end of an exchange that came marked
(a marked message in the last 30 days), and `native_slates`, whether its latest marked slate
claimed native slates with a valid key; a wallet with `native_direct` off records no claim.

Two LEPIC wallets also tell each other what happened to an invoice, with short notices that
never move funds. The payer's next `epicbox drain` hears that the service posted the payment. When the service cancels an invoice with `lepic tx cancel`, or it expires, the payer's
drain deletes it if it was not paid yet, and names the payment if it was, so the payer can give
up on it with `tx cancel`; nothing is cancelled for the payer. `invoice decline` tells the
service, whose next drain or listen names the invoice to withdraw. Notices go only about an
exchange whose slate came marked, to a wallet that has shown it runs LEPIC in the last 30 days,
because `epic-wallet` cannot read them; they are counted as
`notices` and, with human output, shown on stderr.

Unpaid invoices expire after `invoice_expiry_hours`, 24 unless set. Each `epicbox
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

### In person

Face to face, the payee shows a code for one scan and the payer answers it, with no pairing.
The code is a raw `lepic.v1` I1 (RFC 0003 §9): it names no payment proof, and the payer refuses
it after its TTL. The app chooses the TTL: `--ttl-blocks` sets it, and without it LEPIC uses
30 blocks. LEPIC keeps a margin of 10 blocks (the payer stops paying 10 blocks before the
cutoff) and refuses a TTL of 10 blocks or fewer as an invalid argument. Online, it also names a
mailbox on the payee's own relay for the answer; with that relay on this device it names none,
and the answer is shown back.

```
$ lepic in-person invoice 0.8 --out code.bin
```

The payer reads the code first, then pays it, typing the amount again:

```
$ lepic in-person read --file code.bin
$ lepic in-person pay 0.8 --file code.bin --out answer.bin
$ lepic in-person post <SLATE_ID> --relay-ok
```

`read` shows the amount, the message, the TTL, a fee estimate and, when the code names a
mailbox, its `host`, `port`, `in_relay_list` (this wallet's own or a meeting relay) and
`host_rule`. `post` sends the sealed answer to that mailbox, only with `--relay-ok`, from a key
used for this slate only, over Tor when Epicbox goes over Tor. A loopback or unspecified host is
refused: connecting directly, every address the name resolves to is checked and the connection
goes to the addresses checked; through Tor the exit resolves the name, so the name is checked.
The answer never goes to the Epicbox sender of anything. Offline, the payer shows the answer
back and the payee takes it by hand, as hex, armoured `BEGINEPICTX.` text or UR parts:

```
$ lepic in-person take --file answer.bin
```

The payer's inputs stay locked until the payment is posted or cancelled; past the code's TTL
`epicbox drain` names it as cancellable, as for an Epicbox invoice.

The payee's `contact collect` watches each open code's mailbox until its TTL. It takes only an
I2 to its own I1, sealed to the code's reply key, and drops anything else with a reason. Nothing
is finalized on its own: each answer that checks is listed with its check code, four digits of
the payer's public excess, which the payer's screen shows too. A later answer with the same
check code is flagged. Finalize the answer whose check code the other screen shows:

```
$ lepic in-person answers <SLATE_ID>
$ lepic in-person finalize <SLATE_ID> 1
```

A send works the same way the other way round. The sender shows a raw `lepic.v1` S1, with no
payment proof and the TTL of `in-person invoice` (`--ttl-blocks`, 30 blocks by default, more than 10); it takes the spending
options of `send`. The send is stored and its inputs stay locked until an answer is finalized or
the TTL passes, when refresh expires it.

```
$ lepic in-person send 0.8 --out code.bin
```

The receiver reads the code, receives it and posts or shows back the sealed S2:

```
$ lepic in-person read --file code.bin
$ lepic in-person receive --file code.bin --out answer.bin
$ lepic in-person post <SLATE_ID> --relay-ok
```

The sender collects or takes the answers as the payee of an invoice code does. Each check code
is four digits of the receiver's public excess. `in-person finalize` finalizes the one picked.

### Through an epic1 link

An epic1 address (RFC 0003 §5.13) is the account's for good; a link to it names a mailbox for
the payment. An on-screen link is for one payment; a printed one is kept until it is retired.

```
$ lepic epic1 address
$ lepic epic1 link 0.8
$ lepic epic1 link --printed --epicbox relay.example
$ lepic epic1 links
$ lepic epic1 retire 1
```

`contact collect` takes the payments at the link mailboxes, stores an answer to each and posts
it to the payer's reply mailbox when that relay is in the relay list (the wallet's own relay or
a meeting relay), so the payer's own collect finalizes it. A payment whose amount is not the one
the link asked is refused and creates no transaction. `epic1 answers` lists the answers with the
relay of the reply mailbox, reported as for `in-person read`; `epic1 post-answer <SLATE_ID>
--relay-ok` posts one to a relay outside the list, and posting again is safe. After a restore, `epic1 restore` reads the link mailboxes of the seed on the wallet's own
relay; links named on other relays are not found.

The payer reads the link first, then pays it:

```
$ lepic epic1 read 'epic:epic1…'
$ lepic epic1 pay 'epic:epic1…'
$ lepic epic1 pay 'epic:epic1…' --hosts-ok     # a relay that is not in the relay list
$ lepic epic1 post-next <SLATE_ID>
```

`read` shows the address paid, the amount, the message, the label and each relay with its
`host_rule` and `in_relay_list`. `pay` pays the amount the link asks and refuses another one;
a link that asks none takes the amount that follows it. It takes the spending options of `tx
send`. `--hosts-ok` confirms relays outside the relay list and is not needed when every relay
of the link is in it. `--proof` asks for a payment proof signed with the payee's epic1 proof
key; the report's `proof_address` is that key as hex, and absent without `--proof`. The payment
goes to the first relay of the link; when the post fails, `post-next` tries the next one. In
JSON, `posted` is the index of the relay it went to and `posted_ok` says whether any post went
through. The payer's `contact collect` takes the answer at the reply mailbox and finalizes it.

`lepic epictx open <FILE|->` shows the slate in an `.epictx` file as JSON and takes nothing: a
`lepic.v1` slate with its network, kernel features, header version and tail records, or the V3
JSON of another slate.

## Contacts

Pairing (RFC 0002) ties this wallet to another wallet or a service with keys of their own, so
invoices, withdrawals and slates between the two travel sealed through mailboxes on the
pairing's home relay, the relay of whoever made the invite.

```
$ lepic contact invite --name Anna
Share this invite: epiccash://pair/1/AQAB...
$ lepic contact accept epiccash://pair/1/AQAB... --name Ben      # on the other wallet
$ lepic contact collect                                          # on both
$ lepic contact list
3f1c...  Ben  paired
    check: 🐱 kitty · 🦊 vixen · 🍩 donut · 🎻 fiddle
$ lepic contact sas 3f1c... match
```

Both screens show the same four entries when nobody changed the invite on the way; `sas ...
match` makes the contact verified. `contact open <LINK>` shows what an invite claims first,
`--by-hand` prints the reply as a link instead of posting it, and `contact enter <LINK>` takes a
reply or confirm link sent by hand. In person, each side runs `contact show-card` and then
`contact scan-card <ID> <LINK>` with the other's card.

`contact request <ADDRESS> --name Anna` asks a wallet this one paid or was paid by lately to
pair, at its Epicbox address; it is sent only to a key that ran LEPIC within 30 days and claims
pair requests, and the pairing completes verified when the answer proves that address.
A request waits up to 7 days for the answer and `contact list` shows it under `sent_requests`
(the contact id, the address and when it expires); a second request to that address is refused
while it waits. `contact request-cancel <ID>` withdraws it, so a late answer is refused and a new
request may go out.

`contact requests` lists the pair requests this wallet received, each with a `request_id`, the
address it came from, the name it claims and its invite link. `contact request-accept <REQUEST>
[--name Anna]` pairs through that link, as `contact accept` does, and the pairing completes
verified against the address that asked. `contact request-dismiss <REQUEST>` drops one without an
answer. The request id is 16 hex digits; an unknown one exits 6.

A contact that moves to another relay asks for it in an update; `contact list` then shows
`asks to move to relay <HOST>`, and `contact move <ID> --apply <HOST>` moves this wallet's
mailbox with it there. Until then the contact's mailbox stays where it was.

`contact move-home <HOST> [--drain-days N]` moves this wallet's own home relay for every paired
contact: each is sent this wallet's card naming its mailbox on `<HOST>` once, and its mailboxes
move there at once. With `--drain-days N` (0 to 365, default 0), every collect, `serve` included, still
reads the old mailboxes for N days. What a contact sends there is taken, and a `contact check`
there is answered with the card naming the new mailbox, so a contact that missed the update is
asked to follow. The drain replaces one left by following that contact's own move. The report
gives the drain's end in RFC 3339 (`drain_until` in JSON). With 0 the old mailboxes are not
read again, so a contact that misses the update stops reaching this wallet until it pairs
again. Set `<HOST>` as the wallet's Epicbox relay too, so new invites name it.

`contact check <ID>` asks a paired contact to answer with its current card; a later `contact
collect` takes the answer, and `contact list` shows when the contact was last heard
(`last_heard`) and any relay it moved to.

In JSON, each contact also carries what a host service needs to follow a pairing: `status`
(`waiting`, `paired`, `verified`, `keys-changed` or `ended`), `sas_indexes` (the four SAS table
indexes, in the order of `sas`; empty without a SAS), `peer_heard_at` and `peer_verified_at`
(RFC 3339, or null), `peer_features` (the feature bits the contact claimed, 0 when none),
`native_slates` (true when new slates to the contact go as native slates: `native_direct` is
set and the contact claims them) and,
once the pairing ended, `ended_reason` (`mismatch`, `peer-mismatch`, `unpaired` or
`never-finished`) and `ended_at`.
A wallet answers at most 1 check an hour and 3 a day per contact; more are taken and dropped. A
host app sets these with `contact_check_answers_per_hour` and `contact_check_answers_per_day`.

`contact list` shows a contact's profile when it is not 0 (`profile 3 (no-payments, automated)`),
and its JSON carries `peer_profile` (0 when none). A pairing restored from a backup shows 0 until
the contact answers a `contact check`.

The contact's `kind` (person, shop or exchange) in the JSON of `contact list` is deprecated: it
is an assumption about the peer, kept for machine consumers, and will be removed (ADR 0041). The
`--kind` option of `contact invite` and `contact show-card` is hidden from `--help`, still
accepted, and ignored: it prints `note: --kind is deprecated and ignored; new pairings write
person` on stderr, and new pairings write person.

`lepic profile show` prints the profile this wallet tells, as a number and names (bits without a
name as hex). `lepic profile set no-payments,automated` (or `set --bits 0x1`, or `set ""` to
clear) queues an update for every paired contact; `contact collect` sends them. It prints how many
were queued. The new value is not saved: later updates tell the configured one again, so set
`profile` in the config file too. Updates count against the contact update limits (3 a day per
contact, 100 an hour).

`lepic profile domain` handles the proof of the `domain` setting:

- `show` prints the configured domain (or `none`), the wallet's network, its domain key as 64 hex
  digits and the JSON fragment `{"<network>":{"domain_keys":["<hex>"]}}`. It opens the wallet and
  reaches no relay.
- `file [--path PATH] [--relay HOST:PORT ...] [--force]` writes the well-known file to `PATH`
  (default `./epic-wallet.json`) and prints the path, its size and the URL it must be served at,
  `https://<domain>/.well-known/epic-wallet.json`. It refuses to replace an existing file without
  `--force`. The file must stay under 4 KiB, and the domain must serve it over HTTPS with no
  redirect, or contacts cannot verify it.
- `attach` tells every paired contact the configured domain now and prints `<n> contact updates
  queued for <domain>; `lepic contact collect` takes the answers.` It needs `domain`. Pairings made
  while `domain` is set carry the claim already; `attach` is for pairings made before.

JSON reports: `{"domain","network","domain_key"}`, `{"path","bytes","url"}` and
`{"domain","queued"}`.

For services: run the wallet with the profile in its config and change it with `profile set`
while `serve` is stopped.

```
$ cat ~/.lepic/config.toml
profile = "no-payments,automated"
$ lepic profile set --bits 0x1
Profile 1 (no-payments) queued for 4 contact(s); `lepic contact collect` sends them.
The settings give 3; later updates tell that again unless you set `profile` too.
$ lepic profile show
Profile 3 (no-payments, automated)
```

`contact allow-invoices <ID> on` lets a verified contact send invoices; they arrive with
`contact collect` and wait in `contact invoices` until `contact pay-invoice <SLATE_ID> <AMOUNT>`
or `contact decline <SLATE_ID>`, which tells the contact.
`contact invoice <ID> <AMOUNT>` invoices a contact. `contact collect` also sends what the outbox
holds. `contact export <FILE>` and `contact import <FILE>` carry the pairings in a backup.

`contact invite` takes `--expiry 1h`, `24h` or `7d` (default `24h`), `--pairing-words`, and
`--name` (default `LEPIC`). `contact label <ID> <LABEL>` gives a contact a name of your own.
`contact remove <ID>` removes a pairing; the contact is not told. An id that is no contact exits 6.

`contact key-check <NEW> <OLD>` asks whether a contact paired again, for example after a restore,
still holds the keys of the older pairing; `contact collect` takes the answer. Either the keys are
back and the new pairing goes, or the new pairing shows keys-changed, and `contact keys <NEW>
keep-old` or `use-new` settles it: `keep-old` deletes the new pairing, `use-new` deletes the old
one and leaves the new one not verified.

`contact seal <ID> <TX_ID>` seals a transaction's slate to a contact as text, for a file or a
paste, and `contact send-slate <ID> <TX_ID>` sends it sealed through the contact's mailbox. Both
take `--purpose` (`payment`, `deposit`, `withdrawal`, `refund` or `request`). `contact plain
<TX_ID>` writes the slate plain, for a contact that cannot open sealed text. `seal` and `plain`
take `--out <FILE>`.

`contact collect` reports the mailboxes it read, the messages it took, and what was stopped at the
message limit, kept, refused, timed out or not reached. Its JSON has `mailboxes`, `capped`, `kept`,
`refused`, `timed_out`, `not_reached`, `quarantined`, `quarantine_dropped`, `buffered`, `messages`,
`paired`, `delivered`, `failed` and `unreachable`.

`contact quarantine` lists the contact messages kept in quarantine (ADR 0049), with `id`,
`contact_id`, `reason`, `first_seen`, `attempts` and `size`. The host app retries and discards
them.

`contact payload post <ID> --hex <HEX>` (or `--file <FILE>`) sends the host app's bytes, at
most 64 KiB, to a paired contact or a verified private pairing, and prints the payload's id; LEPIC
never reads them. `contact collect`, or `serve` on its own, takes arriving payloads; `contact
payload list` shows each one's id, contact, arrival time and bytes as hex until `contact payload
ack <ID>...` forgets it; a payload acknowledged is not kept again if it arrives once more. A
payload whose record no longer reads is dropped from the list and frees its place. At most 32 wait
per contact (256 from private pairings); more stay on the relay until some are acknowledged, and
`contact collect` leaves them unopened until then. When the contact's wallet is known not to claim
app payloads, `post` prints a warning to stderr and sets `peer_lacks_app_payloads` in its JSON;
the payload is sent all the same.

`tx send <AMOUNT> --to-contact <ID>` pays a contact through its mailbox: the slate is sealed to
the contact, queued in the outbox and posted at once when the relay answers. `--purpose
withdrawal` (or `payment`, `refund`, ...) tells the contact what the payment is for. A contact
that cannot take the slate is refused before anything is locked, and a send that cannot be
queued is cancelled. `contact collect` posts what is still queued and finalizes the answer.
`--slate-id` works as for any send; a repeat must name the same contact. The send is stored with
the `file` transport, since the slate leaves as a sealed file.

## Outputs

`lepic wallet outputs [-a LABEL]` lists the stored outputs of an account, spent ones included,
from the wallet's database only; it does not call the node. Its JSON is `account` and `outputs`,
each output with `commitment` (hex), `value` (EPIC), `status` (`unconfirmed`, `unspent`, `locked`
or `spent`), `category` (where it counts in the balance: `spendable`, `awaiting_confirmation`,
`awaiting_finalization`, `immature`, `locked` or `unpaid_invoice`; `null` for a spent output),
`is_coinbase`, `height`, `lock_height` (`null` when none), `confirmations` and `tx_id` (`null`
when no transaction is linked). Key ids and derivation paths are not shown.

## Transactions

```
$ lepic tx list
   ID  DIR       STATE                   AMOUNT          FEE  TRANSPORT  CREATED (UTC)
    1  incoming  confirmed          20.00000000            -  file       2026-10-03 11:24:52
    3  outgoing  posted             -1.50000000   0.00800000  epicbox    2026-10-03 11:28:32
```

States: `sent` (S1 or I2 handed over), `received` (S2 or I1 answered, waiting for the other side),
`finalized`, `posted` (with the node), `confirmed` (in a block), `cancelled`, `expired`.
`tx list` and `tx show` read the states as the last refresh stored them. `--refresh` refreshes
from the node first, as `lepic wallet info` does, so the listing shows current confirmations.
`lepic tx show <ID>` (or `--slate-id <UUID>` for a send) adds the slate id, timestamps, the slate stages stored, the final kernel's
excess (`Kernel`, JSON `kernel_excess`, in hex) and the block height the transaction was
confirmed at (`Confirmed at`, JSON `confirmed_height`). The kernel is known once this wallet has
finalized the transaction or paid the invoice, so not for a payment taken by `tx receive` or one
restored from the chain. The height is known once a refresh or scan confirms the transaction.
When a reorganisation mines a confirming output at another height, the next refresh moves the
height with it. A transaction with no change output is confirmed by its kernel instead, and
keeps the height of that first confirmation: a reorganisation is not followed. Human output
prints `-` for what is unknown; the JSON document leaves the key out.
A mining reward (see [Block rewards for a mining node](#block-rewards-for-a-mining-node)) adds
`Kind mining reward` (JSON `"coinbase": true`).

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
transaction shows `confirmed` and its change is back in the balance. Later, a refresh finds it by
its change instead. A send with no change mined later than that keeps showing `cancelled`.
`lepic tx post <ID>` sends a finalized transaction to the node again, for one the node dropped. A
node whose pool already holds it counts as having taken it. When the node refuses it and its chain
already holds the transaction's kernel, lepic records the transaction as posted and the next `lepic wallet info`
confirms it. Human output then reads `Transaction <ID> is posted; its kernel is already on chain at
height <n>.` The JSON document keeps `"state": "posted"` and adds `"already_on_chain": true` and
`"height": <n>`; for a normal accept `already_on_chain` is `false` and there is no `height`.

## Service

`lepic serve` keeps one unlocked wallet open and answers the wallet API over HTTP/1.1 on a local
socket (ADR 0050). A script that makes many calls, such as a bot, then unlocks the wallet once and
never fights over `.lepic.lock`. Unix only: on other platforms `serve` fails with a usage error.

```
lepic serve &                               # asks for the password once
curl --unix-socket ~/.lepic/mainnet/lepic.sock http://lepic/v1/wallet
```

`serve` opens the wallet as every other command does (password from the environment, a file or a
prompt) and holds `.lepic.lock` until it stops. While it runs it also:

- listens on the Epicbox relay and expires invoices, as `epicbox listen` does;
- collects the contacts' mailboxes at start, every mailbox at once, then every minute as the app's
  foreground tick does, keeping relay backoff;
- refreshes the wallet from the node at start and every minute.

A failed tick is logged at `warn` and never ends `serve`. `GET /v1/status` shows, for the refresh
and the collect, the failures since the last success, the last error and the time of the last
success; `serve` only reports them and keeps trying every minute. Each of `refresh` and `collect`
holds `consecutive_failures`, `last_error` (`null` before any failure, kept after a success) and
`last_success` (`null` before the first). The status also holds `uptime_s`, the `requests`
served, in flight and refused, the `epicbox` listener's state, the wallet's `height` and the
`node_tip`.

`lepic serve --http` also answers payments over HTTP on the wallet it holds, with the listener of
`http listen` (same limits, same `/v2/foreign` wire format). `--port`, `--internet`, `--coinbase`
and `--coinbase-remote` mean what they mean for `http listen` and need `--http`; without `--port`
the configured listen port is used. A port that cannot be bound stops `serve` from starting.
Behind a local reverse proxy every caller is loopback, so `--coinbase` then serves every caller
the proxy forwards. Payments, API calls and Epicbox receipts take turns on the wallet. The status
then shows the listener, and the report `serve` prints when it stops holds its counts:

```
{"refresh": {...}, "collect": {...},
 "http": {"port": 3415, "exposure": "local", "received": 2, "repeated": 0, "refused": 0,
          "coinbase": "off"}}
```

`coinbase` is `off`, `local` or `remote`. The `http` object is absent without `--http`; in the
final report it has the same fields without `coinbase`.

The socket is `<data_dir>/lepic.sock`; `--socket <PATH>` picks another. The path must fit a Unix
socket (107 bytes on Linux), or `serve` exits with a usage error that names `--socket`. The socket
has mode 600 and `serve` drops connections from any other user. A socket file left by an earlier
`serve` is replaced; any other file at the path is an error and is left alone. The socket is removed
when `serve` stops.

### Commands while serve runs

While `serve` holds a wallet, a `lepic` command on that wallet that has a route in the API runs on
serve's wallet through its socket (ADR 0053). `lepic` tries the socket the data directory's
`serve-socket` file names (`serve --socket <path>` writes it, and removes it on exit), then the
default `<data dir>/lepic.sock`. A command prints what it prints when it runs on its own: the same
JSON with `--output json`, the same text without it (including the hint under an error), and the
same error, kind and exit code when it fails. It asks for no password: the socket admits only
serve's own user, and serve holds the wallet unlocked. It runs with serve's settings, and prints
no progress lines on stderr.

Files a command reads (`--file`, payloads, codes, answers, a contact backup) are read by `lepic` and
sent in the request. Files it writes (`contact export`, `profile domain file`) are written by
`lepic` from the answer, with the same checks as a direct run (`--force`, owner-only mode).

| Command | Route |
| --- | --- |
| `wallet info` | `GET /v1/wallet` |
| `wallet address` | `GET /v1/wallet/address` |
| `wallet outputs` | `GET /v1/outputs` |
| `wallet scan` | `POST /v1/wallet/scan` |
| `node status` | `GET /v1/node` |
| `tx list` | `GET /v1/transactions` |
| `tx show <TX_ID>` | `GET /v1/transactions/{id}` |
| `tx cancel`, `tx release`, `tx post` | `POST /v1/transactions/{id}/cancel`, `/release`, `/post` |
| `tx send --to <ADDRESS or URL>` | `POST /v1/transactions` |
| `epicbox status` | `GET /v1/epicbox` |
| `epicbox peer` | `GET /v1/epicbox/peers/{address}` |
| `profile show`, `profile set` | `GET`, `PATCH /v1/profile` |
| `profile domain show`, `attach`, `file` | `GET /v1/profile/domain`, `POST .../attach`, `POST .../file` |
| `peer pins`, `peer forget` | `GET`, `DELETE /v1/peer-pins` |
| `contact invite`, `request`, `requests`, `request-accept`, `request-dismiss`, `request-cancel` | `/v1/contacts/invites`, `/v1/contacts/requests`, `/v1/contacts/requests/{id}/accept`, `DELETE /v1/contacts/requests/{id}`, `DELETE /v1/contacts/{id}/request` |
| `contact open`, `accept`, `enter`, `collect`, `sas`, `show-card`, `scan-card` | `/v1/contacts/preview`, `/accept`, `/enter`, `/collect`, `/{id}/sas`, `/card`, `/cards/scan` |
| `contact list`, `remove`, `label`, `allow-invoices` | `GET /v1/contacts`, `DELETE /v1/contacts/{id}`, `PATCH /v1/contacts/{id}` |
| `contact move`, `move-home`, `check`, `key-check`, `keys` | `/v1/contacts/{id}/move`, `/move-home`, `/{id}/check`, `/{id}/key-check`, `/{id}/keys` |
| `contact invoices`, `quarantine` | `GET /v1/contact-invoices`, `GET /v1/contacts/quarantine` |
| `contact export`, `import` | `POST /v1/contacts/export`, `/import` |
| `contact payload post`, `list`, `ack <ID>` | `POST /v1/contacts/{id}/payloads`, `GET /v1/payloads`, `POST /v1/payloads/{id}/ack` |
| `in-person invoice`, `send`, `read`, `pay`, `receive` | `POST /v1/in-person/invoices`, `/sends`, `/read`, `/pay`, `/receive` |
| `in-person post`, `take`, `answers`, `finalize` | `POST /v1/in-person/{id}/post`, `POST /v1/in-person/take`, `GET .../{id}/answers`, `POST .../{id}/finalize` |
| `epic1 address`, `link`, `links`, `retire`, `read`, `pay` | `/v1/epic1/address`, `/links`, `/links/{n}/retire`, `/read`, `/pay` |
| `epic1 post-next`, `answers`, `post-answer`, `restore` | `/v1/epic1/{id}/post-next`, `/answers`, `/{id}/post-answer`, `/restore` |
| `epictx open` | `POST /v1/epictx/open` |

The route names above are shortened; `docs/api/openapi.json` has each in full.

A command given an option its route has no field for runs on its own and meets the lock. These
options keep a command off serve: `--to-file`, `--to-contact`, `--purpose`, `--allow-plain-http`,
`--tor-binary`, `--lib-dir`, `--fluff` and `--ttl-blocks` on `tx send` (`--ttl-blocks` also on
`in-person read`, `in-person pay` and `epic1 pay`), a `--selection` other than the default, `--offline`
and `--epicbox-off` on the contact, in-person and epic1 commands, `--kind` on `contact invite` and
`contact show-card`, `--out` on the in-person commands, `contact payload ack` with several ids, and an
`epictx open` with text on the command line. `tx send` to an onion address, `tx show --slate-id` and
`epicbox status --listing` do not go through serve either.

Commands that still exit 5 while serve runs, with the reason:

| Command | Reason |
| --- | --- |
| `wallet init`, `restore`, `import-seed`, `import-history` | They create or replace the wallet in the directory serve holds. |
| `wallet password` | The route exists, but the command asks for both passwords on the terminal and `lepic` would hold them in the request; it runs on its own with serve stopped. |
| `serve`, `epicbox listen`, `epicbox drain`, `http listen`, `tor listen`, `tor address` | They are listeners or take the wallet for their own run. |
| `api client add`, `list`, `remove` | They edit the client file serve reads at start. |
| `invoice issue`, `pay`, `list`, `decline` | No route covers them. |
| `tx receive`, `tx finalize`, `tx resend` | They read or write slate files, or send by a route with no field for their options. |
| `contact seal`, `open-sealed`, `send-slate`, `plain`, `invoice`, `pay-invoice`, `decline` | No route covers them. |

Any of these exits 5 with `lepic serve is running on this wallet (socket <path>) and this command
does not go through its API`: stop serve to run it, or call the API. A serve whose socket cannot be
reached (its pointer file is stale, or the socket is gone) is not found, and the command meets the
lock: `another lepic process is using the data directory`.

### The API

`docs/api/openapi.json` is the OpenAPI 3.1 document; `GET /v1/openapi.json` serves it.

| Route | Command it runs |
|---|---|
| `GET /v1/status` | the running serve, above |
| `GET /v1/methods` | the methods serve's registry holds, in order, and what each does: `delivers`, `listens` (whether this serve receives slates over it: `epicbox` always, `http` with `--http`), `exchanges`, `notices`, and what a slate over it `carries` |
| `GET /v1/events` | the wallet's events, as server-sent events |
| `GET /v1/wallet` | `wallet info` |
| `GET /v1/wallet/address` | `wallet address` |
| `PUT /v1/wallet/password` | `wallet password`, with `current_password` and `new_password` |
| `GET /v1/outputs?account=` | `wallet outputs` |
| `GET /v1/node` | `node status` |
| `GET /v1/transactions?account=&refresh=` | `tx list`; `refresh=true` as `--refresh` |
| `GET /v1/transactions/{tx_id}?refresh=` | `tx show`; `refresh=true` as `--refresh` |
| `POST /v1/transactions` | `tx send`: `amount`, `to`, and optionally `method` (one of `GET /v1/methods`; Epicbox when absent; the API sends over `epicbox` and `http`), `slate_id`, `account`, `message`, `min_confirmations`, `change_outputs` and `legacy` (as `--legacy`; the report's `dialect` says which went). Over TLS an `http` send goes to other computers only: a `to` naming `localhost`, a loopback or an unspecified address is a 400 `usage` problem and stores nothing, and a host that resolves only to such addresses fails to connect, leaving the send stored and undelivered |
| `POST /v1/slates/receive` | `tx receive`, with the `slate` text; the reply slate is in the report |
| `POST /v1/slates/finalize` | `tx finalize`, with the `slate` text and `fluff` |
| `POST /v1/transactions/{tx_id}/cancel` | `tx cancel` |
| `POST /v1/transactions/{tx_id}/release` | `tx release` |
| `POST /v1/transactions/{tx_id}/post` | `tx post`, with `fluff` |
| `POST /v1/wallet/scan` | `wallet scan`, with `start_height` or `reset_chain` |
| `GET /v1/epicbox` | `epicbox status` |
| `GET /v1/epicbox/peers/{address}` | `epicbox peer` |
| `GET /v1/peer-pins?account=` | `peer pins` |
| `DELETE /v1/peer-pins?origin=&account=` | `peer forget`; `forgotten` is false when no key was pinned |
| `GET /v1/profile` | `profile show` |
| `PATCH /v1/profile` | `profile set`, with `names` or `bits` |
| `GET /v1/profile/domain` | `profile domain show` |
| `POST /v1/profile/domain/file` | `profile domain file`; the file text is in the report, nothing is written |
| `POST /v1/profile/domain/attach` | `profile domain attach` |
| `GET /v1/contacts` | `contact list` |
| `DELETE /v1/contacts/{id}` | `contact remove` |
| `PATCH /v1/contacts/{id}` | `contact label` and `contact allow-invoices`, with `label` or `allow_invoices` |
| `POST /v1/contacts/invites` | `contact invite` |
| `POST /v1/contacts/requests` | `contact request` |
| `GET /v1/contacts/requests` | `contact requests` |
| `POST /v1/contacts/requests/{id}/accept` | `contact request-accept`, with `name` |
| `DELETE /v1/contacts/requests/{id}` | `contact request-dismiss` |
| `DELETE /v1/contacts/{id}/request` | `contact request-cancel` |
| `POST /v1/contacts/preview` | `contact open`, with the `link` text |
| `POST /v1/contacts/accept` | `contact accept` |
| `POST /v1/contacts/enter` | `contact enter`, with one to five `input` words |
| `POST /v1/contacts/collect` | `contact collect` |
| `POST /v1/contacts/{id}/sas` | `contact sas`, which records the verdict |
| `POST /v1/contacts/{id}/check` | `contact check` |
| `POST /v1/contacts/{id}/key-check` | `contact key-check`, with the old pairing in `old` |
| `POST /v1/contacts/{id}/keys` | `contact keys`, which records the choice |
| `POST /v1/contacts/{id}/move` | `contact move`, with `host` for `--apply` |
| `POST /v1/contacts/move-home` | `contact move-home` |
| `POST /v1/contacts/card` | `contact show-card` |
| `POST /v1/contacts/cards/scan` | `contact scan-card` |
| `GET /v1/contacts/quarantine` | `contact quarantine` |
| `GET /v1/contact-invoices` | `contact invoices` |
| `POST /v1/contacts/export` | `contact export`; the records are in `backup`, nothing is written |
| `POST /v1/contacts/import` | `contact import`, with the `backup` text |
| `POST /v1/contacts/{id}/payloads` | `contact payload post` |
| `GET /v1/payloads` | `contact payload list` |
| `POST /v1/payloads/{id}/ack` | `contact payload ack` |
| `POST /v1/in-person/invoices` | `in-person invoice`, with `amount`, `account`, `message` and `ttl_blocks`; the code is `code`, as hex |
| `POST /v1/in-person/sends` | `in-person send`, with `amount`, `account`, `message`, `ttl_blocks`, `min_confirmations` and `change_outputs`; the code is `code`, as hex |
| `POST /v1/in-person/read` | `in-person read`, with the scanned `code` as hex |
| `POST /v1/in-person/pay` | `in-person pay`, with `amount` and the scanned `code` as hex; the sealed answer is `envelope`, as hex |
| `POST /v1/in-person/receive` | `in-person receive`, with the scanned `code` as hex, `account` and `message`; the sealed answer is `envelope`, as hex |
| `POST /v1/in-person/{slate_id}/post` | `in-person post`, with `relay_ok` |
| `POST /v1/in-person/take` | `in-person take`, with `answer`: the hex digits, the armoured text, or the UR parts |
| `GET /v1/in-person/{slate_id}/answers` | `in-person answers` |
| `POST /v1/in-person/{slate_id}/finalize` | `in-person finalize`, with `answer` and `fluff` |
| `GET /v1/epic1/address` | `epic1 address`, with `account` in the query |
| `POST /v1/epic1/links` | `epic1 link`, with `account`, `amount`, `message`, `printed` and `relays` |
| `GET /v1/epic1/links` | `epic1 links` |
| `POST /v1/epic1/links/{n}/retire` | `epic1 retire`, with `account` |
| `POST /v1/epic1/read` | `epic1 read`, with `link` |
| `POST /v1/epic1/pay` | `epic1 pay`, with `link`, `amount`, `account`, `message`, `proof` and `hosts_ok` |
| `POST /v1/epic1/{slate_id}/post-next` | `epic1 post-next`, with `hosts_ok` |
| `GET /v1/epic1/answers` | `epic1 answers` |
| `POST /v1/epic1/{slate_id}/post-answer` | `epic1 post-answer`, with `relay_ok` |
| `POST /v1/epic1/restore` | `epic1 restore` |
| `POST /v1/epictx/open` | `epictx open`, with the file's `text` |

A response body is the command's `--output json` report. Amounts are strings with eight
decimals. An error is RFC 9457 problem details (`application/problem+json`): `type`
`about:blank`, `title`, `status`, `detail` (the error and its causes) and `code`, the error kind
of the table below, plus `tx_id` when the error is about a stored transaction. The kind sets the
status: `usage` 400, `wrong_password` 403, `not_found` 404, `wallet_state` 409, `rejected` and
`insufficient_funds` 422, `internal` and `config` 500, `node`, `transport` and `incomplete` 502,
`interrupted` 503. A route answered on the socket only is 403 `usage` over TLS (see below). An
unknown route is 404, a wrong method 405 with `Allow`, bad JSON or an unknown
field 400, and a body over the limit 413.

In `GET /v1/events` each event's `event` field is its `kind` and its `data` line the event as
JSON. A client that falls behind gets a `lagged` event with `missed`, and the stream goes on.

`lepic-config.toml`'s `[api]` table bounds the API: connections served at once (more are closed
unanswered and counted as refused), the time for a request's headers and for its body, and the
largest body. A call to the wallet has no deadline.

On SIGINT or SIGTERM `serve` stops accepting connections and stops the listener. Each running
request is interrupted as Ctrl-C interrupts the command run on its own, and `serve` waits for every
one to answer: most end at once with `interrupted`, and a send that may have stored its
transaction answers `incomplete` with its `tx_id`. Event streams end. A second signal does nothing,
as for any `lepic` command; SIGKILL ends `serve` at once. It then locks the wallet, removes the
socket and releases the lock. Its report names the socket, the number of requests served and what
the listener received.

### Owner calls over TLS

`lepic serve --owner-tls` also answers the API over TLS 1.3 on TCP, for a client on another
machine. Both sides present a certificate. The address comes from `settings.toml`, and has no
default; without it `--owner-tls` exits with a `config` error before it opens the wallet:

```
[api]
owner_tls = "192.0.2.10:3420"
```

At each start `serve` writes its certificate to `api-tls.pem` in the data directory. It is
self-signed, issued to `lepic-wallet`, never expires, and its key comes from the recovery phrase,
so a restored wallet serves the same certificate. A client trusts that file and checks the name
`lepic-wallet` in place of a host name.

A client presents an Ed25519 certificate. Its dates and issuer are not checked: `serve` accepts it
when the SHA-256 of its public key info is listed in `api-clients` in the data directory.

```
openssl genpkey -algorithm ed25519 -out client.key
openssl req -new -x509 -key client.key -subj /CN=laptop -days 36500 -out client.pem
lepic api client add laptop client.pem
curl --cacert api-tls.pem --cert client.pem --key client.key \
  --resolve lepic-wallet:3420:192.0.2.10 https://lepic-wallet:3420/v1/wallet
```

`lepic api client list` shows the listed clients and `lepic api client remove <name>` takes one
off. They need no wallet and edit `api-clients`, one `<name> <sha256 hex>` per line, where `#`
starts a comment; a name is 1 to 64 letters, digits, `.`, `-` and `_`, and a name or key is
listed once. `add` refuses a file that is not a PEM certificate with an Ed25519 key. `serve`
reads the file at each handshake and again at each request, and resumes no TLS session, so a
change applies without a restart: a removed client's next request gets a 403 problem with code
`usage` and its connection closes. A connection lasts at most `tls_max_connection_age_s` of
`[api]`, which also ends an event stream. A missing file accepts no client; a malformed one
accepts none and logs a warning. The JSON reports are `{"name", "fingerprint"}` for `add` and
`remove`, and `{"clients": [...]}` of those for `list`.

The routes and the `[api]` bounds are those of the socket. Each listener has its own
`max_connections`, so TLS clients cannot take the socket's connections. A handshake that fails
or does not end within the header time counts as refused.
`PUT /v1/wallet/password` is answered on the socket only: over TLS it is a 403 problem with code
`usage`. `GET /v1/status` then holds the listener's address and the fingerprint of its
certificate, the value `lepic api client add` lists for `api-tls.pem`:

```
{"owner_tls": {"address": "192.0.2.10:3420", "fingerprint": "<sha256 hex>"}}
```

## Data and logs

The data directory, `~/.lepic/<network>` unless `data_dir` says otherwise, holds:

- `wallet.vault`, the seed, encrypted with your password through Argon2;
- `wallet.sqlite3`, outputs and transaction history, with private transaction data encrypted;
- `api-tls.pem` and `api-clients`, the certificate of `serve --owner-tls` and the clients it
  accepts;
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

A command line that does not parse is an error of kind `usage` too: with `--output json`, or
`LEPIC_OUTPUT=json`, it prints the same document (exit 2, the parser's message as `message`) and
nothing on stderr. `--help` and `--version` still print text.

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
| 12 | `interrupted` | stopped by Ctrl-C or SIGTERM before it finished |

An error about one stored transaction also carries its `tx_id`. Exit 11 also carries `recovery`,
the commands that finish or give up that transaction, in the order to try them:

```
{"error":{"kind":"incomplete","exit_code":11,"message":"finalize failed","causes":["transaction 3 is finalized but the node did not accept it","..."],"tx_id":3,"recovery":["lepic tx post 3","lepic tx cancel 3"]}}
```

A slate that was not delivered lists `lepic tx resend <ID> --to <ADDRESS>` and `lepic tx cancel
<ID>`; an invoice that was not delivered lists `lepic tx cancel <ID>`; a transaction the node did
not accept lists `lepic tx post <ID>` and `lepic tx cancel <ID>`. The serve API's problem document
carries the same `recovery` list.

 A `tx send` stopped by Ctrl-C
or SIGTERM after it stored its transaction exits 12 with that `tx_id`; `lepic tx show` tells
whether it was delivered, and `tx resend` or `tx cancel` settles it.

## Common errors

With human output, an error ends with a `hint:` line that names what to try next.

| You see | What it means |
|---|---|
| `no wallet exists`, hint `no floonet wallet in ...` | Wrong data directory or network, or no wallet yet: `wallet init` or `wallet restore`. |
| `wallet database belongs to a mainnet wallet, the configuration says floonet` | The data directory holds a wallet of the other chain; pass the matching `--network`. |
| `password did not unlock the wallet` | Wrong password, or `LEPIC_PASSWORD` is set to an old one. |
| `another lepic process is using the data directory` | A `lepic epicbox listen` or other command has the wallet open; stop it first. |
| `lepic serve is running on this wallet (socket ...) and this command does not go through its API` | Stop `serve` to run the command, or call its API; see "Commands while serve runs". |
| `other users can access the data directory` | Run `chmod 700` on it. |
| `could not connect to the node` (exit 9) | The node is not running at `node_url`, or listens elsewhere. |
| `node rejected the api secret` | Set `node_api_secret_file` to the node's `.foreign_api_secret`. |
| `not enough funds` (exit 8) | The hint shows what is spendable. Recent receives and change need `--min-confirmations` blocks, and `--selection all` locks every output until its transaction confirms. |
| `epicbox address rejected` (exit 2) | The address is mistyped or belongs to the other network. Nothing was stored. |
| `stored but was not delivered` (exit 11) | The relay did not take the slate; check the address and its port, then `tx resend` or `tx cancel`. |
| `... is on this device, which a native send does not reach` (exit 7) | A native send to a listener on this computer. Nothing was stored; `--legacy` sends the V2 or V3 slate. |
| `epicbox subscription failed` | The relay at `epicbox_relay` is unreachable. |
| `http address rejected` (exit 2) | The `--to` URL is not `http(s)://host[:port][/path]`, or is plain `http` to another computer without `--allow-plain-http`. Nothing was stored. |
| `invoices go over epicbox or through a slate file, not over http` (exit 2) | `invoice issue --to` was given an address with a scheme (`://`). |
| `the http listener could not start` (exit 10) | Another program holds the port, or the port needs privileges; pick another with `--port`. |
| `the send to the listener stopped: ... shows another key than the pinned one` (exit 7) | The listener's key is not the one pinned for its origin; the hint names both. Nothing was stored. Confirm the change with the payee, then `lepic peer forget <ORIGIN>`, or send with `--legacy`. |
| `the send to the listener stopped: ... is pinned but advertises no native endpoint` (exit 7) | The pinned listener no longer offers native slates. Nothing was stored; `--legacy` sends the V2 or V3 slate. |
| `the send to the listener stopped: transaction N is stored and its native exchange failed` (exit 11) | The endpoint refused or could not be reached; nothing went as a V2 or V3 slate. `tx resend`, with `--legacy` if wanted, or `tx cancel`. |
| `give --tor-binary to use tor` (exit 2) | `tor listen`, or a send to an onion address, needs the path of the tor binary. Nothing was stored. |
| `onion address rejected` (exit 2) | The `--to` address names an onion that is not a valid onion v3 address, or has a typo. Nothing was stored. |
| `tor is not working: tor failed (missing)` (exit 3) | No tor binary at the `--tor-binary` path. Nothing was stored. |
| `tor is not working: tor failed (network)` (exit 10) | Tor could not connect to the Tor network: no internet, or a network that blocks Tor. `(clock)` means the computer's clock is wrong. |
| `invoice amount differs from the approved amount` | The amount you typed is not the one in the invoice; nothing was paid. |
| `invoice ... is not waiting to be paid` (exit 6) | The slate id is not a parked invoice: it was paid, declined or expired. `lepic invoice list` shows the ones waiting. |
| `goes only to the allowed address of its invoice` (exit 7) | `tx resend` of an invoice payment names another key than the invoice's sender; `invoice list` showed it. |
| `was already received as transaction N` | The file is a different slate under the id of one received before, or that transaction was cancelled or expired. The same slate again would have rewritten its reply. |
| `transaction N cannot be released` (exit 7) | The send is not finalized or posted, or no refresh at the height `lepic tx show` names has missed its kernel yet. |
| `transaction N is in the node's pool` (exit 7) | The node may still mine it; refresh later instead of releasing it. |
| `finalized but the node did not accept it` (exit 11) | The node neither took the transaction nor holds its kernel. Check the node, then `lepic tx post <ID>`. |
| `a restore scan must complete before new outputs are created` (exit 5) | The wallet was restored with `--no-scan`, or its database was rebuilt, and its restore scan, from genesis or from the restore's `--from-height`, has not completed since. Run `lepic wallet scan`. |
| `The node is behind the last refresh; balances not updated.` from `wallet info` | The node is still syncing, or the wallet stored a height this chain does not have. Once the node is synced, `lepic wallet scan --reset-chain` recovers. |
