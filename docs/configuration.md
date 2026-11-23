# Configuration

LEPIC takes every server, timeout and limit from its caller. The library crates hold no host and
no default timeout. The `lepic` CLI reads them from three files; a host app passes them through
`lepic-ffi` when it creates, restores or opens a wallet.

This page lists every key of the CLI's files, then the values an app passes through the FFI.
[cli.md](cli.md) covers the commands that use them.

## The three CLI files

| File | Holds | Who changes it |
|---|---|---|
| `config.toml` | The CLI's own settings: data directory, network, logging, Tor, switches | The user |
| `settings.toml` | The node and Epicbox servers, and the owner TLS address | The user |
| `lepic-config.toml` | Timeouts, ports, limits and onion routes | Compiled into the binary |

A setting is resolved once per command, in this order:

1. the command-line flag;
2. its `LEPIC_*` variable;
3. its key in `config.toml`;
4. the default.

An empty variable counts as unset. The CLI reads only `LEPIC_*` variables and `HOME` (else
`USERPROFILE`) from the environment.

## config.toml

The CLI looks for the file here, in order:

1. the path `--config` gives;
2. the path `LEPIC_CONFIG` gives;
3. `~/.lepic/config.toml`.

A file named by the flag or the variable must exist. The default file is read only when it
exists.

The format is a flat subset of TOML: one `key = value` per line, no sections. A value is a bare
word or a double-quoted string, and `#` starts a comment. An unknown key, a repeated key or a
line without `=` fails the command with exit code 3 and names the file and line. A file above
64 KiB is refused.

A relative path in the file is relative to the file's directory. A relative path from a flag or
a variable is relative to the working directory.

```toml
# ~/.lepic/config.toml
node_url = "https://node.btlabs.uk"
log_level = "info"
password_file = "wallet.pass"
refuse_unsolicited_invoices = true
```

### Keys

Switches take `true` or `false` and default to `false`.

| Key | Variable | Meaning and default |
|---|---|---|
| `data_dir` | `LEPIC_DATA_DIR` | The wallet directory. Default `~/.lepic/mainnet`, `~/.lepic/floonet` on floonet |
| `network` | `LEPIC_NETWORK` | `mainnet` or `floonet`, the test chain. Default `mainnet`. Floonet has its own data directory, settings file, node and mailbox; see [Floonet](cli.md#floonet). A wallet opens only on the chain it was created on |
| `log_level` | `LEPIC_LOG_LEVEL` | A level or tracing directives. Default `warn` |
| `log_format` | `LEPIC_LOG_FORMAT` | `pretty`, `compact` or `json`. Default `compact` |
| `output` | `LEPIC_OUTPUT` | `human` or `json`. Default `human` |
| `node_url` | `LEPIC_NODE_URL` | The node API root. Default: see [Which node and relay](#which-node-and-relay) |
| `node_api_secret_file` | `LEPIC_NODE_API_SECRET_FILE` | A file holding the node's foreign API secret |
| `password_file` | `LEPIC_PASSWORD_FILE` | A file holding the wallet password, readable by its owner only |
| `epicbox_relay` | `LEPIC_EPICBOX_RELAY` | The relay, as `wss://host[:port]`, `host[:port]`, or `ws://host[:port]` for a loopback host |
| `local_mailbox` | `LEPIC_LOCAL_MAILBOX` | `true` to make the relay the whole mailbox list, for a stack on this device, such as the acceptance stack. Only with a loopback `epicbox_relay` and no `[mailboxes] added` or `removed`. Default `false` |
| `connection_mode` | `LEPIC_CONNECTION_MODE` | `all`, `tor-only` or `offline`; also `--connection-mode`. `tor-only` connects only through the Tor the `epicbox_tor` keys name, and is `offline` without one. `offline` connects nowhere. Default `all` |
| `http_direct` | `LEPIC_HTTP_DIRECT` | Switch: reach http payees, the `http` entries of links and the webhook directly while a Tor is named. Refused with `connection_mode` `tor-only`. Default `false` |
| `epicbox_tor_socks` | `LEPIC_EPICBOX_TOR_SOCKS` | Reach the relay through the Tor SOCKS5 proxy at this loopback `ip:port` |
| `epicbox_tor_binary` | `LEPIC_EPICBOX_TOR_BINARY` | Reach the relay through a Tor the CLI runs from this binary |
| `epicbox_tor_lib_dir` | `LEPIC_EPICBOX_TOR_LIB_DIR` | The libraries that Tor binary needs |
| `node_over_tor` | `LEPIC_NODE_OVER_TOR` | Switch: reach the node through the same Tor as the relay |
| `relay_sockets` | `LEPIC_RELAY_SOCKETS` | `lepic serve`: `shared` or `split`, see [Relay sockets](#relay-sockets). Default `shared`, `split` when a Tor key is set |
| `refuse_unsolicited_payments` | `LEPIC_REFUSE_UNSOLICITED_PAYMENTS` | Switch: refuse payments nobody asked for |
| `refuse_unsolicited_invoices` | `LEPIC_REFUSE_UNSOLICITED_INVOICES` | Switch: refuse invoices from contacts |
| `max_open_receipts` | `LEPIC_MAX_OPEN_RECEIPTS` | Payments nobody asked for that wait for their senders to finalize, over all senders, 1 to 100000. Default 100. At the cap a further payment is refused with `receipts_full` and nothing is cancelled to make room |
| `max_open_receipts_per_sender` | `LEPIC_MAX_OPEN_RECEIPTS_PER_SENDER` | The same count for one sender key, 1 to 100000. Default 10 |
| `epic1_web_listener` | `LEPIC_EPIC1_WEB_LISTENER` | Switch: the HTTP listener also answers `/api/v1/inbox` and takes payments sealed to this wallet's epic1 addresses there. Off by default: the path is then not found, as on a stock listener |
| `epic1_onion_listener` | `LEPIC_EPIC1_ONION_LISTENER` | Switch: the same, for the onion listener |
| `epic1_require_proof` | `LEPIC_EPIC1_REQUIRE_PROOF` | Switch: cancel a payment to an epic1 address whose answer brings no valid payment proof, as `--require-proof` does for one payment. Off by default |
| `invoice_expiry_hours` | `LEPIC_INVOICE_EXPIRY_HOURS` | Hours an unpaid Epicbox invoice is kept, a whole number of at least 1. Default 24 |
| `send_ttl_blocks` | `LEPIC_SEND_TTL_BLOCKS` | Blocks after which an unanswered send expires when `--ttl-blocks` or `ttl_blocks` names none, 1 to 525600. Default 10080 (7 days). An invoice keeps 1440 |
| `final_confirmations` | `LEPIC_FINAL_CONFIRMATIONS` | Confirmations after which a payment is final: `lepic serve` sets `final` on it and logs `payment.confirmations_reached`, 1 to 1440. Default 6 |
| `payment_confirmations` | `LEPIC_PAYMENT_CONFIRMATIONS` | The old name of `final_confirmations`, read when that is not set |
| `host_features` | `LEPIC_HOST_FEATURES` | Host feature bits the wallet claims, comma-separated: `device-forwarding`, `name-service`. Default none |
| `profile` | `LEPIC_PROFILE` | Profile bits told to paired contacts: `no-payments`, `automated`, or a number 0 to 65535. Default 0 |
| `domain` | `LEPIC_DOMAIN` | A domain the wallet claims to paired contacts, proven by its well-known file. Default none |
| `shell_idle_lock_minutes` | `LEPIC_SHELL_IDLE_LOCK_MINUTES` | Minutes with no line entered before the interactive shell locks the wallet; 0 never locks it. Default 15 |
| `webhook_url` | `LEPIC_WEBHOOK_URL` | `lepic serve`: the `https://` endpoint that gets the event log by POST. Needs `webhook_secret_file`. Default none |
| `webhook_secret_file` | `LEPIC_WEBHOOK_SECRET_FILE` | A file only its owner can read, one `whsec_<base64>` secret per line, read before each delivery |
| `webhook_types` | `LEPIC_WEBHOOK_TYPES` | Event types the webhook sends, comma-separated, `payment.*` allowed. Default all |
| `webhook_allow_private` | `LEPIC_WEBHOOK_ALLOW_PRIVATE` | Switch: the webhook URL may be `http://` and may resolve to a loopback, private or link-local address |
| `settings_file` | `LEPIC_SETTINGS` | The settings file. Default `~/.lepic/settings.toml`, `~/.lepic/settings-floonet.toml` on floonet |

The Tor keys go together as follows:

- `epicbox_tor_socks` and `epicbox_tor_binary` exclude each other.
- `epicbox_tor_lib_dir` needs `epicbox_tor_binary`.
- `node_over_tor` needs one of the two.

Any other combination fails with exit code 3.

### Relay sockets

`lepic serve` reads mail over mux/1 sessions, one socket for many slots, where the mailbox
offers it. `relay_sockets` says which slots share a socket:

| `relay_sockets` | What the mailbox can link | Sockets per mailbox | Suits |
|---|---|---|---|
| `shared` | the payments address and every contact | 1 | a public service |
| `split` | nothing across the two, only under Tor | 2 | a private user, or a service that hides its contacts |

The default is `shared`, and `split` when `epicbox_tor_socks` or `epicbox_tor_binary` is set. A
socket for each contact is not offered. `split` without a Tor logs one warning at start, because
every socket then comes from the same address and the split hides little. Any other value fails
with exit code 3.

A mailbox may cap the slots on one socket. When serve reaches the cap it opens another socket
in the same group, so it holds hundreds of contacts. The Epicmail server's defaults: 256 slots per
socket, 64 per Attach frame, 30 Attach frames a minute per socket, 64 mux sockets per IP prefix
and 1200 signature checks a minute per IP. That is about 16,000 slots per IP.

## settings.toml

`settings.toml` lists the servers. Its layout is that of the Epic Cash wallet app's file of the
same name, so a copy of the app's file works. The CLI reads the keys below and ignores every
other key and section.

The CLI finds the file in this order:

1. the path `--settings` gives;
2. the path `LEPIC_SETTINGS` gives;
3. `settings_file` in config.toml;
4. `~/.lepic/settings.toml`, or `~/.lepic/settings-floonet.toml` on floonet.

A file named by any of the first three must exist; otherwise the command fails with exit code 3
and "settings file … could not be read".

When `~/.lepic/settings.toml` does not exist, the CLI writes it from the copy it ships with,
`crates/lepic-cli/settings.default.toml`; after that only `lepic mailbox add` and
`lepic mailbox remove` change it. When the file cannot
be written, the shipped servers are used as they are.

On floonet the file is `~/.lepic/settings-floonet.toml`, written the same way from
`crates/lepic-cli/settings.floonet.toml`: the node `https://floo-node.btlabs.uk` and the
mailbox `epicbox.btlabs.uk`. The two files do not share edits.

The file must be valid TOML of at most 256 KiB. An invalid server or mailbox fails the command
with exit code 3 and names the key.

### Keys

| Key | Type | Meaning |
|---|---|---|
| `[node] servers` | list of URLs | The nodes the wallet knows. The first is the one in use; the shell offers the others when it does not answer |
| `[epicbox] servers` | list of `host` or `host:port` | The Epicbox relays of the wallet's Legacy address, reached over TLS. The first is the one in use. A wallet upgraded from a release that read its mail there also keeps its relay as an added mailbox, unless it is not a public name over TLS, is in the list already, the user removed it, or the list is full |
| `[mailboxes] added` | list of `host` or `host:port` | Mailboxes the user added to the shipped list, in order. Each is a public domain reached over TLS |
| `[mailboxes] removed` | list of `host` or `host:port` | Mailboxes the user took off the shipped list. A removed host stays removed when a later release ships it |
| `[api] owner_tls` | `"ip:port"` | Where `lepic serve --owner-tls` listens. No default: `--owner-tls` refuses to start without it |

An empty list is allowed when `node_url` or `epicbox_relay` names the server instead. Without
either, every command fails with exit code 3 and names that key.

The file stores only the user's changes to the mailbox list, so a release that changes its
shipped list (`[mailboxes] shipped` in lepic-config.toml) reaches every wallet. The list is the
shipped mailboxes without the removed ones, then the added ones, at most 16. More than 16
entries in `added` or `removed`, an entry that is not a public domain with an optional port
other than 0, or a list with nothing left fails the command with exit code 3 and names the key.

### The shipped file

```toml
version = 1

[node]
servers = ["http://127.0.0.1:3413"]

[epicbox]
servers = ["epicbox.btlabs.uk", "epicbox.epiccash.com", "epicbox.epicnet.us", "epicbox.stackwallet.com"]

[mailboxes]
# added = ["mailbox.example.com"]
# removed = []

[api]
# owner_tls = "ip:port"

[online]
```

The shipped file carries a comment on each key; `version` and `[online]` are part of the app's
layout and the CLI reads neither.

### Which node and relay

- **Node:** `node_url` when set, else the first of `[node] servers`. The shell's `node use`
  writes `node_url` to config.toml.
- **Relay:** `epicbox_relay` when set, else the first of `[epicbox] servers`. It serves the
  Legacy Epicbox address. An upgraded wallet also reads native mail there, as a carried mailbox
  (see `[epicbox] servers` above).
- **Mailboxes:** the list above. Native mail, payment links and in-person codes use it.

## lepic-config.toml

The built-in configuration is compiled into the binary from `crates/lepic-cli/lepic-config.toml`
and changes only with a new build. Every key is required and unknown keys are refused; a zero,
or a minimum above its maximum, is refused too. Its layout is that of the Epic Cash wallet
app's `app-config.toml`.

### [node]

| Key | Value | Meaning |
|---|---|---|
| `connect_timeout_s` | 15 | Opening a connection to the node. A dial without Tor in the FFI gives the name lookup and the connect this long each |
| `request_timeout_s` | 90 | From sending a request to the last byte of its answer |
| `idle_timeout_s` | 10 | How long an idle connection is kept |
| `retry_attempts` | 3 | Tries of a failed read, the first included |
| `retry_backoff_min_ms` | 500 | The wait before the second try; it doubles after that |
| `retry_backoff_max_ms` | 4000 | The longest wait between tries |
| `outputs_per_request` | 500 | Outputs asked for in one request |
| `concurrent_requests` | 4 | Output requests in flight at once |
| `public` | `https://node.btlabs.uk`, `https://node.epiccash.com:3413`, `https://node.epicnet.us:3413`, `https://epic.stackwallet.com:3413` | Public nodes the shell offers when the node in use does not answer: those the Epic Cash wallet app ships with |

### [epicbox]

| Key | Value | Meaning |
|---|---|---|
| `address_default` | `epicbox.epiccash.com` | The relay of an Epicbox address written without one |
| `connect_timeout_s` | 15 | The TCP, TLS and websocket handshakes together |
| `response_timeout_s` | 15 | Each relay answer |
| `ping_interval_s` | 25 | Websocket pings to the relay |
| `reconnect_min_s` | 1 | The first wait before reconnecting; it doubles after that |
| `reconnect_max_s` | 60 | The longest wait before reconnecting |
| `drain_timeout_s` | 120 | One whole mailbox drain |
| `tor_connect_timeout_s` | 90 | The least a relay connection through Tor is given |
| `onion_discovery_timeout_s` | 45 | Asking a relay for its onion through Tor |
| `onion_discovery_retry_s` | 600 | How long a relay that could not be asked is left alone |

### [mailboxes]

| Key | Value | Meaning |
|---|---|---|
| `shipped` | `epicbox.btlabs.uk`, `epicbox.epiccash.com`, `epicbox.epicnet.us` | The mailboxes this release ships, each `host` or `host:port` reached over TLS. A native message goes to 3 mailboxes of the list, the healthiest, and is read on all of them. 1 to 16 distinct public domains; a release ships at least 3 that serve push sessions, run by at least two operators, and changes at most one of them. `settings.toml` `[mailboxes]` adds to and removes from it |

### [floonet]

What differs on floonet. The CLI picks this table instead of `[node] public`,
`[epicbox] address_default` and `[mailboxes] shipped` when `network` is `floonet`.

| Key | Value | Meaning |
|---|---|---|
| `public` | `https://floo-node.btlabs.uk` | The public node the shell offers |
| `address_default` | `epicbox.btlabs.uk` | The relay of an Epicbox address written without one; `epicbox.epiccash.com` has no floonet relay |
| `mailboxes` | `epicbox.btlabs.uk` | The shipped mailbox list, 1 to 16 distinct public domains |

### [http]

The HTTP listener of `lepic listen` and sends to other wallets' listeners.

| Key | Value | Meaning |
|---|---|---|
| `listen_port` | 3415 | The port `listen` takes unless `--port` names another |
| `header_timeout_s` | 10 | A request line and headers |
| `body_timeout_s` | 15 | A body, once the headers are in |
| `request_timeout_s` | 60 | From the first byte of a request to the last byte of its answer |
| `answer_timeout_s` | 10 | The sender taking the answer |
| `max_connections` | 16 | Connections served at once |
| `max_connections_per_address` | 4 | Connections served at once from one address |
| `requests_per_minute` | 120 | Requests of any kind taken in a minute |
| `receives_per_minute` | 30 | Payments taken in a minute |
| `send_connect_timeout_s` | 10 | Opening a connection to another wallet's listener |
| `send_request_timeout_s` | 60 | A send, to the last byte of its answer |

### [api]

The wallet API of `lepic serve`.

| Key | Value | Meaning |
|---|---|---|
| `max_connections` | 32 | Connections served at once on the socket, and again on the TLS listener. As many more on each are answered 503 `busy` with `Retry-After`; past those a connection is closed unanswered |
| `header_timeout_s` | 10 | A request line and headers, and an idle connection |
| `body_timeout_s` | 15 | A body, once the headers are in |
| `max_body_kib` | 8192 | The largest request body read |
| `tls_max_connection_age_s` | 600 | How long one owner TLS connection lasts |

### [tor]

| Key | Value | Meaning |
|---|---|---|
| `bootstrap_timeout_s` | 120 | Bootstrapping with a cached consensus |
| `cold_bootstrap_timeout_s` | 240 | Bootstrapping without one |
| `stall_timeout_s` | 60 | Unchanged bootstrap progress this long is a network failure |
| `cold_stall_timeout_s` | 120 | The same without a cached consensus |
| `publish_timeout_s` | 180 | Uploading the wallet's onion descriptor |
| `connect_timeout_s` | 75 | Reaching a host or an onion through Tor |
| `request_timeout_s` | 120 | One send to an onion, to the last byte of its answer |
| `onion_only_domains` | `["btlabs.uk"]` | Hosts under these domains refuse Tor exits, so over Tor they are reached only at their onion |

### [[tor.onions]]

Servers that are also onion services, at most 256. While the CLI reaches the relay or the node
through Tor, a connection to `host:port` goes to `onion:onion_port` and still checks the TLS
certificate of `host`. Only routes with `tls = true` are used.

| Key | Meaning |
|---|---|
| `host`, `port` | The server's name and port |
| `onion`, `onion_port` | Its onion service: 56 characters and `.onion`, and the port |
| `tls` | Whether the server speaks TLS |

The built-in routes are for `epicbox.btlabs.uk` and `node.btlabs.uk`, both on port 443.

## Through the FFI

An app passes the same values to `lepic-ffi` in a `WalletConfig` when it creates, restores or
opens a wallet (`EpicWallet::create`, `open` and their PIN and seed-file forms). The app keeps its own copies of the two files: the user's
`settings.toml` and its built-in `app-config.toml`. [ffi.md](ffi.md) covers the calls.

### WalletConfig

| Field | Meaning |
|---|---|
| `data_dir` | The wallet's own directory; it must exist |
| `chain` | `Mainnet` or `Floonet` |
| `node_url`, `node_api_secret` | The node API root and its basic-auth secret. The secret never goes in the URL |
| `epicbox_domain`, `epicbox_port` | The relay. An empty domain turns Epicbox off. A loopback host gets a plain websocket, any other TLS |
| `onion_routes` | The `[[tor.onions]]` routes, as `OnionRoute { host, port, onion, onion_port }` |
| `tuning` | The `[node]`, `[epicbox]`, `[http]` and `[tor]` values, as `NetTuning` |
| `offline` | A cold-wallet session: every node and relay call fails at once with `Offline` |
| `tor_wanted` | The app starts Tor for this session, so nothing goes out directly before it |
| `host_features` | The app's host feature bits: 4 (linked-device forwarding) and 5 (name service) |
| `profile` | The owner's profile bits for paired contacts, 0 for none |
| `domain` | The domain the wallet claims, `None` for none |
| `policy` | The app's limits and presets, as `HostPolicy` |

`EpicWallet::set_servers` moves an open wallet to another node or relay; it keeps the
wallet's tuning and onion routes. `EpicWallet::set_onion_routes` replaces the routes.

### NetTuning

`NetTuning` has four groups, `node`, `epicbox`, `http` and `tor`. Their fields carry the names and
units of the `lepic-config.toml` keys above, without `listen_port` and `address_default`. `epicbox.collect_every_s` is the binding's only: the base interval of the
binding's delivery loop, in seconds, which Dart fills with 30 when it is left out. Every other field
is required. A zero, or a minimum above its maximum, fails the call with `InvalidArgument` and names
the key, for example `tuning node.retry_attempts is out of range`. The `tor` group is checked in a
build without Tor too, so one app configuration fits both builds.

### HostPolicy

Limits and presets that are the app's to choose. Every field is optional; `None` takes the
default below. A value out of range fails the create, restore or open call with
`InvalidArgument`.

| Field | Default | Allowed |
|---|---|---|
| `default_strategy` | `Smallest` | |
| `send_ttl_blocks` | 10080 | at least 1 |
| `invoice_ttl_blocks` | 1440 | at least 1 |
| `max_change_outputs` | 10 | at least 1 |
| `max_excluded_outputs` | 500 | 0 allows none |
| `invoice_expiry_default_s` | 86400 | 1 to `invoice_expiry_max_s` |
| `invoice_expiry_max_s` | 172800 | at least 1 |
| `max_invoice_ttl_lead_blocks` | 2880 | 1 to 525600 |
| `max_open_receipts_per_sender` | 10 | |
| `max_open_receipts` | 100 | |
| `default_minimum_confirmations` | 6 | at least 1 |
| `contact_check_answers_per_hour` | 1 | at most the per-day value |
| `contact_check_answers_per_day` | 3 | 1 to 24 |
| `contact_hold_attempts` | 3 | 1 to 10 |
| `contact_hold_patience_s` | 180 | 1 to 86400 |
| `refuse_unsolicited_payments` | off | |
| `refuse_unsolicited_invoices` | off | |
| `listener_held_rounds` | no limit | 1 to 64 |
| `listener_challenge_rounds` | 3 | 2 to 10; the interval is the gap between two periodic challenges (not the greeting), at least 30 s, 60 s until two are seen |
| `quarantine_max_bytes` | no limit | 1 to 67108864 |
| `early_notice_max_count` | no limit | 1 to 10000, set with `early_notice_max_age_s` |
| `early_notice_max_age_s` | no limit | 1 to 2592000 |
| `publish_previous_onion` | `false` | |

The doc comments in `crates/lepic-ffi/src/api/policy.rs` say what each field limits.

### PinSettings

The PIN rules are runtime-wide. An app passes them to `LepicRuntime::with_pin_settings`; every
field is optional.

| Field | Default | Meaning |
|---|---|---|
| `min_len` | 6 | The shortest PIN, at least 1 |
| `free_failures` | 3 | Wrong PINs before a delay |
| `first_delay_s` | 30 | The first delay; it doubles after each further failure |
| `max_delay_s` | 3600 | The longest delay, at least `first_delay_s` |

## Settings or host parameters

Two decisions split the values between the files and the caller.

- **Servers and tuning come from configuration**
  ([ADR 0030](adr/0030-all-configuration-in-settings-toml.md)). No host name, URL, address,
  port, onion or server timeout is written in LEPIC's code. The servers sit in the user's
  `settings.toml`; the timeouts, ports, limits and onion routes in the built-in file. What both
  sides of a protocol must agree on stays in code: the default ports of an address without one,
  wire formats and size limits, crypto and consensus values, the node's API paths and the
  bounds against a hostile relay or node.
- **Policy values are host parameters**
  ([ADR 0036](adr/0036-policy-values-are-host-parameters.md)). A limit or preset that is the
  app's choice is a `HostPolicy` or `PinSettings` field with a default. Bounds that guard the
  engine stay in core: a minimum of 1 confirmation, and 525,600 blocks for the payer's lag cap
  and the invoice TTL lead. The length of a new password and an upper bound on confirmations
  are the host's to check; the CLI checks neither.

The CLI runs the engine with its policy defaults, except for the two `refuse_unsolicited_*`
switches of config.toml. It applies `invoice_expiry_hours` itself.

## Related

- [cli.md](cli.md): the commands, data directory and exit codes
- [ffi.md](ffi.md): the Flutter binding
- [ADR 0030: all configuration in settings.toml](adr/0030-all-configuration-in-settings-toml.md)
- [ADR 0036: policy values are host parameters](adr/0036-policy-values-are-host-parameters.md)
- [`lepic-cli`](../crates/lepic-cli/README.md)
