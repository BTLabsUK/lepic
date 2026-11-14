# Logging and diagnostics

LEPIC logs with `tracing`. Library crates emit spans and events; the CLI and the mobile runtime
install the subscriber. This page lists how to emit a record, the field names, the levels, the
device log ring and what is never logged.

## Mechanics

- Library crates only emit. They never install a subscriber.
- `lepic-telemetry` builds the subscribers:
  - `CliTelemetry` writes to stderr in `pretty`, `compact` or `json` format. It can also write a
    rotating file (`FileLog`); the CLI does not enable the file.
  - `host_dispatch` forwards each record to a `LogSink` of the host app. The FFI runtime
    (`lepic-ffi`) uses it, and the app sends the records to Logcat or os_log and to its own log
    export.
- `LogFilter` takes `tracing-subscriber` env-filter syntax, for example
  `info,lepic_epicbox=debug`. Anything a directive does not cover is recorded at `info` and above.
  `LogFilter::from_env` reads `LEPIC_LOG`.
- Instrument operations, not helpers: `#[instrument(skip_all, fields(...))]` on an engine
  operation, a transport session or a node call. Use `skip_all` and list the fields to record, so
  arguments are never debug-printed.

### CLI settings

| Setting | Environment variable | Default |
|---|---|---|
| `log_level` | `LEPIC_LOG_LEVEL` | `warn` |
| `log_format` | `LEPIC_LOG_FORMAT` | `compact` |

`log_level` takes a level or filter directives. `log_format` is `pretty`, `compact` or `json`.
A JSON line is one flattened event: its fields at the top level and a `spans` list of the
enclosing spans.

```sh
LEPIC_LOG_LEVEL=info,lepic_epicbox=debug LEPIC_LOG_FORMAT=json lepic wallet info
```

### Mobile settings

The app picks a `LogLevel` (`error` to `trace`) when it starts the runtime. The app logs through
`LepicRuntime::log_message(level, tag, message)`. Those records use the target `dart`. The tag
keeps ASCII letters, digits and `_`, at most 32 characters. The message is cut at 1,024 bytes.

## Field names

A message is a short lowercase statement of fact, in the past tense: `"slate received"`,
`"epicbox subscribed"`. Context goes into fields, never into the message. Use these names; add a
new name to this table in the same change.

| Field | Meaning |
|---|---|
| `wallet` | wallet instance id (not the seed, not an address) |
| `account` | account label |
| `tx_id` | local transaction log id |
| `slate_id` | slate UUID |
| `stage` | slate stage, for example `S1` |
| `codec` | slate codec id |
| `transport` | transport id: `epicbox`, `file` |
| `relay` | Epicbox relay host of the wallet itself |
| `peer_relay` | host of a contact's relay or of a meeting relay |
| `node` | node host |
| `msg_id` | relay message id |
| `reason` | why a message was dropped or quarantined: a stable name |
| `height` | block height |
| `tip` | chain tip height |
| `event_id` | id of an API event |
| `attempt` | retry number, starting at 1 |
| `retry_in_ms` | delay before the next attempt |
| `paused_ms` | length of a process pause, after which Tor deadlines moved |
| `rounds` | rounds a listener held, or challenge intervals it waited without a challenge, before it moved to a fresh socket |
| `interval_s` | seconds between the relay's challenges as a listener learned them; absent until learned |
| `code` | close code a relay sent, or a node's error code |
| `mailbox` | index a mux/1 session gave a mailbox |
| `attach_per_frame`, `mailboxes_per_socket`, `inflight_per_socket` | the limits a relay granted a mux/1 session |
| `retry`, `wait_s` | retry number and wait in seconds while an onion is not reachable yet |
| `elapsed_ms` | duration of the operation |
| `error` | the error with its source chain (`ErrorChain`) |
| `text` | message a node's rejection carried |
| `tag` | app-chosen tag of a line logged under target `dart` |
| `status` | outcome of an operation that reports one instead of failing, or an HTTP status |
| `count` | number of records an operation handled |
| `cleared` | number of quarantined messages cleared by a retry |
| `kind` | kind of a link envelope, or of a node's rejection |
| `origin` | origin of a native endpoint |
| `online` | whether an in-person code was made with a relay host |
| `answer`, `same_code` | answer number of an in-person code, and whether an earlier answer had the same check code |
| `amount` | value of a coinbase output; `debug` only |

The ring keeps the values of the fields marked in the next section and redacts the rest.

## Levels

| Level | Use for |
|---|---|
| `error` | The operation failed and the user or operator must act. |
| `warn` | Degraded or retrying; the wallet recovers on its own. |
| `info` | State changes a user recognises: transaction stages, sync progress, connection up or down. |
| `debug` | Protocol steps and decisions useful to a developer. |
| `trace` | Wire-level detail. Off by default. |

Log an error once, where it is handled, not at every layer it passes through.

## The log ring

`LogRing` keeps redacted records on the device for a problem report. The app opens it with
`LepicRuntime::open_log_ring(dir, max_bytes)`. `max_bytes` is between 4 KiB and 16 MiB; the
default limit is 1 MiB. The ring writes four segment files, `lepic.0.log` to `lepic.3.log`, each a
quarter of the limit, and reuses the oldest when all are full. The app attaches the files to a
report as they are, so the ring's redaction is the last one before a report leaves the device.
Redaction runs before a record reaches the disk.

A line has the form:

```text
<timestamp> <level> <target>[:span...]: <message> name=value ...
```

A line holds at most 4 KiB.

### Fields

The ring keeps the values of these fields: `wallet`, `account`, `tx_id`, `slate_id`, `stage`,
`codec`, `transport`, `msg_id`, `height`, `attempt`, `elapsed_ms`, `retry_in_ms`, `code`, `error`
and `tag`. Every other field, including `relay`, `peer_relay`, `node` and the amounts, is written
as `name=[redacted]`.

Targets, span names and field names are written as they are, so they never carry values.

### Text redaction

Messages (LEPIC's own and the app's), kept values and `error` texts go through one text redaction:

| What | Written as |
|---|---|
| A slate (JSON with a slate key), from its first `{` on | `[slate]` |
| An armoured slatepack | `[slatepack]` |
| 8 or more recovery-phrase words in a row, any case and separators; one other word per 8 is allowed as a typo | `[words]` |
| The value after a key-like name (`password`, `pin`, `seed`, `mnemonic`, `phrase`, `token`, `secret`, `key`, `nonce`, `mask`, `blind`, `commit`, `excess`, `signature`, `slate`, `cookie`, `authorization` and the like), also inside longer names (`wallet_password`, `apiKey`) unless the name ends in `id`, `len`, `count` or similar; after `:` or `=`, up to the end of the line or the next `,` or `;` | `[redacted]` |
| `Bearer` and `Basic` credentials, `--password` arguments, 4 to 8 digits after `pin` | `[redacted]` |
| A number before `EPIC` or `nanoEPIC` (also glued: `1.5EPIC`), an amount bucket such as `[<10 EPIC]`, a number after `amount`, `fee`, `balance`, `spendable` and the like, a bare decimal such as `1.5` (not `v4.1`, `1.5s` or `99.5%`) | `[amount]` |
| A number after `port` | `[redacted]` |
| Text quoted with `"` or `` ` `` | `[redacted]` |
| A URL | its scheme and `[host]`, without user, port, path or query; on an onion address, the address's fingerprint; on a loopback host, that host and port |
| An email address | `[email]` |
| An IP address or host name, with its port. A name of two lower-case labels counts as a host only with a port, a known top-level domain or a two-letter one, so `state.balance` stays. Loopback addresses and `localhost` stay. | `[ip]`, `[host]` |
| A home folder: `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `/root`; a UNC host | `~`; `\\[host]\` |
| An Epicbox, onion, slatepack or other base58 address or key | its first and last 4 characters: `esWW…K3oa@[host]`, `abcd…wxyz.onion`, `epic1qpzr…4khc` |
| A UUID, such as a slate id | its first 8 characters: `0436430c…` |
| 32 or more hex digits | `[hex]` |
| Base64 of 40 or more characters, or any other run of 64 or more token characters that is not a URL or a path (`/…`, `~/…`) | `[redacted]` |

A fingerprint the app wrote with 6 leading characters is cut to 4.

The redaction reads at most four times the line limit of each message or value. A cut there also
drops the last 512 bytes of what the redaction produced, so no piece of a value cut in two is
written.

## Never log

Seeds, mnemonics, passwords, private keys, blinding factors, nonces, keychain masks, decrypted
Epicbox payloads, full slates, range proofs and signatures. Amounts and addresses appear at
`debug` and below only. Secret types wrap their contents so `Debug` and `Display` print
`[redacted]`. `lepic_telemetry::capture` and `assert_no_secrets` let a test check captured output
for known secrets.
