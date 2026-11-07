# Logging and diagnostics

Logs are how a user's bug report becomes a fix. Every log line must be useful to someone who has only
the log file, and none may leak what protects the user's money or privacy.

## Mechanics

- Use `tracing` only. Library crates emit spans and events and never install a subscriber.
- `lepic-telemetry` builds subscribers for the CLI (pretty, compact or JSON, optional rotating file)
  and for mobile (records forwarded to a host callback, which the app sends to Logcat or os_log and
  its own log export).
- Instrument operations, not helpers: `#[instrument(skip_all, fields(...))]` on each engine
  operation, transport session and node call. Always `skip_all`, then list the fields you want, so
  arguments are never Debug-printed by accident.

## One vocabulary

Messages are short lowercase statements of fact in the past tense: `"slate received"`,
`"epicbox subscribed"`, `"output restored"`. Context goes in fields, never interpolated into the
message. Use these field names and add new ones to this list in the same change:

| Field | Meaning |
|---|---|
| `wallet` | wallet instance id (not the seed, not an address) |
| `account` | account label |
| `tx_id` | local transaction log id |
| `slate_id` | slate UUID |
| `stage` | slate stage, for example `S1` |
| `codec` | slate codec id |
| `transport` | transport id: `epicbox`, `file` |
| `relay` | Epicbox relay host of the wallet itself; the log ring redacts it |
| `peer_relay` | a contact's or a meeting relay's host; the log ring redacts it |
| `node` | node host; the log ring redacts it |
| `msg_id` | relay message id |
| `reason` | why a contact message is in quarantine: a stable name |
| `height` | block height |
| `attempt` | retry number, starting at 1 |
| `elapsed_ms` | duration of the operation |
| `error` | the error, with its source chain |
| `tag` | app-chosen tag of a line the app logs under target `dart` |
| `status` | outcome of an operation that reports one instead of failing, such as a history import |
| `count` | number of records an operation handled |

## Levels

| Level | Use for |
|---|---|
| `error` | The operation failed and the user or operator must act. |
| `warn` | Degraded or retrying; the wallet will recover on its own. |
| `info` | State changes a user would recognise: transaction stages, sync progress, connection up or down. |
| `debug` | Protocol steps and decisions useful to a developer. |
| `trace` | Wire-level detail, always redacted. Off by default everywhere. |

Log an error once, where it is handled, not at every layer it passes through.

## The log ring

On mobile, `LogRing` (`LepicRuntime::open_log_ring`) keeps records on the device for a problem
report. The app attaches the ring's files to the report as they are, so the ring's redaction is the
last one before a report leaves the device. It runs before a record reaches the disk:

- Field values are kept for `wallet`, `account`, `tx_id`, `slate_id`, `stage`, `codec`,
  `transport`, `msg_id`, `height`, `attempt`, `elapsed_ms`, `retry_in_ms`, `code`, `error` and
  `tag`. Every other field, including `relay`, `peer_relay` and `node`, is written as
  `name=[redacted]`.
- Messages, LEPIC's own and the app's (`dart` target, through `LepicRuntime::log_message`), the
  kept values and `error` texts all go through one text redaction:

| What | Written as |
|---|---|
| A slate (JSON with a slate key), from its first `{` on | `[slate]` |
| An armoured slatepack | `[slatepack]` |
| 8 or more recovery-phrase words in a row, any case and separators, one typo per 8 words | `[words]` |
| The value after a key-like name: `password`, `pin`, `seed`, `mnemonic`, `phrase`, `token`, `secret`, `key`, `nonce`, `mask`, `blind`, `commit`, `excess`, `signature`, `slate`, `cookie`, `authorization`…, also inside longer names (`wallet_password`, `apiKey`) unless they end in `id`, `len`, `count` or similar; after `:` or `=` up to the end of the line or the next `,` or `;` | `[redacted]` |
| `Bearer` and `Basic` credentials, `--password` arguments, 4 to 8 digits after `pin` | `[redacted]` |
| A number before `EPIC` or `nanoEPIC`, also glued to it (`1.5EPIC`), an amount bucket such as `[<10 EPIC]`, a number after `amount`, `fee`, `balance`, `spendable` and the like, a bare decimal number such as `1.5` (not `v4.1`, `1.5s` or `99.5%`) | `[amount]` |
| A number after `port` | `[redacted]` |
| Text quoted with `"` or `` ` `` | `[redacted]` |
| A URL | its scheme and `[host]`, without user, port, path or query; on an onion address the address's fingerprint; on a loopback host that host and port |
| An email address | `[email]` |
| An IP address or a host name, with its port; a name of two lower-case labels only with a port or a known or two-letter top-level domain, so `state.balance` stays | `[ip]`, `[host]`; loopback and `localhost` are kept |
| A home folder: `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `/root`; a UNC host | `~`; `\\[host]\` |
| An Epicbox, onion, slatepack or other base58 address or key | its first and last 4 characters: `esWW…K3oa@[host]`, `abcd…wxyz.onion`, `epic1qpzr…4khc` |
| A UUID, such as a slate id | its first 8 characters: `0436430c…` |
| 32 or more hex digits | `[hex]` |
| Base64 of 40 or more characters, any other run of 64 or more token characters that is not a URL or a path (`/…`, `~/…`) | `[redacted]` |

A line holds at most 4 KiB. The redaction reads at most four times that of each message or value;
one cut there also loses the last 512 bytes of what its redaction gives, so no piece of a value cut
in two is written.

Targets, span names and field names are kept as they are, so they must never carry values.

## Never log

Seeds, mnemonics, passwords, private keys, blinding factors, nonces, keychain masks, decrypted
Epicbox payloads, full slates, range proofs or signatures. Amounts and addresses appear at `debug`
and below only. Secret types wrap their contents so `Debug` and `Display` print `[redacted]`, and a
test in `lepic-telemetry` asserts that known secrets never appear in captured output.
