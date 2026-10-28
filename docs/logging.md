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
| `relay` | Epicbox relay host of the wallet itself |
| `peer_relay` | a contact's or a meeting relay's host; support bundles redact it |
| `node` | node host |
| `msg_id` | relay message id |
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

## Never log

Seeds, mnemonics, passwords, private keys, blinding factors, nonces, keychain masks, decrypted
Epicbox payloads, full slates, range proofs or signatures. Amounts and addresses appear at `debug`
and below only. Secret types wrap their contents so `Debug` and `Display` print `[redacted]`, and a
test in `lepic-telemetry` asserts that known secrets never appear in captured output.
