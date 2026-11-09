# lepic-telemetry

Tracing subscribers and redaction for the LEPIC binaries. Library crates only emit `tracing`
spans and events; the CLI and the mobile binding install a subscriber from this crate. Tests in
any crate use it to check what their code logs.

## Where it fits

- Depends on no other LEPIC crate.
- Used by `lepic-cli` and `lepic-ffi`, which install subscribers, and by `lepic-keychain`,
  `lepic-epicbox` and `lepic-wallet` in their tests.
- No features.
- Holds no global state of its own. A host installs the `Dispatch` it gets from this crate.

## Core concepts

- **Filter.** `LogFilter` takes `tracing` directives, from a string or from the `LEPIC_LOG`
  environment variable (`LOG_FILTER_ENV`).
- **CLI subscriber.** `CliTelemetry` writes pretty, compact or JSON lines to stderr, keeping stdout
  for command output, and optionally a rotating log file (`FileLog`). Keep the value alive until
  exit: dropping it flushes and closes the file.
- **Host subscriber.** `host_dispatch` hands every record, as a `LogRecord`, to a `LogSink` the
  host app implements. The mobile binding passes records to the app this way.
- **Device log.** `LogRing` is a `LogSink` that keeps records in a directory the app owns, within
  a size limit (`LogRingLimit`, 1 MiB by default), for the app to package into a support report.
  Records are redacted before they reach the disk: field values outside a short list of kept
  fields become `[redacted]`, and messages lose slates, recovery phrases, amounts, hosts, home
  folders and key-like values. Addresses keep a short fingerprint so two can be told apart.
- **Leak checks.** `capture` runs a closure with a subscriber that records every span and event on
  the current thread. `assert_no_secrets` then fails if a secret appears in any record, as raw
  bytes or in hex.

## Public API

| Area | Items |
|---|---|
| Filter | `LogFilter` (`parse`, `from_env`), `LOG_FILTER_ENV` |
| CLI | `CliTelemetry` (`new`, `with_console_writer`, `dispatch`), `CliConfig`, `FileLog`, `LogFormat`, `Rotation` |
| Host | `host_dispatch`, `HostLayer`, `LogSink`, `LogRecord`, `LogLevel` |
| Device log | `LogRing` (`open`, `limit`), `LogRingLimit`, `LogRingError` |
| Tests | `capture`, `Captured`, `assert_no_secrets`, `LeakCheckError`, `Encoding` |
| Errors | `TelemetryError`, `ErrorChain` (an error with its source chain, for a log field) |

## Example

A test that checks a function never logs a key. It needs `tracing` beside `lepic-telemetry`.

```rust
use lepic_telemetry::{assert_no_secrets, capture};

fn unlock(key: &[u8]) {
    tracing::info!(key_len = key.len(), "wallet unlocked");
}

fn main() {
    let key = [0x8c, 0x01, 0xfe, 0x42];
    let ((), captured) = capture(|| unlock(&key));
    assert_eq!(captured.records.len(), 1);
    assert_no_secrets(&captured.records, &[&key]).expect("the key was logged");
}
```

## Related

- [Logging](../../docs/logging.md): the field vocabulary and the JSON line format
- [Architecture](../../docs/architecture.md)
- [CLI](../../docs/cli.md), [FFI](../../docs/ffi.md)
