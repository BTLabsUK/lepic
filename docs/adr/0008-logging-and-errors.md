# ADR 0008: tracing everywhere, host-installed subscribers, typed errors

Status: accepted

## Context

`epic-wallet` logs through `log4rs` initialised by the binary, panics if a logger already exists
when initialised from a library, carries plain strings in its error variants, and flattens typed
errors into strings at layer boundaries. A mobile app cannot install its own logger cleanly under
that design.

## Decision

- Libraries emit `tracing` spans and events and never install a subscriber.
- `lepic-telemetry` provides the subscribers:
  - `CliTelemetry`: pretty, compact or JSON lines on stderr, and an optional rotating file through
    `tracing-appender`.
  - `HostLayer`: hands each record to a `LogSink` the host app implements; the app sends records to
    Logcat or os_log and to its own log export.
  - `LogRing`: a `LogSink` that keeps redacted records on the device within a size limit, for the
    host to package into a support report.
- One field vocabulary and level policy, in `../logging.md`.
- Secret types redact themselves. `capture` and `assert_no_secrets` let a test check that known
  secrets never appear in captured output.
- Errors are `thiserror` enums per crate with sources kept. The binding exposes one error enum
  with stable numeric codes (ADR 0007).

## Consequences

- Each engine operation has a span, so a log file reads as a sequence of named operations with their
  outcomes.
- A new field name is added to the vocabulary in `../logging.md` in the same change.

## Related

- ADR 0007: the binding's error enum.
