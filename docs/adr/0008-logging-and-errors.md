# 0008 tracing everywhere, host-installed subscribers, typed errors

Status: accepted
Date: 2026-10-02

## Context

`epic-wallet` logs through `log4rs` initialised by the binary, panics if a logger already exists when
initialised from a library, has 34 error variants that carry plain strings, and flattens typed errors
into strings at layer boundaries. Mobile apps cannot install their own logger cleanly.

## Decision

- Libraries emit `tracing` spans and events and never install a subscriber.
- `lepic-telemetry` provides subscribers: pretty, compact and JSON output for the CLI, an optional
  rotating file through `tracing-appender`, and a forwarding layer that hands structured records to a
  host callback on mobile. The app sends them to Logcat or os_log and to its own log export.
  Direct Logcat and os_log layers are optional, because the maintained crates for them are small
  and quiet. (https://github.com/Absolucy/tracing-oslog, https://github.com/raftario/paranoid-android)
- One field vocabulary and level policy, defined in `docs/logging.md`.
- Secret types redact themselves; a test asserts known secrets never appear in captured output.
- Errors: `thiserror` enums per crate with sources kept. The binding exposes one error enum with
  stable numeric codes, so apps can map errors to messages without parsing text.

## Consequences

- Each engine operation gets a span, so a log file reads as a sequence of named operations with their
  outcomes.
- Adding a field name means updating the vocabulary in `docs/logging.md` in the same change.

## Alternatives considered

- `log` facade with `android_logger`. Loses spans and structured fields.
