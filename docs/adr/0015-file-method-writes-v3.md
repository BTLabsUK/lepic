# ADR 0015: The file method writes V3

Status: accepted

## Context

`epic-wallet` writes a slate file in the V3 shape only when the slate carries a TTL or a payment
proof, and in the V2 shape otherwise. Its file path reads header version 2 or 3 and dispatches
on that number. LEPIC fixes one slate shape per method (ADR 0003) and files carry TTL and
payment proofs, so the file method uses the V3 shape.

## Decision

| Transport | Accepts | New slate | Reply |
|---|---|---|---|
| File | V2 and V3 | V3, header `3/3/<b>` | V3, header `3/3/<b>` |

- `<b>` is the block header version of the received slate's header, or the chain's current one
  for a slate this wallet starts. `FilePolicy::choose` in `lepic-transport` implements the rule.
- A reader dispatches on `version_info.version`, as `epic-wallet` does. Version 2 is read as V2
  and ignores V3-only keys, so a V3-shaped file with a version 2 header loses its TTL and
  payment proof. Version 3 is read as V3.
- When the sender has a reply key (RFC 0002), the V3 file carries it in the LEPIC marker, which
  stock wallets ignore. Without a reply key the file has no marker.
- The reply to the file at `<path>` goes to `<path>.response`, as the `epic-wallet` command
  line names it.
- Imports read a regular file of at most `MAX_WIRE_SLATE_LEN` bytes. Exports refuse a symbolic
  link at the target and sync the file before they return.

## Consequences

- LEPIC's file output does not match `epic-wallet`'s bytes for slates without TTL or payment
  proof. The differential and interop suites show compatibility: `epic-wallet` reads every LEPIC
  file and LEPIC finalizes every reply (ADR 0009).
- Payment proofs and TTL travel in files. Over Epicbox the legacy policy cannot represent them
  (ADR 0003).
- LEPIC reads the headers `epic-wallet` v4.0.2 and v4.1.0 write (ADR 0020).

## Related

- ADR 0003, ADR 0009, ADR 0020
