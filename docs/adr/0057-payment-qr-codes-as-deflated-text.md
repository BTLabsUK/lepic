# ADR 0057: Payment QR codes carry deflated slate text only

Status: accepted
Date: 2026-11-11

## Context

A payment file shown as an animated QR code is scanned by whatever wallet the other person
runs. A QR code cannot tell which reader will scan it, and released wallets read only the
deflated slate text of `ur:epic-slate` version 1 (ADR 0025). The in-person flow uses version 2,
native `lepic.v1` slates and envelopes as bytes, between wallets that both run it.

## Decision

- Payment QR codes are `ur:epic-slate` version 1: the slate JSON a file would hold, deflated.
  The binding's `encode_ur_slate(json, max_fragment_len, single_code_max_len)` writes nothing
  else, and the CLI and `lepic serve` write the same.
- The binding's `decode_ur_slate` reads version 1 and returns the slate text. A version 2 code
  is an in-person code or answer, refused as `ForeignUrCode` so the scanner drops that scan.
- Version 2 stays the in-person format: `in_person_qr_parts` and `in_person_qr_read` write and
  read it, and `in_person_qr_read` refuses version 1 text as `InvalidSlate`.
- An answer is checked against the stored proposal as before: an S2 or I2 file or text that
  leaves out the initiator's inputs, change or message is refused as changed.

## Consequences

- Every wallet that reads `ur:epic-slate` reads a payment code from any LEPIC release.
- A payment code takes about twice the parts a native slate would: an S2 at 107-byte fragments
  is 23 parts, about 12 seconds per loop at 6 frames a second.
- The writer's display limits (fragment length, single-code limit) stay the caller's choice
  and do not change what is on the wire.

## Related

- ADR 0012, ADR 0024, ADR 0025; supersedes ADR 0056
