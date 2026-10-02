# 0012 A compact native slate format for LEPIC-to-LEPIC methods

Status: proposed
Date: 2026-10-02

## Context

The legacy JSON slates are large (each range proof is about 1.3 KB of hex), carry the whole
transaction back and forth, repeat data, encode numbers as strings, and have no explicit stage. They
are awkward for QR codes and copy-paste on phones.

Grin, which Epic descends from, replaced the same formats with compact slates (Slate V4: explicit
stage, no full transaction body, optional binary form) and Slatepack (armored text, optional
encryption to the recipient).
(https://github.com/mimblewimble/grin-rfcs/blob/master/text/0012-compact-slates.md,
https://github.com/mimblewimble/grin-rfcs/blob/master/text/0015-slatepack.md)

## Proposal

- A versioned binary codec `lepic.v1`: explicit stage, slate id, amount and fee as integers, only the
  data the counterparty needs at that stage (the sender keeps its own inputs and change locally), and
  a field bitmask for optional parts.
- An armored text form for copy-paste and QR, with a checksum and clear begin and end markers.
- Optional encryption to the recipient's address, so the armored text is safe to send over any
  channel.
- Capability discovery before any legacy method uses it: a LEPIC address or QR payload advertises the
  formats it accepts. Legacy peers never receive it.
- Written as a specification that `epic-wallet` could adopt.

## Open questions

- Which key the recipient address encodes, and how it relates to the Epicbox address.
- Whether to reuse Grin's Slatepack framing or define an Epic-specific one.
- How capability advertisement survives address books and QR codes in other wallets.

## Consequences

The domain model in ADR 0002 already supports partial bodies and explicit stages, so this format can
be added later without engine changes. The specification is task X-01; the implementation
is in a later change.
