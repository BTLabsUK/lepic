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

The specification is `docs/rfcs/0001-lepic-slate-v1.md` (task X-01). It answers the open questions
below with options and a recommendation, and gives example encodings and sizes from the G-03
vectors: a first-leg slate is 149 bytes against 2,315 to 2,472 bytes of legacy JSON, and a reply is
about a quarter of its legacy size.

## Open questions and the recommended answers

| Question | Recommended answer (RFC 0001) |
|---|---|
| Which key the recipient address encodes, and how it relates to the Epicbox address | The payment-proof ed25519 key at index 0, in bech32m (`epic1...`, `tepic1...`). It derives from the same secret as the Epicbox address, so one restore brings both back, and it gives payment proofs and encryption from one address. (D1 option K-A) |
| Whether to reuse Grin's Slatepack framing or define an Epic-specific one | An Epic framing on Slatepack's armor mechanics: base58 words, double-SHA-256 checksum, `BEGINEPICSLATE.` and `ENDEPICSLATE.` markers, a binary pack header with network and mode. Encryption with HPKE (RFC 9180) instead of age. (D2 F-B, D4 E-B) |
| How capability advertisement survives address books and QR codes in other wallets | It travels apart from the Epicbox address, which is never changed: holding a peer's native address is the advertisement, learned from a contact card or an authenticated native Epicbox message. A wallet that drops it treats the peer as legacy, which still works. (D3 C-A) |

RFC 0001 also recommends self-contained replies (D5 R-A) and fixed-width integers (D6 I-A).

## Operator decision (OD-5)

Pending. The operator accepts, rejects or amends the recommendations D1 to D6 of RFC 0001; the
integrator records the choice here and sets the status.

## Consequences

- The domain model in ADR 0002 already holds partial bodies and explicit stages, so the codec needs
  no model change. The engine does need one rule: the initiator finalizes from its stored slate plus
  the responder's additions, instead of from the reply alone (RFC 0001, section 11). Written that way
  in W-04, W-05 and W-08, it works for legacy replies unchanged.
- The `Codec` trait's "encode is lossless" rule gets one qualification: a native proposal leaves out
  the initiator's own inputs and outputs by definition of the format.
- The recommendation adds the `hpke` and `bech32` crates to ADR 0010.
- The implementation is in a later change: the codec in X-02, packs, addresses, capabilities and the text
  transport in X-03.

## Alternatives considered

RFC 0001 lists the alternatives to each recommendation, among them Slatepack unchanged, age
encryption, the Epicbox key as the native address, a capability suffix on the Epicbox address, and
Grin V4's minimal replies, with the reasons each was not recommended.
