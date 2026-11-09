# lepic-native-slate

The native slate codec `lepic.v1`: a compact, fixed-layout binary slate with an extension tail,
used between LEPIC wallets. A pure crate. Each slate has exactly one encoding, so decoding and
encoding again gives back the same bytes.

## Where it fits

- Depends on `lepic-crypto`, `lepic-primitives` and `lepic-slate`.
- Used by `lepic-wallet-contacts`. Inside an EPICTX envelope it travels sealed by `lepic-seal`.
- No features.
- Does no I/O and no sealing: it maps bytes to a slate and back.

## Core concepts

- **Layout.** A 51-byte header (`HEADER_LEN`): the magic `89 45 53 4C`, the format version `01`,
  the network, the stage, the flags, the kernel features, the block header version, the slate
  id, the amount, the fee and the height. All integers are big-endian. The body follows, then the
  extension tail.
- **Only what the peer needs.** A proposal (S1, I1) has no inputs or outputs, and an answer (S2,
  I2) leaves out the initiator's message. `NativeSlate::new` drops both and decoding refuses
  them.
- **One network per codec.** `NativeV1Codec::new(network)` refuses slates of the other network,
  and a block header version that does not match the slate's height (6 below the first hard
  fork, 7 from it).
- **Extension tail.** Records after the body, each a type byte, a big-endian `u16` length and
  the value, types strictly increasing. Type `01` is a reply key and `02` a reply mailbox. An
  unknown type below `0x80` refuses the slate; one from `0x80` up is kept verbatim.
  `NativeSlate` keeps the tail; `NativeV1Codec`, the `Codec` form, checks it on decode, drops it
  and encodes an empty tail.
- **JSON view.** `SlateView` names every field of the binary form for tools and the API. It is
  never sent on the wire, and reads back only when it is exactly the view of a slate.
- **Typed refusals.** Every refusal is a `NativeError` or `TailError`, found before anything
  larger than the input is allocated.

## Public API

| Area | Items |
|---|---|
| Codec | `NativeV1Codec` (`new`, `network`), `NATIVE_V1` (`lepic.v1`), `MEDIA_TYPE` (`application/vnd.lepic.slate`), `MAGIC`, `VERSION`, `HEADER_LEN` |
| Slate with tail | `NativeSlate` (`new`, `decode`, `decode_any`, `encode`, `slate`, `tail`, `into_parts`), the `FLAG_*` constants, `INPUT_LEN`, `OUTPUT_LEN` |
| Tail | `tail::{Tail, ReplyKey, ReplyMailbox, UnknownRecord, REPLY_KEY, REPLY_MAILBOX, FIRST_IGNORABLE}` |
| JSON view | `SlateView` (`new`, `into_native`) and the per-part views |
| Errors | `NativeError`, `TailError` |

## Related

- [EPICTX native slates](../../docs/protocols/epictx.md)
- [RFC 0003: EPICTX native slates and sealing](../../docs/rfcs/0003-epictx-native-slates.md)
- [ADR 0012: native slate format](../../docs/adr/0012-native-slate-format.md),
  [ADR 0052: legacy at the edge](../../docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)
- [`lepic-slate`](../lepic-slate/README.md), [`lepic-legacy-slate`](../lepic-legacy-slate/README.md),
  [`lepic-seal`](../lepic-seal/README.md)
