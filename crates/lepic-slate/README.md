# lepic-slate

The slate model every other crate shares: the version-free `Slate`, the stages of the standard and
invoice flows, the `Codec` trait that maps a wire format to and from a slate, and the registry
that picks a codec for an unknown slate. A pure crate. The codecs themselves live in
`lepic-legacy-slate` and `lepic-native-slate`.

## Where it fits

- Depends on `lepic-crypto` and `lepic-primitives`.
- Used by both codec crates, `lepic-transport`, the engine and everything above it.
- No features.
- Holds no wire format of its own except `ur:epic-slate`, the QR framing that carries slate text
  or bytes.

## Core concepts

- **Version-free slate** (ADR 0002). A `Slate` is built only through `Slate::propose`, the stage
  transitions (`receive`, `pay`, `finalize`) or `Slate::from_parts`, and each checks the
  invariants, so every value is consistent with its stage.
- **Flows and stages.** The standard flow goes S1 → S2 → S3 (`Flow::Standard`), the invoice flow
  I1 → I2 → I3 (`Flow::Invoice`). `Role` names the parties by where funds go: `Sender` and
  `Receiver`.
- **Codecs.** One `Codec` per wire format, with an id (`CodecId`) and a `MediaType`. A codec
  turns a `WireSlate` (text or bytes) into a `Slate` and back. Codecs never convert into each
  other.
- **Origin.** A decoded slate remembers its `WireOrigin`, the codec and legacy header it came in,
  so a reply can answer in the same shape.
- **Limits.** `MAX_WIRE_SLATE_LEN` (8 MiB) caps every slate a codec reads. The `validate` module
  holds the checks every legacy codec applies on decode.

## Public API

| Module | Main items |
|---|---|
| `model` | `Slate`, `SlateId`, `SlateParts`, `Participant`, `ParticipantMessage`, `PaymentProof`, `Proposal`, `Receipt`, `Payment`, `FinalKernel`, `KernelLock` |
| `stage`, `role` | `Stage` (S1–S3, I1–I3), `Step`, `Flow`, `Role` |
| `codec` | `Codec`, `CodecId`, `MediaType`, `WireSlate`, `WireContent`, `EncodeContext`, `MAX_WIRE_SLATE_LEN` |
| `registry` | `CodecRegistry` (`register`, `detect`, `decode`, `encode`) |
| `origin` | `WireOrigin`, `LegacyHeader` |
| `ur_slate` | `encode_ur_slate`, `encode_ur_slate_split` (a single-code limit apart from the fragment length), `decode_ur_slate`, `encode_ur_binary`, `decode_ur_parts` |
| `error`, `validate` | `SlateError`, `DecodeError`, `EncodeError`, `RegistryError`; shared decode checks |

## Related

- [Architecture: slates, codecs and methods](../../docs/architecture.md#slates-codecs-and-methods)
- [ADR 0002: slate domain and codecs](../../docs/adr/0002-slate-domain-and-codecs.md),
  [ADR 0025: animated QR slates](../../docs/adr/0025-animated-qr-slates.md)
- [Legacy slates](../../docs/compat/legacy-slates.md), [ur:epic-slate](../../docs/compat/ur-epic-slate.md)
- [`lepic-legacy-slate`](../lepic-legacy-slate/README.md), [`lepic-native-slate`](../lepic-native-slate/README.md)
