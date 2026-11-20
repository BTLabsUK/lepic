# ADR 0002: One version-free slate model, one codec per wire format

Status: accepted

## Context

In `epic-wallet` the internal slate mirrors the V3 JSON, and version handling is spread across the
code with four rules: the file method picks by content, Epicbox hard-codes the V2 shape, HTTP
negotiates, and serialization follows `orig_version`. The `version_info` header and the JSON shape
can disagree: an Epicbox payload has the V2 shape while its header says version 3. Conversions
between versions drop payment proofs and the TTL silently. Participant roles are positional and
flip in the invoice flow. Numbers travel as strings, and the same data appears in several fields
(slate fee, kernel fee, transaction fee).

LEPIC has to speak V2 and V3 exactly and stay free to use better formats on new methods.

## Decision

`lepic-slate` defines the model and the codec framework:

- `Slate`, the domain model. It is version-free and typed: `SlateId`, `Flow` (`Standard` or
  `Invoice`), an explicit `Stage` (`S1`, `S2`, `S3`, `I1`, `I2`, `I3`), `Amount`, `Fee`,
  `KernelLock`, an optional TTL cutoff height, the offset, the sender and receiver `Participant`
  keyed by `Role` rather than by position, the part of the transaction body the slate carries,
  and an optional payment proof. A slate can hold a partial body, so a compact format need not
  carry the sender's own inputs and outputs.
- `WireOrigin`, attached to a decoded slate: the `CodecId` it came from and, for legacy codecs,
  the `version_info` triple (`LegacyHeader`) as received. Codecs and transport policies read it
  to echo what a peer sent; the engine stores it and passes it on without interpreting it.
- The `Codec` trait: `id`, a cheap structural `detect`, `decode` to `Slate` and `encode` from
  `Slate`. Each codec owns its private wire structs. Codecs never convert into each other. A
  `WireSlate` is text or bytes labelled with a `MediaType`.
- Codecs `legacy-v2` and `legacy-v3` (`lepic-legacy-slate`, `v2_json` and `v3_json`), frozen to
  the behaviour of the `epic-wallet` release named in `upstream.toml`, quirks included
  (`docs/compat/legacy-slates.md`). They detect by JSON shape: the `ttl_cutoff_height` key marks
  V3. They derive the stage from the participant entries and map roles to legacy participant ids,
  including the inversion in the invoice flow.
- `CodecRegistry`, the ordered set of codecs a wallet speaks. `detect` asks them in registration
  order, `detect_accepted` only those a transport accepts, and `decode` runs the detected codec.
  Registering a codec id twice is an error.
- Lossless encoding: an encode that would drop something fails with
  `EncodeError::Unrepresentable`, naming the codec and what it cannot carry (`TimeToLive`,
  `PaymentProof`, a `Flow`, a block header version or a range proof length the format cannot
  write). The caller decides what to do.
- Strict decoding: input over `MAX_WIRE_SLATE_LEN` (8 MiB) is refused before parsing, hex fields
  have exact or bounded lengths, curve points and commitments are parsed, array lengths are
  bounded while reading, the participant count is two with unique ids below it, there is exactly
  one kernel, fee, kernel features and lock height agree, and the fee covers the weight of the final transaction at the network's base fee. Both legacy codecs share these
  checks (`lepic_slate::validate`).

## Consequences

- Adding a format touches neither existing formats nor the engine.
- The engine reasons about stages and roles, never about versions.
- Legacy round trips are proven against vectors at every stage, for both flows and both methods.
- Redundant legacy fields (slate, kernel and transaction fee) are checked for consistency on
  decode. A slate that `epic-wallet` emits must never be rejected.

## Related

- [ADR 0003](0003-transport-format-policy.md): which codec a transport uses.
- [ADR 0012](0012-native-slate-format.md) and [ADR 0052](0052-legacy-at-the-edge-native-between-lepic-wallets.md): the native codec.
- [Legacy slate formats](../compat/legacy-slates.md)
