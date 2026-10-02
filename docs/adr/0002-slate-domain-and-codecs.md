# 0002 One version-free slate model, one codec per wire format

Status: accepted
Date: 2026-10-02

## Context

In `epic-wallet` the internal slate mirrors the V3 JSON, and version handling is spread across the
code with four different rules: the file method picks by content, Epicbox hard-codes the V2 shape,
HTTP negotiates, and serialization follows `orig_version`. The `version_info` header and the JSON
shape can disagree: an Epicbox payload has the V2 shape while its header says version 3. Conversions
between versions drop payment proofs and TTL silently, and there are two parse paths with different
rules. Participant roles are positional and flip in the invoice flow. Numbers travel as strings, and
the same data appears in several fields (slate fee, kernel fee, transaction fee).

LEPIC must keep speaking V2 and V3 exactly, and must also be free to use better formats on new
methods.

## Decision

`lepic-slate` defines:

- `Slate`, the domain model. Version-free and typed: `SlateId`, `Flow` (standard or invoice), an
  explicit `Stage` (S1, S2, S3, I1, I2, I3), `Amount`, `Fee`, `KernelLock`, an optional TTL, the
  offset, participants keyed by `Role` (sender or receiver, not position), the known part of the
  transaction body, an optional payment proof. It can represent a partial body, so a compact format
  need not carry the sender's own inputs and outputs.
- `WireOrigin` attached to a decoded slate: the codec it came from and, for legacy codecs, the
  `version_info` triple exactly as received. Replies use it to echo what the peer sent. The engine
  never reads it.
- A `Codec` trait: an id, a cheap `detect`, `decode` to `Slate`, `encode` from `Slate`. Each codec owns
  its private wire structs. Codecs never convert into each other.
- Codecs `legacy::v2_json` and `legacy::v3_json`, frozen to the behaviour of `epic-wallet` `v4.0.2`,
  quirks included (`docs/compat/legacy-slates.md`). Detection is by JSON shape, as upstream's Epicbox
  path does, not by the `version_info` header. They derive the stage from content and map roles to
  legacy participant ids, including the invoice inversion.
- A `CodecRegistry` that detects the codec of an unknown input and returns the decoder.
- Encoding is lossless or fails: a V2 encode of a slate with a payment proof or TTL returns
  `EncodeError::Unrepresentable`, and the caller decides.
- Decoding is strict: exact hex lengths, valid curve points, bounded counts and sizes, consistent
  participant data, no duplicate ids. Both legacy codecs share one validation path.

## Consequences

- Adding a format never touches existing formats or the engine.
- The engine reasons about stages and roles, never about versions.
- Legacy round trips must be proven against vectors at every stage, for both flows and both methods.
- Some redundancy in legacy formats (three fee fields) is checked for consistency on decode, which is
  stricter than `epic-wallet`. A vector of a slate `epic-wallet` emits must never be rejected.

## Alternatives considered

- Keep the V3 structs as the model, as `epic-wallet` does. Ties every future format to V3's shape.
- One codec with version switches inside. That is the current spread of version logic in one file.
