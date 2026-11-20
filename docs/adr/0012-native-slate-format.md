# ADR 0012: A compact native slate format for LEPIC-to-LEPIC methods

Status: proposed

## Context

Legacy JSON slates are large (each range proof is about 1.3 KB of hex), carry the whole
transaction back and forth, repeat data, encode numbers as strings and have no explicit stage.
They are awkward for QR codes and copy-paste on phones. Grin, which Epic descends from,
replaced the same formats with compact slates (Slate V4: explicit stage, no full transaction
body, a binary form).

## Decision

- LEPIC defines its own binary slate format `lepic.v1`, in the crate `lepic-native-slate`. The
  layout follows Grin's V4 slates; the magic, version and network byte are LEPIC's.
- A slate starts with a 51-byte header: the magic `89 45 53 4C`, the format version, the
  network, the stage (S1 to S3 are 1 to 3, I1 to I3 are 4 to 6), flags, the kernel features, the
  block header version, the slate id, the amount, the fee and the height. Integers are
  big-endian. The body follows: lock height and TTL cutoff when flagged, the offset, the
  participants, the payment proof when flagged, the inputs, the outputs, the kernel at a final
  stage, and an extension tail of typed records.
- A slate carries what the other party needs at its stage. A proposal (S1, I1) has no inputs or
  outputs, and an answer (S2, I2) leaves out the initiator's message. Decoding refuses a slate
  that carries them, so each slate has one encoding and `encode(decode(x)) == x`.
- The block header version of a slate follows the network's fork table. A slate whose version
  differs from the one its height takes, or whose network is not the codec's, is refused.
- `NativeV1Codec` is the `Codec` form of ADR 0002. It checks the tail on decode and drops it,
  unknown records included. `SlateView` is a JSON form that names every field, for tools.
- Every refusal is a typed `NativeError`, found before anything larger than the input is
  allocated.
- Native slates are not sent to legacy peers. Sealing a native slate, the `epic1` address and
  link, the direct endpoint and the Epicbox use are in ADR 0052, which adopts this format, and
  in [RFC 0003](../rfcs/0003-epictx-native-slates.md). The envelope that seals it is that of
  ADR 0024. The marker that tells a LEPIC peer from a stock one on legacy methods is ADR 0015.

## Consequences

- The domain model of ADR 0002 already holds partial bodies and explicit stages, so the codec
  needs no model change. The engine finalizes from its stored slate plus the responder's
  additions, not from the reply alone, which also works for legacy replies.
- The `Codec` rule "encode is lossless" has one qualification: a native proposal leaves out the
  initiator's own inputs and outputs by definition of the format.
- A first-leg native slate is a fraction of the size of legacy JSON, which makes QR codes and
  pasted text practical (ADR 0025).

## Related

- ADR 0002, ADR 0015, ADR 0024, ADR 0025, ADR 0052
- [RFC 0001](../rfcs/0001-lepic-slate-v1.md), [RFC 0003](../rfcs/0003-epictx-native-slates.md)
