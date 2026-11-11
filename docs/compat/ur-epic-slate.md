# Slates in QR codes (`ur:epic-slate` versions 1 and 2)

Two phones side by side exchange a slate without a relay, a server or a file: the sender's phone
shows its S1 (or an issuer its I1) as a looping sequence of QR codes, the other phone scans it,
then shows its S2 (or I2) the same way for the first phone to scan. The codes carry the slate
JSON text that the file method would write, unencrypted (ADR 0025). LEPIC implements the format
in `lepic_slate::ur_slate`, and the binding exposes it as `encode_ur_slate` and
`decode_ur_slate`.

The format builds on the Uniform Resources scheme of Blockchain Commons (BCR-2020-005, URs;
BCR-2020-012, bytewords; and its multipart fountain encoding). This page states only what Epic
slates add and require; the referenced papers define the framing.

## Payload

The message carried by the code is a CBOR map with two entries, definite length, keys in
ascending order:

| Key | Value |
|---|---|
| `1` | Version, an unsigned integer. This page defines version `1`. |
| `2` | A byte string: the slate JSON text, UTF-8, compressed as a raw DEFLATE stream (RFC 1951, no zlib or gzip header). |

Readers refuse any other version, any other key, a missing key, a value of another type and bytes
after the map. The inflated text must be valid UTF-8 and valid JSON. It is the slate exactly as
the sending wallet wrote it; readers pass it on unchanged to the slate decoder they use for slate
files, which decides whether it is a slate they accept.

## Codes

The UR type is `epic-slate`.

- A payload that fits in one fragment is one single-part UR, `ur:epic-slate/<bytewords>`. The
  writer may choose another single-code limit, from 0 to 1024 bytes (`encode_ur_slate_split`):
  a payload of at most that many bytes is one single-part UR, and a longer one is split.
- A longer payload is a multipart UR: parts `ur:epic-slate/<seq>-<count>/<bytewords>`, where
  `<count>` is the number of fragments and `<seq>` starts at 1. Parts 1 to `<count>` carry the
  fragments in order. Parts after them are fountain parts, each the XOR of fragments chosen from
  `<seq>` and the message checksum, as the multipart scheme defines.
- Bytewords are the minimal style, two letters per byte, with the scheme's CRC-32 of the part.
- A QR code holds the uppercase form, for example `UR:EPIC-SLATE/1-7/LPAD...`. Every character
  is then in the QR alphanumeric alphabet, which packs 5.5 bits per character instead of 8.
  Readers accept either case.

LEPIC writes the `<count>` pure parts followed by `max(2 × count, 10)` fountain parts, so a
sequence holds `max(3 × count, count + 10)` parts. Showing the list in a loop lets a scanner that
missed frames complete from fountain parts before the loop comes round again.

## Fragment size

200 bytes is the recommended fragment length. It keeps every part of a typical slate inside a
version 11 QR code at error correction level L in alphanumeric mode (at most 468 characters),
which a phone camera reads at arm's length from another phone's screen. Smaller fragments give
more, smaller codes; larger ones fewer codes that are harder to read.

The encoder splits the payload into equal fragments no longer than the requested length, so the
actual fragment is often a little shorter.

## Limits

| Limit | Value |
|---|---|
| Slate text, written or inflated | 64 KiB |
| Fragment length the encoder accepts | 16 to 1024 bytes |
| Fragments in one code | 256 |
| Characters in one part a reader accepts | 2400 |
| Parts in one call to the decoder | 1024 |
| Characters in all parts of one call | 1 MiB |

A reader checks the counts and lengths before decoding anything, inflates with the output
limit, and never allocates past it. A slate over the limits does not fit a QR sequence anyone
waits for; such a payment uses a file instead.

## Reading

Decoding is stateless: the app keeps the distinct texts it has scanned and passes all of them
on each call. The answer is the number of fragments recovered so far, the fragment count, and
the slate text once every fragment is recovered. Duplicates and order do not matter.

The reader refuses, with distinct errors:

- text that is no UR, such as an address or a web link: drop that scan and keep scanning;
- a UR of another type, such as `ur:bytes` or `ur:crypto-psbt`: another wallet's code;
- parts of two different codes, which disagree in fragment count, fragment length, message
  length or checksum, or mix a single-part code with parts: start over with the newest scan;
- a damaged code: a malformed index, bytewords that fail their checksum, a fountain part that
  is no valid CBOR or disagrees with its index, fragments that fail the message checksum, a
  malformed payload map, an unknown version, data that is no DEFLATE stream, text that is not
  UTF-8 or not JSON;
- more text than the limits allow, including a payload that inflates past 64 KiB.

## Age and network

A code says nothing of its age or its network. The slate inside does, through its TTL. The rules
a LEPIC payer applies to an I1's cutoff (the 10-block margin and the lead and lag limits) and the
codes they raise are in [states.md](states.md). An I1 without a TTL has no margin and no limit.

## Example

`crates/lepic-slate/tests/snapshots/ur_slate__small_encodings.snap` records the exact codes of a
short text in both forms. At a fragment length of 200 bytes,
`{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"1000000"}` is the single-part code

```text
UR:EPIC-SLATE/OEADADAOHDFHCALEESBALADYBESSZEEYECDNSNCKASBGRSVYISDELAAMDRMWRSIOBZHGMTVWCTVDLYAHBNPEVYUOSKENNYGHLUEERDGANLHKPDOLNLLDASWMYKKEYLNDRSJPLATBADCPAESNYT
```

At a fragment length of 24 bytes it is 3 fragments, written as parts `UR:EPIC-SLATE/1-3/...`
to `UR:EPIC-SLATE/3-3/...` and 10 fountain parts, `UR:EPIC-SLATE/4-3/...` to
`UR:EPIC-SLATE/13-3/...`. A scanner that caught all 3 pure parts holds the slate. One that missed
a pure part recovers it from a fountain part whose other fragments it already has.

## Version 2

Version 2 carries a native `lepic.v1` slate or an envelope as bytes, nothing compressed
(RFC 0003 §5.18). It has the same UR type, framing and case as version 1. `lepic_slate::ur_slate`
reads and writes both versions: version 1 through `encode_ur_slate` and `decode_ur_slate`,
version 2 through `encode_ur_binary` and `decode_ur_parts`. The binding uses version 2 for the
codes and answers of the in-person flow.

### Payload

The message is the same CBOR map with two entries, definite length, keys in ascending order:

| Key | Value |
|---|---|
| `1` | Version, the unsigned integer `2`. |
| `2` | A byte string: the native slate or the envelope, exactly as written to a file. |

The first four bytes of the byte string name its kind:

| Bytes | Kind |
|---|---|
| `89 45 53 4C` | Native slate |
| `89 45 53 45` | Envelope |

The reader returns the whole byte string, magic included, as `UrBinary::NativeSlate` or
`UrBinary::Envelope`, and refuses any other first four bytes. It checks nothing else about the
bytes: the codec that reads a slate file reads them next. `decode_ur_parts` reads codes of
either version and returns the slate JSON text (version 1) or the bytes (version 2); the
version 1 reader refuses a version 2 code as an unsupported version.

### Codes

The UR type is `epic-slate`, the bytewords style, the case and the part framing are those of
version 1. A payload of at most 360 bytes (the CBOR map, not the byte string inside it) is one
single-part code. A longer payload is split into fragments of at most 200 bytes, which is the
recommended length, and written as `<count>` pure parts followed by the fountain parts, as
version 1 writes them. The encoder accepts fragment lengths from 16 to 1024 bytes.

The 360-byte limit is the default. Whether a payload is one code or an animated sequence is the
writer's display choice, so `encode_ur_binary_split` takes the single-code limit, 0 to 1024
bytes (0 always splits), next to the fragment length. A writer that draws every code at level H
with a logo in the centre picks small values, for example 80 and 64, to keep each frame near a
version 11 symbol. Readers take a single-part code or parts either way; nothing on the wire
says which limit the writer used.

### Limits

| Limit | Value |
|---|---|
| Byte string, written or read | 67,648 bytes, the largest slate envelope |
| Fragments in one code | 256 |

A code holds at most 256 fragments, so 200-byte fragments carry up to 51,200 bytes. A larger
envelope is written with longer fragments, up to 1024 bytes, or is exchanged as a file. The
other limits of version 1 (part text, parts per call, total text) apply to version 2 codes as
well.
