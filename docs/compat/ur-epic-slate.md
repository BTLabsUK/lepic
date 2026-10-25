# Slates in QR codes (`ur:epic-slate` version 1)

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

- A payload that fits in one fragment is one single-part UR, `ur:epic-slate/<bytewords>`.
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

A code says nothing of its age or its network; the slate inside does, through its TTL. An I1
the binding issues (`issue_invoice_slate`, `issue_invoice_file`) carries a TTL cutoff 1,440
blocks, a day, above the issuer's tip, as the binding's sends carry their limit. A LEPIC payer
refuses one whose cutoff the chain has reached (`PaymentExpired`) and one whose cutoff lies
more than 2,880 blocks above its tip (`InvoiceNotForThisChain`), which a request from a
network with a longer chain has; nothing is stored either way. A floonet request read on
mainnet has a cutoff far below the tip, so it is refused as expired. An I1 without a TTL, from
an older app or the CLI, is paid as before. The issuer refuses a payment from its cutoff on.

## Worked example

The S1 and S2 of the `send_file_plain` slate vectors (`testdata/vectors/slates`), at three
fragment lengths. The payload is the CBOR map with the compressed slate; QR versions are the
smallest at level L that hold the longest part in alphanumeric mode.

| Slate | JSON | Payload | Fragment limit | Fragments | Parts written | Longest part | QR version |
|---|---|---|---|---|---|---|---|
| S1 | 2426 B | 1263 B | 150 B | 9 | 27 | 337 characters | 10 |
| S1 | 2426 B | 1263 B | 200 B | 7 | 21 | 415 characters | 11 |
| S1 | 2426 B | 1263 B | 250 B | 6 | 18 | 475 characters | 12 |
| S2 | 4248 B | 2243 B | 150 B | 15 | 45 | 356 characters | 10 |
| S2 | 4248 B | 2243 B | 200 B | 12 | 36 | 430 characters | 11 |
| S2 | 4248 B | 2243 B | 250 B | 9 | 27 | 555 characters | 13 |

At 200 bytes, the S1 becomes 7 fragments of 181 bytes, written as parts `UR:EPIC-SLATE/1-7/...`
to `UR:EPIC-SLATE/7-7/...` and fountain parts `UR:EPIC-SLATE/8-7/...` to
`UR:EPIC-SLATE/21-7/...`. A scanner that caught all 7 pure parts holds the slate, and so does
one that missed a pure part but caught a fountain part whose other fragments it already has. A short JSON text such as
`{"amount":"1"}` fits one fragment and is a single-part code.

`crates/lepic-slate/tests/snapshots/ur_slate__small_encodings.snap` records the exact codes of a
short text in both forms.
