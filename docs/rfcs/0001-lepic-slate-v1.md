# RFC 0001 lepic.v1: the native slate's stages, framing and engine contract

Status: partly superseded by [RFC 0003](0003-epictx-native-slates.md)
RFC 0003 §5.10 holds the `lepic.v1` byte layout; this RFC keeps what each stage carries (§3), the
text framing (§7) and how an answer is completed (§11).

`lepic.v1` is the binary slate format LEPIC wallets exchange with each other. At each stage it
carries only what the next party needs: a proposal has no inputs or outputs, and an answer leaves
out the initiator's message. This RFC states those stage rules, the framing every LEPIC armor
shares, and how a wallet rebuilds the full slate from an answer and the proposal it stored.

The key words MUST, MUST NOT and MAY are used as in RFC 2119.

## Scope

This RFC covers the stage rules, the text framing and the engine contract of `lepic.v1`. Byte
layout, envelope, armor payload, addresses and adverts are in RFC 0003:

| Topic | Where |
|---|---|
| Slate header, body and extension tail | [RFC 0003 §5.10](0003-epictx-native-slates.md#510-native-slate-lepicv1) |
| Encryption to a recipient | The envelope of [RFC 0003 §5.3](0003-epictx-native-slates.md#53-envelope-layout) |
| Armor payload and limits | [RFC 0003 §5.11](0003-epictx-native-slates.md#511-armor) |
| Address of a LEPIC wallet | The epic1 of [RFC 0003 §5.13](0003-epictx-native-slates.md#513-epic1-address) |
| How a peer says it takes native slates | [RFC 0003 §5.15, §5.16](0003-epictx-native-slates.md#515-advert-and-native-direct-endpoint) and the contact card of [RFC 0002 §6](0002-contact-pairing.md) |

The legacy V2 and V3 codecs are out of scope; they follow `epic-wallet` byte for byte
([rules](../rules.md)).

## 1 Conventions

- Integers are unsigned big-endian.
- `Commitment` and `PublicKey` are 33-byte compressed secp256k1 points. `Signature` is a 64-byte
  compact Schnorr signature.
- A range proof is exactly 675 bytes, the single 64-bit Bulletproof.
- Stage numbers: S1 = 1, S2 = 2, S3 = 3, I1 = 4, I2 = 5, I3 = 6.
- The initiator is the sender in the standard flow and the receiver in the invoice flow. The
  responder is the other party.

## 2 Binary slate

The layout is [RFC 0003 §5.10](0003-epictx-native-slates.md#510-native-slate-lepicv1). Codec id
`lepic.v1`, media type `application/vnd.lepic.slate`, magic `89 45 53 4C`, version `01`.

## 3 What each stage carries

| Stage | Written by | Sender | Receiver | Inputs and outputs | Kernel |
|---|---|---|---|---|---|
| S1 | Sender | Keys, unsigned, message | Absent | None | No |
| S2 | Receiver | Keys, unsigned, no message | Keys, signed, message | The body as the receiver holds it | No |
| S3 | Sender | Keys, signed, message | Keys, signed, message | All | Yes |
| I1 | Receiver | Absent | Keys, unsigned, message | None | No |
| I2 | Sender | Keys, signed, message | Keys, unsigned, no message | The body as the sender holds it | No |
| I3 | Receiver | Keys, signed, message | Keys, signed, message | All | Yes |

"Keys" are the party's public blind excess and public nonce. "Message" means the message is
written when the party has one; "no message" means its flag MUST be clear. A payment proof is
allowed only in the standard flow; its receiver signature is present from S2.

Presence is fixed by the stage, so the format spends no bits on it:

| Step | Initiator | Responder |
|---|---|---|
| Proposed (S1, I1) | Unsigned | Absent |
| Responded (S2, I2) | Unsigned, no message | Signed |
| Finalized (S3, I3) | Signed | Signed |

**Writing the views:**

- At S1 and I1 the encoder writes no inputs or outputs. The initiator keeps its own in its stored
  slate; the responder does not need them to sign.
- At S2 and I2 the encoder writes the slate's body as given and leaves out the initiator's message,
  which the initiator already has.
- At S3 and I3 the encoder writes the whole slate. A finalized slate is not sent to the other party:
  the initiator posts the transaction. The encoding exists for export and archive.

A decoder refuses a body in a proposal, a message flag for an absent party, and an initiator's
message at S2 or I2. Every accepted slate has one encoding: `encode(decode(bytes)) == bytes`.

## 4 Decoding

[RFC 0003 §5.10](0003-epictx-native-slates.md#510-native-slate-lepicv1) lists the decoder's
refusals. The decoder checks the length against 8 MiB first, then the magic and version, then the
header, before it allocates anything larger than the input.

## 5 Pack

Not used. A native slate travels in a type `0A` envelope
([RFC 0003 §5.6](0003-epictx-native-slates.md#56-inner-content)) or, in person, as a raw slate
with an extension tail ([RFC 0003 §9](0003-epictx-native-slates.md#9-in-person-codes)).

## 6 Encryption

Not used. Native slates are sealed in the envelope of
[RFC 0003 §5.3 to §5.9](0003-epictx-native-slates.md#53-envelope-layout), to dedicated seal keys.
No signing key is converted to an encryption key.

## 7 Armor

Every LEPIC armor is framed the same way:

```text
BEGIN<NAME>. <payload>. END<NAME>.
```

- A reader splits on the first three periods: header, payload, footer. Anything after the third
  period is ignored.
- Header and footer are the markers with optional `>`, spaces, tabs, `\r` and `\n` around them, so
  text quoted in mail or chat still reads.
- Spaces, tabs, line breaks and `>` inside the payload are removed before decoding.
- A wrong checksum is an error of its own ("damaged"), apart from a malformed frame.

The marker pairs are `BEGINEPICTX.`/`ENDEPICTX.` and `BEGINEPICSEALED.`/`ENDEPICSEALED.`. Their
payload encoding, checksum, line length and size limit are in
[RFC 0003 §5.11](0003-epictx-native-slates.md#511-armor).

## 8 Native address

Not used. A LEPIC wallet's payment address is the epic1 of
[RFC 0003 §5.13](0003-epictx-native-slates.md#513-epic1-address): a proof key and a seal key, both
dedicated.

## 9 Contact card

Not used. Paired contacts exchange the contact card of
[RFC 0002 §6](0002-contact-pairing.md). Payment links are in
[RFC 0003 §5.14](0003-epictx-native-slates.md#514-payment-links).

## 10 Capability records and transport policy

Not used. A wallet sends a native slate only to a peer that claimed native slates: a paired
contact's card, a listener's advert
([RFC 0003 §5.15](0003-epictx-native-slates.md#515-advert-and-native-direct-endpoint)), or the
marker of an Epicbox message
([RFC 0003 §11](0003-epictx-native-slates.md#11-native-slates-over-epicbox)).

## 11 Engine contract

The engine stores and works on V3 JSON. A native slate becomes V3 at the edge, before the engine
sees it:

- **A proposal** is taken as it came. The responder validates it from what it carries (TTL,
  duplicate slate id, participant data) and does not require a body.
- **An answer** is completed from the V3 JSON of the proposal this wallet stored. It takes the
  stored inputs and outputs and the initiator's message. An input or output the answer repeats
  MUST be identical to the stored one, and the answer MUST be the next stage of the same slate;
  otherwise it is refused.

The initiator then checks the completed answer against its stored slate as it checks a legacy
answer: same slate id, amount, lock, offset, initiator keys and payment proof addresses, and, in
the standard flow, the same fee, height and TTL. In the invoice flow the payer sets the fee, height
and TTL, so they come from the answer.

## Security

- **Untrusted input.** Every decoder is bounded by size before it allocates.
- **Authentication.** A native slate authenticates nothing by itself. The envelope's signature
  (between paired contacts), the partial signatures and payment proofs bind the parties.
- **Replay and duplicates.** Inbound slates are idempotent on `(slate_id, stage)`.
- **Network separation.** The slate's network byte and its block header version tie it to one
  network and fork.
- **Privacy.** A proposal carries none of the initiator's inputs or change outputs.

## Example

The S1 of vector `slates_native/send_file_plain_s1_mainnet` is 153 bytes; the V3 JSON of the same
slate is 2,472. Its 51-byte header:

| Offset | Field | Bytes |
|---|---|---|
| 0 | Magic | `8945534c` |
| 4 | Version | `01` |
| 5 | Network, mainnet | `00` |
| 6 | Stage S1 | `01` |
| 7 | Flags | `00` |
| 8 | Kernel features, plain | `00` |
| 9 | Block header version 6 | `0006` |
| 11 | Slate id | `0436430c2b02624c2032570501212b00` |
| 27 | Amount 100,000,000 | `0000000005f5e100` |
| 35 | Fee 800,000 | `00000000000c3500` |
| 43 | Height 4 | `0000000000000004` |

Then the offset (32 bytes), the sender's public blind excess and nonce (33 bytes each), and two
zero counts for inputs and outputs. The vectors in
[`testdata/vectors/slates_native`](../../testdata/vectors/slates_native/README.md) cover every stage
of every flow on both networks, after the fork, and with tails.

| Case, mainnet | Stage | V3 JSON | `lepic.v1` |
|---|---|---|---|
| `send_file_plain` | S1 | 2,472 | 153 |
| | S2 | 4,294 | 1,735 |
| | S3 | 4,420 | 1,896 |
| `send_file_payment_proof` | S1 | 2,665 | 217 |
| | S2 | 4,613 | 1,863 |
| `invoice_file_plain` | I1 | 2,361 | 153 |
| | I2 | 4,294 | 1,735 |

## References

- [RFC 0003](0003-epictx-native-slates.md) EPICTX
- [ADR 0012](../adr/0012-native-slate-format.md) Native slate format;
  [ADR 0052](../adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md) Legacy at the edge
- Crate [`lepic-native-slate`](../../crates/lepic-native-slate/README.md)
- Grin RFC 0012, Slate V4:
  https://github.com/mimblewimble/grin-rfcs/blob/master/text/0012-compact-slates.md
- Grin RFC 0015, Slatepack: https://github.com/mimblewimble/grin-rfcs/blob/master/text/0015-slatepack.md
