# EPICTX

EPICTX is how two LEPIC wallets exchange a slate: the slate in the binary format `lepic.v1`,
sealed with HPKE in the envelope of RFC 0002, as type `0A`. This guide shows which crate does
what, the calls a wallet makes to seal, open and read a slate, and the errors each step returns.
The byte layouts are in [RFC 0003](../rfcs/0003-epictx-native-slates.md); this guide links to
the section for each.

A wallet that is not LEPIC never sees any of this. LEPIC reads and writes V2 and V3 JSON for it,
at the edge ([ADR 0052](../adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md)).

## Crates

| Crate | Holds |
|---|---|
| [`lepic-native-slate`](../../crates/lepic-native-slate/README.md) | The `lepic.v1` codec and its extension tail |
| [`lepic-seal`](../../crates/lepic-seal/README.md) | The envelope, HPKE key classes, padding, armor, file classifier |
| [`lepic-slate`](../../crates/lepic-slate/README.md) | `ur_slate`: slates in QR codes |
| `lepic-wallet` | Seal key derivation |
| `lepic-wallet-contacts` | Contact, epic1 and in-person flows that use the above, through the [delivery](delivery.md) layer |

`lepic-native-slate` and `lepic-seal` are pure: the caller passes keys, the RNG and the time in.

## The native slate

`NativeSlate` is a `Slate` plus its extension `Tail`
([RFC 0003 §5.10](../rfcs/0003-epictx-native-slates.md#510-native-slate-lepicv1)).

```rust
use lepic_native_slate::{NativeSlate, Tail};

let native = NativeSlate::new(slate, Tail::default())?; // drops what the stage does not carry
let bytes = native.encode(network);
let back = NativeSlate::decode(network, &bytes)?;      // refuses another network
let (network, any) = NativeSlate::decode_any(&bytes)?; // reads the network byte
```

`NativeSlate::new` drops the inputs and outputs of a proposal and the initiator's message at an
answer, so every slate has one encoding and `encode(decode(x)) == x`. `SlateView` is a JSON
form that names every field;
`lepic epictx open` prints it.

| Constant | Value |
|---|---|
| `NATIVE_V1` | Codec id `lepic.v1` |
| `MEDIA_TYPE` | `application/vnd.lepic.slate` |
| `MAGIC`, `VERSION` | `89 45 53 4C`, `1` |
| `HEADER_LEN` | 51 bytes |
| `INPUT_LEN`, `OUTPUT_LEN` | 34 and 709 bytes |
| Slate limit | 8 MiB, and within the block weight limit |
| Message limit | 256 bytes |

A refusal is a `NativeError`, found before anything larger than the input is allocated. The ones
a caller meets most:

| Variant | Cause |
|---|---|
| `Magic`, `Version` | Not a `lepic.v1` slate |
| `WrongNetwork` | A floonet slate given to a mainnet reader, or the other way |
| `HeaderVersion` | The block header version is not the one the height takes: 6 before the first hard fork, 7 from it |
| `BodyAtProposal` | An S1 or I1 with inputs or outputs |
| `InitiatorMessage` | An S2 or I2 that repeats the initiator's message |
| `ProofInInvoice` | A payment proof in the invoice flow |
| `Tail` | A `TailError` in the extension tail |

### Extension tail

The tail carries what a raw slate needs when no envelope is around it, which only happens in
person ([RFC 0003 §9](../rfcs/0003-epictx-native-slates.md#9-in-person-codes)).

| Type | Record | Rule |
|---|---|---|
| `01` | `ReplyKey`, 32 bytes | Proposal only |
| `02` | `ReplyMailbox`: mailbox key (33) and relay `domain[:port]`, at most 128 bytes | Proposal only, needs record `01` |
| `80` and up | `UnknownRecord` | Kept verbatim and in order |

An unknown type below `80` is `TailError::UnknownRequired`. A slate inside an envelope has an
empty tail.

## The slate envelope

`seal_tx` seals a `TxContent` to one recipient key. The `TxKey` names the key's class, which sets
the HPKE `info` and the hint
([RFC 0003 §5.4, §5.5](../rfcs/0003-epictx-native-slates.md#54-hpke)):

| `TxKey` | Recipient | Hint |
|---|---|---|
| `Seal(rule)` | A contact key or a one-time reply key | From the contact's hint key or the reply key |
| `Epic1` | An epic1 seal key (kind `00`) | Zero |
| `Listener` | A listener seal key (kinds `01`, `02`) | Zero |
| `Epicbox` | An Epicbox payments seal key (kind `03`) | Zero |

No wallet seals to or opens with a `Listener` or `Epicbox` key. The codec keeps both classes, and
the pairing kit's vectors cover them.

```rust
use lepic_seal::{TxContent, TxKey, armor_tx, seal_tx};

let mut content = TxContent::new(native.encode(network));
content.reply_key = Some(my_reply_key);
let envelope = seal_tx(network, &epic1_seal_key, TxKey::Epic1, &content, None, &mut rng)?;
let text = armor_tx(&envelope); // BEGINEPICTX. ... ENDEPICTX.
```

`seal_tx` always pads the content to `max(padme(L), 768)` bytes
([§5.7](../rfcs/0003-epictx-native-slates.md#57-padding)). With a `signer` the envelope carries
the sender key and an Ed25519 signature over the header, the recipient key and the fields
([§5.8](../rfcs/0003-epictx-native-slates.md#58-signature)). A `reply_route` needs a
`reply_key` and no signer, at least one entry, and values of at most 255 bytes, an `epicbox`
value being a 33-byte key that starts with `02` or `03`; otherwise sealing fails with
`EncodeError::ReplyRoute`.

To open, decode the header for the wallet's network, then open with the key and class the hint
points to:

```rust
use lepic_seal::{KeyClass, SealedEnvelope, dearmor};

let bytes = dearmor(&text)?;
let envelope = SealedEnvelope::decode(&bytes, network)?;
let opened = envelope.open_tx(&seal_secret, KeyClass::Epic1)?;
// opened.sender is Some(key) only for a signed envelope whose signature verified
let native = NativeSlate::decode(network, &opened.content.body)?;
```

Which key a hint points to:

- a zero hint means one of the wallet's own seal keys of RFC 0003 §5.2;
- any other hint names a contact or the reply key of a slate the wallet started.

What the wallet then takes depends on that key
([§5.9](../rfcs/0003-epictx-native-slates.md#59-opening-rules)). For example, an anonymous
envelope opened with a seal key is taken only as a proposal with a reply key.

What comes to an epic1 address is opened with `open_epic1` instead of `open_tx`: a slate, or a
`posted` or `cancelled` notice from the payer (type `02`, anonymous, hint zero, padded as a
slate, no tag `09`), told apart by `TxOpened::kind` (`TxKind::Slate` or `TxKind::Notice`).
`seal_epic1_notice` seals such a notice; `open_tx` still refuses one. The [epic1](epic1.md#notices)
guide says when each notice goes and what it changes.

| Constant | Value |
|---|---|
| `MAGIC` | `89 45 53 45` |
| `ENVELOPE_VERSION`, `SUITE` | `1`, `1` (`SUITE_PSK` `0x41` is for private pairings only) |
| `HEADER_LEN` | 16 bytes |
| `NATIVE_SLATE` | Message type `0x0a` |
| `MAX_BODY_LEN` | 65,535 bytes |
| `MAX_ENVELOPE_LEN` | 1 MiB |
| `PADDING_FLOOR` | 768 bytes |

Errors while opening are `DecodeError`:

| Variant | Cause |
|---|---|
| `Damaged` | The armor checksum is wrong |
| `WrongNetwork` | The header names the other network |
| `NewerVersion` | An envelope version above `1` |
| `UnsupportedSuite` | A suite this reader does not take |
| `CannotOpen` | The key does not open it. HPKE failures are not told apart. |
| `BadSignature` | Tag `FF` does not verify |
| `Malformed(..)` | A framing, field order, field length or missing-field error |
| `Oversized` | Over a size limit |

## Reply keys

An anonymous proposal names where its answer goes:

- tag `03` holds the X25519 reply key the answer is sealed to;
- tag `09` holds an optional reply route, a list of entries
  `count (u8) || count × (method (u8) || len (u8) || value)`. Method `01` (`epicbox`) holds the
  33-byte secp256k1 key of a one-time reply mailbox. No relay travels with it: the payee answers
  on the relay it read the proposal from. A reader skips entries of other methods and uses the
  first `epicbox` entry.

Both derive per slate from the seed, so a restored wallet finds them again and a relay cannot
join two payments by mailbox ([RFC 0003 §5.2](../rfcs/0003-epictx-native-slates.md#52-keys-and-derivation)).
The reply key is the one-time key of [RFC 0002 §2.3](../rfcs/0002-contact-pairing.md#23-one-time-reply-keys).

The answer is a type `0A` envelope sealed to the reply key with `TxKey::Seal`. Its hint comes
from the reply key, so the initiator finds the slate it answers without trying every key. An
answer carries no tag `09`.

## Armors and files

Every armor is `BEGIN<NAME>. <payload>. END<NAME>.`; the payload is base64url without padding of
the envelope and a 4-byte double-SHA256 checksum ([§5.11](../rfcs/0003-epictx-native-slates.md#511-armor)).

| Marker | Carries | File extension |
|---|---|---|
| `BEGINEPICTX.` | A slate envelope, type `0A` | `.epictx` |
| `BEGINEPICSEALED.` | Any other envelope, such as a V3 slate sealed to a contact | `.epicsealed` |

- `armor_tx` writes `BEGINEPICTX.` and `armor` writes `BEGINEPICSEALED.`. Both break the
  payload into 76-character lines.
- `dearmor` reads either pair, and `dearmor_marked` also returns which `ArmorMarker` it found.
- Readers refuse text over `MAX_ARMOR_LEN`, 96 KiB. They trim `>`, spaces, tabs and line breaks
  around the markers, so text quoted in mail still reads.

`classify` decides what a file or paste is by its content, never its name
([§5.12](../rfcs/0003-epictx-native-slates.md#512-files-and-media-type)):

| Content after whitespace and `>` | Result |
|---|---|
| `BEGINEPICTX.` or `BEGINEPICSEALED.` | `PaymentFile::Armour` |
| Hex digits only, of even length | `ClassifyError::StockSavedTx` |
| `{` | `PaymentFile::LegacyJson` |
| Anything else | `ClassifyError::NotPaymentFile` |

`epic-wallet` keeps hex records of its own sends in `saved_txs/<uuid>.epictx`. That is why hex is
refused with its own message.

A raw `lepic.v1` slate is never written to a file or read from one. It is read only from a scan.

## In-person codes

In person, one phone shows a proposal as a QR code and the other scans it
([RFC 0003 §9](../rfcs/0003-epictx-native-slates.md#9-in-person-codes)). The code is a raw
`lepic.v1` I1 or S1 with:

- a TTL cutoff height;
- tail record `01`, the reply key;
- tail record `02`, a reply mailbox on the wallet's own relay, when the wallet is online.

It never carries a payment proof. The answer is an anonymous slate envelope sealed to the reply
key. It is posted to the reply mailbox, or shown back as a code.

| Constant (`lepic-wallet-contacts`) | Value |
|---|---|
| `IN_PERSON_TTL_BLOCKS` | 30 blocks past the tip when the caller passes no TTL |
| TTL margin | A TTL of 10 blocks or fewer is refused (`InPersonRefusal::TtlTooShort`) |
| `MAX_ANSWERS_PER_CODE` | 16 |

Nothing finalizes by itself. Each answer is stored with a four-digit check code from the
answering party's public excess:

```text
check = u32(SHA256("epic-check/1" || excess)[0..4]) mod 10000
```

The answering wallet shows its check code once it posts the answer; an answer shown back as a
code carries none, and the side that takes it reports the code. The user finalizes the answer
whose check code the other screen shows. `InPersonRefusal` names
why a code or an answer was refused. Examples: `Proof`, `NoReplyKey`, `NoTtl`, `Signed`,
`ReplyMailboxTag`, `OtherSlate`, `TooManyAnswers` and `Loopback`.

### QR codes

`lepic_slate::ur_slate` puts slates in QR codes under the UR type `epic-slate`
([§5.18](../rfcs/0003-epictx-native-slates.md#518-slates-in-qr-codes)):

| Payload version | Content |
|---|---|
| `PAYLOAD_VERSION` 1 | Deflated V3 JSON |
| `BINARY_PAYLOAD_VERSION` 2 | CBOR `{1: version, 2: bytes}`, the bytes a native slate or an envelope, told apart by magic |

| Constant | Value |
|---|---|
| `SINGLE_CODE_MAX_LEN` | 360 bytes fit one code, the default; the writer may pick 0 to 1024 |
| `BINARY_FRAGMENT_LEN` | 200-byte fragments in an animation, the default |
| `MIN_FOUNTAIN_PARTS` | 10 fountain parts after the pure ones |
| `MAX_BINARY_LEN` | 67,648 bytes |
| `MIN_FRAGMENT_LEN`, `MAX_FRAGMENT_LEN` | The shortest and longest fragment: 16 and 1024 bytes |
| `MAX_SEQUENCE_LEN` | 256 fragments in one message |
| `MAX_PARTS`, `MAX_PART_TEXT_LEN` | 1024 parts, 2400 characters each |

## Where each channel is described

| Channel | Guide | RFC 0003 |
|---|---|---|
| Paired contact | [Pairing](pairing.md) | §6.1 |
| epic1 link entry over HTTP or Tor | [HTTP](http.md) | §5.15 |
| epic1 link | [epic1](epic1.md) | §5.19, §6.3 |
| In person | This page | §9 |
