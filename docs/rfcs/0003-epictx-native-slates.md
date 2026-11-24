# RFC 0003 EPICTX: native slates and sealing between LEPIC wallets

Status: accepted (2026-11-09)
Decision record: [ADR 0052](../adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md),
[ADR 0062](../adr/0062-the-address-decides-the-protocol.md) and
[ADR 0063](../adr/0063-the-epic1-address-carries-its-own-mailbox.md); §5.13, §5.14 and §5.19 follow
[ADR 0066](../adr/0066-one-address-per-account.md) and
[ADR 0065](../adr/0065-mail-goes-where-the-receiver-reads.md); §3.2, §5.20, §6.10 and §9 follow
[ADR 0068](../adr/0068-invoices-the-payer-opens-need-no-pairing.md). This RFC says relay for a server
that runs Epicmail (a mailbox) and mailbox for the box of one key (a slot).
Amends [RFC 0001](0001-lepic-slate-v1.md) and builds on the sealed envelope of
[RFC 0002](0002-contact-pairing.md).

EPICTX is how two LEPIC wallets exchange a slate in the native binary format `lepic.v1`, sealed
with HPKE inside the RFC 0002 envelope. It defines the native slate's layout, the `0A` envelope
type that carries it, the `BEGINEPICTX.` armor, the epic1 address and payment link, how a payment
reaches an epic1 address, and slates exchanged in person as QR codes. Wallets that are not LEPIC
get V2 or V3 JSON: the address decides the protocol, and a classic address gets the legacy format
only.

Parts of this RFC are in releases since 0.4.0; the epic1 address with its delivery key (ADR 0063)
and the delivery described here are in no release yet. Section 13 lists the files that
implement each part.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Byte values are hex.
Integers are big-endian unless a section says otherwise.

## 1 Purpose and scope

This RFC states, for implementers of other wallets and reviewers:

- the `lepic.v1` slate bytes (5.10) and the envelope that carries them (5.3 to 5.9);
- text armor and files (5.11, 5.12);
- the epic1 address and payment link (5.13, 5.14, Appendix B);
- how a payment reaches an epic1 address: its delivery mailbox and a link's `http` and `tor`
  entries (5.15, 5.19);
- slates in QR codes and in person (5.18, 9).

Pairing, contact cards, mailboxes and the RFC 0002 message types are out of scope; RFC 0002 states
them. Transport framing of Epicbox is in [Epicbox](../protocols/epicbox.md). Sections 5.16, 6.2, 6.4
and 11 keep their numbers and are not part of LEPIC.

## 2 Terms

| Term | Meaning |
|---|---|
| Native slate | A slate in `lepic.v1` bytes (5.10). |
| Legacy slate | A V2 or V3 JSON slate as `epic-wallet` reads and writes it. |
| Classic address | An Epicbox address, a listener URL or an onion: stock V2 or V3 behaviour. |
| Envelope | The RFC 0002 sealed envelope (5.3). |
| Slate envelope | An envelope of type `0A` whose body is a native slate (5.6). |
| EPICTX text | A slate envelope armored `BEGINEPICTX.` (5.11). |
| epic1 | A LEPIC payment address of two public keys (5.13). |
| Seal key | An X25519 key an envelope is sealed to (5.2). |
| Reply key | A one-time X25519 key an answer is sealed to. |
| Reply mailbox | A one-time Epicbox mailbox an answer is posted to (5.2). |
| Delivery mailbox | The Epicbox mailbox of an epic1 address: its delivery key, the same on every relay (5.2). |
| Relay list | The wallet's one list of relays for native mail: shipped, plus added, minus removed (5.19). |
| Post key | The Epicbox `from` key used to post one slate (5.2). |
| Proposal | A slate at S1 or I1. |
| Answer | A slate at S2 or I2. |
| Initiator, responder | The party that makes the proposal, and the one that answers it. |
| Consumer | The application that embeds LEPIC and talks to the user. |

## 3 Overview

A slate goes through three stages. The sender's flow is S1, S2, S3; the invoice flow is I1, I2,
I3. The initiator makes the proposal, the responder answers, and the initiator finalizes and
posts the transaction.

Between LEPIC wallets the slate is sealed:

| Channel | Carrier | Section |
|---|---|---|
| Paired contact (file, paste, mailbox) | V3 slate in a type `01` envelope, signed | 6.1 |
| epic1 address or link | Slate envelope to the epic1 seal key, posted to the delivery mailbox or to a link's `http` or `tor` entry | 5.15, 5.19, 6.3 |
| In person | Raw `lepic.v1` code, answered with a slate envelope | 9 |

A classic address gets the legacy format of its method, and nothing else (6.5).

### 3.1 Which way a payment goes

Two codes are shown for receiving, never mixed:

- the **Epicbox link** `epic:<epicbox address>`, which every Epic Cash wallet can pay;
- the **epic1 address** or **epic1 link** `epic:<epic1>?...`, which only LEPIC wallets read
  (5.13, 5.14).

No code carries both an Epicbox address and an epic1. The delivery mailbox of an epic1 is never
shown, paid or answered as an address.

In person, one phone shows a proposal as a code and the other scans it (9). The answer is sealed
to the code's reply key and posted to the code's reply mailbox, or shown back as a code when the
answering wallet is offline.

### 3.2 LEPIC and the consumer

LEPIC builds, seals, opens, checks and stores slates. It never asks the user anything: where a
flow needs a person's decision (pick an in-person answer, approve a payment), LEPIC reports what
it found and the consumer asks. LEPIC finalizes an in-person answer by itself only when the code
asked for it (9, `finalize: first`), and only in `lepic serve`; the library calls stay single calls.

## 4 Design summary

- **The address decides the protocol.** A classic address gets V2 or V3 JSON and no LEPIC bytes.
  A native slate goes only to an epic1 address. A wallet that is not LEPIC never receives a
  native slate, an envelope or an epic1.
- **One envelope.** Native slates reuse the RFC 0002 envelope with a type of their own (`0A`), so
  one reader handles contacts and payments.
- **Key classes.** An envelope sealed to an epic1 seal key uses an HPKE `info` of its own (5.4),
  so it opens only under the key class it was sealed for.
- **Fresh keys per slate.** Reply keys, reply mailboxes and post keys are derived per slate from
  the seed (5.2), so a relay cannot join payments by mailbox, and a restored wallet finds them
  again.
- **The address carries its mailbox.** An epic1's delivery key is its mailbox on every relay, so
  a link names no relay and the payer posts to every relay of its own list (5.19).
- **Content decides.** Readers classify input by its bytes, never by file name or folder (5.12).

## 5 Wire and format detail

### 5.1 Conventions

- `||` is concatenation. `u8`, `u16`, `u32` and `u64` are unsigned big-endian integers.
- `net` is `00` for mainnet and `01` for floonet, in every structure of this RFC.
- Lengths are in bytes unless stated.
- A reader MUST refuse what this RFC does not allow, with a typed error, before it allocates
  anything larger than the input.

### 5.2 Keys and derivation

All keys of this section derive from the wallet seed, so a restore needs nothing else. Keys of
the LEPIC namespace are the keyed BLAKE2b-256 MAC of the seed over a versioned label and a
fixed-width context:

```text
key = BLAKE2b-256-MAC(key = seed, label || context)
```

No key here sits on a BIP32 path, so none can equal an output or address key.

| Key | Label | Context |
|---|---|---|
| Seal key | `lepic-wallet seal key v1` | `account (u32) || net || kind` |
| epic1 seal key, index 1 and above | `lepic-wallet epic1 seal key v1` | `account (u32) || net || index (u32)` |
| epic1 delivery key | `lepic-wallet epic1 delivery key v1` | `account (u32) || net || index (u32) || counter` |
| Reply mailbox | `lepic-wallet reply mailbox v1` | `account (u32) || net || slate_id (16) || counter` |
| Post key | `lepic-wallet post key v1` | `account (u32) || net || slate_id (16) || role || counter` |
| Receipt payer key | `lepic-wallet receipt payer key v1` | `account (u32) || net || slate_id (16) || counter` |

- **Seal key kinds:** `00` epic1. The 32 output bytes are the X25519 secret. Kinds `01`, `02`
  and `03` are reserved: no wallet seals to them or opens with them, and the values are not
  reused.
- **epic1 keys per address index:** `index` is the number of the epic1 address within the
  account. A wallet uses index 0 only (5.13); the labels for index 1 and above stay defined, and
  the vectors cover them. At index 0 the epic1 seal key is the seal key of kind `00`; index 1 and above
  use `lepic-wallet epic1 seal key v1` with `index`. The delivery key uses one label at every
  index, 0 included. The index is not in the context of the other seal key kinds. Vectors:
  `testdata/vectors/pairing/epic1_seal_keys.json` (indexes 0, 1, 2 and 2³²−1) and
  `testdata/vectors/keys/epic1_delivery_key_seed{16,32}.json` (accounts 0 and 7, indexes 0, 1
  and 2³¹, both networks).
- **epic1 delivery key:** a secp256k1 key, made as the mailbox keys are. Its public key is the
  delivery key of the epic1 address at that index (5.13). An epic1 address signs no slate-level
  payment proof: a slate that came to one and asks for one is refused (`ForeignProofAddress`).
  Its payment proof is the receipt of tags `84` and `85`, signed by a tweak of the delivery key
  (ADR 0069, `docs/protocols/epic1-receipt.md`).
- **Mailbox and post keys** are secp256k1 keys, the Epicbox key type. `counter` is one byte from
  `00` up; the first output that is a valid secp256k1 secret is the key.
- **Retired labels:** `lepic-wallet epic1 proof key v1`, `lepic-wallet epic1 indexed proof key
  v1` and `lepic-wallet link mailbox v1` name no key. A wallet MUST NOT derive a key under them.
- **Delivery mailbox:** the Epicbox mailbox of an epic1 address is its delivery key, the same on
  every relay. No relay name goes into any derivation.
- **Post key role:** `00` initiator, `01` responder.
- **Reply key:** the one-time reply key of RFC 0002 §2.3, from the contact root and the slate id.

### 5.3 Envelope layout

The envelope is RFC 0002 §3.1's:

```text
envelope = header (16) || enc (32) || ciphertext
header   = magic (4) || version (1) || net (1) || suite (1) || flags (1) || hint (8)
```

| Field | Value |
|---|---|
| magic | `89 45 53 45` |
| version | `01` |
| suite | `01`: base mode; `41`: PSK mode for private pairings (RFC 0002) |
| flags | `00` |
| hint | 8 bytes, 5.5 |
| enc | The HPKE encapsulated key |

The header is the AEAD's associated data. The shortest envelope is 64 bytes (header, `enc` and the
16-byte AEAD tag); the longest is 1 MiB. A reader checks the suite before it splits off `enc`.

### 5.4 HPKE

Suite `01` is RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
ChaCha20-Poly1305. Suite `41` is the same in PSK mode with PSK id `epic-private/1`; a slate
envelope MUST use suite `01`.

The HPKE `info` depends on the class of the recipient key:

| Class | `info` |
|---|---|
| Contact, reply or pairing key | `"epic-seal/1" || net || suite` |
| epic1 seal key (kind 00) | `"epic-tx/1" || net || suite || 00` |
| Reserved | `"epic-tx/1" || net || suite || 01`: no wallet seals to it or opens with it, and the value is not reused |
| Reserved | `"epic-tx/1" || net || suite || 02`: no wallet seals to it or opens with it, and the value is not reused |

A reader opens with one candidate key and one class. Any HPKE failure is "cannot open", whatever
step failed.

Every X25519 key of this RFC (an epic1 seal key, a reply key in tag `03` or in a tail record) must
be canonical: bit 255 clear and the u-coordinate below
2^255 − 19. Any other spelling is refused before the small-order check. Keys X25519 derives are
always canonical. RFC 0002 cards and invites keep their rule, which refuses small order only.
Vectors: `pairing/epictx_public_keys.json`.

### 5.5 Hint

The hint lets the recipient pick the opening key without trying every key it holds.

| Recipient | Hint |
|---|---|
| Paired contact | `HMAC-SHA256(hint_key, enc)[0..8]` |
| Paired contact whose card sets `fixed-hint` | `SHA256("epic-seal/1 fixed" || hint_key)[0..8]` |
| One-time reply key `R` | `HMAC-SHA256(SHA256("epic-seal/1 reply" || R), enc)[0..8]` |
| Pairing reply | The invite id |
| epic1 seal key | `00` × 8 |

A zero hint says only that the envelope is sealed to an epic1 seal key. An envelope to an epic1
address carries it whatever the address index, so a relay or carrier cannot sort payments by
address. The wallet finds the key this way:

- **At a delivery mailbox:** with the seal key of the address whose delivery key is that mailbox
  (6.3).
- **Elsewhere** (a file, transaction text, the native endpoint): by trial, over the seal key of
  index 0 of each account in turn (5.13). The key that opens names the account.
- **The native endpoint** (5.15) is served only on the sockets the host switched on, onion or
  web; both are off by default. Elsewhere the socket answers as the listener of a wallet that is
  not LEPIC, so nobody learns from it whether a listener is that wallet.

Each key tried costs one X25519 and one failed AEAD, one per account.

### 5.6 Inner content

The plaintext is a list of fields, each `tag (u8) || length (u16) || value`, with tags strictly
increasing. A tag below `80` that the reader does not know refuses the envelope; tags from `80`
up are extensions a reader skips. A reader keeps at most 8 extensions and skips the rest unread.

| Tag | Field | Slate envelope |
|---|---|---|
| `01` | Type, 1 byte | `0A` |
| `02` | Body | The `lepic.v1` slate, at most 65,535 bytes |
| `03` | Reply key, X25519, 32 bytes | Anonymous proposals |
| `04` | Purpose, 1 byte | Optional |
| `05` | Reference | Optional |
| `06` | Expires, unix seconds, `u64` | Optional, advisory |
| `07` | Contact card | Signed envelopes |
| `08` | Sender key, Ed25519, 32 bytes | Signed envelopes |
| `09` | Reply route | Anonymous proposals, beside tag `03` |
| `80` | Sent at, unix seconds, `u64` | Optional |
| `81` | Address proof, 32 bytes | Pairing envelopes |
| `82` | Feature bits, `u32` | Optional |
| `83` | Domain claim | Optional |
| `84` | Receipt ask: the payer's one-time key, compressed secp256k1, 33 bytes | S1 to an epic1 address |
| `85` | Receipt: the payee's signature, 64 bytes | S2 answering tag `84` |
| `FE` | Padding, zero bytes | Always, 5.7 |
| `FF` | Signature, Ed25519, 64 bytes | Signed envelopes, last |

Tag `09` is a reply route, a list of entries:

```text
count (u8) || count × (method (u8) || len (u8) || value (len))
```

| Method | Name | Value |
|---|---|---|
| `01` | `epicbox` | The key of a one-time reply mailbox (5.2), 33 bytes, compressed secp256k1 (`02` or `03` first) |

No relay travels in the route. The payee posts the answer to the mailbox on the relay it read the
proposal from, and the payer watches the mailbox on every relay it posted to and on every
relay of its list (5.19). A proposal posted to a link's `http` or `tor` entry is answered in the
same request (5.15). A reader skips an entry of an unknown method, whose value may be 0 to 255
bytes, and uses the first `epicbox` entry. It refuses as malformed a count of 0, an `epicbox` value
that is not 33 bytes or does not start with `02` or `03`, an entry that runs past the field, and
bytes left after the last entry. A writer refuses an empty route and a value over 255 bytes. Tag
`09` is valid only beside tag `03` in an anonymous envelope.

Type `0A` and tag `09` exist only for the slate envelope reader. The RFC 0002 reader refuses type
`0A`, and refuses tag `09` as an unknown tag; the slate envelope reader refuses every type other
than `0A`. An extension of the wrong length is skipped as an unknown extension.

### 5.7 Padding

Every slate envelope carries the padding field `FE`, placed before the signature so that it is
signed. Its value is zero bytes; a reader refuses a non-zero byte.

Let `L` be the length of every field written before the padding, plus the padding field's 3-byte
header, plus 67 bytes for the signature field when the envelope is signed. The padding value holds
`max(padme(L), 768) - L` bytes, so the inner content is `max(padme(L), 768)` bytes:

```text
padme(L) = L                                  for L < 2
E = floor(log2(L)), S = floor(log2(E)) + 1
mask = 2^(E - S) - 1
padme(L) = (L + mask) & ~mask
```

The floor of 768 bytes makes every sealed proposal one size, whatever its message length or
payment proof. In type `0A` a reader requires the `FE` field and refuses inner content whose
length is not `max(padme(L), 768)` for the `L` it implies. A V3 slate in a type `01` envelope to
a contact is written unpadded; readers take it padded and unpadded.

### 5.8 Signature

A signed envelope carries the sender key (tag `08`) and the signature (tag `FF`) over:

```text
"epic-seal/1 sig" || header (16) || recipient public key (32) || fields before FF
```

The recipient key in the signed input binds the signature to the recipient. An envelope without
tag `FF` is anonymous and authenticates nothing.

### 5.9 Opening rules

A reader of a slate envelope MUST:

1. decode the header for its own network and suite `01`;
2. open with the key the hint names and that key's class (5.4, 5.5);
3. parse the fields (5.6) and require type `0A` and a body, or at an epic1 seal key also a
   padded type `02` with no tag `09`;
4. verify the signature when tag `FF` is present;
5. refuse tag `09` without tag `03`, or in a signed envelope;
6. decode the body of a type `0A` as `lepic.v1` for its own network (5.10).

What a wallet then takes depends on the key that opened it:

| Opened with | Takes |
|---|---|
| A contact key, signed by that contact | The contact's slates, under RFC 0002's rules |
| An epic1 seal key | An anonymous S1 with a reply key and a reply route (tag `09`), or with a reply key alone at the native endpoint |
| An epic1 seal key, type `02` | An anonymous `posted` or `cancelled` notice. It authenticates nothing, names a payment by slate id, and acts only on a payment that key took (`posted` after the excess matches the payee's own answer; `cancelled` only marks) |
| A reply key of a slate this wallet started | The answer to that slate, same slate id, next stage; or a `declined` notice for that slate (6.3) |

An anonymous invoice is refused: an I1 is taken only from a paired contact with invoices allowed
(RFC 0002 §11), or by scanning it in person (9). An anonymous slate proves itself only by
answering a slate the wallet stored, or by its partial signatures. Duplicates are idempotent on
`(slate_id, stage)`.

### 5.10 Native slate `lepic.v1`

The native slate is a fixed-layout binary form. The codec id is `lepic.v1` and its media type is
`application/vnd.lepic.slate`. The layout is implemented in
[`lepic-native-slate`](../../crates/lepic-native-slate/README.md).

**Header, 51 bytes:**

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `89 45 53 4C` |
| 4 | 1 | Version `01` |
| 5 | 1 | Network: `00` mainnet, `01` floonet |
| 6 | 1 | Stage: S1 `01`, S2 `02`, S3 `03`, I1 `04`, I2 `05`, I3 `06` |
| 7 | 1 | Flags |
| 8 | 1 | Kernel features: plain or height-locked |
| 9 | 2 | Block header version |
| 11 | 16 | Slate id |
| 27 | 8 | Amount, in the smallest unit |
| 35 | 8 | Fee |
| 43 | 8 | Height |

**Flags:**

| Bit | Value | Meaning |
|---|---|---|
| 0 | `01` | Reserved, MUST be zero |
| 1 | `02` | TTL cutoff height present |
| 2 | `04` | Payment proof present |
| 3 | `08` | Sender message present |
| 4 | `10` | Receiver message present |

Bits 5 to 7 MUST be zero.

**Body, in order:**

1. Lock height, `u64`, when the kernel is height-locked. Zero is refused.
2. TTL cutoff height, `u64`, when flag `02` is set.
3. Offset, 32 bytes.
4. The sender, then the receiver, each as its stage has it (below).
5. Payment proof, when flag `04` is set: sender address (32), receiver address (32), and the
   receiver's signature (64) at an answer or final stage.
6. Input count (`u16`), inputs of 34 bytes each: features (1) and commitment (33).
7. Output count (`u16`), outputs of 709 bytes each: features (1), commitment (33) and one
   bulletproof (675).
8. At a final stage: kernel excess (33) and excess signature (64).
9. The extension tail.

**A party** is its public blind excess (33) and public nonce (33), then its partial signature (64)
when it has signed, then its message when its flag is set: length (`u16`, at most 256), UTF-8
text, and the message signature (64).

| Stage step | Initiator | Responder |
|---|---|---|
| Proposed (S1, I1) | Present, unsigned | Absent |
| Responded (S2, I2) | Present, unsigned, no message | Present, signed |
| Finalized (S3, I3) | Present, signed | Present, signed |

The initiator is the sender in S1–S3 and the receiver in I1–I3.

**One encoding per slate.** A proposal carries no inputs or outputs, and an answer leaves out the
initiator's message, since the other party already has both. A writer drops them; a reader refuses
them. Every point, commitment and signature must be the encoding the codec writes back, so
`encode(decode(x)) == x` for every accepted `x`.

**Reader refusals** include: a slate over 8 MiB; a wrong magic or version; an unknown network,
stage or kernel feature; a set reserved flag; a slate of another network than expected; a block
header version other than the one its height takes on its network (6 before the first hard fork,
7 from it); a payment proof in an invoice; a message flag for an absent party or for the initiator
at an answer; a body in a proposal; duplicate inputs or outputs, a coinbase output, or an output
spent by an input; a body heavier than the block weight limit; and a truncated field.

**Extension tail.** Records follow the body to the end of the bytes, each
`type (u8) || length (u16) || value`, types strictly increasing:

| Type | Record | Value |
|---|---|---|
| `01` | Reply key | X25519 public key, 32 bytes |
| `02` | Reply mailbox | Mailbox key (33) and relay `domain[:port]` (1–128 bytes, `relay-domain`) |
| `81` | Direct route | 1 to 4 entries, each `method (1) \|\| len (1) \|\| host`; method 1 = `http`, 2 = `tor` |
| `F0` | Request claim | `key (32) \|\| issued_at (u64 BE) \|\| sig (64) \|\| domain (1–253 bytes)` |

A reply mailbox needs a reply key. Records `01`, `02`, `81` and `F0` are allowed only in a proposal,
and `81` and `F0` only in an I1. An unknown
type below `80` refuses the slate; from `80` up it is kept verbatim and in order, so a reader that
does not know `81` and `F0` pays through the reply mailbox as before. Record `F0` is always the
last record. 5.20 describes `81` and `F0`. A slate inside an
envelope has an empty tail: the envelope carries the reply key and mailbox in tags `03` and `09`.
The tail is for raw slates shown in person (9).

`lepic epictx open` shows an EPICTX file as JSON with every field named; see
[the CLI reference](../cli.md).

### 5.11 Armor

Envelopes travel as text in one of two marker pairs:

```text
BEGINEPICTX. <payload>. ENDEPICTX.
BEGINEPICSEALED. <payload>. ENDEPICSEALED.
```

- `BEGINEPICTX.` carries a slate envelope (type `0A`).
- `BEGINEPICSEALED.` carries any other envelope, including a V3 slate sealed to a contact and a
  `declined` notice (6.3).

The payload is base64url without padding of `envelope || checksum`, where the checksum is the
first 4 bytes of `SHA256(SHA256(envelope))`. Writers break the payload into lines of 76
characters.

A reader:

1. refuses text over 96 KiB;
2. splits at the first three periods into header, payload and footer;
3. trims `>`, spaces, tabs, `\r` and `\n` from header and footer, and removes them from the
   payload, so text quoted in mail still reads;
4. takes either marker pair;
5. decodes at most 1 MiB and checks the checksum. A wrong checksum is "damaged"; a wrong frame is
   "malformed".

### 5.12 Files and media type

| Item | Value |
|---|---|
| EPICTX file | `BEGINEPICTX.` armored text, UTF-8. Extension `.epictx`. |
| Sealed envelope file | `BEGINEPICSEALED.` armored text. Extension `.epicsealed`. |
| Legacy slate file | V2 or V3 JSON |
| HTTP media type of an envelope | `application/vnd.lepic.epictx`, binary envelope bytes (5.15) |

The answer to an EPICTX file is written as `.epictx`, and to any other sealed text as
`.epicsealed`. A raw `lepic.v1` slate is never written to a file; it is read only from a scan (9).

**Content decides.** A reader classifies a file or paste by its first bytes after whitespace and
`>`, never by its name or folder:

| Content | Read as |
|---|---|
| `BEGINEPICTX.` or `BEGINEPICSEALED.` | Armor (5.11) |
| Hex digits only, of even length | A transaction record another Epic Cash wallet keeps; refused as "a saved transaction, not a slate" |
| `{` | A legacy JSON slate |
| Anything else | "Not a payment file" |

The cases cannot overlap: armor starts with `BEGIN`, and `G`, `I` and `N` are not hex digits.

`epic-wallet` keeps a record of each transaction it sends in `saved_txs/<uuid>.epictx`, as hex.
LEPIC writes a file named `*.epictx` only with armored text and never writes into a directory
named `saved_txs`.

### 5.13 epic1 address

An epic1 is bech32m (BIP 350) over 66 data bytes:

```text
data = version (01) || seal key (32) || delivery key (33)
```

| Part | Value |
|---|---|
| HRP | `epic` on mainnet, `tepic` on floonet |
| Seal key | X25519 public key of the epic1 seal key at the address index (5.2) |
| Delivery key | Compressed secp256k1 public key, prefix `02` or `03`, of the epic1 delivery key at the same index (5.2) |
| Length | 117 characters on mainnet, 118 on floonet |

A writer writes the address in lower case, except in a QR code (5.18).

The address carries nothing else: no mailbox, relay, transport or index. Appendix B.1 has the
layout.

A reader decodes in this order and refuses with the first error:

1. bech32m, all lower or all upper case (mixed case refused), at most 256 characters;
2. the prefix: the other network's prefix is "wrong network", any other is "unknown prefix";
3. 66 data bytes;
4. version `01`;
5. the seal key: canonical (5.4) and not of small order;
6. the delivery key: a compressed secp256k1 point, prefix `02` or `03`, on the curve.

**One address per account.** Each account has one epic1 address: index 0, with the keys and the
delivery slot of 5.2. Anyone pays it any number of times. The wallet makes, issues, watches and
tries no other address of an account (ADR 0066). The index is not in the address.

- The wallet tries the seal key of index 0 of each account, and watches that address's delivery
  slot on every mailbox of its list. Coins never depend on this; it only says which seal key to
  try (5.5).
- A wallet restored from the recovery phrase watches the address of each account and the slots of
  its contacts in one pass, with no gap and no window. It can share its address and make request
  links at once.
- Two installs on one phrase share the address. A slot has one reader at a time on a mailbox: the
  newest attach takes it, and the replaced install attaches again after a hold-off (10 minutes),
  at start and on resume, so neither stays deaf. Mail not acknowledged is delivered again to the
  new reader. Both may answer one payment; the transaction an answer belongs to decides, and the
  answer the payer did not finalize is superseded. Linked devices tell each other through their
  device notices; unlinked installs see the coins through the chain only.
- Numbered addresses (index 1 and up) and links made by earlier builds are not read. A payment to
  one is not taken, and the payer's wallet cancels it at its deadline. Coins already received at
  one stay in the wallet, because they come from the seed. LEPIC sets no migration for them.
- The CLI commands are `epic1 address`, `epic1 link`, `epic1 read` and `epic1 pay`.

### 5.14 Payment links

An epic1 link names the address, where else to deliver to it, and what to pay:

```text
epic:epic1qqqq...example?http=pay.example.com&amount=1.5&message=Lunch
```

Appendix B.2 has the grammar. The parameters:

| Key | Meaning |
|---|---|
| `http` | A host that takes the sealed S1 over HTTPS, `<host>[:<port>]`, port 443 by default. May repeat. |
| `tor` | An onion service that takes the sealed S1, `<56 base32>.onion[:<port>]`, port 80 by default. May repeat. |
| `amount` | Decimal EPIC |
| `message`, `note`, `memo` | The payee's message |
| `label` | A label for the payee |

A payment link is the address as a link, with no parameter. A request link adds an amount, a
message or both. Both are the same address (5.13): the amount and the message only fill in the
payer's Send screen, the payer may change them, and the payer's wallet does not refuse a payment
whose amount differs from the link's. The payee keeps no record of a link, so making one stores
nothing and derives no key, and the same fields give the same text. A payment to the address is
a normal payment with the payer's message; nothing matches it to a link and nothing refuses it
because of one. A link names no mailbox.

**Reader rules:**

- The whole link is at most 2048 bytes. The scheme `epic:` matches in any case. The address must
  start with `epic1` or `tepic1`, and decode as 5.13; the link's network is the address's own.
- `http` and `tor` are route entries, kept in link order. A link with more than 3 of them, usable
  or not, is refused whole (`TooManyEntries`).
- An `http` entry is skipped and reported when its host and port break the syntax of the host
  rule below.
- A `tor` entry is skipped and reported unless it is exactly 56 characters of `a` to `z` and `2` to
  `7`, then `.onion`, then an optional port, in lower case. The reader checks the form only. The
  onion checksum needs SHA3 and lives with the Tor client, so the sender checks it before it
  connects and reports an address error.
- An `epicbox` key is not read: each one is reported as skipped. The address's delivery key is its
  mailbox on every relay, so a link names no other.
- A kept entry is stored in its canonical form: lower case, and the port written only when the
  link wrote one.
- `amount`: the first one only. Up to 8 decimals; signs, exponents, separators, spaces and zero
  are refused.
- `message` (or `note`, or `memo`) and `label`: the first one only, percent-decoded UTF-8, at
  most 256 bytes, no control characters, else skipped.
- `method`, `direct`, `require`, `min` and unknown keys are ignored. No parameter is ever read as a
  second payee.

**Paying a link.** A link with kept route entries is paid through those entries only, in link
order, and never through the delivery mailbox. The payer leaves out an entry the host rules
below refuse, and moves to the next entry only when a post fails; with none left the payment
fails (`CannotPay`). A link with no kept entry is paid as a bare address: through the delivery
mailbox, on every relay of the payer's list (5.19).

**Writer rules:** lower case; at most 3 route entries in their order, then `amount`, `message`
and `label`; everything outside RFC 3986 unreserved characters percent-encoded. The link for a
QR code keeps the address, the first route entry and the amount only, so the code stays small.
A wallet refuses to issue a link with more than 3 entries, or with a message over 256 bytes or
with control characters.

**Posting to an `http` or `tor` entry.** The sender seals the S1 to the address's seal key as for
the delivery mailbox (5.19) and posts it once to `POST /api/v1/inbox` on that host (5.15). The
address in the link names the key. The answer is the S2 envelope sealed to the reply key.

**Hosts from untrusted input.** The host of an `http` entry and the relay in tail record `02`
follow these rules:

- **Syntax:** `host[:port]` of at most 128 bytes. Labels of 1 to 63 letters and digits, with no
  hyphen; lower-cased. A last label that starts with a digit makes the host an IPv4 literal:
  exactly four decimal labels, each at most 255, without leading zeros. An IPv6 literal cannot be
  written. A port is 1 to 65535, at most 5 digits.
- **No hyphens:** an Epicbox relay checks `from` and `to` of every `PostSlate` with Epicbox's
  address rule and refuses a hyphenated domain, so a relay on such a domain could never carry
  the answer.
- **Addresses:** checked on the addresses actually connected to, after resolution. Loopback is
  refused: `localhost` and names under it, `127.0.0.0/8`, `::1`, IPv4-mapped and IPv4-compatible
  forms, `0.0.0.0` and `::`. A local-network address is allowed and reported to the consumer:
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`,
  `fc00::/7`, `fe80::/10` and names ending in `.local`. Everything else is public.
- **Hosts of `http` entries:** a wallet issues a link, and a payer keeps an entry, whose `http`
  host name is on the local network only when that host is a relay of its own relay list. The
  sender refuses both loopback and local-network addresses after resolution, and does not send.
  The rule does not apply to `tor` entries, which go through the Tor client and are never
  resolved by the sender.

### 5.15 Native endpoint

A LEPIC listener on HTTP or Tor can take payments to its epic1 addresses at one path:

**Endpoint:**

| Request | Answer |
|---|---|
| `POST /api/v1/inbox` | The reply envelope, `application/vnd.lepic.epictx` |

A sender makes no request before the POST. The body is a slate envelope sealed to an epic1 seal
key: anonymous, with a zero hint and a reply key (tag `03`), carrying a native S1. The endpoint
opens it by trial over the seal key of each account's address (5.5, 5.13) and takes nothing else: an envelope
that is signed, carries no reply key, or holds another stage or an invoice is refused. One
exception: an anonymous envelope whose hint (5.5) names the reply key of an open in-person code
(9) is taken as the answer to that code, an I2 or an S2. It runs the take path of the code's wallet
and is answered `200` when accepted and `422` with `code` `refused` when not, in the same request.
A wallet with no open code takes none. Its
`Content-Type` MUST be `application/vnd.lepic.epictx` (parameters ignored). The body is at most
69,632 bytes. The media type, length and envelope decoding are checked before a post counts
against the payment budget. The listener answers with the S2, sealed to the reply key with the
hint by reply key. It caches the last 64
answers by the SHA-256 of the request, so a repeated request gets the same bytes; refusals are not
cached.

Errors are RFC 9457 `application/problem+json` with `type` `about:blank` and a `code`:

| Status | `code` | When |
|---|---|---|
| 408 | | The body did not arrive in time |
| 413 | `too_large` | The declared or read length is over the limit |
| 415 | `unsupported_format` | Wrong `Content-Type` |
| 422 | `refused` | The envelope or slate was refused |
| 429 | `rate_limited` | Too many requests |
| 503 | `not_ready` | The wallet cannot answer yet; `Retry-After` in seconds |

A client reads at most 4096 bytes of a problem and follows no redirects.

The endpoint is served only on the sockets the host switched on, onion or web; both are off by
default. A socket without it answers as the listener of a wallet that is not LEPIC: its
`check_version` result carries no `lepic` key, and the path is not found.

[HTTP](../protocols/http.md) describes the endpoint for client writers.

### 5.16 Not part of LEPIC

This section number is kept so citations stay valid. A legacy slate carries no LEPIC key (8).

### 5.17 Bounds summary

| Bound | Value |
|---|---|
| Envelope | 64 bytes to 1 MiB |
| Body of a field | 65,535 bytes |
| Inner content floor | 768 bytes |
| Extensions kept per list | 8 |
| Armored text | 96 KiB |
| Armor line | 76 characters |
| Native slate | 8 MiB, and within the block weight limit |
| Message in a slate | 256 bytes |
| Relay `domain[:port]` | 128 bytes |
| epic1 address | 256 characters read, 117 or 118 written |
| epic1 link | 2048 bytes, 3 `http` or `tor` entries, 256 bytes per value |
| Native endpoint body | 69,632 bytes |
| Native endpoint cached answers | 64 |
| Relay message | 131,071 bytes, the armored envelope as posted |
| Binary QR payload | 67,648 bytes |
| Single QR code | 360 bytes of framed payload by default |
| In-person answers per code | 16 |

A slate's size depends on its inputs and outputs: each input adds 34 bytes and each output 709.
The test `sizes_of_native_and_v3_slate_envelopes` in `crates/lepic-wallet-contacts/src/native.rs`
prints the sizes of native and V3 slates and their envelopes with `--nocapture`.

### 5.18 Slates in QR codes

A slate in a QR code uses the UR type `epic-slate`:

| Payload version | Content |
|---|---|
| 1 | Deflated V3 JSON |
| 2 | CBOR map `{1: version, 2: bytes}`, the bytes a native slate (`89 45 53 4C`) or an envelope (`89 45 53 45`) |

- A payload of at most 360 bytes is one code, in upper case.
- A longer one is a fountain-coded animation of 200-byte fragments, with at least 10 fountain
  parts after the pure ones.
- Both numbers are the writer's defaults: a writer may pick another single-code limit (0 to
  1024 bytes) and fragment length (16 to 1024), for example smaller ones to keep codes drawn at
  level H with a logo small. Readers take either.
- A reader takes fragments of 16 to 1024 bytes, at most 256 fragments, parts of at most 2400
  characters, at most 1024 parts and 1 MiB per decode, and binary payloads of at most 67,648
  bytes.

An in-person proposal is a raw `lepic.v1` slate with its tail (9); an answer is a slate envelope.
A payment file is deflated JSON, version 1, never version 2 (ADR 0057).

An epic1 address alone in a QR code is written `EPIC:EPIC1...` (`EPIC:TEPIC1...` on floonet), all
in upper case, so the code can use the alphanumeric mode. A link with parameters stays in lower
case (5.14).

### 5.19 epic1 payments

An epic1 address receives at its delivery mailbox (5.2) on every relay of the payee's relay
list. A wallet has one relay list for all native mail: the relays shipped with its release, plus
the ones the user added, minus the shipped ones the user removed. The payer posts to its own list,
so payer and payee meet on every relay the two lists share. A relay's health is shown and never
used to drop it. If the payer's list holds no shipped relay and the call names none, the pay call
fails at once with `NoSharedMailbox`. No link and no sealed payment names a relay.

**Payer.** The payer:

1. builds the S1, with a TTL of 1440 blocks unless the send sets one and no payment proof. The
   amount is the payer's: a link's amount only filled in the Send screen;
2. seals it in an anonymous, padded slate envelope to the address's seal key, hint zero, with tag
   `03` (its reply key) and tag `09` (a reply route naming the key of a reply mailbox of its own,
   one per payment);
3. measures the envelope armored `BEGINEPICTX.` and sealed for each relay, and refuses the send
   with nothing stored when the longest is over the relay's 131,071 bytes (`SlateTooLarge`);
4. posts it, by the rule of 5.14: to the delivery mailbox on every relay of its list at
   once, with a post key of role initiator, or to a link's `http` and `tor` entries in turn.

A post sent and not answered is posted again on the same route; the payer moves to the next
entry only when a post reaches nothing.

**Payee.** A message at a delivery mailbox armored `BEGINEPICTX.` is a payment;
`BEGINEPICSEALED.` is a notice from a payer (6.3); anything else is dropped. The payee opens a
payment with the seal key of the address whose delivery key is that mailbox, and refuses a
signed envelope, a non-zero hint, a missing tag `03` or `09`, and a stage other than S1. It
takes any amount, builds the S2, seals it to the reply key with the hint by reply key, and posts
it to the reply mailbox on every relay a copy of the S1 was read on, with a post key of role
responder. A copy of the same S1 read on another relay is not taken again: the stored answer is
posted again, the same bytes.

**Payee declines.** The payee receives nothing and answers with a `declined` notice (6.3) when:

| Payment | `reason` |
|---|---|
| To the address while the wallet refuses unsolicited payments (`refuse_unsolicited_payments`); a request link does not make a payment asked for | `declined` |
| Asking for a slate-level payment proof, which an epic1 address does not sign | `declined` |

A wallet keeps at most 64 refusals, each for 7 days; a payment refused past that gets none.

**Payer on collect.** While the transaction is open, the payer watches the reply mailbox on every
relay it posted to and on every relay of its list. It opens an answer with the reply key,
checks it is the S2 of its stored S1, and finalizes it. Once it takes an answer or a `declined`
notice, it cancels the copies of its post on the other relays where the relay offers cancel
(txcancel/1); the rest expire at the relay's retention. A payment to an `http` or `tor` entry is
answered in the request (5.15) and has no reply mailbox to watch.

### 5.20 Checkout requests

A shop's `lepic serve` issues an I1 for one order, signed for the shop's domain, and shows it as a
code or as an invoice link. This section is the wire of that request; 9 is the flow.

**Direct route, record `81`.** One to four entries, each `method (1) || len (1) || host`. Method 1
is `http`: an HTTPS `host[:port]`, port 443 by default, where `host` is a lower-case DNS name
(labels of `a-z`, `0-9` and `-`, not led or ended by a hyphen, no trailing dot) or an IPv4
literal, and never an onion name. Unlike a link's `http=` entry, a hyphen is allowed: the entry
names the shop's own host, not a mailbox. Method 2 is `tor`: a v3 onion
`<56 base32>.onion[:port]`, port 80 by default. An entry is at most 128 bytes, and the four
entries are distinct. The payer applies the host rules of 5.14 before it posts (no loopback, no
local-network address after resolution, the onion checksum), and skips an entry that fails them. The payer posts the sealed answer to each kept
entry as 5.14 says, at `/api/v1/inbox` (5.15), in addition to the reply mailbox. Over Tor only,
the payer uses `tor` entries and never an `http` entry.

**Request claim, record `F0`.** The value is
`key (32) || issued_at (u64 BE, seconds) || sig (64) || domain (1 to 253 bytes)`. `domain` is
written as in ADR 0043: lower case ASCII. `key` is the Ed25519 verifying key of the shop's
domain key (ADR 0043). The signature is Ed25519 by that key over:

```text
"epic-request/1" || net (1 byte: 00 mainnet, 01 floonet) || key (32) || SHA256(P) || issued_at (u64 BE) || domain
```

`P` is the code's bytes up to the start of record `F0`: the header, the slate and every other tail
record. The signature so covers the whole code: the amount, the message, the TTL, the reply key
and every route. A code whose `F0` is malformed, or not the last record, does not decode.

**Verifying.** The wallet reads the claim, fetches `https://<domain>/.well-known/epic-wallet.json`
(ADR 0043; HTTPS only, no redirects, at most 4,096 bytes), and passes the bytes to a pure
function. The result is one of:

| Result | Meaning |
|---|---|
| Unsigned | The code carries no `F0` |
| Checked, with the domain | The file lists `key` for the network and `sig` is valid |
| Refused, with the domain and a reason | The file or the claim fails: the ADR 0043 reasons, plus `BadSignature` and `KeyNotListed` |

LEPIC fetches nothing. The host fetches, calls the function and applies 9.

**Invoice link.** A code as a link:

```text
epiccash://invoice/1/<base64url of the code bytes, no padding>
```

The reader refuses a link over 8 KiB, decodes the bytes and runs the normal `lepic.v1` decode, so
a link carries nothing a scan could not. The rules of 9 for a raw code apply to the link.

## 6 Flows

### 6.1 Paired contact

1. A seals the S1 (or I1) to B's contact seal key, signed, with its current card: a V3 slate in a
   type `01` envelope, armored `BEGINEPICSEALED.`. An answer takes the format of its request, and
   a native slate (type `0A`) from a contact is read as well.
2. It travels by B's mailbox, a file or a paste (RFC 0002 §9).
3. B opens it by hint, checks the signature against the pairing, and answers on the same channel,
   sealed and signed to A.
4. A finalizes.

### 6.2 Not part of LEPIC

A listener URL or an onion is a classic address and gets V2 or V3 JSON (6.5).

### 6.3 epic1 link

1. B shows or prints an epic1 address or link (5.14): the account's one address.
   The address names B's delivery mailbox; a link may add `http` and `tor` entries.
2. A reads it and builds the S1 sealed to the address (5.19). Without route entries A posts it to
   the delivery mailbox on every relay of its list. With them, A posts it to the first
   entry's `/api/v1/inbox`; when that fails, the host may post the same bytes to the next entry
   (`epic1_post_next`).
3. B opens it with the seal key of the address and answers. Over Epicbox, B
   posts the S2 to A's reply mailbox on the relay it first read the S1 from; a copy read again
   on any relay posts the same S2 to that first relay once more.
   Over `http` or `tor`, B returns the S2 sealed to the reply key as the answer to the post.
4. A takes the S2 from its reply mailbox, or reads it from the answer, finalizes, and cancels the
   copies of its post on the other relays.

When B declines the S1 (5.19), B seals a `declined` notice to the same reply key: an anonymous
type `02` envelope with the hint by reply key, whose body is the JSON
`{"lepic":1,"type":"declined","slate_id":"<slate id>","reason":"amount"}`, with `reason`
`amount` or `declined`. B posts it once as `BEGINEPICSEALED.` text to A's reply mailbox on the
relay it read the S1 from. A takes the notice only while the send is `sent` with no S2; it then
cancels the send, frees its inputs and reports the refusal once.

Over Epicbox, A tells B's address what became of the payment with a `posted` once it finalized
and posted it, or a `cancelled` once it cancelled a payment a relay took or may hold. Either is
an anonymous type `02` envelope sealed to the address's seal key (5.9), posted to its delivery
mailbox on every relay of A's list. A payment over `http` or `tor` gets no notice.

### 6.4 Not part of LEPIC

A V3 S1 in a file is plain V3, and a LEPIC receiver answers it with a plain V3 S2 (6.5).

### 6.5 Wallets that are not LEPIC

The address decides the protocol. A classic address (an Epicbox address, a listener URL or an
onion) gets the stock format of its method, V2 or V3 JSON, and nothing else: no envelope, card,
invite, notice or invoice, and no LEPIC key in a slate.

- A legacy sender to a LEPIC listener uses `/v2/foreign` with V2 or V3.
- A LEPIC sender to a classic address sends V2 or V3.
- A legacy wallet pays the Epicbox link and refuses an epic1 link as an unknown address.

### 6.6 Exchange

An exchange that runs `epic-wallet` takes deposits and sends withdrawals over HTTP `/v2/foreign`
and Epicbox in V2 or V3, as in 6.5. An exchange paired as a service (RFC 0002 §12) sends deposits
as invoices from its mailbox and withdrawals as S1s, sealed and signed, as in 6.1.

### 6.7 Face to face, two phones

**Payee starts (invoice).**

1. B shows an I1 as a code: raw `lepic.v1` with a TTL, tail record `01` (its reply key) and, when
   online, record `02` (a reply mailbox on B's relay). No payment proof.
2. A scans it. The consumer shows the amount, the fee, B's message and the reply relay, and A's
   user approves.
3. A builds the I2, seals it anonymously to the reply key and posts it to the reply mailbox, or
   shows it as a code when there is none or A is offline.
4. B takes the answer, stores it with its check code, and reports it. B's user picks the answer;
   B finalizes and posts the I3.

**Payer starts (send).** A shows an S1 the same way; its inputs stay locked until an answer is
finalized, the TTL passes or the send is cancelled. B scans it, answers with a sealed S2, and
shows its check code; B's wallet gives the check code with the post of the answer, not when it
builds the answer. A's consumer asks A's user to confirm the code on B's screen before A
finalizes.

Section 9 states the rules for both.

### 6.8 Paypoint

A paypoint is a shop terminal that shows codes and scans answers. It asks for money only by
showing an I1, as in 6.7 "Payee starts", with a reply mailbox on its own relay. A payer may also
show an S1 to a paypoint, as in 6.7 "Payer starts".

### 6.9 Payment code or link over Epicbox

1. B shows the plain Epicbox link, with an amount and a message if set.
2. A sends V2 JSON to B's Epicbox address.
3. B answers when online; A finalizes when the S2 arrives.

### 6.10 Invoices: who started it

[ADR 0068](../adr/0068-invoices-the-payer-opens-need-no-pairing.md) sets the rule:

| How an invoice arrives | Rule |
|---|---|
| Pushed through a mailbox | Taken only from a paired, verified contact the payer allowed (RFC 0002 §11) |
| Opened by the payer: a scan, a file or an invoice link | No pairing needed. Paid only on the user's approval (9). Nothing is stored before. |
| To an address (classic or epic1) | Refused before anything is stored |

An invoice link needs a checked domain, and a false claim is refused (9). A scan with no claim,
or whose file cannot be fetched, is shown with a caution. The RFC 0002 §11.5 file rule applies to a
file.

No invoice is ever pushed to a receive code. A printed code can be covered by another sticker;
the payer checks the amount and the payee before approving.

## 7 Threat model

The device and seed are assumed sound. HPKE base mode gives IND-CCA2 to the recipient, Ed25519
gives EUF-CMA, and Mimblewimble partial signatures bind the parties to a transaction.

### 7.1 Per party

| Party | Can learn | Can do |
|---|---|---|
| Carrier of a slate envelope (chat, mail, drive) | Network, suite, hint, `enc`, padded size, timing | Drop, delay, replay (idempotent); seal its own anonymous S1 to a public epic1 key |
| Whoever hands the payer a link or code | Nothing more | Replace the whole link, as with any address; replace only a route entry, whose host receives an S1 it cannot open |
| Onlooker in person | The raw proposal: amount, messages, public keys, reply key, reply mailbox, direct route, claimed domain | Post its own answer, which LEPIC reports with its check code and finalizes only for a code that asked for it (9) |
| Relay of a delivery or reply mailbox | Which mailbox receives messages, when, sizes, the poster's IP address and post key | Drop, delay, replay, deny service |
| Host of an `http` entry | The poster's IP address, envelope size, timing | Drop, delay, deny service; the S1 is sealed to the address, not to the host |
| Network observer of an `http` entry | IP addresses, envelope size, timing | Nothing more; the post is HTTPS and the slate is sealed |
| Active attacker, onion | Nothing | Deny service; the onion address authenticates the host |

A sealed envelope cannot be read or changed by any of these parties: the AEAD covers the content
and the header.

### 7.2 Properties claimed

- **Confidentiality** of native slates against carriers, relays and passive observers.
- **Integrity** of header and content (AEAD with the header as associated data).
- **Sender authentication** between paired contacts only (5.8).
- **Recipient binding** of signatures.
- **Network separation:** `net` in the header, the HPKE `info`, the derivation contexts, the
  slate's network byte and the address prefix.
- **Key-class separation:** an envelope opens only under the class it was sealed for (5.4).
- **Sender-side forward secrecy:** a fresh ephemeral key per envelope.
- **Replay safety:** idempotent on `(slate_id, stage)`.
- **Unlinkability by key:** each epic1 address has its own seal key and delivery mailbox, and a
  classic address has no key in common with an epic1; reply mailboxes and post keys are per slate.
  The delivery mailbox of one address links the payments made to it.
- **Everyone who holds a user's links sees the same address.** An account has one epic1 address
  (5.13). A user who wants two payers not to know they pay the same wallet uses a second account.
  Every envelope to an address carries the zero hint (5.5). The payee's answers come from the
  payee's IP address. An epic1 payment carries a receipt
  (tags `84` and `85`) that names the payer only by a one-time key.
- **Length hiding** of sealed proposals above the 768-byte floor.
- **Delivery cannot redirect payment:** a link's route entries decide where an S1 is posted,
  never who can open it.

### 7.3 Not claimed

- Anonymity of the sender towards the receiver.
- Protection of plain legacy flows beyond what the legacy format gives.
- Post-quantum confidentiality.
- Recipient-side forward secrecy: a leak of a static seal key opens past envelopes to it.
- Confidentiality of a raw in-person code.
- Who controls a domain beyond its HTTPS files: a request's domain check says the claimed key is
  listed in the file the domain serves. It stops a code swapped by a script or a relayed page, not
  someone who can change the domain's own files. A look-alike domain passes the check for its own
  name.
- That the first answer to an in-person code comes from the intended party. A code that asked for
  `finalize: first` is completed by the first valid answer, so whoever holds the code first pays
  that order. The payer's coins go nowhere else.
- Hiding the answering wallet's IP address from a relay the other party named.
- Protection against a hacked paypoint or a covered printed code.
- Delivery when the payer's and the payee's relay lists share no relay, and the link has no
  `http` or `tor` entry.

## 8 Compatibility

- **Wallets that are not LEPIC** get stock V2 or V3 JSON with no LEPIC key, in `check_version`
  answers and in slates. They refuse an epic1 link as an unknown address.
- **LEPIC readers** take both armor marker pairs and both padded and unpadded type `01`
  envelopes.
- **Senders** use type `0A` and `BEGINEPICTX.` only to an epic1 address or link.
- **Stored data:** a transaction finishes in the format it started in; resends use stored bytes.
  Native keys come from the seed, so a restore needs no migration.
- **Host switch:** the native endpoint is served only on the sockets the host switched on (5.15).
- **Format stability:** `lepic.v1` does not change. A change is a new codec id or a tail record.

## 9 In-person codes

A code shown on one screen and scanned by the other wallet: an I1 by a payee, or an S1 by a
sender. Raw `lepic.v1` is read only from a scan; file and paste paths refuse it.

**The code.** The proposal MUST carry a TTL cutoff height, tail record `01` (the reply key of RFC
0002 §2.3 for the slate id) and no payment proof. When the wallet is online it also carries
record `02`, a reply mailbox (5.2) on the wallet's own relay, which the wallet then watches until
the TTL.

- The default TTL is 30 blocks past the chain tip. The consumer may pass its own.
- A TTL at or under 10 blocks is refused: the payer stops paying 10 blocks before the cutoff.

**Reading a code.** A scanner refuses a code with a payment proof, without a reply key or TTL, or
whose reply mailbox is a loopback or unspecified host. It stores nothing until the user pays.

**The answer.** An anonymous slate envelope, hint from the reply key (5.5), no tag `09`, sealed to
the reply key. It is posted to the reply mailbox with a post key of role responder, or shown back
as a code.

**Taking answers.** The code's wallet opens answers whose hint names its reply key. It refuses a
signed answer, an answer with tag `09`, and an answer for another slate. It keeps at most 16
different answers per code; a repeat of one already taken changes nothing.

**Check code.** Each answer has a four-digit check code:

```text
check = u32(SHA256("epic-check/1" || excess)[0..4]) mod 10000, written with 4 digits
```

`excess` is the 33-byte public excess of the answering party: the payer's in an I2, the
receiver's in an S2. Both screens show the same digits for the same answer. Two answers with the
same digits are flagged.

**Finalizing.** By default nothing finalizes by itself. Each answer is stored and reported with
its number and check code; the user picks the one to finalize. Answers that arrive before the TTL
are still recorded.

A checkout request (5.20) may ask that `lepic serve` finalize the first valid answer and post it
(`finalize: first`, per request, default `manual`). Serve then finalizes at most one answer per
code, never a second, and once across a crash or restart. An answer is valid when it opens, has
the right slate and balances for the code's amount, and the node shows its inputs unspent; a node
that cannot be reached means the answer is not counted and is tried again on the next take. Only
a code that asked for it is completed this way.

**Direct answers.** An envelope posted to `/api/v1/inbox` (5.15) whose hint names the reply key of
an open code goes through the same take path as one from the reply mailbox. The listener answers
`200` when the answer was accepted, `422 refused` with a `reason` when it was refused for good
(`already_finalized`, `expired`, `inputs_spent`, `bad_answer`, `cancelled`), and `503 not_ready` when it could
not be checked now (the node does not answer); a payer may post a `503` answer again. An envelope
that answers no open code is `422 refused` without a reason. An answer taken twice, by both
routes, counts once.

A serve holds one reply slot per account for all its open codes and sorts answers by hint. The
slot's Epicbox key is derived from the seed with the label `lepic-wallet shared reply mailbox v1`
and the context `account (u32 BE) || net`, so it names no slate. The slot is watched while any
code on it is open. Codes issued before this change keep their own slot.

**Domain.** A code with a claim (5.20) is verified before the payer is asked. An invoice link
without a checked domain is refused, and so is any code whose claim is false. A scan with no claim,
or whose file cannot be fetched, shows a caution that the requester is unknown.

## 10 Security considerations

- **Anyone who saw a raw code can answer it.** The check code lets the users confirm they hold
  the same answer; a wrong pick in an I1 flow costs the payer nothing, since the paying wallet
  is the one that answered.
- **Relays named by the other party** see the answering wallet's IP address. LEPIC reports the
  relay, whether it is in the relay list and its host class, before it posts; the consumer shows
  it with the payment.
- **A delivery mailbox is one per address,** so its relays can link every payment made to that
  address. A second account keeps payments apart.
- **Static seal keys** open every past envelope sealed to them if leaked. All of them derive from
  the seed.
- **Anonymous envelopes** authenticate nothing. A wallet trusts an anonymous slate only as far as
  the slate proves itself (5.9).
- **A `cancelled` at an epic1 address can be forged** by anyone who knows the slate id, which only
  the payer and the payee do. At worst the payee shows a payment it still holds as cancelled by
  its sender; the payment stays received, no coins move, and the chain still decides (5.9). A
  forged `posted` counts only with the kernel excess the payee's stored S2 implies, so a forged
  one changes nothing.
- **Trial decryption has no cheap filter.** A file, transaction text or a payment at the native
  endpoint sealed to an epic1 is tried with the seal key of each account until one opens (5.5).
  Anyone can post envelopes that no key opens. A payment at a delivery mailbox is opened with one
  key.

## 11 Not part of LEPIC

This section number is kept so citations stay valid. A native slate goes over Epicbox only to an
epic1 delivery mailbox (5.19).

### 11.1 Not part of LEPIC

An Epicbox address is a classic address and gets V2 JSON (6.5).

## 12 References

- [RFC 0001](0001-lepic-slate-v1.md), [RFC 0002](0002-contact-pairing.md)
- [ADR 0052](../adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md) Legacy at the edge,
  native between LEPIC wallets
- [ADR 0062](../adr/0062-the-address-decides-the-protocol.md) The address decides the protocol
- [ADR 0063](../adr/0063-the-epic1-address-carries-its-own-mailbox.md) The epic1 address carries
  its own mailbox
- [ADR 0016](../adr/0016-epicbox-notices.md) LEPIC notices, the `declined` notice
- [ADR 0044](../adr/0044-the-onion-has-its-own-key.md) The onion has its own key
- [ADR 0025](../adr/0025-animated-qr-slates.md) Animated QR slates
- Guides: [EPICTX](../protocols/epictx.md), [epic1](../protocols/epic1.md),
  [HTTP](../protocols/http.md), [Epicbox](../protocols/epicbox.md)
- Crates: [`lepic-seal`](../../crates/lepic-seal/README.md),
  [`lepic-native-slate`](../../crates/lepic-native-slate/README.md),
  [`lepic-epic1`](../../crates/lepic-epic1/README.md),
  [`lepic-peer`](../../crates/lepic-peer/README.md)
- RFC 9180 HPKE; RFC 9457 Problem Details; BIP 350 bech32m; RFC 5234 ABNF; RFC 3986 URI

## 13 Where it is built

Paths in the LEPIC repository. Parts of this RFC are in releases since 0.4.0; the epic1 address
with its delivery key (ADR 0063) and the delivery described here are in no release yet.

| Part | Files |
|---|---|
| Envelope, HPKE suites, hint, PSK, armor, type `0A`, padding, EPICTX files | `crates/lepic-seal/src/{envelope,tlv,hint,keys,psk,armor,tx}.rs` |
| Seal keys, epic1 keys, mailbox and post keys | `crates/lepic-wallet/src/namespace.rs`, `epic1_keys.rs` |
| `lepic.v1` codec and tail records | `crates/lepic-native-slate/src/{codec,slate,wire,view,tail}.rs` |
| Native slates to paired contacts | `crates/lepic-wallet-contacts/src/native.rs` |
| Slates in QR codes | `crates/lepic-slate/src/ur_slate.rs` |
| In-person codes | `crates/lepic-wallet-contacts/src/in_person.rs` (`IN_PERSON_TTL_BLOCKS`, 30) |
| Checkout request: records `81` and `F0`, the verify function, the invoice link | `crates/lepic-native-slate/src/tail*`, `crates/lepic-seal/src/domain.rs`, `crates/lepic-wallet-contacts/src/{domain,invoice_link}.rs` |
| Hosts from untrusted input | `crates/lepic-transport/src/host_rule.rs`, `crates/lepic-epic1/src/relay.rs` |
| epic1 address and link | `crates/lepic-epic1/src/{address,bech32m,link,relay}.rs` |
| The account's one epic1 address | `crates/lepic-wallet/src/epic1_index.rs` |
| epic1 payments, declined notice, sealed files, native endpoint handler | `crates/lepic-wallet-contacts/src/{epic1,sealed,direct}.rs` (`EPIC1_TTL_BLOCKS`, 1,440) |
| Relay list, delivery mailbox posts and watches, cancel of copies | `crates/lepic-wallet-contacts/src/delivery/` |
| Relay message limit | `crates/lepic-epicbox/src/crypto.rs` (`RELAY_MAX_STR_BYTES`, 131,071), `crates/lepic-wallet/src/send.rs` (`SlateTooLarge`) |
| `/api/v1/inbox` | `crates/lepic-peer/src/`, `crates/lepic-wallet-contacts/src/delivery/peer.rs` |
| Fuzz targets | `fuzz/fuzz_targets/{slate_native,envelope_inner,armor_sealed,seal_open,epic1_link}.rs` |

A slate too large to seal (`FieldTooLong`, `BodyTooLarge`) is a typed error: a usage error in the
CLI and `InvalidArgument` in the FFI. `lepic epictx open` prints an EPICTX slate as JSON.

## Appendix A Field sizes

| Item | Bytes |
|---|---|
| Public key, commitment, kernel excess | 33 |
| Signature (partial, message, excess) | 64 |
| Offset | 32 |
| Payment proof address | 32 |
| Payment proof signature | 64 |
| Input | 34 |
| Output | 709 |
| Slate id | 16 |

## Appendix B epic1 layout and link grammar

### B.1 epic1 v1

```text
epic1 address  = hrp "1" data checksum          ; bech32m, BIP 350, written in lower case,
                                                ; read in all lower or all upper case
hrp            = "epic" (mainnet) / "tepic" (floonet)
data (66 B)    = version (1) = 0x01
               || seal key (32)      X25519 public key, the epic1 seal key at the index
               || delivery key (33)  compressed secp256k1 public key, the epic1 delivery key
                                     at the same index
characters     = 106 data + 6 checksum + "epic1" = 117 (tepic1: 118)
```

Any version other than `01` is refused.

### B.2 Links (ABNF, RFC 5234)

```abnf
link            = epicbox-link / epic1-link

epicbox-link    = "epic:" ["epicbox://"] epicbox-address [ "?" e0-param *( "&" e0-param ) ]
epicbox-address = 52base58char [ "@" domain [ ":" port ] ]
e0-param        = pay-param / other-param

epic1-link      = "epic:" epic1-address [ "?" e1-param *( "&" e1-param ) ]
epic1-address   = ( "epic1" / "tepic1" ) 112bech32char
e1-param        = route-param / pay-param / other-param
route-param     = http-route / tor-route              ; may repeat; at most 3 in a link
http-route      = "http=" relay-domain [ ":" port ]   ; <= 128 octets; port 443 by default
tor-route       = "tor=" onion-name [ ":" port ]      ; port 80 by default
onion-name      = 56onionchar ".onion"                ; the sender checks the checksum
pay-param       = ( "amount" / "message" / "note" / "memo" / "label" ) "=" value
other-param     = key "=" value                       ; ignored by readers; "epicbox" is
                                                      ; reported as skipped

domain          = 1*128( ALPHA / DIGIT / "." )
relay-domain    = label *( "." label )
label           = 1*63( ALPHA / DIGIT )               ; no hyphen; a last label led by a digit
                                                      ; makes the domain an IPv4 literal
port            = 1*5DIGIT                            ; 1-65535
key             = 1*( ALPHA / DIGIT / "_" / "-" )
value           = *( unreserved / pct-encoded )       ; RFC 3986
base58char      = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
bech32char      = DIGIT / %x61-7A                     ; the decoder checks the bech32 alphabet
onionchar       = %x61-7A / %x32-37                   ; a-z, 2-7
```

Links are written in lower case, and a mixed-case epic1 is refused. `relay-domain` is used in the
`http` entries of epic1 links and in tail record `02`. It keeps Epicbox's characters, letters and
digits, because an Epicbox relay refuses a post whose `from` or `to` names a hyphenated domain. An
IPv4 literal is four decimal numbers up to 255 without leading zeros; `127.1`, `0x7f.0.0.1` and
`relay.example.1a` are refused. The host rule of 5.14 applies to every `relay-domain`. The cases
every reader runs are in `testdata/vectors/pairing/epictx_relay_hosts.json`.
