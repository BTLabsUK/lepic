# RFC 0003 EPICTX: native slates and sealing between LEPIC wallets

Status: accepted
Decision record: [ADR 0052](../adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md).
Amends [RFC 0001](0001-lepic-slate-v1.md) and builds on the sealed envelope of
[RFC 0002](0002-contact-pairing.md).

EPICTX is how two LEPIC wallets exchange a slate in the native binary format `lepic.v1`, sealed
with HPKE inside the RFC 0002 envelope. It defines the native slate's layout, the `0A` envelope
type that carries it, the `BEGINEPICTX.` armor, the epic1 address and payment link, the native
direct endpoint of a listener, native slates over Epicbox, and slates exchanged in person as QR
codes. Wallets that are not LEPIC keep getting V2 or V3 JSON: legacy formats exist at the edge of
LEPIC only.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Byte values are hex.
Integers are big-endian unless a section says otherwise.

## 1 Purpose and scope

This RFC states, for implementers of other wallets and reviewers:

- the `lepic.v1` slate bytes (5.10) and the envelope that carries them (5.3 to 5.9);
- text armor and files (5.11, 5.12);
- the epic1 address and payment link (5.13, 5.14, 5.19, Appendix B);
- the listener advert and the native direct endpoint (5.15);
- the LEPIC marker on legacy slates (5.16);
- slates in QR codes and in person (5.18, 9);
- native slates over Epicbox (11).

Pairing, contact cards, mailboxes and the RFC 0002 message types are out of scope; RFC 0002 states
them. Transport framing of Epicbox is in [Epicbox](../protocols/epicbox.md).

## 2 Terms

| Term | Meaning |
|---|---|
| Native slate | A slate in `lepic.v1` bytes (5.10). |
| Legacy slate | A V2 or V3 JSON slate as `epic-wallet` reads and writes it. |
| Envelope | The RFC 0002 sealed envelope (5.3). |
| Slate envelope | An envelope of type `0A` whose body is a native slate (5.6). |
| EPICTX text | A slate envelope armored `BEGINEPICTX.` (5.11). |
| epic1 | A LEPIC payment address of two public keys (5.13). |
| Seal key | An X25519 key an envelope is sealed to (5.2). |
| Reply key | A one-time X25519 key an answer is sealed to. |
| Reply mailbox | A one-time Epicbox mailbox an answer is posted to (5.2). |
| Link mailbox | The Epicbox mailbox an epic1 link names (5.2). |
| Post key | The Epicbox `from` key used to post one slate (5.2). |
| Proposal | A slate at S1 or I1. |
| Answer | A slate at S2 or I2. |
| Initiator, responder | The party that makes the proposal, and the one that answers it. |
| Consumer | The application that embeds LEPIC and talks to the user. |

## 3 Overview

A slate goes through three stages. The sender's flow is S1, S2, S3; the invoice flow is I1, I2,
I3. The initiator makes the proposal, the responder answers, and the initiator finalizes and
posts the transaction.

Between LEPIC wallets the slate is native and sealed:

| Channel | Carrier | Section |
|---|---|---|
| Paired contact (file, paste, mailbox) | Slate envelope, signed | 6.1 |
| Listener over HTTP or Tor | Slate envelope to the listener's seal key | 5.15, 6.2 |
| epic1 link | Slate envelope to the epic1 seal key, posted to a link mailbox | 5.19, 6.3 |
| Epicbox payments address | Slate envelope to the address's seal key | 11 |
| In person | Raw `lepic.v1` code, answered with a slate envelope | 9 |

With any other wallet LEPIC speaks the legacy format of the method in use (6.4, 6.5).

### 3.1 Which way a payment goes

Two codes are shown for receiving, never mixed:

- the **Epicbox link** `epic:<epicbox address>`, which every Epic Cash wallet can pay;
- the **epic1 link** `epic:<epic1>?epicbox=...`, which only LEPIC wallets read (5.14).

No code carries both an Epicbox address and an epic1. A link mailbox is a delivery point: it is
never shown, paid or answered as an address.

In person, one phone shows a proposal as a code and the other scans it (9). The answer is sealed
to the code's reply key and posted to the code's reply mailbox, or shown back as a code when the
answering wallet is offline.

### 3.2 LEPIC and the consumer

LEPIC builds, seals, opens, checks and stores slates. It never asks the user anything: where a
flow needs a person's decision (accept a relay, pick an in-person answer, approve a payment), LEPIC
reports what it found and the consumer asks. LEPIC never finalizes an in-person answer by itself.

## 4 Design summary

- **Legacy at the edge.** A wallet that is not LEPIC never receives a native slate, an envelope or
  an epic1. LEPIC reads and writes V2 and V3 JSON for them as before.
- **One envelope.** Native slates reuse the RFC 0002 envelope with a type of their own (`0A`), so
  one reader handles contacts and payments.
- **Key classes.** An envelope sealed to an epic1, listener or Epicbox seal key uses an HPKE `info`
  of its own (5.4), so it opens only under the key class it was sealed for.
- **Fresh keys per slate.** Reply keys, reply mailboxes and post keys are derived per slate from
  the seed (5.2), so a relay cannot join payments by mailbox, and a restored wallet finds them
  again.
- **Content decides.** Readers classify input by its bytes, never by file name or folder (5.12).
- **No silent downgrade.** A pinned direct peer that stops advertising, or changes its key, is
  reported and not paid in legacy format (5.15).

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
| epic1 proof key seed | `lepic-wallet epic1 proof key v1` | `account (u32) || net` |
| Reply mailbox | `lepic-wallet reply mailbox v1` | `account (u32) || net || slate_id (16) || counter` |
| Post key | `lepic-wallet post key v1` | `account (u32) || net || slate_id (16) || role || counter` |
| Link mailbox | `lepic-wallet link mailbox v1` | `account (u32) || net || kind || n (u32) || counter` |

- **Seal key kinds:** `00` epic1, `01` onion listener, `02` web listener, `03` Epicbox payments
  address. The 32 output bytes are the X25519 secret. Each kind gives a different key, so an
  advert does not link an onion listener to a web listener, an epic1 or an Epicbox address.
- **epic1 proof key:** the 32 output bytes are an Ed25519 seed. It signs payment proofs of slates
  that came to the epic1.
- **Mailbox and post keys** are secp256k1 keys, the Epicbox key type. `counter` is one byte from
  `00` up; the first output that is a valid secp256k1 secret is the key.
- **Post key role:** `00` initiator, `01` responder.
- **Link mailbox kind:** `00` on screen, with `n` from 0 to 49, a fresh one per receive session or
  share, used in turn; `01` printed, with `n` from 0 to 31, fixed per printed code.
- **Reply key:** the one-time reply key of RFC 0002 §2.3, from the contact root and the slate id.

The Epicbox payments address of account 0 has the seal key of kind `03`. The marker of its slates
names that key (5.16), and it is not the epic1's, so the two addresses are not linkable.

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
| Listener seal key (kinds 01, 02) | `"epic-tx/1" || net || suite || 01` |
| Epicbox payments seal key (kind 03) | `"epic-tx/1" || net || suite || 02` |

A reader opens with one candidate key and one class. Any HPKE failure is "cannot open", whatever
step failed.

### 5.5 Hint

The hint lets the recipient pick the opening key without trying every key it holds.

| Recipient | Hint |
|---|---|
| Paired contact | `HMAC-SHA256(hint_key, enc)[0..8]` |
| Paired contact whose card sets `fixed-hint` | `SHA256("epic-seal/1 fixed" || hint_key)[0..8]` |
| One-time reply key `R` | `HMAC-SHA256(SHA256("epic-seal/1 reply" || R), enc)[0..8]` |
| Pairing reply | The invite id |
| epic1, listener or Epicbox seal key | `00` × 8 |

A zero hint says only that the envelope is sealed to a seal key of 5.2.

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
| `09` | Reply mailbox | Anonymous proposals, beside tag `03` |
| `80` | Sent at, unix seconds, `u64` | Optional |
| `81` | Address proof, 32 bytes | Pairing envelopes |
| `82` | Feature bits, `u32` | Optional |
| `83` | Domain claim | Optional |
| `FE` | Padding, zero bytes | Always, 5.7 |
| `FF` | Signature, Ed25519, 64 bytes | Signed envelopes, last |

Tag `09` is `mailbox key (33) || relay`, the relay `domain[:port]` of 1 to 128 bytes in the
`relay-domain` grammar (Appendix B.2). It is valid only beside tag `03` in an anonymous envelope.

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
payment proof. A V3 slate in a type `01` envelope is padded the same way when the sending wallet
has native slates on, and unpadded otherwise; readers take both.

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
3. parse the fields (5.6) and require type `0A` and a body;
4. verify the signature when tag `FF` is present;
5. refuse tag `09` without tag `03`, or in a signed envelope;
6. decode the body as `lepic.v1` for its own network (5.10).

What a wallet then takes depends on the key that opened it:

| Opened with | Takes |
|---|---|
| A contact key, signed by that contact | The contact's slates, under RFC 0002's rules |
| An epic1, listener or Epicbox seal key | An anonymous proposal with a reply key; an S1 at an Epicbox payments address |
| A reply key of a slate this wallet started | The answer to that slate, same slate id, next stage |

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

A reply mailbox needs a reply key. Records `01` and `02` are allowed only in a proposal. An unknown
type below `80` refuses the slate; from `80` up it is kept verbatim and in order. A slate inside an
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
  sealed answer to a marked legacy file.

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

An epic1 is bech32m (BIP 350) over 65 data bytes:

```text
data = version (01) || proof key (32) || seal key (32)
```

| Part | Value |
|---|---|
| HRP | `epic` on mainnet, `tepic` on floonet |
| Proof key | Ed25519 public key of the epic1 proof key (5.2) |
| Seal key | X25519 public key of seal key kind `00` (5.2) |
| Length | 115 characters on mainnet, 116 on floonet |

The address carries nothing else: no mailbox, relay or transport. Appendix B.1 has the layout.

A reader decodes in this order and refuses with the first error:

1. bech32m, lower case only (mixed case refused), at most 256 characters;
2. the prefix: the other network's prefix is "wrong network", any other is "unknown prefix";
3. 65 data bytes;
4. version `01`;
5. the proof key: a canonical Ed25519 point of large order;
6. the seal key: not of small order.

### 5.14 Payment links

An epic1 link names the address, where to deliver to it, and what to pay:

```text
epic:epic1qqqq...example?epicbox=es1qexample...@relay.example.com&amount=1.5&message=Lunch
```

Appendix B.2 has the grammar. The parameters:

| Key | Meaning |
|---|---|
| `epicbox` | A link mailbox: an Epicbox address on a relay, `<mailbox>@<relay>[:<port>]`. May repeat. |
| `amount` | Decimal EPIC |
| `message`, `note`, `memo` | The payee's message |
| `label` | A label for the payee |

**Reader rules:**

- The whole link is at most 2048 bytes. The scheme `epic:` matches in any case. The address must
  start with `epic1` or `tepic1`, and decode as 5.13; the link's network is the address's own.
- At most 3 `epicbox` entries are read; later ones are reported as over the limit. An entry is
  skipped and reported when it does not decode, names no relay, has a mailbox that is not an
  Epicbox address, has a mailbox of the other network, or has a relay that breaks the host rule
  below.
- `amount`: the first one only. Up to 8 decimals; signs, exponents, separators, spaces and zero
  are refused.
- `message` (or `note`, or `memo`) and `label`: the first one only, percent-decoded UTF-8, at
  most 256 bytes, no control characters, else skipped.
- `method`, `direct`, `require`, `min` and unknown keys are ignored. No parameter is ever read as a
  second payee.
- A link with no usable `epicbox` entry cannot be paid. There is no default relay.

**Writer rules:** lower case; at most 3 `epicbox` entries, then `amount`, `message` and `label`;
everything outside RFC 3986 unreserved characters percent-encoded.

**Hosts from untrusted input.** A relay named in a link, in tag `09`, in tail record `02`, or the
host of a direct endpoint follows these rules:

- **Syntax:** `host[:port]` of at most 128 bytes. Labels of 1 to 63 letters, digits and hyphens,
  with no hyphen at either end; lower-cased. A last label of digits only makes the host an IPv4
  literal: exactly four decimal labels, each at most 255, without leading zeros. An IPv6 literal
  cannot be written. A port is 1 to 65535, at most 5 digits.
- **Addresses:** checked on the addresses actually connected to, after resolution. Loopback is
  refused: `localhost` and names under it, `127.0.0.0/8`, `::1`, IPv4-mapped and IPv4-compatible
  forms, `0.0.0.0` and `::`. A local-network address is allowed and reported to the consumer:
  `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`,
  `fc00::/7`, `fe80::/10` and names ending in `.local`. Everything else is public.

### 5.15 Advert and native direct endpoint

A LEPIC listener advertises native slates in the result of its `check_version` answer, under the key `lepic`:

```json
{
  "foreign_api_version": 2,
  "supported_slate_versions": ["V3", "V2"],
  "lepic": {
    "protocol": 1,
    "formats": ["lepic.v1"],
    "path": "/v1/peer",
    "seal": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

`seal` is the listener's seal key (kind `01` on the onion, `02` on the web listener), 64 hex
characters. A reader takes at most 16 formats of at most 64 characters, a `path` of at most 256
characters that starts with `/`, and ignores unknown keys. A foreign API version below 2 is
incompatible.

**Endpoint:**

| Request | Answer |
|---|---|
| `GET /v1/peer` | `application/json`: `protocol`, `formats`, `network` (`mainnet` or `floonet`), `key` (64 hex) |
| `POST /v1/peer/slates` | The reply envelope, `application/vnd.lepic.epictx` |

The POST body is a slate envelope sealed to the listener key, anonymous, with a reply key (tag
`03`). Its `Content-Type` MUST be `application/vnd.lepic.epictx` (parameters ignored). The body is
at most 69,632 bytes. The listener seals the answer to the reply key. It caches the last 64
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

**When a sender goes native.** A send to a listener goes native only when the wallet has
`native_direct` on, the caller did not ask for legacy, and the advert is present. The listener's
key is pinned per account and origin on the first success:

- a key equal to the pin is used;
- a different key is reported and never stored; the user forgets the pin to take the other key;
- a pinned origin that stops advertising, or fails, is reported and never paid in legacy format.

[HTTP](../protocols/http.md) describes the endpoint for client writers.

### 5.16 LEPIC marker on legacy slates

A LEPIC wallet marks the legacy slates it writes with a last top-level key `lepic`:

```json
"lepic": {"version": 1, "f": 207, "reply": "<64 hex>"}
```

- `version` is 1.
- `f` is the feature word, sent only over Epicbox. Bits: 0 marker, 1 pairing requests, 2 address
  proof, 3 status notices, 4 device forwarding, 5 name service, 6 app payloads, 7 native slates.
  Bits 4 and 5 are claimed by hosts that offer them. A LEPIC wallet claims bits 0, 1, 2, 3 and 6,
  and bit 7 with `native_direct` on.
- `reply` is an X25519 key, 64 hex. On a V3 S1 or I1 in a file or paste it is the slate's one-time
  reply key: a LEPIC receiver answers sealed to it (6.4). Over Epicbox with bit 7 set it is the
  payments address's seal key (kind `03`) (11.1). A small-order key is ignored.

Bits 16 to 31 (the owner's profile) are sent only in the pairing features extension (`82`), never
in the marker. A wallet that is not LEPIC ignores the key.

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
| epic1 address | 256 characters read, 115 or 116 written |
| epic1 link | 2048 bytes, 3 `epicbox` entries, 256 bytes per value |
| Direct endpoint body | 69,632 bytes |
| Direct endpoint cached answers | 64 |
| Advert | 16 formats, 64 characters each, path 256 characters |
| Binary QR payload | 67,648 bytes |
| Single QR code | 360 bytes of framed payload |
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
- A reader takes fragments of 16 to 1024 bytes, at most 256 fragments, parts of at most 2400
  characters, at most 1024 parts and 1 MiB per decode, and binary payloads of at most 67,648
  bytes.

An in-person proposal is a raw `lepic.v1` slate with its tail (9); an answer is a slate envelope.

### 5.19 epic1 payments

An epic1 receives at link mailboxes (5.2) on the relays its links name.

**Payee.** Each link shown on screen uses the next of 50 on-screen mailboxes in a ring. A printed link takes the first of 32 printed mailboxes that is free, and
keeps it until the user retires it. Each collect drains every on-screen mailbox used in the last
7 days and every printed one not retired.

**Payer.** The payer:

1. builds the S1 and seals it in an anonymous slate envelope to the epic1 seal key, hint zero,
   with tag `03` (its reply key) and tag `09` (a reply mailbox on the payer's own relay);
2. armors it `BEGINEPICTX.` and posts it to the first usable `epicbox` entry with a post key
   (role initiator); when that fails it posts the same bytes to the next entry.

The S1's TTL is 1440 blocks unless the send sets one.

**Payee on collect.** A message at a link mailbox that is not `BEGINEPICTX.` armor is dropped. The
payee opens the envelope with the epic1 seal key and refuses a signed envelope, a non-zero hint,
a missing tag `03` or `09`, or a stage other than S1. It builds the S2 and signs a payment proof
with the epic1 proof key when asked, seals the S2 to the reply key, and reports the reply relay.
It posts the answer, with a post key of role responder, once the consumer confirms the relay.

**Payer on collect.** The payer opens the answer with the reply key, checks it is the S2 of its
stored S1, and finalizes it.

## 6 Flows

### 6.1 Paired contact

1. A seals the S1 (or I1) to B's contact key, signed, with its current card. It goes native (type
   `0A`, `BEGINEPICTX.`) when A has `native_direct` on, B's card claims native slates and the
   pairing is not private, and as a sealed V3 slate (type `01`, `BEGINEPICSEALED.`) otherwise.
   An answer takes the format of its request.
2. It travels by B's mailbox, a file or a paste (RFC 0002 §9).
3. B opens it by hint, checks the signature against the pairing, and answers on the same channel,
   sealed and signed to A.
4. A finalizes.

### 6.2 Direct HTTP or Tor peer

1. A reads B's `check_version`. Without the `lepic` advert, A sends V2 or V3 JSON to
   `/v2/foreign`.
2. With it, A checks the seal key against its pin (5.15), seals the S1 anonymously to it with a
   reply key, and POSTs it to `/v1/peer/slates`.
3. B opens it with the listener's seal key, answers, and returns the S2 sealed to the reply key.
4. A opens and finalizes it.

### 6.3 epic1 link

1. B shows or prints an epic1 link (5.14).
2. A reads it, builds the S1 and posts it sealed to the link mailbox (5.19).
3. B collects it, answers, and posts the S2 to A's reply mailbox once B's user accepts the relay.
4. A collects the S2 from its reply mailbox and finalizes.

### 6.4 Receiver with no known key

1. A writes a V3 S1 file marked with `"lepic":{"version":1,"reply":"<reply key>"}`.
2. A wallet that is not LEPIC ignores the marker and answers a plain V3 S2.
3. A LEPIC receiver answers with an anonymous type `01` envelope, V3 S2 body, sealed to the reply
   key, as `BEGINEPICSEALED.` text.
4. A finalizes either answer.

The S1 is plain V3: whoever carries it reads it.

### 6.5 Wallets that are not LEPIC

- A legacy sender to a LEPIC listener uses `/v2/foreign` with V2 or V3.
- A LEPIC sender to a listener without the advert sends V2 or V3.
- Over Epicbox to an address without the marker's bit 7, LEPIC sends V2 JSON.
- A legacy wallet pays the Epicbox link and refuses an epic1 link as an unknown address.
- A legacy wallet never receives an envelope, card, invite or notice.

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
shows its check code. A's consumer asks A's user to confirm the code on B's screen before A
finalizes.

Section 9 states the rules for both.

### 6.8 Paypoint

A paypoint is a shop terminal that shows codes and scans answers. It asks for money only by
showing an I1, as in 6.7 "Payee starts", with a reply mailbox on its own relay. A payer may also
show an S1 to a paypoint, as in 6.7 "Payer starts".

### 6.9 Payment code or link over Epicbox

1. B shows the plain Epicbox link, with an amount and a message if set.
2. A sends to B's Epicbox address: V2 JSON, or a native slate when section 11 allows it.
3. B answers when online; A finalizes when the S2 arrives.

### 6.10 Invoices: who started it

| How an invoice arrives | Rule |
|---|---|
| The payer scans it in person | No pairing needed. Paid only on the user's approval (9). |
| Pushed by Epicbox, a mailbox or a link | Taken only from a paired contact with invoices allowed (RFC 0002 §11) |
| As a native slate at an Epicbox payments address | Refused, with nothing stored |
| In a file the user opens | The RFC 0002 §11.5 file rule |

No invoice is ever pushed to a receive code. A printed code can be covered by another sticker;
the payer checks the amount and the payee before approving.

## 7 Threat model

The device and seed are assumed sound. HPKE base mode gives IND-CCA2 to the recipient, Ed25519
gives EUF-CMA, and Mimblewimble partial signatures and payment proofs bind the parties to a
transaction.

### 7.1 Per party

| Party | Can learn | Can do |
|---|---|---|
| Carrier of a slate envelope (chat, mail, drive) | Network, suite, hint, `enc`, padded size, timing | Drop, delay, replay (idempotent); seal its own anonymous S1 to a public epic1 key |
| Carrier of a marked legacy file | The whole V3 S1, including its reply key | Replace the reply key and answer as the receiver, unless the sender required a payment proof to a key it trusts |
| Whoever hands the payer a link or code | Nothing more | Replace the whole link, as with any address; replace only a mailbox, which receives an S1 it cannot open |
| Onlooker in person | The raw proposal: amount, messages, public keys, reply key, reply mailbox | Post its own answer, which LEPIC reports with its check code and never finalizes by itself |
| Relay of a link or reply mailbox | Which mailbox receives messages, when, sizes, the poster's IP address and post key | Drop, delay, replay, deny service |
| Network observer, plain HTTP | The advert, IP addresses, envelope size, timing | Nothing more; slates are sealed |
| Active attacker on first contact, plain HTTP | Everything | Strip the advert, which gives legacy; replace the seal key, which is then pinned |
| Active attacker, onion | Nothing | Deny service; the onion address authenticates the listener |

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
- **Unlinkability by key:** listener, epic1 and Epicbox seal keys differ; reply mailboxes and post
  keys are per slate; on-screen link mailboxes rotate over 50. A printed code's mailbox links the
  payments made with it.
- **Length hiding** of sealed proposals above the 768-byte floor.
- **Delivery cannot redirect payment:** a link's transport entries decide where an S1 is posted,
  never who can open it.
- **No silent downgrade** for contacts and pinned direct peers.

### 7.3 Not claimed

- Anonymity of the sender towards the receiver.
- Protection of plain legacy flows beyond what the legacy format gives.
- Post-quantum confidentiality.
- Recipient-side forward secrecy: a leak of a static seal key opens past envelopes to it.
- Confidentiality of a raw in-person code.
- That the first answer to an in-person code comes from the intended party.
- Hiding the answering wallet's IP address from a relay the other party named.
- Protection against a hacked paypoint or a covered printed code.

## 8 Compatibility

- **Wallets that are not LEPIC** see an extra `lepic` key in `check_version` answers and in
  legacy slates, which they ignore. They refuse an epic1 link as an unknown address.
- **LEPIC readers** take both armor marker pairs and both padded and unpadded type `01`
  envelopes.
- **Senders** use type `0A` and `BEGINEPICTX.` only for a peer that claimed native slates: a
  contact's card, a listener's advert, or bit 7 of an Epicbox marker.
- **Stored data:** a transaction finishes in the format it started in; resends use stored bytes.
  Native keys come from the seed, so a restore needs no migration. Pins start empty.
- **Host switch:** native sending is on only with `native_direct`. The endpoint and the advert are
  served either way.
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
the reply key. It is posted to the reply mailbox with a post key of role responder once the user
confirms the relay, or shown back as a code.

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

**Finalizing.** Nothing finalizes by itself. Each answer is stored and reported with its number
and check code; the user picks the one to finalize. Answers that arrive before the TTL are still
recorded.

## 10 Security considerations

- **Anyone who saw a raw code can answer it.** The check code lets the users confirm they hold
  the same answer; a wrong pick in an I1 flow costs the payer nothing, since the paying wallet
  is the one that answered.
- **Relays named by the other party** see the answering wallet's IP address. LEPIC reports the
  relay, with its class from 5.14, before it posts, and the consumer asks the user.
- **Printed codes** use one link mailbox each, so the relay of that mailbox can link every payment
  made with the code.
- **Static seal keys** open every past envelope sealed to them if leaked. All of them derive from
  the seed.
- **First contact over plain HTTP** can be intercepted; the pin protects later sends. Tor or HTTPS
  listeners avoid it.
- **Anonymous envelopes** authenticate nothing. A wallet trusts an anonymous slate only as far as
  the slate proves itself (5.9).

## 11 Native slates over Epicbox

### 11.1 The payments address

A LEPIC wallet with `native_direct` on claims native slates in the marker of every slate it sends
over Epicbox: bit 7 in `f`, and in `reply` the public seal key of kind `03` of account 0 (5.2).

A sender sends an S1 to an Epicbox address as a native slate when:

- its own `native_direct` is on and it claims native slates;
- the S1 carries a reply key;
- the address is a LEPIC wallet with a marked message within the last 30 days, and its latest
  marked slate claimed native slates with a valid key.

The S1 is then a slate envelope sealed to that key with the Epicbox class (5.4), hint zero, tag
`03` (the reply key) and tag `82` (the sender's feature word), armored `BEGINEPICTX.` and sent as
the Epicbox message. Otherwise it goes as V2 JSON with the marker.

The receiver opens an envelope with a zero hint with its kind `03` key, and any other with the
reply key of a send waiting for its answer. It refuses, with nothing stored:

| Refusal | When |
|---|---|
| Malformed | Not `BEGINEPICTX.` armor, or the envelope does not decode |
| Cannot open | No key opens it |
| Not a slate | The body is not a slate this address takes, or not the expected stage or slate |
| Invoice | An I1 |
| No reply key | An S1 without tag `03` |

The S2 goes back sealed to the S1's reply key, in the same armor.

## 12 References

- [RFC 0001](0001-lepic-slate-v1.md), [RFC 0002](0002-contact-pairing.md)
- [ADR 0052](../adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md) Legacy at the edge,
  native between LEPIC wallets
- [ADR 0044](../adr/0044-the-onion-has-its-own-key.md) The onion has its own key
- [ADR 0025](../adr/0025-animated-qr-slates.md) Animated QR slates
- Guides: [EPICTX](../protocols/epictx.md), [epic1](../protocols/epic1.md),
  [HTTP](../protocols/http.md), [Epicbox](../protocols/epicbox.md)
- Crates: [`lepic-seal`](../../crates/lepic-seal/README.md),
  [`lepic-native-slate`](../../crates/lepic-native-slate/README.md),
  [`lepic-epic1`](../../crates/lepic-epic1/README.md),
  [`lepic-peer`](../../crates/lepic-peer/README.md)
- RFC 9180 HPKE; RFC 9457 Problem Details; BIP 350 bech32m; RFC 5234 ABNF; RFC 3986 URI

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
epic1 address  = hrp "1" data checksum          ; bech32m, BIP 350, lower case only
hrp            = "epic" (mainnet) / "tepic" (floonet)
data (65 B)    = version (1) = 0x01
               || proof key (32)   Ed25519 public key, the epic1 proof key
               || seal key (32)    X25519 public key, seal key kind 00
characters     = 104 data + 6 checksum + "epic1" = 115 (tepic1: 116)
```

Any version other than `01` is refused.

### B.2 Links (ABNF, RFC 5234)

```abnf
link            = epicbox-link / epic1-link

epicbox-link    = "epic:" ["epicbox://"] epicbox-address [ "?" e0-param *( "&" e0-param ) ]
epicbox-address = 52base58char [ "@" domain [ ":" port ] ]
e0-param        = pay-param / other-param

epic1-link      = "epic:" epic1-address [ "?" e1-param *( "&" e1-param ) ]
epic1-address   = ( "epic1" / "tepic1" ) 110bech32char
e1-param        = transport-param / pay-param / other-param
transport-param = "epicbox=" mailbox-address          ; may repeat; at most 3 read
mailbox-address = 52base58char "@" relay-domain [ ":" port ]
                                                      ; relay-domain [":" port] <= 128 octets
pay-param       = ( "amount" / "message" / "note" / "memo" / "label" ) "=" value
other-param     = key "=" value                       ; ignored by readers

domain          = 1*128( ALPHA / DIGIT / "." )
relay-domain    = label *( "." label )
label           = ( ALPHA / DIGIT ) [ *( ALPHA / DIGIT / "-" ) ( ALPHA / DIGIT ) ]
                                                      ; four decimal labels are an IPv4 literal
port            = 1*5DIGIT                            ; 1-65535
key             = 1*( ALPHA / DIGIT / "_" / "-" )
value           = *( unreserved / pct-encoded )       ; RFC 3986
base58char      = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
bech32char      = DIGIT / %x61-7A                     ; the decoder checks the bech32 alphabet
```

Links are written in lower case, and a mixed-case epic1 is refused. `relay-domain` is used in
epic1 links, tag `09` and tail record `02`; it allows hyphens, which `domain` in the plain Epicbox
link does not. The host rule of 5.14 applies to every `relay-domain`.
