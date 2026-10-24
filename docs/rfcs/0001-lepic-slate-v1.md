# RFC 0001 lepic.v1: compact native slates, armored packs and capability advertisement

Status: draft, awaiting the operator's decision OD-5
Date: 2026-10-02
Proposes: ADR 0012. Implemented by X-02 (codec) and X-03 (packs, text transport, capabilities).
Amended by: RFC 0002 for encryption (a dedicated per-contact key instead of D1's payment-proof key,
and its own sealed envelope around V3 JSON).

## TL;DR

`lepic.v1` is a binary slate format that carries, at each stage, only what the next party needs.
A first-leg slate (S1 or I1) is 149 to 471 bytes in the G-03 cases, against 2,315 to 5,394 bytes
of legacy JSON, and the reply
is about a quarter of its legacy size. Slates travel inside a pack: a small header, an optional
reply address, and optional encryption to the recipient with HPKE (RFC 9180). The pack is written
as base58 text between `BEGINEPICSLATE.` and `ENDEPICSLATE.` markers for copy-paste, QR codes and
Epicbox. A party's native address is its existing payment-proof ed25519 key in bech32m
(`epic1...`), so one key gives encryption and payment proofs. Holding a peer's native address is
the capability advertisement; the Epicbox address string is never changed, and a wallet that drops
the advertisement falls back to the legacy formats, which still work.

The operator chooses among the options in "Decisions for OD-5". The normative sections assume the
recommended option for each.

## Scope

In scope: the binary slate, the pack, encryption, the armored text form, the native address, the
contact card, capability records, the transport policy rules that use them, and what the engine
must do with partial bodies.

Not in scope: changes to the legacy V2 and V3 codecs (frozen, `docs/rules.md`), the HTTP and Tor
methods, transactions with more than two parties, per-transaction addresses, and app UI.

## Decisions for OD-5

| # | Question | Options | Recommendation |
|---|---|---|---|
| D1 | Which key the native address encodes (ADR 0012 question 1) | K-A payment-proof ed25519 key; K-B Epicbox secp256k1 key; K-C both | K-A |
| D2 | Slatepack framing or an Epic one (ADR 0012 question 2) | F-A Slatepack as is; F-B Epic framing on Slatepack's armor; F-C new base32 framing | F-B |
| D3 | How capability advertisement survives other wallets (ADR 0012 question 3) | C-A separate native address plus learned records; C-B suffix on the Epicbox address; C-C hint inside legacy slates | C-A |
| D4 | Encryption construction | E-A age, as Slatepack; E-B HPKE base mode; E-C the Epicbox message cipher | E-B |
| D5 | What a reply carries | R-A self-contained reply that echoes the initiator's public keys; R-B Grin V4 minimal reply | R-A |
| D6 | Integer encoding | I-A fixed-width big-endian; I-B variable-length | I-A |

D1, D3 and D4 depend on each other: E-C works only with K-B or K-C. The recommendation set
(K-A, F-B, C-A, E-B, R-A, I-A) needs two crates that ADR 0010 does not list yet, `hpke` and
`bech32` (see "Implementation map").

### D1 Which key the native address encodes

Facts. `epic-wallet` `v4.0.2` has two public keys per account, both derived from the same 32-byte
secret at `m/0/1/<index>` (`docs/compat/epicbox.md`, `docs/compat/keys-and-proofs.md`): the secp256k1
Epicbox key and the ed25519 payment-proof key, which `epic-wallet` takes on the command line as 64
hex characters (`controller/src/command.rs`, `address::ed25519_parse_pubkey`). It always uses index 0
for both. Neither public key can be computed from the other.

- K-A, the ed25519 payment-proof key. A sender that holds the address can request a payment proof
  (the proof's `receiver_address` is this key) and can encrypt to it after the standard
  ed25519-to-X25519 conversion that Slatepack and age use. The address is a sibling of the Epicbox
  address: same secret, different curve, so a restore from the seed brings both back. It cannot
  route over Epicbox alone; routing still needs the Epicbox address (D3).
- K-B, the Epicbox secp256k1 key. One address for routing and encryption, but a sender cannot
  request a payment proof without also learning the ed25519 key from somewhere, and proofs are what
  third parties verify with `epic-wallet`.
- K-C, both keys in one address: 65 bytes of keys, about 115 characters in bech32m, too long to read
  or compare.

Recommendation: K-A. Payment proofs are the one feature the legacy Epicbox path cannot carry today
(ADR 0003), and K-A makes them available to every native transaction with no extra exchange.
Index 0, as `epic-wallet` uses, so a proof address a user already published stays valid.

### D2 Framing

- F-A, Slatepack unchanged (`BEGINSLATEPACK.`, `grin1` addresses, Grin V4 binary). The markers would
  tell Grin wallets the text is theirs; they would accept the framing and fail later on content. No
  Epic wallet reads Slatepack, so reuse buys no interoperability.
- F-B, an Epic framing that reuses Slatepack's armor mechanics: base58 in 15-character words between
  two markers, separated by periods, with a 4-byte double-SHA-256 checksum. Distinct markers and a
  binary pack header with magic bytes, version and network. Uses `bs58` and `sha2`, already in the
  workspace.
- F-C, uppercase base32 text. QR alphanumeric mode stores 5.5 bits per character against 8 bits in
  byte mode, so base32 (1.6 characters per byte) gives a QR code about 20% smaller than base58 (1.37
  characters per byte, byte mode), and decoding is linear. The text is 17% longer, shouts in
  uppercase, and needs a new encoding crate. For the 149-byte S1 and the 1-KB S2 the QR difference is
  one or two QR versions.

Recommendation: F-B. The size difference is small at real slate sizes and F-B needs no new encoding
dependency. Base58 decoding is quadratic, so the armor has a hard size bound (section 7).

### D3 Capability advertisement

Facts. `epic-wallet` parses an Epicbox address with an anchored pattern,
`^(epicbox://)?<52 base58 characters>(@<domain>(:<port>)?)?$`, with the domain limited to
`[a-zA-Z0-9.]` (`libwallet/src/epicbox_address.rs`). It reads a legacy slate with an extra top-level
key and drops the key: vector `slates/malformed_unknown_top_level_key` is accepted by both upstream
parsers and re-encoded without it.

- C-A, the native address is the advertisement. A wallet that holds a peer's native address knows
  the peer speaks `lepic.v1`. LEPIC stores it next to the peer's Epicbox address, from a contact card
  the user imports or from an authenticated native message received over Epicbox (section 10).
  Nothing is added to the Epicbox address, so every wallet keeps reading it. A wallet that does not
  know the native address, or drops it, treats the peer as legacy, which works.
- C-B, a suffix or query on the Epicbox address (`...@epicbox.epiccash.com?lepic=1`). The anchored
  pattern above rejects it, so `epic-wallet` users could no longer paste the address.
- C-C, a hint inside legacy slates (an extra JSON key or a marker in the message field). `epic-wallet`
  drops an unknown key, the message field is shown to users, and the legacy codecs are frozen.
  ADR 0012 also says legacy peers never receive native data.

Recommendation: C-A. The answer to "how does it survive other wallets" is that it does not need to:
the advertisement travels apart from anything other wallets store, and losing it degrades to the
legacy formats instead of breaking a transfer.

### D4 Encryption

- E-A, age v1, exactly as Slatepack. Well reviewed, but the text header costs about 170 bytes for one
  recipient (format line, one X25519 stanza, MAC line) on top of a 16-byte nonce and 16-byte tag,
  more than the whole 149-byte S1. Adds the `age` crate and its dependencies.
- E-B, HPKE (RFC 9180) in base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
  ChaCha20-Poly1305. A standard, single-shot public-key encryption with 48 bytes of overhead
  (32-byte encapsulated key, 16-byte tag). The `hpke` crate is maintained, Apache-2.0 or MIT, and
  its current release builds on `chacha20poly1305` 0.11, `sha2` 0.11 and `rand_core` 0.10, the
  versions ADR 0010 already lists. Joint use of one key for Ed25519 signatures and an X25519 KEM
  with an HKDF-Extract-style KDF is proven secure in the random oracle model
  (https://eprint.iacr.org/2021/509).
- E-C, the Epicbox message cipher, already implemented in `lepic-epicbox`. It encrypts between two
  secp256k1 keys, so it works only with K-B or K-C, and the sender must hold an Epicbox key. E-B
  works with K-A and needs no sender key.

Recommendation: E-B.

### D5 What a reply carries

- R-A, self-contained. S2 and I2 repeat the initiator's public blind excess and public nonce (66
  bytes), and the amount, fee, height, lock, TTL, offset and payment-proof addresses. Every stage
  decodes on its own into a `Slate` that passes `Slate::from_parts` (ADR 0002), so the codec stays a
  pure function as the `Codec` trait requires, and a mismatch is reported as a field error instead of
  a failed signature.
- R-B, Grin V4 minimal: the reply carries only the responder's data. Saves about 80 bytes per reply
  (the initiator's keys, amount and fee; 8% of S2), but a reply cannot become a `Slate` without
  the stored proposal, which needs a second slate type or a codec that reads the store.

Recommendation: R-A.

### D6 Integer encoding

- I-A, fixed 8-byte big-endian integers, as Epic consensus serialization and Grin V4 binary use.
  One encoding per value by construction; trivial to fuzz.
- I-B, LEB128 variable-length integers. Saves about 15 bytes per slate and needs a minimal-encoding
  check on decode.

Recommendation: I-A. Fifteen bytes is under 2% of a reply.

## Specification

The sections below are normative for `lepic.v1` and assume the recommended options. "Must" is a
requirement on every encoder and decoder.

### 1 Conventions

- Integers are unsigned big-endian. `u8`, `u16` and `u64` have 1, 2 and 8 bytes.
- `Commitment` and `PublicKey` are 33-byte compressed secp256k1 points. `Signature` is the 64-byte
  compact Schnorr signature legacy slates carry in hex. `ProofAddress` is a 32-byte ed25519 public
  key that decompresses. `ProofSignature` is a 64-byte ed25519 signature.
- A range proof is exactly 675 bytes, the single 64-bit Bulletproof size
  (`RangeProof::BULLETPROOF_LEN`); only that size can verify.
- Stage numbers follow Grin V4: S1 = 1, S2 = 2, S3 = 3, I1 = 4, I2 = 5, I3 = 6.
- The initiator is the sender in the standard flow and the receiver (issuer) in the invoice flow;
  the responder is the other party (`Flow::initiator`, ADR 0002).

### 2 Binary slate

Codec id `lepic.v1`, media type `application/vnd.lepic.slate`. Fields appear in this order with no
padding:

| Field | Type | Present |
|---|---|---|
| magic | 4 bytes `89 45 53 4C` | always |
| version | u8 = `01` | always |
| stage | u8, 1 to 6 | always |
| flags | u8, see below | always |
| id | 16 bytes, the slate UUID | always |
| amount | u64 | always |
| fee | u64, zero at I1 | always |
| height | u64 | always |
| lock_height | u64, non-zero | flag `LOCK` |
| ttl_cutoff_height | u64 | flag `TTL` |
| offset | 32 bytes | always |
| sender | participant | by stage, section 3 |
| receiver | participant | by stage, section 3 |
| payment proof | proof | flag `PROOF` |
| input count | u16 | always |
| inputs | count times (features u8, Commitment) | |
| output count | u16 | always |
| outputs | count times (features u8, Commitment, 675-byte proof) | |
| kernel excess | Commitment | final stages |
| kernel signature | Signature | final stages |

Flags: bit 0 `LOCK`, bit 1 `TTL`, bit 2 `PROOF`, bit 3 `SENDER_MESSAGE`, bit 4 `RECEIVER_MESSAGE`.
Bits 5 to 7 are zero.

Participant: public blind excess (PublicKey), public nonce (PublicKey), the partial signature
(Signature) when section 3 says the party has signed, then, when its message flag is set, the
message length (u16, at most 256), the UTF-8 message and the message signature (Signature).

Payment proof: sender address (ProofAddress), receiver address (ProofAddress), then the receiver
signature (ProofSignature) at S2 and S3.

Input features: 0 plain, 1 coinbase. Output features: 0 plain, 1 coinbase. Kernel features are not
stored: `Plain` when `LOCK` is clear, `HeightLocked` with `lock_height` when it is set
(`KernelLock`, ADR 0002).

The format has no `num_participants` (always 2) and no block header version. The domain model does
not hold a block header version, both parties read the chain tip themselves, and the final
transaction is serialized for the node at its own protocol version.

### 3 What each stage carries

| Stage | Written by | Sender | Receiver | Inputs and outputs | Kernel | Proof signature |
|---|---|---|---|---|---|---|
| S1 | sender | keys, unsigned, message | absent | none | no | no |
| S2 | receiver | keys, unsigned, no message | keys, signed, message | the receiver's own | no | yes |
| S3 | sender | keys, signed, message | keys, signed, message | all | yes | yes |
| I1 | receiver | absent | keys, unsigned, message | none | no | no proof allowed |
| I2 | sender | keys, signed, message | keys, unsigned, no message | the sender's inputs and change | no | no proof allowed |
| I3 | receiver | keys, signed, message | keys, signed, message | all | yes | no proof allowed |

"Message" means the message is written when the party has one; "no message" means the flag must be
clear. Signed and unsigned follow `Slate::from_parts`; presence is fixed by the stage, so the format
spends no bits on it.

Producing these views:

- At S1 and I1 the encoder writes no inputs or outputs. The initiator keeps its own in its stored
  slate; the responder does not need them to sign. This is the one place where `encode` leaves out
  data the `Slate` holds, by definition of the format; it is not a loss, because the only reader is
  the responder, who has no use for it.
- At S2 and I2 the encoder writes the slate's body as given and leaves out the initiator's message,
  which the initiator already has. A responder that decoded a native proposal holds only its own
  inputs and outputs, so that is what it sends back.
- At S3 and I3 the encoder writes the whole slate.

S3 and I3 are not sent to the other party by the native method: the initiator posts the
transaction. The encoding exists so that a finished slate can be exported or archived.

### 4 Decoding

A decoder must reject, with a typed error, before any allocation larger than the input:

- input longer than `MAX_WIRE_SLATE_LEN`, wrong magic, a version other than 1, a stage outside 1 to
  6, a reserved flag bit, `LOCK` set with a zero lock height, `PROOF` in the invoice flow, a message
  flag for an absent party or for the initiator at S2 or I2;
- truncated input or trailing bytes;
- input and output counts whose transaction weight, with one kernel, exceeds `MAX_TX_WEIGHT`;
- features bytes other than 0 and 1, points that do not parse, a `ProofAddress` that does not
  decompress, a message longer than 256 bytes or not UTF-8;
- the same commitment twice among inputs and outputs;
- anything `Slate::from_parts` rejects.

These rules leave each slate exactly one encoding for a given order of its inputs and outputs, so
`encode(decode(bytes)) == bytes` for every accepted input. The decoded slate carries
`WireOrigin::new("lepic.v1")`.

A responder that decodes S1 or I1 cannot check the fee against the body, because it sees none. It
must reject a fee below the weight-based fee of one input, the outputs it will add and one kernel,
and leaves the full check to the initiator, who runs P-03 validation before posting. The fee comes
out of the sender's inputs; a low fee makes the transaction fail at the node and moves nobody's
funds.

### 5 Pack

Every native slate on a wire travels in a pack:

| Field | Type | Notes |
|---|---|---|
| magic | 4 bytes `89 45 50 4B` | |
| version | u8 = `01` | |
| network | u8 | `00` mainnet, `01` floonet; a pack for another network is rejected |
| mode | u8 | `00` plain, `01` encrypted |
| body | rest | mode 0: the inner content; mode 1: section 6 |

Inner content: a reply-address flag (u8, `00` none or `01` present), the sender's native address
key (32 bytes) when present, then the binary slate.

The reply address tells the responder where to encrypt its answer. It is not proof of identity in
either mode; identity is what a payment proof establishes.

The pack lives in `lepic-transport`, not in the codec, because encryption needs keys and the
`Codec` trait is a pure function of its input.

### 6 Encryption

Mode 1 encrypts the inner content to the recipient's native address with HPKE (RFC 9180):

- Suite: KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0003`
  ChaCha20-Poly1305, mode base, single-shot seal.
- Recipient key: the X25519 form of the recipient's ed25519 public key (the Edwards-to-Montgomery
  map). The sender must reject an address whose point has small order. The recipient's X25519
  secret is the clamped scalar of its ed25519 key, the first 32 bytes of SHA-512 of the seed
  (RFC 8032), as libsodium's `crypto_sign_ed25519_sk_to_curve25519` computes.
- `info` is the ASCII string `epic-slate-pack/1` followed by the network byte. The associated data
  is the 7-byte pack header.
- Body: the 32-byte encapsulated key, then the ciphertext, which is the inner content plus a 16-byte
  tag.

Randomness for the encapsulation comes from the caller's RNG, as for every pure function in LEPIC.
Decryption failure is one typed error that does not say which step failed.

### 7 Armor

```
BEGINEPICSLATE. <payload>. ENDEPICSLATE.
```

- Payload: base58 (Bitcoin alphabet) of the pack followed by the first 4 bytes of
  SHA-256(SHA-256(pack)), the base58check layout without a version byte. Encoders split it into
  words of 15 characters separated by single spaces and do not break lines.
- Decoders split on the first three periods: framing header, payload, framing footer; anything after
  the third period is ignored. The header must match `^[>\n\r\t ]*BEGINEPICSLATE[>\n\r\t ]*$` and the
  footer `^[>\n\r\t ]*ENDEPICSLATE[>\n\r\t ]*$`, as Slatepack's do, so text quoted in mail or chat still
  reads. Spaces, tabs, line breaks and `>` inside the payload are removed before decoding.
- The armored text must be at most 16,384 bytes, checked before base58 decoding, because base58
  decoding is quadratic in the input length. That covers every stage in the size table with room for
  ten more outputs; a larger slate travels as a binary pack in a file.
- A wrong checksum is a typed error distinct from a malformed pack, so the user is told the text was
  damaged in transit.

### 8 Native address

- bech32m (BIP 350) with human-readable part `epic` on mainnet and `tepic` on floonet.
- Data: an address version byte `00`, then the 32-byte ed25519 public key.
- Version `00` means the holder accepts packs in modes 0 and 1 carrying `lepic.v1` slates. A later
  format is announced with a new address version or a contact-card capability (section 9).
- Decoders reject mixed case, a wrong checksum, an unknown version, a key that does not decompress
  and the other network's prefix.
- The key is the payment-proof key at index 0 of the account (D1). Example, the receiver address of
  vector `slates/send_file_payment_proof_s1_v3`:
  `epic1qzcrepxh77qm2dkfve5djwehw6x8sy4hv3yuz740p2w3rgqrc0rnwal22fe`.

`epic-wallet` rejects this string both as an Epicbox address (length and pattern) and as a
payment-proof address (it expects 64 hex characters), so it cannot be mistaken for either.

### 9 Contact card

A contact card pairs a native address with the Epicbox address used to reach it:

```
epic:<native address>?epicbox=<Epicbox address>[&formats=lepic.v1]
```

- The Epicbox address is in the text form `docs/compat/epicbox.md` defines; `@` and `:` are allowed
  in a URI query and are not escaped.
- `formats` lists codec ids, comma-separated; absent means what the address version implies.
  Unknown ids are ignored.
- A card is as trustworthy as the channel that delivered it, exactly like a bare address. A card
  whose native key does not belong to the Epicbox address's owner fails safely: the owner rejects a
  payment proof request for an address that is not its own, and cannot decrypt a pack encrypted to
  someone else.

The host app decides which QR code to show. A wallet that only understands Epicbox addresses needs
the plain Epicbox address; LEPIC peers want the card. This is a product decision for the frontend,
listed under "Open points".

### 10 Capability records and transport policy

LEPIC keeps, per peer Epicbox address, an optional native address and the time it was learned. It is
set only from:

- a contact card the user imported, or
- a pack received over Epicbox from that address whose relay signature verified, carrying a reply
  address. The Epicbox signature binds the native key to the Epicbox key.

It is cleared when a legacy proposal (S1 or I1) arrives from that address, and the user can clear it.
A legacy slate never sets it. Clearing only moves the peer back to the legacy formats, which always
work; setting it requires evidence.

Format policies (ADR 0003), changed only for peers with a record:

| Transport | Peer | New slate | Reply |
|---|---|---|---|
| Epicbox | no record | V2 shape, as today | shape of the inbound slate |
| Epicbox | record | armored pack, mode 0, with our reply address | codec of the inbound slate |
| Text and QR (new, X-03) | native address known | armored pack, mode 1 | mode 1 to the inbound reply address, else mode 0 |
| Text and QR | unknown | armored pack, mode 0, with our reply address | as above |
| File | any | unchanged | unchanged |

Over Epicbox the pack is plain because the Epicbox message cipher already encrypts it, and armored
because the Epicbox plaintext is text (`lepic-epicbox` `Plaintext`). An Epicbox payload is native
exactly when it starts with `BEGINEPICSLATE`, after optional whitespace; anything else goes to the
legacy codecs.

A payment proof over Epicbox is possible for a peer with a record, because its native address is the
proof address. Without a record the existing refusal stands (ADR 0003).

### 11 Engine contract

The native format sends partial bodies, so the engine must not assume a reply repeats the
initiator's inputs and outputs. These rules work unchanged for legacy replies, which do repeat them:

Responder (W-04, W-08):

1. Validate a proposal from what it carries (TTL, duplicate slate id, participant data, the fee
   floor of section 4). Do not require a body.
2. Add own data to the slate as received and reply with it.

Initiator, on a reply (W-05, W-08):

1. Load the stored slate for the id; the reply must be the next stage of the same flow.
2. These must equal the stored values: id, amount, lock, offset, the initiator's public blind excess
   and public nonce, and the payment-proof addresses. In the standard flow also fee, height and TTL.
   In the invoice flow fee, height and TTL come from the reply, because the payer sets them.
3. Take from the reply: the responder's participant data, the payment-proof signature, and every
   input and output whose commitment is not in the stored slate. An entry whose commitment is stored
   must be identical to the stored one.
4. Keep every stored input and output, then sign, aggregate and validate as today.

## Security and privacy

- Untrusted input. Every decoder in this RFC has a pure entry point bounded by size before it
  allocates: the armor (16 KiB), the pack and the slate (`MAX_WIRE_SLATE_LEN`, weight-bounded
  counts). X-02 and X-03 add fuzz targets for the slate, the pack and the armor.
- Authentication. Neither pack mode authenticates the sender. A reply address only says where to
  send the answer. Payment proofs and the partial signatures bind the parties to the transaction;
  over Epicbox, the relay signature binds the message to the sender's Epicbox key.
- Replay and duplicates. Inbound slates stay idempotent on `(slate_id, stage)`.
- Network separation. The pack's network byte, the HPKE `info` and the address prefix keep mainnet
  and floonet data apart.
- Key reuse. The payment-proof key also decrypts packs, as in Slatepack (see D4 for the proof).
- Privacy. A native proposal carries none of the initiator's inputs or change outputs. The native
  address is a long-lived key; per-transaction addresses are a later option, and they need the
  wallet to listen on many keys.
- Secrets. Ed25519 and X25519 secrets stay in `lepic-keychain` and the engine and never cross the
  FFI boundary; the app passes and receives armored text and addresses only.

## Examples

Laid out by hand from the G-03 vectors named below, following sections 2, 3, 5 and 7; the hex and
the base58 text were checked with a throwaway script that is not part of the repository. They are
illustrations, not golden vectors: no upstream implements `lepic.v1`. X-02 turns them into snapshot
tests and checks that decoding each one gives the same slate as decoding the named V3 vector, less
the parts section 3 leaves out.

### S1, `slates/send_file_plain_s1_v3`

149 bytes. The V3 JSON of the same stage is 2,472 bytes; the file method writes 2,426.

| Offset | Field | Bytes |
|---|---|---|
| 0 | magic | `8945534c` |
| 4 | version | `01` |
| 5 | stage S1 | `01` |
| 6 | flags | `00` |
| 7 | id | `0436430c2b02624c2032570501212b00` |
| 23 | amount 100,000,000 | `0000000005f5e100` |
| 31 | fee 800,000 | `00000000000c3500` |
| 39 | height 4 | `0000000000000004` |
| 47 | offset | `d202964900000000d302964900000000d402964900000000d502964900000000` |
| 79 | sender public blind excess | `0380ce1292adbdf4b77828c29a8449d0f964cc247052d1ec2eb70605aae1ab8b75` |
| 112 | sender public nonce | `031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f` |
| 145 | input count | `0000` |
| 147 | output count | `0000` |

As a plain floonet pack without a reply address (157 bytes:
`8945504b` `01` `01` `00` `00` then the slate), armored:

```
BEGINEPICSLATE. KRF4zvxVzSDgSbG CXzUX77TVYDgE6u jjUPhM3Yyfasgkz a4Qnn5881Fz6Ni3 B8MQUyBzNiZwqAG Ym1gMxC7G47JGfb gEKgg2UxAEjtKou mjrRuxjUL9JixFA 8pXtBmRxra4pTjZ FU52XpGh1NiuAZ6 6TsRQR5NJBVA8dE FkggSfAUzq1LafR kWdHZm8TCsFwREi Y6TJiy3UgsTGgoZ u4DSwGEkbY. ENDEPICSLATE.
```

### S2, `slates/send_file_plain_s2_v3`

988 bytes against 4,294 for V3. Offsets 0 to 144 repeat S1 with stage `02`; then:

| Offset | Field | Bytes |
|---|---|---|
| 145 | receiver public blind excess | `02f90db19ac8bc7d0b910bd13160f41db9e0998867132e47827aca845dbddbbba5` |
| 178 | receiver public nonce | `031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f` |
| 211 | receiver partial signature | 64 bytes, `part_sig` of participant 1 |
| 275 | input count | `0000` |
| 277 | output count | `0001` |
| 279 | output features plain | `00` |
| 280 | output commitment | `09bca50d736eba11e8405c8da20b2cde925c313eea9a57ba86b249372978761976` |
| 313 | range proof | 675 bytes, `proof` of that output |

The sender's change output `08ec32...` and its coinbase input are not sent back; the sender has them
in its stored S1.

### S2 with a payment proof, `slates/send_file_payment_proof_s2_v3`

1,116 bytes against 4,613. Flags `04` (`PROOF`). After the receiver's partial signature, at offset
275: sender address `fd5c6c0a...a91e7fd0`, receiver address `b03c84d7...03c3c737` and the 64-byte
receiver signature, then the body from offset 403 as in the plain S2.

### Invoice, `slates/invoice_file_plain_i1_v3` and `_i2_v3`

I1 is 149 bytes against 2,361: stage `04`, fee zero, and the issuer's keys in the receiver slot. The
issuer's output `096ca6...` stays with the issuer. I2 is 1,022 bytes against 4,294: stage `05`, the
payer's keys and partial signature, the issuer's keys echoed, one coinbase input `0889d6...` and
the payer's change output `099d28...` with its proof.

## Sizes

Bytes of legacy JSON as G-03 records it, bytes of the `lepic.v1` slate, and characters of the
armored pack (mode 0 with a reply address, and mode 1 with a reply address).

| Vector case | Stage | V3 JSON | File method | `lepic.v1` | Armored, plain | Armored, encrypted |
|---|---|---|---|---|---|---|
| `send_file_plain` | S1 | 2,472 | 2,426 | 149 | 312 | 382 |
| | S2 | 4,294 | 4,248 | 988 | 1,534 | 1,604 |
| | S3 | 4,420 | 4,374 | 1,892 | 2,851 | 2,921 |
| `send_file_messages` | S1 | 2,624 | 2,578 | 243 | 449 | 519 |
| | S2 | 4,600 | 4,554 | 1,084 | 1,674 | 1,745 |
| | S3 | 4,726 | 4,680 | 2,082 | 3,128 | 3,197 |
| `send_file_ttl` | S1 | 2,472 | 2,472 | 157 | 324 | 394 |
| | S2 | 4,294 | 4,294 | 996 | 1,546 | 1,616 |
| `send_file_payment_proof` | S1 | 2,665 | 2,665 | 213 | 405 | 475 |
| | S2 | 4,613 | 4,613 | 1,116 | 1,721 | 1,790 |
| | S3 | 4,739 | 4,739 | 2,020 | 3,037 | 3,108 |
| `send_file_three_change_outputs` | S1 | 5,394 | 5,348 | 149 | 312 | 382 |
| | S2 | 7,216 | 7,170 | 988 | 1,534 | 1,604 |
| | S3 | 7,342 | 7,296 | 3,310 | 4,917 | 4,986 |
| `invoice_file_plain` | I1 | 2,361 | 2,315 | 149 | 312 | 382 |
| | I2 | 4,294 | 4,248 | 1,022 | 1,584 | 1,654 |
| | I3 | 4,420 | 4,374 | 1,892 | 2,851 | 2,921 |

Over Epicbox (`send_epicbox_plain`) the legacy plaintext is 2,426 bytes at S1 and 4,248 at S2; the
native plaintext would be the 312- and 1,534-character armored packs. The Epicbox cipher's hex
encoding doubles both alike.

The S1 size does not grow with the sender's change outputs (`three_change_outputs`), and the range
proof (675 bytes) is 60 to 68% of every S2. X-02 replaces this table with sizes measured from the codec.

## Implementation map

| Task | Work | Paths and needs |
|---|---|---|
| X-02 | Sections 1 to 4: the `lepic.v1` codec behind a cargo feature, round-trip property tests, the examples above as snapshot tests, fuzz target | Paths as planned. The `Codec` trait's "encode is lossless" sentence needs the section 3 qualification (integrator, `codec/mod.rs`). |
| X-03 | Sections 5 to 10: pack, HPKE, armor, native address, contact card, capability records, text and QR transport, Epicbox policy | Needs `hpke` and `bech32` in `[workspace.dependencies]` (ADR 0010), the ed25519 key from `lepic-keychain` through the engine, a store table for capability records (`lepic-store`), and the Epicbox inbound path recognising armored packs, which is more than the "policy rule only" its paths allow. |
| W-04, W-05, W-08 | Section 11 | Cheaper to write this way now than to change after X-03. |

Crates the recommendation adds: `hpke` (0.14.1 on crates.io on 2026-10-02, X25519, HKDF-SHA256 and
ChaCha20-Poly1305 only) and `bech32` (0.12.0). The ed25519-to-X25519 conversion comes from
`ed25519-dalek`, already listed; X-03 confirms the conversion API in the pinned version.

## Open points

- Which QR code the host app shows by default (section 9). A frontend decision.
- Whether epic-wallet maintainers want to adopt this format. Nothing here depends on it; the RFC is
  written so they could.
- Per-transaction native addresses (privacy), deferred.

## References

- Grin RFC 0012, Slate V4 (compact slates):
  https://github.com/mimblewimble/grin-rfcs/blob/master/text/0012-compact-slates.md
- Grin RFC 0015, Slatepack: https://github.com/mimblewimble/grin-rfcs/blob/master/text/0015-slatepack.md
- RFC 9180, Hybrid Public Key Encryption: https://www.rfc-editor.org/rfc/rfc9180
- RFC 8032, EdDSA: https://www.rfc-editor.org/rfc/rfc8032
- BIP 350, bech32m: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
- E. Thormarker, On using the same key pair for Ed25519 and an X25519 based KEM:
  https://eprint.iacr.org/2021/509
- age v1 format: https://age-encryption.org/v1
- `epic-wallet` `v4.0.2`: `libwallet/src/{address,epicbox_address}.rs`, `controller/src/command.rs`,
  `libwallet/src/api_impl/owner.rs`
- LEPIC: ADRs 0002, 0003, 0012; `docs/compat/{legacy-slates,epicbox,keys-and-proofs}.md`;
  `testdata/vectors/slates/`
