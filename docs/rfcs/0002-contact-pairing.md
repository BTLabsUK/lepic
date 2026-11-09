# RFC 0002 Contact pairing, sealed slates and invoice trust

Status: accepted. Decision record: [ADR 0024](../adr/0024-contact-pairing.md). Edge cases:
[0002-contact-pairing-cases.md](0002-contact-pairing-cases.md).

Two LEPIC wallets pair once: in person by scanning each other's QR code, or online through a
one-time invite link or five pairing words and a throwaway Epicbox mailbox. Each side then holds
keys made for that one contact, derived from the seed in a numbered slot and shared with nothing
else. Both screens show the same four emoji; a user who compares them marks the contact Verified.
Each pairing names a home relay where both sides have a mailbox, so a user who switches relays
changes nothing for paired contacts. After pairing, slates to the contact travel sealed and
signed, and a contact may be allowed to send invoices: the trust sits on its key and its mailbox.
Exchanges and shops pair with customers the same way and take deposits by invoice (section 12).

The key words MUST, MUST NOT and MAY are used as in RFC 2119.

## Scope

This RFC covers the contact key branch, the contact envelope rules, the contact card, invites,
pairing replies and confirms, private pairings, pairing words, the key check, the throwaway and
contact mailboxes, collecting, relay moves, sealed sends between contacts and their plain
fallback, invoice trust, the exchange flows and a reference kit for services.

Elsewhere:

| Topic | Where |
|---|---|
| Envelope bytes, HPKE, padding, signature, armor | [RFC 0003 §5.3 to §5.11](0003-epictx-native-slates.md#53-envelope-layout) |
| Native slates between LEPIC wallets | [RFC 0003](0003-epictx-native-slates.md) |
| Epicbox wire protocol | [Epicbox compatibility](../compat/epicbox.md) |
| Notice shapes | [ADR 0016](../adr/0016-transaction-notices.md) |

Stock `epic-wallet` and other wallets never receive an envelope, a card or an invite.

## Specification

Integers are unsigned big-endian. `||` is concatenation. ASCII strings are written in quotes and
carry no terminator. `H(x)` is SHA-256. `HKDF` is HKDF-SHA256 (RFC 5869). `net` is one byte, `00`
mainnet and `01` floonet.

### 1 Roles and words

- A contact is the other wallet of a pairing. A pairing record is what one side stores about it.
- The inviter (A) makes an invite; the invitee (B) answers it. In person, each side is both.
- A service is a contact that is a shop or an exchange, run by the reference kit (section 13) or
  another implementation of this RFC.
- Sealed means inside an envelope (section 3). Plain means the V3 JSON slate.

### 2 Keys

#### 2.1 Contact-identity root

For the account at parent path `m/<a>/0`:

1. `id = m/<a>/2/0`, built as the Epicbox address key `m/<a>/1/<i>` but with second component 2
   and index 0. Neither `epic-wallet` nor the Epic node uses second component 2.
2. `raw = derive_key(0, id, SwitchCommitment::None)`, the plain BIP32 derivation of the Epicbox
   address key.
3. `root = HKDF(salt = "epic-contact/1", ikm = BLAKE2b-256(raw), info = "root" || net)`, 32 bytes.

`root` is never stored, logged or sent. It depends only on the seed, the account and the network.
No other key is derived from `m/<a>/2/*`; a later key family takes `m/<a>/2/1`.

#### 2.2 Keys for one contact

`HKDF-Expand` below uses `root` as the PRK, with no Extract step. Each pairing record has a `slot`
(u32) and a `box_salt` (16 random bytes). Neither is secret.

| Key | Derivation | Use |
|---|---|---|
| `enc_sk` | `HKDF-Expand(root, "enc" \|\| be32(slot), 32)`, an X25519 private key | Opening envelopes from this contact |
| `sig_sk` | `HKDF-Expand(root, "sig" \|\| be32(slot), 32)`, an Ed25519 seed | Signing envelopes and cards for this contact |
| `hint_key` | `HKDF-Expand(root, "hint" \|\| be32(slot), 32)` | Lets the contact tag envelopes so the key is found fast (3.2) |
| `box_sk` | `HKDF-Expand(root, "box" \|\| be32(slot) \|\| box_salt \|\| ctr, 32)`, a secp256k1 scalar; `ctr` a byte from `00` up, the first valid output | The contact mailbox on the home relay (8.3), and the sender key of what is posted to this contact |

A wallet keeps its ordinary slots below 65,536 (`SLOT_COUNT`) so the search of 2.5 covers them.
Private pairings (7.9) use slots from 65,536 up. A service keeps its records in its own database,
never searches, and MAY use the whole u32 range.

The wallet keeps a slot counter per account and network. Each new pairing record takes the
counter's value and raises it by one; a slot is never handed out twice, even after its pairing is
removed. When the store has no counter (a new wallet, or a restore without the backup), the first
record takes a random start in 0..32,767, so two installs on one seed rarely meet in one slot. When
they do, the two contacts of that slot see the same keys for this wallet. Envelopes reach the right
record because a record is chosen by the sender's signing key (3.4), and the mailboxes stay apart
through `box_salt`. A wallet that has used every ordinary slot refuses new pairings.

`box_salt` is random so two installs on one seed never share a contact mailbox (9.5). It is in the
record and the backup (10.5); a restore without the backup gets a new salt and a new mailbox, and
the contact learns it from the next card.

#### 2.3 One-time reply keys

For a slate this wallet starts (S1 or I1) with id `slate_id` (16 bytes):

- `reply_sk = HKDF-Expand(root, "reply" || slate_id, 32)`, X25519;
- `reply_pk` goes into the LEPIC marker of that slate (section 5).

Nothing is stored: the wallet rebuilds the key from the slate id of any slate it waits on, and a
second install on the same seed can open the answer too.

#### 2.4 Pairing secrets

| Name | Size | Chosen by | Where it goes |
|---|---|---|---|
| `code` | 16 random bytes | A, per invite | In the invite. Derives the reply mailbox (8.1) and the invite id |
| `nA` | 16 random bytes | A | Committed in the invite, revealed in the confirm |
| `nB` | 16 random bytes | B | In the reply |
| `rc` | 16 random bytes | B | In the reply. Derives the confirm mailbox |
| `words` | 5 random bytes | A, only when offered (7.7) | Shown as five SAS-table entries. Finds and opens the posted invite |

`invite_id = H("epic-pair/1 id" || code)[0..8]`. It is unique among the pending pairings of one
store; a collision makes a new `code`.

#### 2.5 Finding a slot again

A wallet restored without its backup has the seed but not its slots. When a contact holds the old
pairing, it sends the key check of 7.8. The restored wallet computes `hint_key` for slots 0 to
65,535 and compares, then checks `enc_pk` and `sig_pk` of the slot that matched. A match gives back
the old keys, so the contact keeps its record, its trust and its Verified mark. No match means the
card was made by another seed.

### 3 Sealed envelope

The envelope is the one of [RFC 0003 §5.3 to §5.9](0003-epictx-native-slates.md#53-envelope-layout),
built in `lepic-seal`. This section lists what contacts rely on.

#### 3.1 Binary layout

| Field | Size | Value |
|---|---|---|
| magic | 4 | `89 45 53 45` |
| version | 1 | `01` |
| network | 1 | `net` |
| suite | 1 | `01` base mode, `41` PSK mode (private pairings, 7.9) |
| flags | 1 | `00`; any other value is refused |
| hint | 8 | 3.2 |
| enc | 32 | The HPKE encapsulated key |
| ciphertext | n + 16 | The inner content (3.3) and the AEAD tag |

- Suite `01` is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305. The 16-byte header
  is the HPKE associated data; `info` is `"epic-seal/1" || net || suite`.
- The ephemeral key pair is `DeriveKeyPair(ikm)` with 32 bytes of the caller's RNG as `ikm`, so a
  fixed RNG gives the same envelope in every implementation.
- The sender MUST refuse a recipient key that is all zeros or of small order.
- The whole envelope is at most 1 MiB. Decoding refuses truncation, trailing bytes, an unknown
  version, suite or flag, and the other network before allocating more than the input. A failure
  to open is one typed error that does not say which step failed.

#### 3.2 Hint

The hint lets a recipient find the right key without trying each one:

| Recipient | Hint |
|---|---|
| A contact | `HMAC-SHA256(key = the contact's hint_key, enc)[0..8]` |
| A contact whose card sets `fixed-hint` (6.1) | `H("epic-seal/1 fixed" \|\| hint_key)[0..8]`, which a service can index |
| A one-time reply key | `HMAC-SHA256(key = H("epic-seal/1 reply" \|\| reply_pk), enc)[0..8]` |
| A pairing reply (7.2) | `invite_id` |

A recipient computes the candidate hints for its live keys and opens only with the keys whose hint
matches. A hint that matches no key means "not for this install" (9.5). A fixed hint lets an
outsider link envelopes to that service, as an Epicbox observer can from the addresses.

#### 3.3 Inner content

The inner content is a TLV list: `tag (u8) || length (u16) || value`, tags strictly increasing, no
tag twice. Unknown tags below `0x80` are refused; tags `0x80` to `0xFE` are extensions, skipped
when unknown and covered by the signature. The signature, tag `FF`, is last.

| Tag | Name | Value and rules |
|---|---|---|
| `01` | type | u8, required. See the table below |
| `02` | body | Per type, at most 65,535 bytes, required |
| `03` | reply key | 32: where the answer is sealed, for an anonymous envelope |
| `04` | purpose | u8: `01` payment, `02` deposit request, `03` withdrawal, `04` refund, `05` request between people. Shown to the user |
| `05` | reference | 1 to 64 bytes UTF-8, the name rules of 6.1. A service's own reference; shown, never trusted for crediting |
| `06` | expires | u64 unix seconds: when the sender stops honouring an invoice or withdrawal. Advisory (12.6) |
| `07` | card | The sender's current card (section 6) |
| `08` | sender key | 32: the sender's Ed25519 `sig_pk` for this contact. Required when `FF` is present |
| `09` | reply mailbox | Defined in [RFC 0003 §5.6](0003-epictx-native-slates.md#56-inner-content) |
| `80` | sent at | u64 unix seconds, in every signed slate, notice and payload |
| `81` | address proof | 32: the MAC of 6.1, in a reply, a confirm and a contact update |
| `82` | features | u32: the sender's feature word, in a reply, a confirm and a contact update |
| `83` | domain claim | `issued_at (8) \|\| signature (64) \|\| domain (1 to 253)`, in a reply, a confirm and a contact update (6.3) |
| `FE` | padding | [RFC 0003 §5.7](0003-epictx-native-slates.md#57-padding) |
| `FF` | signature | 64: Ed25519 by `sig_sk` over the signing input below |

Message types:

| Type | Name | Body |
|---|---|---|
| `01` | slate | A marked V3 JSON slate |
| `02` | notice | JSON in the shape of ADR 0016 |
| `03` | pairing reply | 7.2 |
| `04` | pairing confirm | 7.3 |
| `05` | contact update | A card (8.5) |
| `06` | key check | 7.8 |
| `07` | key check answer | 7.8 |
| `09` | contact check | Empty (8.5) |
| `0A` | native slate | [RFC 0003 §5.10](0003-epictx-native-slates.md#510-native-slate-lepicv1) |
| `40` | app payload | Bytes for the host application; LEPIC never reads them, and a reader with no use for them drops the message |

Every other type value is malformed. A reader that does not know a type refuses the envelope before
it checks the signature, so the message is acknowledged and attributed to nobody.

Signing input: `"epic-seal/1 sig" || header (16) || recipient X25519 public key || every inner
field before FF, as encoded`. The recipient key binds the signature to this recipient, so a
contact cannot re-seal a signed message to a third party.

Field rules:

- An envelope is signed (tags `08` and `FF`) between paired contacts and anonymous otherwise. An
  anonymous envelope authenticates nothing: a slate inside one is trusted only as the slate itself
  proves.
- `FF` without `08` is refused; `08` without `FF` counts as not signed.
- Lengths are exact for fixed-size fields. An unknown suite is its own error (a newer wallet); an
  unknown flag is malformed.
- A reply (`03`) is anonymous. A confirm (`04`) with status `01` is signed by the key in the card
  it carries; every other confirm is anonymous with a one-byte body. Types `05`, `06`, `07` and
  `09` are signed.
- An Ed25519 key of small order is refused wherever a sig key is read (tag `08`, card tag `06`),
  before any verification.
- An anonymous envelope never attributes to a record or updates one, even when it opens with a
  contact slot's key. The reply is the only anonymous type that starts anything.
- A card carried in a signed envelope (tag `07`, or the body of `04` and `05`) MUST carry the
  envelope's sender key as its sig key.
- Extension `80`: a value of another length is skipped. A recipient refuses an envelope sealed
  more than 30 days ago or more than 24 hours ahead of its clock, and remembers what it took for
  32 days. Once a contact sent `80`, that contact's slates, notices and payloads without it are
  refused.
- Extension `82`: bits 0 to 15 are capabilities, bits 16 to 31 the owner's profile, which the host
  names and LEPIC only carries. Unknown bits are kept and never refused, and no bit changes what is
  checked. The profile rides only to paired contacts.
- Extensions `81`, `82` and `83` with a malformed value read as absent.

#### 3.4 Opening rules

1. Decode the header; refuse the other network or an unknown version or suite.
2. Find candidate keys by hint (3.2); none means "not for this install".
3. Open; failure with every candidate is "cannot open".
4. Decode the fields (3.3). If `FF` is present, verify it with tag `08`'s key. A signed envelope
   opened with a slot's `enc_sk` is attributed to the record of that slot whose peer `sig_pk`
   equals tag `08`. When no record of the slot has that key, the envelope is "sealed for another
   wallet or install" (9.5), never a silent update of a record. Keys change only through a new
   pairing and the key check (7.8).
5. Hand the body to its type's handler. Slates go to the V3 decoder and the engine.

#### 3.5 Armor and files

```text
BEGINEPICSEALED. <payload>. ENDEPICSEALED.
```

- Payload: base64url without padding of the envelope followed by `H(H(envelope))[0..4]`.
- Framing as [RFC 0001 §7](0001-lepic-slate-v1.md#7-armor). Encoders MAY break the payload into
  lines of 76 characters.
- At most 96 KiB of armored text, checked before decoding. A wrong checksum is its own typed error.
- Files hold the armored text, UTF-8, extension `.epicsealed`. A stock wallet refuses the file as
  not JSON before reading anything.
- In a contact mailbox (8.3) the Epicbox plaintext is the armored text. A payload is sealed exactly
  when it starts with `BEGINEPICSEALED` after optional whitespace.

### 4 Network separation and versioning

The network byte in envelopes, cards and invites, and `net` in `root` and in HPKE `info`, keep
mainnet and floonet apart. Versions are the envelope's `version`, the format byte of cards and
invites, the version in each `epiccash://` link and the `epic-*/1` domain strings. A wallet reads
only versions it knows and reports a higher one as "made by a newer wallet". A card lists the
highest envelope version its owner reads (6.1); a sender uses the lower of its own and the
contact's.

### 5 The LEPIC marker carries a reply key

Every slate LEPIC starts (S1 and I1) on file, paste and Epicbox carries the marker with a reply key:

```json
"lepic":{"version":1,"reply":"<64 hex of reply_pk>"}
```

- The marked V3 codec writes it as the last top-level key. Stock `epic-wallet` ignores and drops
  the key, so its answers are plain.
- A LEPIC receiver of a plain S1 or I1 whose marker has a valid `reply` answers sealed and
  anonymous, with the S2 or I2 as body, on the same channel (file or paste). Over Epicbox the
  Epicbox cipher covers the answer.
- A `reply` that is malformed or of small order is ignored and the answer goes plain.
- The reply key authenticates nothing. Whoever can change a plain S1 can change the key, and then
  reads the S2, which the plain S2 would have shown anyway.

The marker's other members are in
[RFC 0003 §5.16](0003-epictx-native-slates.md#516-lepic-marker-on-legacy-slates).

### 6 Contact card

#### 6.1 Fields

A card is a self-signed TLV list, the rules of 3.3, at most 1,024 bytes. It takes no extensions.

| Tag | Name | Value |
|---|---|---|
| `01` | format | u8 `01` |
| `02` | network | `net` |
| `03` | kind | u8 `01` person, `02` shop, `03` exchange. Written for older readers and never read for meaning; writers put `01` |
| `04` | name | 1 to 48 bytes UTF-8, the owner's chosen name |
| `05` | enc key | 32: X25519 `enc_pk` for this contact |
| `06` | sig key | 32: Ed25519 `sig_pk` for this contact, not of small order |
| `07` | hint key | 32: `hint_key` for this contact |
| `08` | mailbox | Epicbox address `key@domain[:port]`, at most 128 bytes: where this contact delivers to the owner. A wallet's `box_pk` on the home relay, or a service's shared inbox |
| `09` | payments address | Optional: the owner's ordinary Epicbox address, as `key` or `key@relay`, for plain sends |
| `0A` | home onion | Optional onion domain of the home relay, used when Tor is on |
| `0B` | caps | u16, bits below |
| `0C` | max envelope version | u8 |
| `0D` | seq | u32, raised on every change |
| `0E` | signature | 64: Ed25519 by `sig_sk` over `"epic-card/1" \|\| every field before it` |

Caps: bit 0 opens sealed files, bit 1 pays invoices, bit 2 issues invoices, bit 3 `fixed-hint` (a
service inbox), bit 4 sends withdrawals. Other bits MUST be zero.

Text rules:

- Names and references refuse control, format, surrogate, line and paragraph separator characters
  (Unicode categories Cc, Cf, Cs, Zl, Zp).
- Address texts (card tags `08`, `09`, `0A`; invite tags `09`, `0A`, `0B`) are printable ASCII,
  `!` to `~`, with domains in punycode. A host is at most 255 bytes.

A card from a contact replaces the stored one only when its signature verifies with the recorded
`sig_pk` and its `seq` is higher. The name is the contact's claim: the app shows the user's own
label for the contact, and the claimed name only as "calls themselves".

**Address proof.** The payments address in tag `09` is shown as the contact's address only when
the envelope that delivers the card carries a proof that verifies, extension `81`:

```text
MAC = HMAC-SHA256(K, H(prover card) || H(verifier card) || H(invite))
K   = HKDF(salt = "lepic/addr-proof/1",
           ikm  = x(ECDH(prover's payments key, verifier's mailbox key of this pairing)),
           info = "mac" || net || step)
```

- `step` is `01` for the invitee's reply, `02` for the inviter's confirm, `03` for a contact
  update. Where a step has no such hash the slot is 32 zero bytes: the verifier's card in a reply
  (the invite commits to it), the invite in an update.
- The verifier's key is its own mailbox key of this pairing. For the inviter it is its card's tag
  `08` key, which the invite repeats (7.1).
- A contact update carries a proof only when the sender's payments address changed. A bad proof on
  an update keeps the stored address; the card is taken for its other fields.
- The verifier can compute the same MAC, so the proof convinces nobody else.
- A reply or confirm for a pairing that expects a payments address fails with
  `AddressProofMissing` (kind 82) when the proof is absent or does not verify, and with
  `OtherAddress` (kind 81) when the card names another address. Nothing is stored.
- Vector: `testdata/vectors/keys/address_proofs.json`.

#### 6.2 Text and QR form

`epiccash://contact/1/<base64url of card || H(H(card))[0..4]>`. Every `epiccash://` link in this
RFC (`contact`, `pair`, `pair-reply`, `pair-confirm`) appends the same checksum before base64url.

- The scheme matches in any case, and surrounding whitespace is trimmed.
- A higher version gives "made by a newer wallet".
- The text length is checked before decoding: a card or invite carries at most 1,024 bytes, a
  `pair-reply` or `pair-confirm` envelope at most 4,096 bytes.

A card link is about 400 characters, a version 11 to 13 QR code at medium error correction.
In-person pairing shows it (7.4).

#### 6.3 Domain claim

A service MAY claim a domain so the other side can show where it runs. The claim is a signature by
a domain key over the pairing's signing key, checked against a file the domain publishes. It
travels as extension `83` in the reply, the confirm and the contact update.

Message, signed with Ed25519 by the domain key:

```text
"epic-domain/1" || net || sig_key (32) || issued_at (u64) || domain
```

`sig_key` is card tag `06`, the key that signs this pairing's envelopes. `domain` is the
normalized text of the extension.

Normalization: ASCII only, lowercased, one trailing dot removed. Labels are 1 to 63 characters of
`a-z`, `0-9` and `-`, and neither start nor end with `-`. There is at least one dot and the name is
1 to 253 bytes. A name that fails is no claim, and the extension reads as absent.

Domain key: `HKDF(salt = "epic-domain/1", ikm = root, info = "sign" || net)`, 32 bytes, used as an
Ed25519 seed. One key per account and network; a phrase restore brings it back.

File, served at `https://<domain>/.well-known/epic-wallet.json`, at most 4,096 bytes:

```json
{"version":1,"networks":{"mainnet":{"domain_keys":["<hex 32>"]},"floonet":{"domain_keys":["<hex 32>"]}},"relays":["relay.example:443"]}
```

`relays` is optional and informational. Each network lists at most 8 keys. Unknown members are
ignored.

Verify takes the domain, the file bytes, the claim, the pairing's `sig_key` and the network. The
answer is `Proven` when the file parses, its version is 1, the network lists a key under which the
signature checks, and the claim's domain equals the domain asked about. Otherwise it is `Refused`
with one reason: file too large, file malformed, unsupported version, network absent, domain
mismatch, or no key matches. A key listed only under the other network gives "network absent".

LEPIC stores the domain and the extension as received and does no network access. The host fetches
the file (HTTPS only, no redirects, 4,096 bytes at most), calls verify and keeps the result. The
claim changes no check of the pairing; Verified (7.5) means only the short authentication string.

### 7 Pairing

#### 7.1 Invite

`epiccash://pair/1/<base64url of invite || H(H(invite))[0..4]>`, a TLV list as 3.3, at most 1,024
bytes:

| Tag | Name | Value |
|---|---|---|
| `01` | format | u8 `01` |
| `02` | network | `net` |
| `03` | kind | The inviter's card kind, as 6.1 |
| `04` | name | The inviter's name (6.1 rules) |
| `05` | expires | u64 unix seconds |
| `06` | code | 16 |
| `07` | commit | 32: `H("epic-pair/1 commit" \|\| nA \|\| H(cardA))` |
| `08` | enc key | 32: A's `enc_pk` for this contact, the key B seals its reply to |
| `09` | home relay | `domain[:port]` of the home relay (8.3); the reply and confirm mailboxes live there too |
| `0A` | service inbox | Optional Epicbox address: a service's fixed pairing inbox, used instead of the reply mailbox |
| `0B` | onion | Optional onion domain of the home relay, used when Tor is on |
| `80` | link secret | 32: marks a private invite (7.9) |
| `81` | mailbox key | 33: A's card tag `08` key, a compressed secp256k1 point, against which the reply's address proof is computed. Another length is a malformed invite |

An invite with both a link secret and a service inbox is refused. An invite is expired when the
current time is at or past `expires`.

The home relay is the service's own relay for a service, and the relay A's wallet uses at invite
time for a person. B takes it as given.

A keeps a pending pairing: `slot`, `box_salt`, `code`, `nA`, `cardA`, the expiry and the mailbox
relay. The host chooses the expiry. BT Wallet's invites last 7 days, `lepic contact invite`
defaults to 24 hours, services use 15 minutes, and an invite offered as words lasts 10 minutes
(7.7). One invite pairs one contact. A wallet holds at most 64 pending pairings.

**Standing invite.** A person's wallet MAY keep one standing invite of 7 days, its id stored in
LEPIC settings under `pairing.standing`. It is made again after it was answered, with under 24
hours left, on a relay change and on a rename.

**Pair request.** A wallet MAY send its invite to a payments address as the plain notice
`{"lepic":1,"type":"pair","invite":"epiccash://pair/1/..."}`, padded like every notice (16). It
goes only to a key that is fresh and claims the pair-request feature bit; a failed post takes the
invite back. The receiver keeps at most 20 live and 100 settled requests for 7 days, one per sender
key, a newer one replacing the older, stored before the relay message is acknowledged. A request
from a key with a live pairing, or for an invite that was dismissed or answered, is ignored.
Failures:

| Error | Kind | When |
|---|---|---|
| `PeerNotProven` | 83 | The key is not fresh or did not claim the bit |
| `PairingInProgress` | 84 | A pairing with that key is under way |
| `PairingCrossed` | 85 | Two requests crossed; the one with the lower key keeps its invite |
| `InviteDismissed` | 86 | The user dismissed the request |
| `ForeignProofAddress` | 89 | A listing receive refuses a payment-proof request |

#### 7.2 Reply

B opens the link. The app shows "Pair with <name>?" with the name marked as claimed, the expiry,
and Pair or Not now. On Pair, B takes a slot (2.2), makes `nB`, `rc` and its card for this contact
(`cardB`), and an envelope:

- sealed to the invite's enc key, anonymous, hint `invite_id`;
- type `03`, body `code (16) || nB (16) || rc (16) || cardB`;
- extensions `81`, `82` and `83` as 3.3.

A signed reply is refused. B posts the reply to the reply mailbox (8.1) and keeps a pending pairing
until the confirm arrives; the reply is posted again on every collect until A answers. When the
post fails, or the user picks "Send by hand", the app shows the envelope as
`epiccash://pair-reply/1/<base64url>` to send on any channel.

#### 7.3 Confirm

A drains the reply mailbox (8.2). For the first reply that opens, whose code equals the invite's
and whose card verifies:

1. A stores the pairing record, computes the SAS (7.5) and shows it.
2. A posts to the confirm mailbox (8.1, from `rc`) an envelope sealed to cardB's enc key and signed
   by A: type `04`, body `nA (16) || cardA || 01` (accepted). In manual mode A shows it as
   `epiccash://pair-confirm/1/<base64url>`. `cardA` is the exact card A committed to in the
   invite.
3. A deletes `nA`, so no second reply can pair, and keeps `code`, `invite_id` and the invite's slot
   until the invite would have expired. A is paired from step 1 whether or not the confirm left: a
   confirm whose post failed goes out when the kept reply is drained again. A confirm that has not
   reached the relay one hour after the invite's drain window ends A's record too, since B cannot
   have finished.

All checks on a reply (code, expiry, used, a card A holds already, or A's own card) and storing the
record happen in one store transaction before any confirm leaves. A reply whose card carries the
sig key of a contact A already has is refused, never merged.

A reply that cannot be accepted gets a refusal: type `04`, anonymous, a one-byte body, sealed to the
replier's card.

| Status | Meaning |
|---|---|
| `01` | Accepted (signed, with `nA` and `cardA`) |
| `02` | The invite was used |
| `03` | The invite expired |
| `04` | The inviter cancelled the invite |

A signed refusal or an anonymous acceptance is malformed. A refusal is advisory: B ends its pending
pairing and shows the reason; nothing is stored or trusted on either side. A later reply (hint
`invite_id`) is opened only far enough to read its card and answered with `02`; an invite answers
at most 3 refusals.

B drains the confirm mailbox. For status `01` it checks that the confirm is signed by cardA's sig
key, that `commit == H("epic-pair/1 commit" || nA || H(cardA))`, and that cardA's enc key equals
the invite's. A mismatch ends the pairing with "This invite was changed on the way" and stores
nothing. Otherwise B stores the record and shows the SAS.

#### 7.4 In person

Each phone shows its card QR (6.2, a fresh slot per showing) and scans the other's. Each side
stores the scanned card once both scans are done on that phone, with `nA = nB = 16 zero bytes` and
the cards ordered by sig key for the SAS (the lower key is `cardA`). Both screens show the SAS;
"They match" makes the contact Verified on that phone, because the camera saw the other phone. No
network is used, so this works Offline.

The in-person SAS has no commitment; its strength is the physical channel. When at least one card
went straight from one screen to the other phone's camera, an attacker who replaces the other card
must hit the SAS the real card fixes, about 2^32 card keys, which it cannot do while the pairing
waits. Someone who supplies both cards (each passed on as a screenshot, a photo or over a video
call) picks both after seeing the real ones and needs about 2^16 card keys per side. "They match"
in person therefore stands for "at least one code was scanned from the other device's screen";
when neither was, the pair verifies online (7.1 to 7.3).

There is no invite, so no shared home relay: each card's mailbox (tag `08`) is on the relay its
owner uses when it shows the card, each side delivers to the other's tag `08` and collects its own
mailbox there, and the record keeps both relays. A card QR is seen by anyone nearby, so on its first
collect after an in-person pairing each wallet sends the contact one update (`05`) with a mailbox
from a new `box_salt`; the hint key in the shown card stays.

A one-way scan, where B scans an invite shown as a QR, is an online pairing whose first message went
by camera. When one phone or neither has a camera, "Use words instead" shows pairing words (7.7).

#### 7.5 SAS

```text
sas = H("epic-pair/1 sas" || net || H(cardA) || H(cardB) || nA || nB)[0..4]
```

`cardA` is the inviter's card (in person, the card with the lower sig key). Each of the four bytes
indexes the 256-entry table `testdata/sas/emoji-v1.txt`: an emoji and a name of one or two
syllables per line. No name is in the BIP39 English list, so nobody reads seed words aloud. The app
shows the four emoji with their names, large enough to read on a call.

A commits to `nA` and its card before B chooses `nB`, and reveals `nA` only after B's reply
arrived. A man in the middle fixes what it sends each side before it learns the value that makes
the other side's SAS, so it matches by chance with probability 2^-32 per pairing (Vaudenay 2005).

Outcomes:

- "They match": Verified.
- "Skip": Paired, shown as "Paired, not verified".
- "They don't match": the pairing ends on this side with reason `mismatch`. Its invoices and
  queued messages are dropped and its mailbox is not collected. A contact that claims the status
  notices is told with a sealed `pair-mismatch` (7.6); an inviter also posts a refusal to the
  invitee's confirm mailbox, best effort; the app says the link may have been changed on the way.

#### 7.6 Pairing record

| Field | Notes |
|---|---|
| `contact_id` | A local id, 16 random bytes. Never sent, never used to derive keys |
| `slot`, `box_salt` | Ours; derive our keys for the contact (2.2) |
| peer card | The latest verified card. Absent while the pairing is pending |
| `sas` | The four SAS bytes, kept so the check can be shown again |
| `verified_at` | When the SAS was confirmed |
| `allow_invoices` | Off by default (section 11) |
| `seal` | `on` (default), `off`, or `degraded` after a plain fallback (9.3) |
| `last_sealed_in` | When the last envelope from the contact opened |
| home relay | The relay and onion where both mailboxes live (8.3) |
| `app_contact` | The id of the address-book entry this pairing is attached to, at most 256 bytes |
| label | The user's own name for the contact; empty until set |
| `peer_heard_at`, `peer_verified_at`, `peer_verdict` | What the contact told about its side |
| `peer_features` | The contact's feature word (3.3) |
| `payments_address`, `payments_key` | The proven payments address (6.1) |
| `ended_reason`, `ended_at` | `mismatch`, `peer-mismatch`, `unpaired` or `never-finished` |
| `heard_wait`, `heard_wait_mark` | Collecting time spent waiting for the contact |

The status is derived and never stored, in this order: Ended, Keys changed, Waiting
(`peer_heard_at` empty), then Verified or Paired. An ended pairing is final and never counts as
paired; it takes only slates already in flight, never a new S1 or invoice. Using an ended pairing
fails with `PairingEnded` (kind 87), using one that waits with `PairingWaiting` (88).

**Status notices.** The outcome travels in the pairing's mailbox, sealed and signed, padded like
every notice, and only to a contact whose feature word claims the status notices:

```json
{"lepic":1,"type":"pair-finished"}
{"lepic":1,"type":"pair-match","sas":"<64 hex>"}
{"lepic":1,"type":"pair-mismatch","sas":"<64 hex>"}
{"lepic":1,"type":"unpaired"}
```

- `pair-finished` says the wallet finished its side. `sas` is the unkeyed BLAKE2b-256 of
  `"lepic-wallet pairing verdict v1"` followed by the four SAS bytes, never the SAS itself.
- A verdict counts as heard. One for another SAS is ignored, a repeated match changes nothing, and
  a mismatch ends the pairing on both sides (`mismatch` on the side that found it, `peer-mismatch`
  on the other) and drops its invoices.
- A notice with another version or an unknown type is ignored.
- The outbox keeps these notices 7 days, trying after 30 seconds, 2 minutes, 10 minutes and then
  every 30 minutes, and then drops them without an event.

**Never finished.** An inviter that has not heard the contact ends the pairing as `never-finished`
after 7 days of collecting and tells the contact `unpaired`. Only time the wallet could collect
counts: each gap between two collects adds at most one hour to `heard_wait`.

**Removing.** Removing a contact deletes its record and any pending pairing for it; the slot stays
used (2.2). Before the record goes, the wallet tells the contact once, best effort, with the
`unpaired` notice: type `02`, sealed and signed to the contact's mailbox, waiting at most 10 seconds
for the relay. Nothing is sent Offline, with Epicbox off, or to a contact that removed the pairing
first. The contact accepts it only signed by the pairing's recorded sig key in that pairing's
mailbox. It marks the record "removed by the contact", takes nothing more through it, and keeps it
with its history until its own user removes it. It never touches funds or slates, and a repeat
changes nothing. A wallet that does not know the notice ignores it (ADR 0016).

#### 7.7 Pairing words

Five entries of the SAS table replace a link when there is nothing to scan or paste: read out on a
call, or typed from the other screen. They look like the SAS check, each emoji with its name, and
the user types the names (the field completes them from the table; pasting the emoji also works).
Five entries carry 40 bits.

A makes an invite as in 7.1 with a 10-minute expiry and 5 random bytes `words`. With
`window = floor(unix seconds / 600)` at the time A makes the invite:

- `k = Argon2id(password = words, salt = "epic-pair/1 words" || net || be64(window), t = 3,
  m = 65,536 KiB, p = 1, version 0x13, 32 bytes)`;
- `s = HKDF-Expand(k, "mailbox", 16)`: the seed of a rendezvous mailbox with the keys of 8.1;
- `key = HKDF-Expand(k, "invite", 32)`;
- A posts `base64url(nonce || ChaCha20-Poly1305(key, nonce, aad = "epic-pair/1 words" || net,
  invite))`, with a 12-byte random `nonce`, to the rendezvous mailbox on every one of the wallet's
  built-in relays for the network, whatever the home relay is. The posted text is at most 4,096
  characters. One relay that takes it is enough; when none does, the invite is withdrawn and the words
  are not shown.

The built-in relays are a meeting list for words only, the same fixed order on every wallet. A
wallet's own relay may be any other. Words are not offered on a network with no built-in relay.
Posting to every one means a relay that is down, or blocked on one side's network, does not matter
while both sides reach another. The reply goes to the home relay the invite names (7.2).

B types the words and derives `k` for the current window and the one before, so an invite made near
the end of a window is found. B drains the two rendezvous mailboxes on each built-in relay in the
list's order until one holds a message that opens; a second copy is never looked at. When no relay
could be drained, B says the relays were not reached. B decrypts the invite, acknowledges the
message so nobody else finds it, and goes on as if it had opened the link (7.2). Words that open
nothing show "No invite found for these words. Check them, or ask for new ones."

The words find and open the invite and do nothing more. Argon2id over a salt that changes every 10
minutes makes a table of all 2^40 words good for one window only, and the random nonce keeps apart
two invites that drew the same words in one window. Whoever learns the words, or reads the invite
first, is in the position of a leaked invite (C-15): the SAS and the commitment decide.

#### 7.8 Re-pairing after a restore: the key check

When the user adds a new pairing to an address-book entry that has a pairing record already, the
wallet holding the old record (X) asks the other side (Y) whether it holds the old keys. The app
never offers this because of an address a card claims; the user picks the entry. Each step travels
over the new pairing: sealed to the peer's new key, signed by the sender's new key, to the peer's
new mailbox. `nX` and `nY` are the new pairing's sig keys of X and Y; `R_old` is X's old record and
`cardY_old` the card Y gave X then.

1. **Check (type `06`).** Body `seq (u32) || tag (32)`: `seq` is `cardY_old`'s seq and
   `tag = H("epic-pair/1 keycheck" || cardY_old.hint_key || nY || nX)`. The tag reveals nothing
   about the old pairing to a peer without Y's seed, and is bound to the new pairing.
2. **Search.** Y computes the tag for its own records first, then for slots 0 to 65,535 (2.5). No
   match: Y answers type `07` with body `01` (not this wallet).
3. **Found (type `07`, status `02`).** Y makes `cardY_old'`: its card for the found slot, `seq` one
   above the given one, a mailbox from a new `box_salt` (or its current one if the record exists),
   signed with the slot's `sig_sk`. Body `02 || u16 length || cardY_old' || proofY`, with
   `proofY = Sig_old("epic-pair/1 keycheck found" || H(check envelope) || nY || nX ||
   H(cardY_old'))` by the found slot's `sig_sk`. `H(check envelope)` is over the `06` envelope's
   bytes as received.
4. X accepts the found answer only for its open check, once, within 24 hours: `proofY` verifies
   with `cardY_old`'s sig key, and `cardY_old'` has the same enc, sig and hint keys and a higher
   seq. X then keeps `R_old` with `cardY_old'` as its peer card, raises it to Verified when the new
   pairing was Verified, and answers with step 5. An ordinary contact update on the old pairing
   never completes a check.
5. **Restored (type `07`, status `03`).** Body `03 || u16 length || cardX_old || proofX`, with
   `proofX = Sig_old("epic-pair/1 keycheck restored" || H(found envelope) || nX || nY ||
   H(cardX_old))` by X's old `sig_sk` for `R_old`. X then deletes the new pairing.
6. Y accepts the restored answer only for the found answer it sent: `proofX` verifies with
   `cardX_old`'s sig key and `cardX_old` verifies as a card. Y then keeps (or, after a restore,
   creates) the record for the found slot with `cardX_old` as its peer card, the trust of the new
   pairing, and the slot counter above the slot, and deletes the new pairing.
7. **Not found or no answer.** On `07` with `01`, or with no found answer within 24 hours, `R_old`
   stays as it was and the new pairing goes to Keys changed (C-12): "Anna's keys changed. This can
   mean she uses a different wallet, or someone else is using her name. Check the words again."
   The user keeps the old record (the new pairing is deleted) or uses the new keys (the old record
   is deleted).

Proofs are 64-byte Ed25519 signatures. A wallet starts and answers at most one key check per
pairing and per slot, and only within 24 hours of the new pairing. When X may not start one (the
old slot was checked in the last 24 hours, or the new pairing is older), the new pairing goes to
Keys changed at once, as in step 7. Each proof is made by a key the other side held, over the
envelope it answers and both new keys, so neither side adopts a card or a trust level from a party
that has not shown it holds the old key.

#### 7.9 Private pairings

A private pairing shares nothing with the wallet's ordinary contact keys: its keys come from a
secret only the two sides hold, and every envelope on it is sealed in PSK mode. An invite with
extension `80` (a 32-byte link secret `sA`) is private.

- **Reply.** B picks its own 32-byte secret `sB`. The reply is sealed in PSK mode, suite `41`,
  with `psk = H("epic-private/1 reply" || sA)` and PSK id `"epic-private/1"`. Its plaintext body is
  `sB (32) || reply body (7.2)`.
- **Channel key.** `HMAC-SHA256(key = H("epic-private/1 channel" || sA || sB), H(invite) ||
  H(cardB))`. Every later envelope on the pairing is sealed in PSK mode under it. A base-mode
  envelope on a private pairing is refused.
- **Keys.** Each private record holds a random 32-byte `secret` of its own. Its keys replace
  those of 2.2: `HKDF(salt = "epic-private/1 keys" || secret, ikm = root)` expanded under
  `"private enc" || be32(slot)`, `"private sig" || be32(slot)`, `"private hint" || be32(slot)`
  and `"private box" || be32(slot) || ctr`. The record takes a slot from 65,536 up. Someone with
  the recovery phrase alone cannot derive them.
- **SAS.** `H("epic-private/1 sas" || net || H(cardA) || H(cardB) || nA || nB ||
  H(sA || sB))[0..4]`.
- **Refusals** of 7.3 are sealed under the channel key.
- **Store.** The secrets are sealed in the store. A private record whose secrets do not open is
  kept, and nothing is sent or taken through it.
- **Payloads.** Private pairings carry app payloads (type `40`) only: no slates, invoices or
  notices.
- A relay move of the owner (8.5) leaves private pairings on their relay.

Vector: `testdata/vectors/keys/private_pairing_tags.json`.

### 8 Mailboxes and the home relay

#### 8.1 Pairing mailboxes

For a 16-byte seed `s` (`code` for the reply mailbox, `rc` for the confirm mailbox, the words' `s`
for the rendezvous mailbox of 7.7):

- `pbox_sk = HKDF(salt = "epic-pair/1 mailbox", ikm = s, info = "box" || net || ctr)`, Extract then
  Expand, read as a secp256k1 scalar; `ctr` is a byte from `00` up, taking the first valid output.
- `pfrom_sk` is the same with info `"from"`. Messages to the mailbox are posted from `pfrom_sk`'s
  address, so the relay sees an ordinary message between two unknown keys.
- The address is `pbox_pk@<home relay>`. A service's fixed inbox replaces it for replies only;
  confirms always use `rc`.

These keys never touch the wallet's Epicbox, Tor or proof keys, and are forgotten when the pairing
ends.

#### 8.2 One-off drains

A one-off drain makes one connection to a relay with a client of its own, separate from the
wallet's listener, and for each mailbox in turn subscribes, takes every pending message (at most
32), and acknowledges (`Made`) each once its effect is stored. Then it disconnects.

- A message left unacknowledged blocks that connection for the next mailbox, so the drain opens a
  new connection after keeping one.
- The drain greets the relay as the mailbox's own sender.
- A message for an earlier mailbox that arrives after the drain moved on is left for the next drain.
- The drain follows the wallet's network mode: over Tor when Epicbox over Tor is on, to the onion
  when one is known (a built-in relay's own onion wins over one in a card or invite). It is refused
  Offline and when Epicbox is off (8.7).
- The relay layer deduplicates by message id; the wallet deduplicates by the envelope's hash.

Pairing mailboxes are drained:

- by A while the invite is pending: on the host's screen tick while the invite screen is open, on
  every app open and resume, until the invite expires plus 10 minutes;
- by B after replying: on the screen tick while the waiting screen is open, and on open and resume,
  for 1 hour, and never less than until the invite expires plus 1 hour and 20 minutes.

A pairing mailbox past its deadline is drained once more: the pending pairing ends at the first
drain of its relay that starts after the deadline, or one hour after it when none does. A reply or
confirm that reached the relay in time is taken however late it is collected; A accepts a reply
only while its pending pairing exists. Relays holding pairing mailboxes are retried after the first
backoff step (30 s) whatever their backoff. A drain of an ended pairing's mailbox is skipped.

#### 8.3 Contact mailboxes

After pairing, each side's messages for the relationship go to the other side's mailbox (card tag
`08`) on the home relay.

- A wallet's mailbox for a contact is `box_pk@<home relay>` (2.2). Only that contact knows it.
- A service MAY give every customer one shared inbox (caps bit 3) and find the customer by the
  fixed hint (3.2).
- The mailbox carries sealed invoices and their I2, sealed withdrawals and their S2, notices,
  contact updates and checks (8.5), app payloads, and sealed slates between people. Messages are
  posted from our `box_sk` for that contact, so the relay sees two per-contact keys and neither
  wallet's own address.
- Delivery targets the home relay whatever relay either wallet is connected to. A user who
  switches relays changes nothing for paired contacts, and no message is sent about it.
- The wallet's payments address and its listener serve everything else.

#### 8.4 Collecting

The wallet collects its contact mailboxes with one-off drains, grouped by home relay, one connection
per relay. A collect has a trigger:

| Trigger | Mailboxes | Backoff and outbox |
|---|---|---|
| Open (open, resume, unlock) | All | Every relay's backoff is cleared and every queued entry is sent |
| Pull (pull to refresh, the CLI's collect) | All | As Open |
| Foreground (the host's tick) | Contacts with something pending, or all when they sit on at most 3 relays | Backoff is respected |
| Push | All | Backoff and retry times are kept |

"Something pending" is an open invoice or withdrawal, an outbox entry, a pairing in progress, a send
waiting for an answer, or activity in the last 24 hours. While pairings are in progress, half of a
cycle's mailboxes are kept for contacts.

- At most 50 mailboxes per cycle, round-robin, so many contacts cost a bounded drain.
- A relay that does not answer backs off 30 s, 2 min, 10 min, then 30 min, and the contact shows
  "Exchange X's relay isn't answering".
- Collecting, entering a link by hand and outbox delivery take one lock, so they never interleave.
- The relay keeps messages 7 days, so nothing is lost while the app is closed for less than that.

A contact message that cannot be taken yet (its transaction is not stored, the store is busy) is
left unacknowledged and counted. After the host's number of tries within its patience (at most 10
tries and 24 hours) it is acknowledged and, when the host keeps a quarantine, stored there for 14
days ([ADR 0049](../adr/0049-keep-messages-that-cannot-be-taken-yet.md)).

#### 8.5 A contact moves to another relay

**The mover.** A wallet or service moves its own home relay with `contacts_move_home(host)`. Each
paired contact whose pairing has not ended gets one `05` with the card naming its mailbox on
`host`, queued for the mailbox the contact reads, and the mover's own mailbox for it moves to
`host` in the same write. Nothing waits for contacts. Private pairings and pairings in progress
keep their relay.

The mover passes a drain period of at most 365 days. During it every collect reads the old mailbox
as a previous home, one slot per contact. What arrives there is handled as usual, and a contact
check there is answered with the card naming the new mailbox. A contact that missed the update
learns of the move when it checks. With a zero drain the old mailboxes are not read again, and a
contact that missed the update stops reaching the mover and pairs again. A service keeps its old
relay running and drained for at least 7 days (13.3).

**The receiver** never follows a move by itself:

- An update whose card names a mailbox on the same relay is applied at once.
- An update whose card names a mailbox on another relay is stored as the contact's card, the
  mailbox in use stays, and the wallet raises `ContactRelayMoveRequested` with the contact and the
  relay as `domain:port`. The contact view shows it as `requested_relay` until it is applied.
- When the host calls `apply_relay_move`, the wallet delivers to the new mailbox, moves its own
  mailbox for the contact to that relay, queues its new card to the contact in a `05` in the same
  write, and reads its previous mailbox for 7 days. A move the host does not apply changes nothing.

Which relays to follow is the host's choice.

**Contact check (type `09`).** A wallet MAY ask a paired contact for its current card. A wallet that
takes one from a paired contact whose pairing has not ended answers with a `05`: its current card,
`seq` raised by one, through its outbox, within a pace per contact the host sets (by default one an
hour and three a day, at most 24 a day). Checks beyond the pace are acknowledged and dropped. The
answer is taken as any update: it sets the heard time, refreshes a card on the same relay, and
reports a card on another relay as a move request. It raises no event of its own.

**Limits on updates**, on the receiver:

- Accepted only from a paired key with a valid signature and a `seq` above the stored one. The same
  card again is ignored and reports nothing.
- At most 3 per contact per day and 100 per hour in all. Extra ones are acknowledged and dropped.
  The card in the contact's next envelope (tag `07`) heals a dropped change of name or payments
  address but never a dropped move: a card naming another mailbox is ignored outside a `05`, so the
  contact sends the move again with a higher `seq`.
- A card replaces the stored one only with the same enc, sig and hint keys. Only the user's "Use
  the new keys" (7.8) changes a contact's keys.

#### 8.6 Push

There is no push. The wallet registers no mailbox with a relay or a push service, and a message
waits in its mailbox until the next collect. The `Push` collect trigger exists in the core API.

#### 8.7 Transport, and Epicbox switched off

Pairing messages travel only through Epicbox mailboxes: the reply, confirm and rendezvous
mailboxes, and the contact mailboxes, reached with one-off drains and posts from keys of their own.
They never use the payments address, the listener, HTTP or Tor links, or the node. What can go by
hand goes by hand when no relay is reachable: the invite, `pair-reply` and `pair-confirm` links,
and sealed files and pastes.

The relay mode is Online, Offline or Epicbox off. With Epicbox off the wallet connects to no
Epicbox relay, home relays included, and behaves as Offline (C-10):

- in-person pairing works; an online invite works by hand; pairing words are not offered;
- sealed file and paste sends and answers work;
- collecting, contact invoices, withdrawals and notices pause, and the outbox keeps its entries
  until Epicbox is back.

### 9 Sealed slates between paired contacts

#### 9.1 Sending

When the recipient is a paired contact with `seal` on and caps bit 0, the file and paste methods
write an envelope: type `01` with the marked V3 slate as body (or type `0A`, a native slate, per
[RFC 0003 §6.1](0003-epictx-native-slates.md#61-paired-contact)), the purpose, our card when its
`seq` is newer than what the contact last saw, signed.

Over Epicbox the host picks the route. A send through the contact mailbox posts the envelope there.
That path does not ask the `seal` switch, since a contact mailbox carries only sealed envelopes: it
needs a pairing that is Paired or Verified, not Keys changed, and caps bit 0. This is how a contact
known only by its pairing, with no payments address, is paid:

1. The wallet checks the contact before it locks any input, builds the S1 and queues it in the
   outbox.
2. The S2 comes back by collecting and is finalized only when it arrives from the contact the S1
   went to. The host learns it from `ContactPaymentFinalized` with the contact, transaction and
   slate ids.
3. A contact that never answers leaves the send waiting. Cancelling it unlocks the inputs, and a
   late S2 is refused.

#### 9.2 Receiving

A sealed file or paste opens (3.4). The slate goes to the engine as if it arrived plain over that
method, attributed to the contact. The answer (S2 or I2) is sealed back to the contact, signed, on
the channel it came by.

#### 9.3 The plain fallback

When the contact cannot open a sealed slate (it was restored into a stock wallet, or its pairing
record is gone), the sender's app offers "Send as plain instead" on that transaction. It writes the
stored slate of the same stage in plain V3: same slate id, inputs, outputs and signatures. It never
makes a second transaction, so at most one can be posted. The record's `seal` becomes `degraded`:
the next send asks "Seal or plain?" with seal preselected, and the next envelope that opens from the
contact sets `seal` back to `on`.

#### 9.4 Hint lapse

A contact with no opened envelope for 90 days gets sealed slates as before, and the send screen
adds that the contact's wallet has not been heard in 90 days, with the plain option one tap away.
Identity, verification and invoice trust do not lapse.

#### 9.5 Envelopes for another install

Over file or paste, a hint that matches no key, or a signed envelope whose sender is not the peer
of the slot that opened it (3.4), says "This was sealed for another wallet or install".

Contact mailboxes are per install because `box_salt` is random, so a second install on the same
seed never drains another install's mailbox. Two installs hold the same pairing only when a backup
with pairing records is restored onto a second device while the first runs; both then drain the
same mailbox. Each acknowledges only after storing the effect, so whichever opens a message first
acts on it. The app imports pairing records from a backup as "on another device" and asks "Use your
contacts on this device?"; the first device should then be removed.

### 10 State and storage

#### 10.1 Tables (lepic-store)

- `contact`, keyed by the local `contact_id`, with `slot` and `box_salt`, unique on the peer's sig
  key; the slot counter per account and network.
- `contact_mailbox`: per contact, the peer's mailbox and ours, their home relay and onion, the
  previous home during a drain, and backoff state per relay.
- `pairing`: pending pairings, with the secrets `code`, `nA`, `nB` and `rc` encrypted at rest as
  every store secret (ADR 0005), the expiry, the role, the mailbox addresses, `cancelled_at`,
  `expect_address` and `expect_key` (the payments address a pair request went to, which the answer
  must prove), and the invitee's `reply`.
- `outbox` (12.4): messages that must reach a relay.

#### 10.2 Pairing state machine

```text
            make invite                     reply opened, card ok
 (none) ──────────────► pending-invite ─────────────────────────► paired ──"They match"──► verified
   │                        │  expired / cancelled                  │  ▲                       │
   │ open invite, Pair      ▼                                       │  │ re-verify             │
   └──────────────────► pending-reply ──confirm ok──► paired        │  └──────── keys-changed ◄┘
                            │ refusal / bad confirm / expired       │
                            ▼                                       ▼
                          ended                                   ended
```

- An invite the inviter cancelled before any reply keeps its pending row, with `cancelled_at`,
  until it expires; a reply to it is refused with status `04`.
- Keys changed is a state of the new pairing, reached only through the key check of 7.8. A pairing
  in it seals nothing and accepts no invoices until the user keeps the old record or uses the new
  keys (C-12).
- Ended is final, with one of the reasons of 7.6.

#### 10.3 Limits

| Limit | Value |
|---|---|
| Pending pairings per wallet | 64 |
| Contacts per wallet | 10,000 |
| Replies accepted per invite | 1 |
| Refusals answered per invite | 3 |
| Messages read per mailbox per drain | 32 |
| Mailboxes per collecting cycle | 50 |
| Parked invoices per contact, in all | 10, 100 |
| App payloads kept per contact, in all | 32, 256; each at most 64 KiB |
| Live and settled pair requests | 20, 100 |
| Meeting relays | 16 |
| Contact backup | 32 MiB |

#### 10.4 Events (lepic-wallet to host)

| Event | When |
|---|---|
| `PairingReplied`, `PairingConfirmed`, `PairingFailed{reason}` | Pairing progress |
| `ContactUpdated` | A contact's card changed |
| `ContactKeysRestored`, `ContactKeysChanged` | The key check ended (7.8) |
| `SealedReceived`, `SealedUnopenable` | An envelope opened or did not; the latter at most once per contact per cycle |
| `InvoiceFromContact`, `WithdrawalFromContact` | A contact's invoice or withdrawal parked |
| `HomeRelayUnreachable` | A home relay backs off |
| `OutboxDelivered`, `OutboxStuck` | An outbox entry reached its relay, or has not after 24 hours |
| `ContactPaymentFinalized` | A contact's answer to a send through its mailbox (9.1) |
| `ContactRelayMoveRequested` | A contact's card names another relay (8.5) |
| `InvoiceFinalized` | A contact paid our invoice |

Event fields carry ids and labels, never keys or secrets. A collect also returns the pairings that
ended and why.

A slate id belongs to at most one contact, and the link from a slate to a contact never moves. An
S1 or I1 from a contact whose slate id has a transaction (other than that contact's own repeat) or
belongs to another contact is dropped. Notices from a contact act only on transactions exchanged
with that contact. Paying a contact's invoice checks the contact's trust in the same locked step.
Slates through a contact mailbox are recorded with transport `epicbox`; sealed files stay `file`.
Delivered outbox entries are pruned after 7 days, entries of finished transactions at once.

#### 10.5 Backup and restore

Pairing records hold no secret of their own: ordinary keys come from the seed, the slot and
`box_salt`. LEPIC exports the records, the slot counter and the network as a versioned JSON object,
at most 32 MiB. On import it decodes every card again, refuses another network, and keeps a record
only when its own card carries the keys this seed derives for its slot. The backup carries the
proven payments address and key, never the contact's feature word or its heard and verified
dates. The app adds the object to its `.wfeh` history payload. Pending pairings are not in the
backup.

A restore with the backup brings every pairing back with the same keys, mailboxes and trust;
contacts notice nothing. A restore without it has no records. Re-pairing with a contact that kept
its record runs the key check (7.8): the restored wallet finds its old slot and the contact keeps
its record, its trust and its Verified mark. The restored side's own settings for the contact
("Allow invoices", "Seal payments") start at their defaults, and its mailbox is new; messages left
in the old mailbox expire on the relay after 7 days.

A send delivered to the old mailbox is lost, and a send to a restored side that has no pairing
reaches nothing. After `ContactKeysRestored` the core redirects undelivered outbox entries to the
new mailbox. A host MAY post a waiting send again with `contact_post_slate`; a receiver that holds
the S1 sends its stored S2 again, and the slate id keeps the repost harmless.

### 11 Invoice trust on contacts

#### 11.1 Rules

- "Allow invoices from <contact>" is a switch per pairing record, off by default and never
  preselected: an invite's name is a claim.
- The switch can be turned on only for a Verified contact. Paying is money leaving on a contact's
  request, so it waits for the check that rules out a swapped invite.
- An invoice is trusted when it arrives in the contact's mailbox, sealed and signed by that
  contact, with `allow_invoices` on and the record Verified. Where it was posted from does not
  matter.
- Turning the switch off takes effect at once: new invoices from the contact are acknowledged and
  dropped, parked unpaid ones are deleted, each with a sealed `declined` to the contact, and a paid
  one finishes as any paid invoice does.

#### 11.2 Receiving an invoice

In the contact mailbox, a sealed payload opens with the contact's key (by hint) and MUST be signed
by the contact: type `01` with an I1 body, or type `02`. A plain payload in a contact mailbox is
acknowledged and dropped. The I1 parks attributed to the contact and raises `InvoiceFromContact`
with the purpose, reference and expiry. Nothing pays without the user's approval.

Two requests for the same amount from one contact within 10 minutes are grouped, and the wallet
asks before a second payment.

#### 11.3 Abuse

A mailbox is known only to its contact, so there is no prefilter. A contact that floods its mailbox
is bounded by the read limit (32 messages a mailbox per drain) and the parked-invoice caps, 10 per
contact and 100 in all. Over a cap its invoices are acknowledged, dropped and logged, and the
contact's status does not change. Turning invoices off stops it at once.

#### 11.4 Notices

`declined`, `withdrawn` and `posted` (ADR 0016) travel sealed and signed in the contact mailboxes,
type `02`. `posted` also goes from the sender of a payment through the mailbox (9.1) to its
receiver once the sender posted it. `unpaired` and the status notices (7.6) are about the pairing
rather than a slate. Accepting them follows ADR 0016, with "the recorded counterparty" meaning the
contact. A signed `withdrawn` for a paid invoice cancels the payment and releases its inputs
(12.6); for an unpaid one it deletes it.

#### 11.5 No address-based invoice trust

There is no allowlist of invoice senders and no separate invoice address. Settings › Wallet ›
Invoices lists the paired contacts with their "Allow invoices" switch and offers "Pair with a shop
or exchange". Issuing an invoice over Epicbox to someone requires a pairing in which they allow
our invoices; issuing by file is unchanged. The engine and the CLI can issue to an Epicbox address
for interoperability tests, and no address-based payer path can list, pay or decline a contact's
invoice.

### 12 Worked example: exchange deposits and withdrawals

#### 12.1 Why invoices

A normal send makes the user's wallet do two of three steps: create S1, then receive the exchange's
S2, finalize and post. The phone is the weak link (asleep, offline, on another relay), and its funds
stay locked while it waits. With an invoice the exchange creates I1, the wallet pays once (I2), and
the exchange finalizes and posts. A withdrawal is the mirror: the exchange sends S1, the wallet
signs once (S2), the exchange finalizes and posts. In both directions the exchange, which runs
servers, does two of the three steps.

#### 12.2 Pairing, bound to the account

1. The user, logged in at Exchange X, opens Deposit › "Pair your Epic Cash wallet". The kit makes an
   invite (7.1): 15 minutes, home relay the exchange's own relay with its onion, and its fixed
   pairing inbox. It stores `invite_id → account`. The page shows the invite as a QR and as a button
   that opens `epiccash://pair/1/…` on the same device.
2. The wallet shows "Pair with Exchange X?" with the name marked as claimed and, below, "Allow
   Exchange X to request payments", off. The user taps Pair. The reply goes to the inbox.
3. The kit opens the reply by `invite_id`, binds the reply card's sig key to the account, and sends
   the confirm with its card: mailbox its shared customer inbox, caps bits 2, 3 and 4. The page and
   the wallet show the SAS; the user compares them and taps "They match" in the wallet and
   "Confirm" on the page. Both mark the pairing Verified.
4. A second pairing for the same account (a second phone, a reinstall) is a new contact on the
   account; the page lists the account's paired wallets with a remove button.

Crediting is by contact key: every I2 and S2 the exchange accepts arrives signed by a key bound to
one account. The slate id ties it to the deposit or withdrawal; no memo or address is used.

#### 12.3 Deposit

1. The user clicks "Deposit 250 EPIC". The kit asks the exchange's `epic-wallet` for an invoice
   (`issue_invoice_tx`, V3) with a TTL of 1,440 blocks and seals it: purpose deposit request,
   reference, expiry, signed. It posts it to the user's mailbox on the exchange's relay.
2. The wallet collects it (8.4) on open, on pull, or on the foreground tick. It raises
   `InvoiceFromContact`; the app shows "Exchange X requests 250 EPIC" with a Verified badge, the
   reference, the fee and the expiry. The user approves.
3. The wallet builds I2 once, locks its inputs, seals it to the exchange, signed, and puts it in
   the outbox (12.4). The app says "Paid — waiting for Exchange X to post".
4. The kit drains its inbox, opens the I2 by fixed hint, checks the slate id belongs to this
   account's open deposit, finalizes (`finalize_invoice_tx`), posts (`post_tx`) and sends a sealed
   `posted` notice with the kernel excess.
5. The wallet shows confirmations from the chain as for any payment, with or without the notice.

A service MAY stop honouring an invoice before the TTL; `expires` (3.3) says when, and 12.6 covers
a payment that arrives after it. Crediting is the service's rule, counted in kernel sightings from
the chain, never from the `posted` notice.

#### 12.4 Delivery that survives

The outbox holds each message that must reach a relay: the armored payload, the destination (the
contact's mailbox on the home relay), the attempt count and the next try.

- A post succeeds when the home relay answers `Ok`; the relay then holds it 7 days. Until then the
  outbox tries at once, then after 30 s, 2 min, 10 min and every 30 min, and on every app open,
  network regain and collect.
- It lives in the store, so it survives the app being killed. It posts to the home relay, so the
  user's own relay switch does not matter. A home relay move (8.5) changes the destination of
  entries not yet delivered.
- Delivered but not finalized after 2 hours: the transaction shows "Exchange X has not posted yet"
  with "Send again", which posts the same stored I2 again. The kit treats a repeated slate id as a
  duplicate.
- Undelivered after 24 hours: `OutboxStuck`, and "Couldn't reach Exchange X yet. Your funds are
  safe; they unlock if it doesn't post." The payment then ends as any unfinished one does: at its
  TTL, after the unfinalized-receive limit, or on a signed `withdrawn`.

#### 12.5 Withdrawal

1. The user asks Exchange X to withdraw 100 EPIC to a paired wallet. The kit has `epic-wallet` make
   S1 (`init_send_tx`, locked), seals it to the user's contact key with purpose withdrawal and a
   reference, signed, and posts it to the user's mailbox.
2. The wallet collects it like a deposit request and receives it as any S1, attributed:
   "Withdrawal from Exchange X: 100 EPIC". Receiving needs no approval. It signs S2 once, seals it
   back, signed, and puts it in the outbox. The app shows "Received — waiting for Exchange X to
   post".
3. The kit finalizes (`finalize_tx`) and posts. The wallet shows confirmations from the chain.

#### 12.6 Timing, failure and duplicates

| Situation | What happens | The user sees |
|---|---|---|
| Exchange down when the user pays | The I2 waits on the home relay (7 days). The kit finalizes when it is back, while the slate's TTL has not passed | "Paid — waiting for Exchange X to post", then confirmations |
| Home relay down | The outbox retries with backoff; after 24 hours `OutboxStuck` | "Exchange X's relay isn't answering", then "Couldn't reach Exchange X yet" with Send again |
| User's own relay down or switched | Nothing in this flow uses it | Nothing changes |
| User offline after paying | A post that succeeded needs nothing more; otherwise the outbox posts on the next open | Same states, later |
| App closed when the request is sent | It waits in the mailbox and appears on the next open | The request, later |
| Double click on Deposit | The kit returns the open invoice for the same account, amount and idempotency key. Two that arrive are grouped (11.2) | One request, or a question before the second payment |
| Invoice expires after payment | The kit finalizes a valid I2 until the TTL height; past it, it sends a signed `withdrawn` and the wallet cancels and releases its inputs | "Exchange X withdrew the request; your funds are unlocked" |
| Withdrawn before payment | The parked invoice is deleted; approving it is refused | "Exchange X withdrew this request" |
| Declined by the user | A signed `declined` to the exchange; the kit marks the deposit declined | "Declined" |
| Exchange posts after the wallet cancelled | If the inputs are unspent the transaction confirms; refresh shows a cancelled payment whose kernel reached the chain as confirmed | Confirmed |
| Withdrawal while the user switches relay | The S1 is in the mailbox on the home relay | The withdrawal on the next collect |
| Exchange moves its home relay mid-withdrawal | The S1 on the old relay is collected (8.5); the S2 goes to the new mailbox | Nothing |

### 13 Reference exchange kit

A service MAY run a kit beside its own `epic-wallet` owner API instead of a LEPIC wallet. Its crypto
core is a second implementation of this RFC and generates the test vectors LEPIC checks (14). The
crypto parts below exist; 13.2 to 13.4 are requirements for an implementer of the service side.

#### 13.1 Parts

- `envelope`, `card`, `invite`, `sas`: this RFC, with HPKE base mode checked against RFC 9180
  Appendix A.2.
- `epicbox`: an Epicbox client (connect, subscribe, drain, `Made`, post) speaking the protocol in
  [Epicbox compatibility](../compat/epicbox.md).
- `wallet`: an owner-API v3 client for `issue_invoice_tx`, `finalize_invoice_tx`, `init_send_tx`,
  `tx_lock_outputs`, `finalize_tx`, `post_tx` and `retrieve_txs`.
- `service`: the flows of section 12 as a worker with a storage interface.

#### 13.2 Endpoints and hooks

| Call | What it does |
|---|---|
| `create_invite(account_id)` | Makes the invite of 12.2 and returns the link and QR payload |
| `pairing_status(invite_id)` | Pending, replied (with the SAS), verified, expired |
| `confirm_sas(invite_id)` | The user clicked Confirm on the page. Deposits are taken only after it; a service offers no skip |
| `request_deposit(account_id, amount, idempotency_key)` | Issues and sends the sealed invoice; returns the open one for a repeated key |
| `request_withdrawal(account_id, contact_id, amount, idempotency_key)` | Makes, locks and sends the sealed S1 |
| `on_credit(callback)` | Called once per posted deposit with account, amount, slate id and kernel |
| `on_withdrawal_posted(callback)` | Called once per posted withdrawal |
| `revoke_contact(contact_id)` | Removes the pairing; later envelopes from it are dropped |

#### 13.3 Worker

The worker drains the pairing inbox and the shared customer inbox on its own relay every few
seconds; opens envelopes by fixed hint; deduplicates on message id and slate id; finalizes and
posts; and delivers to each customer's mailbox on the home relay, which is the exchange's own relay.
Moving the home relay is a kit command: it starts the new relay, sends each customer one signed
update (8.5) and keeps draining the old relay for at least 7 days.

#### 13.4 Scale and abuse

- Lookups by fixed hint are indexed; the kit opens at most one envelope per message, and only after
  the hint matched a customer or an open invite. Messages whose hint matches neither are dropped
  unopened.
- Invites: 3 open per account, 15 minutes, one reply each; a replay of a used invite gets status
  `02` and nothing else.
- Per customer key, a ceiling of messages per minute and 3 contact updates a day; a global ceiling
  per minute. Over it, messages are acknowledged, dropped and counted.
- A customer who floods is revoked; pairing again needs the logged-in account, so an attack costs
  accounts, which the exchange rate-limits already.
- Rate limits on `create_invite` and `request_deposit` per account and per IP are the exchange's;
  the kit exposes counters.

### 14 Test vectors

The kit generates these from fixed inputs (the raw account key, slots, `box_salt`, RNG bytes) and
LEPIC checks them byte for byte. Files under `testdata/vectors/pairing/`:

| File | Content |
|---|---|
| `hpke_rfc9180_a2.json` | RFC 9180 Appendix A.2.1 base-mode vectors |
| `contact_keys.json` | Raw account key to `root`, `enc_pk`, `sig_pk`, `hint_key` and `box_sk` for slots 0, 1 and 65,535 with fixed `box_salt`s, both networks |
| `reply_keys.json` | Slate ids to `reply_pk` |
| `seal_keys.json` | Seal keys of [RFC 0003 §5.2](0003-epictx-native-slates.md#52-keys-and-derivation) |
| `mailbox_keys.json` | Seeds to mailbox and sender secrets; the `ctr` loop is tested with an injected curve order |
| `words.json` | Words and a window to `k`, the rendezvous secrets, the invite key and the posted text |
| `keycheck.json` | A full key check between two fixed wallets: tags, the `06`, the found and restored answers with proofs, and the not-found answer |
| `envelopes.json` | Each contact type, anonymous and signed, with fixed RNG: bytes, armor, hint, opened fields |
| `cards_invites.json` | Card, invite, reply and confirm bytes and their link forms |
| `sas.json` | Inputs to four bytes to emoji and names |
| `domain.json` | Domain key, claim and file on both networks, with refused cases |
| `malformed.json` | Each refusal of 3.1, 3.3, 3.5, 6.1 and 7.1 with its typed error |
| `epictx_*.json` | The EPICTX envelopes, files, padding, reply mailbox and malformed cases of RFC 0003 |

Address proofs and private pairing tags are in `testdata/vectors/keys/`. The SAS table
`testdata/sas/emoji-v1.txt` is frozen; a change is `emoji-v2` with a new SAS domain string.

### 15 Threat model

| Threat | What stops it | What remains |
|---|---|---|
| Man in the middle on the invite channel | Commitment and SAS (7.5); B checks the commitment | A user who skips the SAS is "Paired, not verified" and cannot allow that contact's invoices |
| Malicious home relay | It sees only Epicbox-encrypted envelopes between per-contact or throwaway keys; it can drop, delay or replay but not read or forge; replays are deduplicated; the outbox retries | It can deny service to that relationship and sees which per-contact keys talk and when |
| Leaked or forwarded invite | One reply per invite; A sees the replier's claimed name and the SAS; services bind the invite to a logged-in account | Whoever answers first pairs with an unverified A; the SAS reveals it |
| Seed restored into a stock wallet | Sealed messages go only to paired LEPIC contacts, into mailboxes a stock wallet never reads; the plain fallback resends the same slate | The sender must use the fallback |
| Replay of a sealed slate or notice | Slates are idempotent on `(slate_id, stage)`; notices on the slate's state; cards on `seq`; extension `80` bounds the age | None |
| Replay of a pairing reply | One reply per invite; `nA` is deleted after the first | None |
| Guessing pairing words | Argon2id with a salt that changes every 10 minutes, a random nonce, a 10-minute expiry, one acknowledged message; the SAS and commitment decide (7.7) | A party that reads the invite first is in the leaked-invite position |
| A false key check | The check reveals only a tag bound to the new keys; "found" and "restored" need proofs by the old keys over the new pairing; a failed check leaves the old record untouched; one check per pairing and slot within 24 hours (7.8) | An impostor learns that the user took it for the contact |
| A card QR photographed in person | The first collect moves the mailbox to a new `box_salt` (7.4) | The hint key in the shown card links envelopes to that contact |
| Forged invoice | It must arrive in the contact's mailbox, sealed and signed by that contact, with invoices allowed | A contact the user allowed can request; nothing pays without approval |
| Spam against a service from many paired keys | Each pairing needs a logged-in account and an invite; per-key and global limits (13.4); only hint-matched envelopes are opened; revocation | An attacker with many accounts costs the service drains and hint lookups |
| Flood of updates | Relay switches need none (8.3); updates are signed, `seq` only rises, 3 a day per contact and 100 an hour in all; a move to another relay is only reported (8.5) | A contact can ask the host to follow it to a relay of its choosing |
| Spam into a contact mailbox | Only the contact knows it; the read limit and invoice caps; turning invoices off or removing the pairing stops it | A paired contact can annoy the user until removed |
| Downgrade to plain | Between contacts the sender seals by policy, not by a signal the channel could strip; plain only by the user's choice; a plain payload in a contact mailbox is dropped | Stripping the reply key from an unpaired plain S1 gives a plain S2 |
| Key reuse and linking | Contact keys and mailboxes share nothing with Epicbox, Tor or proofs; one set per slot | Two installs on one seed that meet in one slot give its two contacts the same keys (2.2). A card's payments address is the same for every contact; leaving it out keeps contacts unlinkable |
| Address proof shown to others | The proof is a MAC the verifier could make, so it convinces nobody else | None |
| Pair request links mailboxes to addresses | Padding; Tor is recommended | A request from A's address to B's, followed by posts to two new mailboxes, ties them to both people at the relay |
| Another wallet makes the proof | The MAC is computed inside the contacts crate only; no listing or address-signature call produces it | None |
| Compromised phone | Out of scope: it holds the seed | Past sealed messages to it open with keys from the seed |
| Forward secrecy | Sender side: each envelope uses a fresh HPKE key | A recipient key leak opens past messages to that key (RFC 9180 §9.7.4); re-pairing rotates |

Secrets do not cross the FFI boundary: the app passes invite links, armored text and file paths in,
and receives cards, SAS emoji, labels and states. The invite code inside a link is the one pairing
secret the app sees, because the link reaches the app first; the app does not store it.

### 16 Compatibility

- Stock `epic-wallet` and other wallets never receive an envelope, a card, an invite or a contact
  notice: all go only to paired contacts, and pairing needs LEPIC or the kit.
- A LEPIC S1 or I1 carries `reply` in its marker, which stock `epic-wallet` ignores (C-31).
- An older LEPIC peer without `reply` support gets plain answers; one that cannot open a link lets
  the invite expire; one that sees a sealed file as "not a slate" leaves the sender the fallback.
- The relay is told version `4.1.0`, as by `epic-wallet`.
- Writers pad every notice and the pair request to the size buckets 2,452, 2,551 and 2,650 bytes;
  readers accept notices up to 8 KiB.
- The marker carries the feature word on Epicbox slates only.
- The legacy codecs are unchanged; the marked V3 codec writes one more key.

### 17 UX

#### 17.1 Screens

The app calls the feature Pairing: "Pair", "Pair with Anna", "Paired", "Verified". Copy is plain and
impersonal, never says HPKE, envelope or key, and makes no claim about other wallets. Icons carry
the trust states: Verified (shield with a check), Paired, not verified (outline shield), Keys
changed (shield with a warning), Sealed (lock chip).

| Flow | Phone | Desktop |
|---|---|---|
| Pair in person | Contacts › Pair › In person: "Show my code" and "Scan theirs"; "Use words instead"; after both scans, the words check | "Show my code" with pairing words, and "Enter link or words" |
| Pair online | Contacts › Pair › Invite: the share sheet with the link; pending invites under Contacts › Pending | The same, with Copy |
| Pairing words | Five emoji with names, laid out as the words check, with a 10-minute countdown; the other side types the names | The same |
| Open an invite | "Pair with Anna?" with "Name chosen by them · not checked yet", expiry, Pair or Not now; then "Waiting for Anna's wallet…", which continues in the background | A dialog with the same content |
| Check the words | Four emoji with names, large; "They match", "They don't match" (a warning and Stop pairing), "Skip for now" | The same in a dialog |
| Contact page | Trust badge; "Seal payments" and "Allow invoices" (disabled until Verified), each with an info icon; "Delivered via <home relay>", a notice when the relay does not answer; Remove pairing | The same in the contact panel |
| Keys changed | The text of 7.8 step 7 with Check the words, Keep the old keys, Use the new keys | The same |
| Pair with an exchange | Opened from the exchange's page; the sheet names the site as claimed; the check step offers "Allow invoices from Exchange X", off | The same |
| Deposit request | The Review invoice layout with Sealed and Verified chips, fee, total, Approve; then Paid, Delivered to Exchange X's relay, Posted, confirmations | The same, in the invoices screen |
| Settings › Wallet › Invoices | Paired contacts with an "Allow invoices" switch each, unverified ones greyed with "Check the words first", and "Pair with a shop or exchange" | The same |

The share text of an invite carries the link only; Pairing › Enter link or words also takes the
link pasted as text, for apps that do not open custom links.

#### 17.2 Contacts with several addresses

An address-book entry holds at most one address per method: one Epicbox address, one HTTP address
and one Tor address. Pasting an address detects its method and shows it as a badge. An unpaired
entry's addresses change only when the user edits them. Invoices go only through pairing. A pairing
attaches to one entry (C-21).

## References

- RFC 9180 Hybrid Public Key Encryption; RFC 8032 EdDSA; RFC 7748 X25519; RFC 5869 HKDF; RFC 4648
  base64url; RFC 9106 Argon2.
- S. Vaudenay, "Secure Communications over Insecure Channels Based on Short Authenticated Strings",
  CRYPTO 2005.
- [RFC 0001](0001-lepic-slate-v1.md), [RFC 0003](0003-epictx-native-slates.md).
- ADRs [0016](../adr/0016-transaction-notices.md), [0024](../adr/0024-contact-pairing.md),
  [0049](../adr/0049-keep-messages-that-cannot-be-taken-yet.md).
- Crates [`lepic-seal`](../../crates/lepic-seal/README.md),
  [`lepic-contact`](../../crates/lepic-contact/README.md),
  [`lepic-wallet-contacts`](../../crates/lepic-wallet-contacts/README.md).
- [Epicbox compatibility](../compat/epicbox.md).
