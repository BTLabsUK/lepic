# RFC 0002 Contact pairing, sealed slates and pairing-based invoice trust

Status: accepted by the operator with the review of 2026-10-24 (defaults taken for OD-P1 to OD-P4)
Date: 2026-10-24
Proposes: ADR 0024. Amends RFC 0001 (D1 key choice, D4 suite, sections 5 and 6) for the envelope
only. Edge cases: [0002-contact-pairing-cases.md](0002-contact-pairing-cases.md). Tasks: the
ids in "Effort".

## TL;DR

Two LEPIC wallets pair once: in person by scanning each other's QR code, or online through a
one-time invite link, or five pairing words read out or typed, and a throwaway Epicbox mailbox.
Each side then holds a key pair made for that one contact (X25519 to encrypt, Ed25519 to sign),
derived from the seed in a numbered slot on a branch of its own and never shared with Epicbox,
Tor or payment proofs. A restore brings every contact's keys back: from the backup, or, without
it, by finding the slot again when the contact re-pairs. Both screens show the same four emoji
with names; users who compare them mark the contact Verified.

Each pairing also agrees on a home relay: the service's own relay, or the inviter's relay when the
contact is a person. Each side gets a mailbox there under a per-contact key, and both sides always
deliver the relationship's messages to it, whatever relay each wallet uses day to day. A user who
switches relays changes nothing for paired contacts. The wallet collects from home relays with
one-off drains when it opens and while it is in the foreground; the relay keeps messages 7 days.

After pairing:

- every slate to the contact over file or paste travels sealed: HPKE (RFC 9180) to the contact's
  key, signed with ours, so a copied file shows nothing and cannot be forged;
- a contact can be allowed to send invoices. The trust sits on its key, and invoices come only
  through its mailbox on the home relay, so neither relay switches nor address changes affect
  it. This replaces today's address-based trusted services and the separate invoice address;
- exchanges and shops pair with their customers the same way, and deposit by invoice: the
  exchange creates the invoice, the wallet pays once, the exchange finalizes and posts. Section 12
  is the worked example and the reason for most choices here.

Unpaired LEPIC peers still gain sealed replies: a LEPIC S1 or I1 carries a one-time reply key in
its marker, and a LEPIC receiver seals its answer to it. Stock wallets see plain V3 slates exactly
as today; nothing sealed ever goes to them.

## Goal and scope

In scope: the contact-identity key branch, the sealed envelope and its armor, the contact card,
invites, pairing replies and confirms, the throwaway mailbox and its one-off drains, the SAS, the
pairing record and its state machine, sealed sends and the plain fallback, contact updates
(relay and address changes), invoice trust on contacts, the exchange deposit and withdrawal flows,
the reference exchange kit, the threat model, test vectors and the effort.

Out of scope:

- Sealing over Epicbox for person-to-person payments (S1 and S2 between people keep the Epicbox
  cipher, as RFC 0001 section 10 argues), over Tor or HTTPS (Direct), and in QR slates (the
  animated `ur:epic-slate` codec of ADR 0025 carries plain slates).
- Telegram carriage or a bot. Invites and armored text are shared through the OS share sheet;
  a later RFC may carry sealed slates through Telegram unchanged.
- The `lepic.v1` binary slate (RFC 0001 sections 2 to 4). The envelope wraps today's V3 JSON.
- Groups, multi-device sync of pairing records, per-contact Epicbox addresses.
- Any change to stock `epic-wallet`, Epic Pay, the GUI or the relay.

## Options considered

| Question | Options | Chosen | Why |
|---|---|---|---|
| Encryption key | K-A payment-proof ed25519 key (RFC 0001 D1); the Epicbox secp256k1 key; a dedicated seed-derived key per contact | Per-contact keys on a new branch | No key reuse with Epicbox, Tor or proofs; contacts cannot link a user by key; restore still works (section 2) |
| Envelope | Epicbox message cipher; age; HPKE base mode | HPKE base mode, X25519, HKDF-SHA256, ChaCha20-Poly1305 | Standard, official test vectors, 48 bytes overhead, sender-side forward secrecy (RFC 0001 D4) |
| Sender authentication | HPKE auth mode; Ed25519 signature inside the ciphertext | Ed25519 inside | Signature binds the recipient key (no forwarding), hides the sender from outsiders, and is the key invoice trust sits on |
| What is sealed | a new binary slate; today's V3 JSON | V3 JSON with the LEPIC marker | Works now, every engine path stays; `lepic.v1` can replace the content later under the same envelope |
| Online pairing transport | invite plus reply link both by hand; a rendezvous server; a throwaway Epicbox mailbox | Throwaway mailbox, by-hand links as fallback | Uses relays that exist, keys from the invite code, never wallet keys |
| Delivery after pairing | each wallet's current payments address plus "my relay changed" notices; a home relay per pairing with per-contact mailboxes | Home relay per pairing | A relay switch needs no message, so there is nothing to flood or lose; invoices no longer need a shared invoice address or prefilter; services drain one inbox |
| MITM check | none (TOFU); SAS over keys; SAS with commitments | SAS with a commitment from the inviter | A plain SAS of 32 bits can be ground by a MITM; the commitment makes one try per pairing (section 7) |
| SAS alphabet | BIP39 words; PGP words; emoji | 256 emoji, each with a one-word name not in BIP39 | One table serves sight and voice; users are never asked to read BIP39 words aloud |
| Invoice trust | allowlist of Epicbox addresses (today); paired contacts | Paired contacts, allowlist removed | No users yet; trust follows the key; the address is exchanged in pairing |
| Exchange side | LEPIC as the exchange's wallet; a separate kit beside the exchange's `epic-wallet` | A Python kit beside `epic-wallet`'s owner API | Exchanges keep their wallet; the kit is also the independent second implementation for test vectors |

## Specification

"Must" binds every implementation. Integers are unsigned big-endian. `||` is concatenation. ASCII
strings are written in quotes and carry no terminator. `H(x)` is SHA-256. `HKDF` is HKDF-SHA256
(RFC 5869). `net` is one byte, `00` mainnet and `01` floonet, as in RFC 0001.

### 1 Roles and words

- A contact is the other wallet of a pairing. A pairing record is what one side stores about it.
- The inviter (A) makes an invite; the invitee (B) answers it. In person, both are both.
- A service is a contact that is a shop or an exchange, run by the reference kit (section 13) or
  another implementation of this RFC.
- Sealed means inside an envelope (section 3). Plain means the V3 JSON as today.

### 2 Keys

#### 2.1 Contact-identity root

For the account at parent path `m/<a>/0`:

1. `id = m/<a>/2/0`, built as `address_key_id` builds `m/<a>/1/<i>` but with second component
   2 and index 0. Neither `epic-wallet` nor the Epic node uses second component 2.
2. `raw = derive_key(0, id, SwitchCommitment::None)`, the same plain BIP32 key derivation as the
   Epicbox address key.
3. `root = HKDF(salt = "epic-contact/1", ikm = BLAKE2b-256(raw), info = "root" || net)`, 32 bytes.

`root` is never stored, logged or sent. It depends only on the seed, the account and the network.
No other key is derived from path `m/<a>/2/*`; a later key family takes `m/<a>/2/1`.

#### 2.2 Keys for one contact

`HKDF-Expand` below uses `root` itself as the PRK (no Extract step). Each pairing record has a
`slot`, a u32, and a `box_salt`, 16 random bytes. Neither is secret. A wallet keeps its slots
below 65,536 so that the search of 2.5 covers them; a service keeps its records in its own
database, never searches, and may use the whole u32 range. From them:

| Key | Derivation | Use |
|---|---|---|
| `enc_sk` | `HKDF-Expand(root, "enc" \|\| be32(slot), 32)` as an X25519 private key (clamped by X25519) | Opening envelopes from this contact |
| `sig_sk` | `HKDF-Expand(root, "sig" \|\| be32(slot), 32)` as an Ed25519 seed (RFC 8032) | Signing envelopes and cards for this contact |
| `hint_key` | `HKDF-Expand(root, "hint" \|\| be32(slot), 32)` | Lets this contact tag envelopes so we find the key fast (3.2) |
| `box_sk` | `HKDF-Expand(root, "box" \|\| be32(slot) \|\| box_salt \|\| ctr, 32)` as a secp256k1 scalar; `ctr` a byte from `00` up, the first valid output | Our contact mailbox on the home relay (8.3): subscribe, `Made`, and the Epicbox sender key of what we post to this contact |

Slots are numbered so that a restore finds the keys again (2.5). The wallet keeps a slot counter
per account and network: each new pairing record takes the counter's value and raises it by one,
and a slot is never handed out twice, not even after its pairing is removed. When the store has no
counter (a new wallet, or a restore without the backup), the first record takes a random start in
0..32,767, so two installs on one seed rarely meet in the same slot. When they do, the two contacts
of that slot see the same keys for this wallet; envelopes still go to the right record, because a
record is chosen by the sender's signing key (3.4), and mailboxes stay apart through `box_salt`.
A wallet that has used every slot below 65,536 refuses new pairings; every invite and every card
showing takes a slot, which a wallet with at most 64 pending pairings never comes near.

`box_salt` is random so that two installs on one seed never share a contact mailbox even in one
slot (9.5). It is in the record and in the backup (10.5); a restore without the backup gets a new
salt and so a new mailbox, and the contact learns it from the next card (2.5).

#### 2.3 One-time reply keys

For a slate this wallet starts (S1 or I1) with id `slate_id` (16 bytes):

- `reply_sk = HKDF-Expand(root, "reply" || slate_id, 32)`, X25519.
- `reply_pk` goes into the LEPIC marker of that slate (section 5).

Nothing is stored: the wallet rebuilds the key from the slate id of any slate it waits on, and a
twin install on the same seed can open the answer too.

#### 2.4 Pairing secrets

| Name | Size | Chosen by | Where it goes |
|---|---|---|---|
| `code` | 16 random bytes | A, per invite | In the invite. Derives the reply mailbox (section 8) and the invite id |
| `nA` | 16 random bytes | A | Committed in the invite, revealed in the confirm |
| `nB` | 16 random bytes | B | In the reply |
| `rc` | 16 random bytes | B | In the reply. Derives the confirm mailbox |
| `words` | 5 random bytes | A, per invite, only when offered (7.7) | Shown to the user as five SAS-table entries. Finds and opens the posted invite |

`invite_id = H("epic-pair/1 id" || code)[0..8]`. It is unique among the pending pairings of one
store; a collision makes a new `code`.

#### 2.5 Finding a slot again

A wallet restored without its backup has the seed but not the slots it used. When a contact still
holds the old pairing, it sends the card it holds for us (7.8). The restored wallet computes
`hint_key` for slot 0, 1, 2 … up to 65,535 and compares it with the card's hint key (one HMAC per
slot, about 0.1 s on a phone for the whole range), then checks `enc_pk` and `sig_pk` of the slot
that matched. A match gives back the old keys, so the contact keeps its record, its trust and its
Verified mark. No match means the card was made by another seed.

### 3 Sealed envelope

#### 3.1 Binary layout

| Field | Size | Value |
|---|---|---|
| magic | 4 | `89 45 53 45` |
| version | 1 | `01` |
| network | 1 | `net` |
| suite | 1 | `01`: KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0003` ChaCha20-Poly1305, mode base |
| flags | 1 | `00`; any other value is rejected |
| hint | 8 | section 3.2 |
| enc | 32 | the HPKE encapsulated key |
| ciphertext | n + 16 | the inner content (3.3) and the AEAD tag |

- The 16-byte header (magic to hint) is the HPKE associated data. `info` is
  `"epic-seal/1" || net || suite`. Single-shot `SealBase` and `OpenBase` (RFC 9180 section 6).
- Encapsulation randomness comes from the caller's RNG, as for every pure function in LEPIC: the
  ephemeral key pair is `DeriveKeyPair(ikm)` (RFC 9180 section 7.1.3) with 32 bytes of RNG output
  as `ikm`, so a fixed RNG gives the same envelope in every implementation.
- The sender must reject a recipient key that is all zeros or of small order (the X25519 output
  would be all zeros; RFC 9180 section 7.1.4 makes `DH` fail).
- Bounds: the whole envelope is at most 1 MiB. Decoding rejects truncation, trailing bytes, an
  unknown version, suite or flag, and the other network, before any allocation larger than the
  input. Opening failure is one typed error that does not say which step failed.

#### 3.2 Hint

The hint lets a recipient find the right key without trying each one:

- To a contact: `HMAC-SHA256(key = contact's hint_key, enc)[0..8]`. A contact whose card sets
  the `fixed-hint` capability (services, 6.1) asks for `H("epic-seal/1 fixed" || hint_key)[0..8]`
  instead, which it can index; outsiders can then link envelopes to that service, which an Epicbox
  observer can already do from the addresses.
- To a one-time reply key: `HMAC-SHA256(key = H("epic-seal/1 reply" || reply_pk), enc)[0..8]`.
- A pairing reply (section 7): `invite_id`.

A recipient computes the candidate hints for its live keys (HMAC is cheap) and opens only with the
keys whose hint matches. A hint that matches no key means "not for this install"; section 9.5 says
what that means on each channel.

#### 3.3 Inner content

A sequence of fields, each `tag (u8) || length (u16) || value`, tags strictly increasing, no tag
twice, unknown tags rejected below `0x80` and ignored from `0x80` to `0xFE` (room for later
optional fields, covered by the signature). The signature, tag `FF`, is last.

| Tag | Name | Value | Rules |
|---|---|---|---|
| `01` | type | u8 | `01` slate (V3 JSON), `02` notice (JSON, ADR 0016 shape), `03` pairing reply, `04` pairing confirm, `05` contact update, `06` key check, `07` key check answer (7.8). Required |
| `02` | body | bytes | Per type. Slates at most `MAX_WIRE_SLATE_LEN` and in practice under 64 KiB (armor bound, 3.5). Required |
| `03` | reply key | 32 | Where the answer should be sealed, for an anonymous envelope |
| `04` | purpose | u8 | `01` payment, `02` deposit request (invoice from a service), `03` withdrawal, `04` refund, `05` request between people. Shown to the user |
| `05` | reference | 1 to 64 bytes UTF-8, the name rules of 6.1 | A service's own reference (deposit or withdrawal id). Shown; never trusted for crediting |
| `06` | expires | u64 unix seconds | When the sender stops honouring it (invoices and withdrawals). Advisory, see 12.6 |
| `07` | card | bytes | The sender's current contact card (section 6), so every message refreshes delivery addresses |
| `08` | sender key | 32 | The sender's Ed25519 `sig_pk` for this contact. Required when tag `FF` is present |
| `FF` | signature | 64 | Ed25519 by `sig_sk` over the signing input below. Last |

Signing input: `"epic-seal/1 sig" || header (16 bytes) || recipient X25519 public key || every
inner field before tag FF, exactly as encoded`. The recipient key binds the signature to this
recipient, so a contact cannot re-seal our signed message to a third party.

An envelope is signed (tags 08 and FF) between paired contacts and anonymous otherwise. An
anonymous envelope authenticates nothing; a slate inside one is trusted only as the slate itself
proves (it answers a slate this wallet started, or its partial signatures verify).

Field rules: tag FF without tag 08 is refused; tag 08 without FF counts as not signed. Type and
purpose outside the values above are malformed; an unknown suite is its own error (a newer
wallet), an unknown flag is malformed. Lengths are exact for fixed-size fields. Type-specific
rules sit above the envelope: a reply (03) is anonymous; a confirm (04) with status 01 is signed
by the key in the card it carries, any other confirm is anonymous with a one-byte body (7.3);
types 05, 06 and 07 are signed. An Ed25519 key of small order is refused wherever a sig key is
read (tag 08, card tag 06), before any verification. Anonymous envelopes never attribute to a
record or update one, even when they open with a contact slot's key; the reply (03) is the only
anonymous type that starts anything. A card carried in a signed envelope (tag 07,
or the body of 04 and 05) must carry the envelope's sender key as its sig key.

#### 3.4 Opening rules

1. Decode the header; reject the other network or an unknown version or suite.
2. Find candidate keys by hint (3.2); none means "not for this install".
3. `OpenBase`; failure with every candidate is "cannot open".
4. Decode the fields (3.3). If tag FF is present, verify it with tag 08's key. A signed
   envelope opened with a slot's `enc_sk` is attributed to the record of that slot whose peer
   `sig_pk` equals tag 08. If no record of the slot has that key, it is treated as "sealed for
   another wallet or install" (9.5), never as a silent update of a record. Keys change only
   through a new pairing and the key check (7.8).
5. Hand the body to its type's handler. Slates go to the existing V3 decoder and engine.

#### 3.5 Armor and files

```
BEGINEPICSEALED. <payload>. ENDEPICSEALED.
```

- Payload: base64url without padding (RFC 4648 section 5) of the envelope followed by
  `H(H(envelope))[0..4]`. Base64 decoding is linear, unlike base58, so the bound can be large.
- Framing as RFC 0001 section 7: split on the first three periods, headers matched with optional
  `>`, spaces, tabs and line breaks around them; whitespace and `>` inside the payload are
  removed. Encoders may break the payload into lines of 76 characters.
- At most 96 KiB of armored text, checked before decoding. A wrong checksum is its own typed error
  ("the text was damaged on the way").
- Files hold the armored text, UTF-8, extension `.epicsealed`. A stock wallet refuses the file as
  not JSON before reading anything.
- In a contact mailbox (8.3) the Epicbox plaintext is the armored text. A payload is sealed
  exactly when it starts with `BEGINEPICSEALED` after optional whitespace.

### 4 Network separation and versioning

The network byte in envelopes, cards and invites, `net` in `root` and in HPKE `info` keep mainnet
and floonet apart. Version bytes: the envelope `version`, the card's and invite's format byte,
and the `epic-*/1` domain strings. A wallet reads only versions it knows and says "made by a newer
wallet" for a higher one. A card lists the highest envelope version its owner reads (6.1); senders
use the lower of theirs and the contact's.

### 5 The LEPIC marker carries a reply key

Every slate LEPIC starts (S1 and I1) on file, paste and Epicbox carries the marker with one more
key:

```
"lepic":{"version":1,"reply":"<64 hex of reply_pk>"}
```

- `MarkedV3JsonCodec` writes it as the last top-level key; `carries_lepic_marker` already
  accepts extra keys. Stock `epic-wallet` ignores and drops the key (vector
  `slates/malformed_unknown_top_level_key`; `docs/compat/epicbox.md` fact 2), so its answers are
  plain as today.
- File S1 starts carrying the marker, which today goes only on Epicbox invoice stages. The interop
  suite must show a stock `epic-wallet` v4.1.0 receives a marked V3 S1 file, and the cases file
  lists Epic Pay as unverified (C-31).
- A LEPIC receiver of a plain S1 or I1 whose marker has a valid `reply` answers sealed, anonymous,
  with the S2 or I2 as body, over the same channel (file or paste). Over Epicbox it answers as
  today: the Epicbox cipher already covers it.
- A `reply` that is malformed or of small order is ignored and the answer goes plain.
- The reply key authenticates nothing. Whoever can change a plain S1 can change the key; they then
  read the S2, which is what they would have read before this RFC.

### 6 Contact card

#### 6.1 Fields

A card is the binary payload below, self-signed:

| Tag | Name | Value |
|---|---|---|
| `01` | format | u8 `01` |
| `02` | network | `net` |
| `03` | kind | u8 `01` person, `02` shop, `03` exchange |
| `04` | name | 1 to 48 bytes UTF-8, the owner's chosen name. No control, format, bidi, line or paragraph separator characters (Unicode categories Cc, Cf, Cs, Zl, Zp) |
| `05` | enc key | 32, X25519 `enc_pk` for this contact |
| `06` | sig key | 32, Ed25519 `sig_pk` for this contact |
| `07` | hint key | 32, `hint_key` for this contact |
| `08` | mailbox | Epicbox address text, `key@domain[:port]`, at most 128 bytes: where this contact delivers to the owner. A wallet's `box_pk` at the home relay; a service's shared inbox (8.3) |
| `09` | payments address | Optional: the owner's ordinary Epicbox address, for plain person-to-person sends as today. Never used for the relationship's own messages |
| `0A` | home onion | Optional onion domain of the home relay, used when Tor is on |
| `0B` | caps | u16 bits: 0 opens sealed files, 1 pays invoices, 2 issues invoices, 3 `fixed-hint` (a service inbox), 4 sends withdrawals; rest zero |
| `0C` | max envelope version | u8 |
| `0D` | seq | u32, raised on every change |
| `0E` | signature | 64, Ed25519 by `sig_sk` over `"epic-card/1" \|\| every field before it` |

Tags `0F` (a Link · HTTP address) and `10` (a Link · Tor address) are reserved for the
multi-address contacts that follow this RFC (one address per method per contact, 17.2); until a
later version defines them they are rejected as unknown. A card is at most 1,024 bytes; the
`contact` and `pair` links at most 4,096 characters, the `pair-reply` and `pair-confirm` links
at most 96 KiB.

The sig key (tag 06) must not be of small order. Address texts (tags 08, 09, 0A here, and 09, 0A, 0B of the invite) are printable ASCII, `!` to
`~`, with domains in punycode. Same TLV rules as 3.3. A card from a contact replaces the stored one only when its signature
verifies with the recorded `sig_pk` and its `seq` is higher. The name is the contact's claim; the
app shows the user's own label for the contact and the claimed name only as "calls themselves".

#### 6.2 Text and QR form

`epiccash://contact/1/<base64url of card || H(H(card))[0..4]>`. Every `epiccash://` form in this
RFC (`contact`, `pair`, `pair-reply`, `pair-confirm`) appends the same 4-byte checksum to its
payload before base64url. About 400 characters (470 with every
optional field), a version 11 to 13 QR code at medium error correction. In-person pairing shows this card (section 7.4).

### 7 Pairing

#### 7.1 Invite

`epiccash://pair/1/<base64url of invite || H(H(invite))[0..4]>`, TLV as 3.3:

| Tag | Name | Value |
|---|---|---|
| `01` | format | u8 `01` |
| `02` | network | `net` |
| `03` | kind | the inviter's card kind |
| `04` | name | the inviter's name (6.1 rules) |
| `05` | expires | u64 unix seconds |
| `06` | code | 16 |
| `07` | commit | 32: `H("epic-pair/1 commit" \|\| nA \|\| H(cardA))` |
| `08` | enc key | 32: A's `enc_pk` for this contact, the key B seals its reply to |
| `09` | home relay | domain[:port] of the relationship's home relay (8.3); the reply and confirm mailboxes live there too |
| `0A` | service inbox | optional Epicbox address: a service's fixed pairing inbox, used instead of the derived reply mailbox |
| `0B` | onion | optional onion domain of the home relay, used when Tor is on |

The home relay is the service's own relay for a service, and the relay A's wallet uses at invite
time for a person. B accepts it as given; B's own relay does not matter.

About 230 characters for a person. The share text carries the link only; the app's
Pairing › Enter link or words field also takes the link pasted as text, for apps that do not open
custom links.

A keeps a pending pairing: `slot`, `box_salt`, `code`, `nA`, `cardA`, expiry, mailbox relay; the
peer card is absent until the reply. Default expiry 24 hours; the user may choose 1 hour or 7
days; services use 15 minutes; an invite offered as pairing words lasts 10 minutes (7.7). One
invite pairs one contact.

#### 7.2 Reply

B opens the link: the app shows "Pair with <name>?" with the name marked as claimed, the expiry,
and Pair or Not now. On Pair, B takes a slot (2.2), makes `nB`, `rc`, its card for this contact
(`cardB`), and an envelope:

- sealed to the invite's enc key, anonymous, hint `invite_id`;
- type `03`, body: `code (16) || nB (16) || rc (16) || cardB`.

B posts it to the reply mailbox (8.1) and keeps a pending pairing until the confirm arrives. If the
post fails, or the user chooses "Send by hand", the app shows the same envelope as
`epiccash://pair-reply/1/<base64url>` to send back on any channel.

#### 7.3 Confirm

A drains the reply mailbox (8.2). For the first reply that opens, whose code equals the invite's
and whose card verifies:

1. A stores the pairing record (state `paired`), computes the SAS (7.5) and shows it.
2. A posts to the confirm mailbox (8.1, from `rc`) an envelope sealed to cardB's enc key and
   signed by A: type `04`, body `nA (16) || cardA || 01` (accepted). A manual-mode A shows it as
   `epiccash://pair-confirm/1/<base64url>` instead. `cardA` is the exact card bytes A committed
   to in the invite, kept with the pending pairing for that purpose.
3. A deletes `nA` from the pending pairing, so no second reply can pair, and keeps `code` (for the
   reply mailbox), `invite_id` and the invite's slot until the invite would have expired. A later
   reply (hint `invite_id`) is opened only far enough to read its card and answered with status
   02; an invite answers at most 3 refusals. All checks on a reply (code, expiry, used, a card A
   already holds or its own) and storing the record happen in one store transaction before any
   confirm leaves.

A reply that cannot be accepted (status 02 invite already used, 03 expired, 04 cancelled by the
inviter) gets a confirm without nonce or card: type `04`, anonymous, body one byte, the status,
sealed to the replier's card. It is advisory: B ends its pending pairing and shows the reason,
and nothing is stored or trusted on either side. A reply whose card carries the sig key of a
contact A already has is refused (a replayed card), never merged.

B drains the confirm mailbox. For status 01 it checks that the confirm is signed by cardA's sig
key, `commit == H("epic-pair/1 commit" || nA || H(cardA))`, and that cardA's enc key equals the
invite's. A mismatch ends the pairing with "This invite was changed on the way" and nothing is
stored. Otherwise B stores the record and shows the SAS.

#### 7.4 In person

Each phone shows its card QR (6.2, a fresh slot per showing) and scans the other's. Each
side stores the scanned card once both scans are done on that phone, with `nA = nB = 16 zero
bytes` and the cards ordered by sig key for the SAS. Both screens show the SAS; one tap on "They
match" makes the contact Verified on that phone, because the camera saw the other phone. No
network is used, so this works Offline.

There is no invite, so no shared home relay: each card's mailbox (tag 08) is on the relay its
owner uses when it shows the card (a service's card names its inbox), each side delivers to the
other's tag 08 and collects its own mailbox there. The record keeps both relays. A card QR is
seen by anyone nearby, so on its first collect after an in-person pairing each wallet sends the
contact one update (05) with a mailbox from a new `box_salt`; the hint key in the shown card stays.

A one-way scan (B scans A's invite QR, the invite of 7.1 shown as a QR) is an online pairing whose
first message went by camera. When only one phone has a camera, or neither, "Use words instead"
shows pairing words (7.7) for the other to type.

#### 7.5 SAS

```
sas = H("epic-pair/1 sas" || net || H(cardA) || H(cardB) || nA || nB)[0..4]
```

`cardA` is the inviter's card (in person: the card with the lower sig key). Each of the four bytes
indexes the 256-entry SAS table `testdata/sas/emoji-v1.txt` (an emoji and a name of one or two
syllables per line; names never appear in the BIP39 English list, so nobody is asked to read seed
words aloud). The app shows `🐱 kitty · 🦊 vixen · 🍩 donut · 🎻 fiddle`, with names large
enough to read on a call.

Security: A commits to `nA` and its card before B chooses `nB`, and reveals `nA` only after B's
reply arrived. A MITM must fix what it sends each side before it learns the value that makes the
other side's SAS, so it matches by chance with probability 2^-32 per pairing (the SAS-MCA
argument, Vaudenay 2005). Without the commitment it could grind 2^32 keys offline.

Outcomes: "They match" → `verified`; "They don't match" → the record is deleted on this side, a
status 04 confirm (A) or nothing (B) is sent, and the app says the link may have been changed on
the way; "Skip" → `paired` (shown as "Paired, not verified", trust on first use).

#### 7.6 Pairing record

| Field | Notes |
|---|---|
| `contact_id` | A local id of the record, 16 random bytes. Never sent and never used to derive keys |
| `slot`, `box_salt` | Ours. Derive our keys for the contact (2.2) |
| peer card | The latest verified card: keys, hint key, addresses, caps, seq. Absent while `pending-invite` |
| state | `pending-invite`, `pending-reply`, `paired`, `verified`, `keys-changed` (cases C-12) |
| `sas` | The four SAS bytes, kept so the check can be shown again (7.8) |
| `verified_at` | When the SAS was confirmed |
| `allow_invoices` | Default off. Section 11 |
| `seal` | `on` (default), `off` (the user turned it off), `degraded` (last fallback was plain, 9.3) |
| `last_sealed_in` | When the last envelope from the contact opened |
| `home relay` | The relationship's relay and onion; both mailboxes live there (8.3) |
| `app_contact` | The id of the shared address-book contact (one list for every wallet on the device) this pairing is attached to; at most 256 bytes |
| label | The user's own name for the contact, empty until the user sets one; the app shows the claimed name as "calls itself" meanwhile |

Removing a contact deletes its record and any pending pairing for it. The record's slot stays
used (2.2).

#### 7.7 Pairing words

Five words from the SAS table replace a link when there is nothing to scan or paste: read out on a
call, or typed from the other screen. They look exactly as the SAS check does, each emoji with its
name below it, and the user types the names (the field completes them from the table; pasting the
emoji also works). Five entries carry 40 bits.

A makes an invite as in 7.1, with a 10-minute expiry, and 5 random bytes `words`. With
`window = floor(unix seconds / 600)` at the time A makes the invite:

- `k = Argon2id(password = words, salt = "epic-pair/1 words" || net || be64(window), t = 3,
  m = 65,536 KiB, p = 1, version 0x13, 32 bytes)`;
- `s = HKDF-Expand(k, "mailbox", 16)`: the seed of a rendezvous mailbox with the keys of 8.1;
- `key = HKDF-Expand(k, "invite", 32)`;
- A posts `base64url(nonce || ChaCha20-Poly1305(key, nonce, aad = "epic-pair/1 words" || net,
  invite))`, with `nonce` 12 random bytes, to the rendezvous mailbox on its home relay.

Words are offered only when the home relay is one of the wallet's built-in relays for the network.
B types them and derives `k` for the current window and the one before (an invite made near the
end of a window is still found), and drains the two rendezvous mailboxes on each built-in relay in
the list's order until one holds a message that opens. B decrypts the invite, acknowledges the
message so nobody else finds it, and goes on as if it had opened the link (7.2). Words that open
nothing show "No invite found for these words. Check them, or ask for new ones."

Security: the words find and open the invite, nothing more. Argon2id over a salt that changes
every 10 minutes makes guessing useless: a table of all 2^40 words is good for one window only,
and two invites share a key only when they draw the same words in the same window. The random
nonce keeps even those apart. Whoever does learn the words, or reads the invite first, is in the
position of a leaked invite (C-15): the SAS and the commitment still decide.

#### 7.8 Re-pairing after a restore: the key check

When the user adds a new pairing to an address-book contact that already has a pairing record
(the app never offers this because of an address a card claims; the user picks the contact), the
wallet that holds the old record (X) asks the other side (Y) whether it holds the old keys. Each
step travels over the new pairing: sealed to the peer's new key, signed by the sender's new key,
to the peer's new mailbox. `nX` and `nY` are the new pairing's sig keys of X and Y; `R_old` is
X's old record, `cardY_old` the card Y gave X then.

1. **Check (type 06).** Body `seq (u32) || tag (32)`, where `seq` is `cardY_old`'s seq and
   `tag = H("epic-pair/1 keycheck" || cardY_old.hint_key || nY || nX)`. The tag reveals nothing
   about the old pairing to a peer that does not hold Y's seed, and is bound to this new pairing.
2. **Search.** Y computes the tag for its own records first (both invited each other, C-17), then
   for slots 0 to 65,535 (2.5: one HMAC and one hash per slot). No match: Y answers type `07`
   with body `01` (not this wallet).
3. **Found (type 07, status 02).** Y makes `cardY_old'`: its card for the found slot with `seq`
   one above the given one, a mailbox from a new `box_salt` (or its current one, if the record
   exists), signed with the slot's `sig_sk`. Body `02 || u16 length || cardY_old' || proofY`,
   `proofY = Sig_old("epic-pair/1 keycheck found" || H(check envelope) || nY || nX ||
   H(cardY_old'))` by the found slot's `sig_sk`. `H(check envelope)` is over the 06 envelope's
   bytes as received.
4. X accepts the found answer only for its open check, once, within 24 hours: `proofY` verifies
   with `cardY_old`'s sig key, and `cardY_old'` has the same enc, sig and hint keys and a higher
   seq. X then keeps `R_old` with `cardY_old'` as its peer card, raises it to Verified if the new
   pairing was Verified, and answers with step 5. An ordinary contact update (05) on the old
   pairing never completes a check.
5. **Restored (type 07, status 03).** Body `03 || u16 length || cardX_old || proofX`,
   `proofX = Sig_old("epic-pair/1 keycheck restored" || H(found envelope) || nX || nY ||
   H(cardX_old))` by X's old `sig_sk` for `R_old`. X then deletes the new pairing.
6. Y accepts the restored answer only for the found answer it sent: `proofX` verifies with
   `cardX_old`'s sig key and `cardX_old` verifies as a card. Y then keeps (or, after a restore,
   creates) the record for the found slot with `cardX_old` as its peer card, the trust of the new
   pairing, and the slot counter above the slot, and deletes the new pairing. "Anna's keys are
   back."
7. **Not found or no answer.** On a 07 with `01`, or with no found answer within 24 hours, `R_old`
   stays exactly as it was. The new pairing goes to `keys-changed` (C-12): "Anna's keys changed.
   This can mean she uses a different wallet now, or someone else is using her name. Check the
   words again." The user keeps the old record (the new pairing is deleted) or uses the new keys
   (the old record is deleted).

A wallet starts and answers at most one key check per pairing and per slot, and only within 24
hours of the new pairing. Each proof is made by a key the other side already held, over the
envelope it answers and both new keys, so neither side adopts a card or a trust level from a
party that has not shown it holds the old key.

### 8 Mailboxes and the home relay

#### 8.1 Pairing mailboxes

For a 16-byte seed `s` (`code` for the reply mailbox, `rc` for the confirm mailbox, the words'
`s` for the rendezvous mailbox of 7.7):

- `pbox_sk = HKDF(salt = "epic-pair/1 mailbox", ikm = s, info = "box" || net || ctr)`, Extract
  then Expand, `info` in exactly that byte order, read as a secp256k1 scalar; `ctr` is a byte
  from `00` up, taking the first output that is a valid key.
- `pfrom_sk` the same with info `"from"`. Messages to the mailbox are posted from `pfrom_sk`'s
  address, so the relay sees an ordinary message between two unknown keys.
- The address is `pbox_pk@<home relay>`. A service's fixed inbox replaces it for replies only;
  confirms always use `rc`.

These keys never touch the wallet's own Epicbox, Tor or proof keys, and are forgotten when the
pairing ends.

#### 8.2 One-off drains

LEPIC adds `drain_mailbox_once(relay, keys)`: one connection to that relay with a client of its
own (not the wallet's listener or its drains), and for each key in turn: subscribe, take every
pending message, `Made` each once its effect is stored. Then it disconnects. A message for an
earlier key that arrives after the socket moved on is left unacknowledged and is collected by the
next drain, so nothing is lost (`docs/compat/epicbox.md` facts 4 and 6). The relay accepts
sequential subscribes on one socket, with two rules from the probe: a message left
unacknowledged blocks that connection for the next mailbox, so the drain opens a new connection
after keeping one; and the drain greets the relay as the mailbox's own sender.
It follows the wallet's network mode: over Tor when Epicbox over Tor is on, to the onion when
one is known (the wallet's built-in onion for a built-in relay wins over one in a card or
invite); refused in Offline and when Epicbox is off (8.7). The relay layer deduplicates by
message id; the wallet deduplicates by the envelope's hash.

Pairing mailboxes are drained:

- by A while the invite is pending: every 10 s while the invite screen is open, then on every app
  open and resume, until the invite expires plus 10 minutes;
- by B after replying: every 5 s while the waiting screen is open, then on open and resume, for
  1 hour.

#### 8.3 Contact mailboxes

After pairing, each side's messages for the relationship go to the other side's mailbox (card
tag 08) on the home relay:

- A wallet's mailbox for a contact is `box_pk@<home relay>` (2.2). Only that contact knows it.
- A service may instead give every customer one shared inbox (caps bit 3), so it drains one
  address however many customers it has; it finds the customer by the fixed hint (3.2).
- What goes there: sealed invoices and their I2, sealed withdrawals and their S2, notices, home
  relay moves (8.5), and Epicbox-delivered sealed slates between people when the user picks
  Epicbox for a paired contact. Messages are posted from our `box_sk` for that contact, so the
  relay sees two per-contact keys and nothing of either wallet's own address.
- Delivery always targets the home relay, whatever relay either wallet is connected to. A user
  who switches relays changes nothing for paired contacts, and no message is sent about it.
- The wallet's own payments address and its listener are unchanged, for everything else.

#### 8.4 Collecting

The wallet collects from its contact mailboxes with one-off drains, grouped by home relay, one
connection per relay:

- on app open and resume, after unlock, and on pull-to-refresh: every contact mailbox;
- every 45 s while the app is in the foreground: the mailboxes of contacts with something pending
  (an open invoice or withdrawal, an outbox entry, a pairing, or activity in the last 24 hours),
  or all of them when they sit on at most 3 distinct relays;
- on a push wake-up for a mailbox that registered push (8.6).

App open, resume, unlock and pull-to-refresh clear every relay's backoff and send every queued
outbox entry at once; the foreground tick and push wake-ups respect the backoff. Collecting,
entering a link by hand and outbox delivery take one lock, so they never interleave.

At most 50 mailboxes per cycle, round-robin, so many contacts cost a bounded drain. A relay that
does not answer backs off (30 s, 2 min, 10 min, 30 min) and the contact shows "Exchange X's relay
isn't answering". Signing a withdrawal or paying an invoice needs the wallet unlocked, so
collecting on open fits the flows: nothing is lost while the app is closed, because the relay keeps
messages 7 days.

#### 8.5 A service moves its home relay

That is rare and is the service's job. It keeps the old relay running at least 7 days, and sends
each customer one contact update (type `05`, its new card with the new mailbox, higher `seq`,
signed) to the customer's mailbox on the old home relay. The customer's wallet then delivers to the
new mailbox and drains its own mailbox on both relays for 7 days. A person moving a pairing's home
relay re-pairs; the protocol does not offer it.

Limits on updates, on the receiver (wallet and kit):

- accepted only from a paired key with a valid signature, and only with a `seq` above the stored
  one; the same card again is ignored;
- at most 3 per contact per day and 100 per hour in total; extra ones are acknowledged and dropped,
  and the contact's next envelope (tag 07 carries the card) heals anything dropped;
- a card replaces the stored one only with the same enc, sig and hint keys; nothing but the user's
  "Use the new keys" (7.8) changes a contact's keys;
- a move of the home relay comes only in a 05 within these limits, never changes the contact's
  kind, and goes only to a built-in relay or a named host on port 443 (no address literals). A
  person's mailbox stays where it is. Our own new card for the moved relationship is queued to
  the service in the same write.

A user's own relay switch needs no update because of 8.3, so the flood of "my relay changed"
notices that per-wallet addresses would need cannot happen. Section 15 has the remaining abuse
cases.

#### 8.6 Push

Push only works on relays that run LEPIC's push service. When the home relay does, the wallet
registers its mailbox for that contact for push (signed with `box_sk`), so a
deposit request or a withdrawal wakes the phone. Elsewhere the wallet collects on open. The push
service learns which mailboxes share a device token; that is the cost of the wake-up, and the
setting "Wake for contacts" lets the user turn it off. A service may run its own push later; out of
scope.

#### 8.7 Transport, and Epicbox switched off

Pairing messages travel only through Epicbox mailboxes: the reply, confirm and rendezvous
mailboxes of 8.1 and 7.7, and the contact mailboxes of 8.3, all reached with one-off drains and
posts from keys of their own. They never use the wallet's payments address, its listener, Direct
(HTTP or Tor links) or the node. Anything that can go by hand goes by hand when no relay is
reachable: the invite, `pair-reply` and `pair-confirm` links, and sealed files and pastes.

When the user switches Epicbox off (the per-method switch that follows this RFC), the wallet
connects to no Epicbox relay at all, home relays included. Then, as in Offline (C-10):

- in-person pairing (two-way QR) works; an online invite works by hand (link, reply link, confirm
  link); pairing words are not offered;
- sealed file and paste sends and answers work;
- collecting, contact invoices, withdrawals and notices pause; the outbox keeps its entries and
  posts them when Epicbox is back; the contact page and Settings › Invoices say "Paused while
  Epicbox is off".

### 9 Sealed slates between paired contacts

#### 9.1 Sending

When the recipient is a paired contact with `seal` on and caps bit 0, the file and paste methods
write an envelope: type `01`, the marked V3 slate as body, purpose, our current card when its seq
is newer than what the contact last saw, signed. The app shows "Sealed for Anna". Over Epicbox,
a send to a paired contact goes to its payments address as today, unless the user chooses "Send
through Anna's mailbox", which posts the envelope to the contact mailbox.

#### 9.2 Receiving

A sealed file or paste opens (3.4). The slate goes to the engine as if it arrived plain over that
method, attributed to the contact. The answer (S2 or I2) is sealed back to the contact, signed, on
the channel it came by (file, paste or the contact mailbox).

#### 9.3 The plain fallback

If the contact cannot open a sealed slate (it was restored into a stock wallet, it runs an older
LEPIC, or its pairing record is gone), the sender's app offers "Send as plain instead" on that
transaction. It writes the stored slate of the same stage in plain V3: the same slate id, the
same inputs and outputs, the same signatures. It never makes a second transaction, so at most
one can be posted. The record's `seal` becomes `degraded`: the next send to the contact asks
"Seal or plain?" with seal preselected, and the next envelope that opens from the contact sets
`seal` back to `on`.

#### 9.4 Hint lapse

A contact with no opened envelope for 90 days still gets sealed slates, and the send screen adds
"Not heard from Anna's wallet in 90 days; they will need LEPIC to open this", with the plain
option one tap away. Identity, verification and invoice trust do not lapse.

#### 9.5 Envelopes for another install

Over file or paste, a hint that matches no key, or a signed envelope whose sender is not the
peer of the slot that opened it (3.4), says "This was sealed for another wallet or install" and
offers nothing else. Contact mailboxes are per install, because `box_salt` is random, so a twin
install on the same seed never drains another install's mailbox. Two installs
hold the same pairing only when a backup with pairing records is restored onto a second device
while the first still runs; both then drain the same mailbox. Each processes idempotently and
acknowledges only after storing the effect, so whichever opens a message first acts on it and
the other may never see it. The app therefore imports pairing records from a backup as "on another
device" and asks "Use your contacts on this device?"; the first device should then be removed.

### 10 State and storage

#### 10.1 Tables (lepic-store)

- `contact` keyed by the local `contact_id`; `slot` and `box_salt`; unique on the peer's sig key.
  The slot counter per account and network.
- `contact_mailbox`: per contact, the peer's mailbox and ours, their home relay and onion, and
  for 7 days after a home relay move the previous ones; backoff state per relay.
- `pairing`: pending pairings (secrets `code`, `nA`, `nB`, `rc` encrypted at rest as the store
  encrypts every secret, ADR 0005), expiry, role, mailbox addresses, state.
- `outbox` (section 12.4): messages that must reach a relay.
- The `allowed_peer` table is dropped and the invoice address retired (section 11.5).

#### 10.2 Pairing state machine

```
           make invite                      reply opened, card ok
 (none) ───────────────► pending-invite ─────────────────────────► paired ──"They match"──► verified
   │                          │  expired / cancelled                 │  ▲                       │
   │ open invite, Pair        ▼                                      │  │ re-verify             │
   └──────────────────► pending-reply ──confirm ok──► paired         │  └──────── keys-changed ◄┘
                              │ confirm bad / expired                 │            (new keys for a
                              ▼                                       ▼             known contact)
                          (deleted)                                (deleted: "Remove pairing")
```

`keys-changed` is a state of the new pairing, reached only through the key check of 7.8 when the
other side's slot is not found or it does not answer; the old record stays as it was. A new
pairing in `keys-changed` seals nothing and accepts no invoices until the user keeps the old
record (the new pairing is deleted) or uses the new keys (the old record is deleted, the new one
goes on as paired or verified). The cases file, C-12, has the details.

#### 10.3 Limits

At most 64 pending pairings per wallet (services: 3 per account), 10,000 contacts per wallet
(services: no fixed cap, indexed lookups, 13.4), one reply accepted per invite, 32 messages read
per mailbox per drain, 50 mailboxes per collecting cycle.

#### 10.4 Events (lepic-wallet → host)

`PairingReplied`, `PairingConfirmed`, `PairingFailed{reason}`, `ContactUpdated`,
`ContactKeysRestored`, `ContactKeysChanged`, `SealedReceived`, `SealedUnopenable`, `InvoiceFromContact`,
`WithdrawalFromContact`, `HomeRelayUnreachable`, `OutboxDelivered`, `OutboxStuck`, and the existing
`InvoiceFinalized` for a contact's payment. Event fields carry ids and labels, never keys or
secrets. `SealedUnopenable` is raised at most once per contact per cycle. A collect also returns
the pairings that ended and why.

A slate id belongs to at most one contact, and a link from a slate to a contact is never moved. An
S1 or I1 from a contact whose slate id already has a transaction (other than that contact's own
repeat) or belongs to another contact is dropped; notices from a contact act only on transactions
exchanged with that contact. Contact invoices are capped per contact, apart from the payments
address's caps, and paying one checks the contact's trust in the same locked step. Slates that go
through a contact mailbox are recorded with transport `epicbox`; sealed files stay `file`.
Delivered outbox entries are pruned after 7 days, entries of finished transactions at once.

#### 10.5 Backup and restore

Pairing records hold no secret: our keys come from the seed, the slot and `box_salt`. LEPIC
exports the records, the slot counter and the network as a versioned JSON object; on import it
decodes every card again, refuses another network, and keeps a record only when its own card
carries the keys this seed derives for its slot. The app adds the object to its `.wfeh`
history payload and gives it back on restore (9.5). A restore with the backup brings every
pairing back unchanged: same keys, same mailboxes, same trust; contacts notice nothing.

A restore without the backup has no records. Re-pairing with a contact that kept its record runs
the key check (7.8): the restored wallet finds its old slot, the keys are the same as before,
and the contact keeps its record, its trust and its Verified mark. Only the restored side's own
settings for that contact ("Allow invoices", "Seal payments") start at their defaults, and its
mailbox is new (new `box_salt`); messages left in the old mailbox expire on the relay after 7
days. Pending pairings are not in the backup.

### 11 Invoice trust on contacts

#### 11.1 Rules

- "Allow invoices from <contact>" is a switch per pairing record, off by default, offered right
  after pairing when the contact's card says it issues invoices (caps bit 2). It is never
  preselected: an invite's kind and name are claims.
- The switch can be turned on only for a `verified` contact; an unverified one shows "Check the
  words first". Paying is money leaving on a contact's request, so it waits for the one check
  that rules out a swapped invite.
- An invoice is trusted when it arrives in the contact's mailbox, sealed and signed by that
  contact, with `allow_invoices` on and the record `verified`. Where it was posted from does not
  decide trust.
- Turning the switch off is immediate: new invoices from the contact are acknowledged and dropped;
  parked unpaid invoices from it are deleted with "Invoices from X are off"; a paid one finishes
  as any paid invoice does.

#### 11.2 Receiving an invoice

In the contact mailbox, after the Epicbox layer, a sealed payload opens with the contact's key (by
hint) and must be signed by the contact: type `01` with an I1 body, or type `02` notice. A plain
payload in a contact mailbox is acknowledged and dropped: a paired contact always seals. The I1
parks attributed to the contact and raises `InvoiceFromContact` with the purpose, reference and
expiry. Nothing pays without the user's approval (PIN).

#### 11.3 Abuse

A mailbox is known only to its contact, so there is no prefilter to maintain. A contact that
floods its mailbox is bounded by the per-drain read limit and the parked-invoice caps,
counted per contact; over the cap its invoices are acknowledged and dropped and the contact shows
"Exchange X sent too many requests". Turning invoices off stops it at once.

#### 11.4 Notices

`declined`, `withdrawn` and `posted` (ADR 0016) travel sealed and signed in the contact
mailboxes, type `02`. Accepting them follows ADR 0016, with "the recorded counterparty" meaning
the contact. A signed `withdrawn` for a paid invoice cancels the payment automatically and
releases its inputs (12.6); for an unpaid one it deletes it as today.

#### 11.5 Replacing trusted services and the invoice address

There are no users of the address allowlist yet. The `allowed_peer` table, the invoice address
(`m/0/1/<index>`, index 1 and up) with its connection and prefilter, and the FFI calls
`invoice_address`, `invoice_address_index`, `set_invoice_address_index`,
`rotate_invoice_address`, `invoice_senders`, `allow_invoice_sender` and `remove_invoice_sender`
go, with the app's "Add trusted service" screen and the invoice address card. Settings › Wallet ›
Invoices lists the paired contacts with their "Allow invoices" switch and offers "Pair with a shop
or exchange". Issuing an invoice over Epicbox to someone requires a pairing in which they allow
our invoices; issuing by file is unchanged. The app offers nothing else; the engine and the CLI
keep issuing to an Epicbox address for interoperability tests, and no address-based payer path
can list, pay or decline a contact's invoice.

### 12 Worked example: exchange deposits and withdrawals

#### 12.1 Why invoices

A normal send makes the user's wallet do two of three steps: create S1, then receive the
exchange's S2, finalize and post. The phone is the weak link (asleep, offline, on another relay),
and its funds stay locked while it waits. With an invoice the exchange creates I1, the wallet pays
once (I2, fire and forget), and the exchange finalizes and posts. A withdrawal is the mirror: the
exchange sends S1, the wallet signs once (S2), the exchange finalizes and posts. In both
directions the exchange, which runs reliable servers, does two of the three steps and posts.

#### 12.2 Pairing, bound to the account

1. The user, logged in at Exchange X, opens Deposit › "Pair your Epic Cash wallet". The exchange's
   kit makes an invite (7.1): kind exchange, 15 minutes expiry, home relay = the exchange's own
   relay (with its onion), its fixed pairing inbox. It stores `invite_id → account`. The page shows
   the invite as a QR and as a button that opens `epiccash://pair/1/…` on the same device.
2. The wallet shows "Pair with Exchange X?" with the name marked as claimed and, below, "Allow
   Exchange X to request payments", off: the kind and name in an invite are not authenticated, so
   nothing is preselected from them. The user taps Pair. The reply goes to the inbox.
3. The kit opens the reply by `invite_id`, binds the reply card's sig key to the account, and sends
   the confirm with its card: mailbox = its shared customer inbox (caps bits 2, 3, 4). The page and
   the wallet both show the SAS; the user compares the two screens and taps "They match" in the
   wallet and "Confirm" on the page. Both mark the pairing verified.
4. A second pairing for the same account (a second phone, a reinstall) is a new contact on the
   account; the page lists the account's paired wallets with a remove button.

Crediting is by contact key: every I2 and S2 the exchange accepts arrives signed by a key bound to
one account. The slate id ties it to the deposit or withdrawal; no memo or address is used.

#### 12.3 Deposit

1. The user clicks "Deposit 250 EPIC". The kit asks the exchange's `epic-wallet` for an invoice
   (`issue_invoice_tx`, V3) with a TTL of 1,440 blocks, and seals it: purpose deposit request,
   reference, expiry, signed. It posts it to the user's mailbox for the exchange, on the exchange's
   relay; when the user's mailbox registered push there, the phone wakes.
2. The wallet collects it (8.4): on push, on open, or within 45 s while the app is open. It opens
   it and raises `InvoiceFromContact`. The app shows "Exchange X requests 250 EPIC" with a Verified
   badge, the reference, the fee and the expiry. The user approves with the PIN.
3. The wallet builds I2 once, locks its inputs, seals it to the exchange, signed, and puts it in
   the outbox (12.4). The app says "Paid — waiting for Exchange X to post".
4. The kit drains its inbox, opens the I2 by fixed hint, checks the slate id belongs to this
   account's open deposit, finalizes (`finalize_invoice_tx`), posts (`post_tx`) and sends a sealed
   `posted` notice with the kernel excess.
5. The wallet shows confirmations from the chain as for any payment (refresh watches the kernel
   and the change output), with or without the notice.

#### 12.4 Delivery that survives

The outbox holds each I2 or S2 that must reach a relay: the armored payload, the destination (the
contact's mailbox on the home relay), the attempt count and the next try.

- A post succeeds when the home relay answers `Ok`; the relay then holds it 7 days. Until then it
  retries: at once, then 30 s, 2 min, 10 min, then every 30 min, and on every app open, network
  regain and collecting cycle.
- It lives in the store, so it survives the app being killed. It posts to the home relay, so the
  user's own relay switch does not matter. A home relay move (8.5) changes the destination of
  entries not yet delivered.
- Delivered but not finalized after 2 hours: the transaction shows "Exchange X has not posted
  yet" with "Send again", which posts the same stored I2 again. The kit treats a repeat slate id
  as a duplicate.
- After 24 hours undelivered, `OutboxStuck` and "Couldn't reach Exchange X yet. Your funds are
  safe; they unlock if it doesn't post." The payment then ends as any unfinished one does: at its
  TTL or after `UNFINALIZED_RECEIVE_BLOCKS`, or on a signed `withdrawn`.

#### 12.5 Withdrawal

1. The user asks Exchange X to withdraw 100 EPIC to a paired wallet. The kit has `epic-wallet`
   make S1 (`init_send_tx`, locked), seals it to the user's contact key, purpose withdrawal,
   reference, signed, and posts it to the user's mailbox for the exchange.
2. The wallet collects it like a deposit request. It receives it as any S1, attributed:
   "Withdrawal from Exchange X: 100 EPIC". Receiving needs no approval, as for any incoming
   payment; it signs S2 once, seals it back, signed, and puts it in the outbox. Its job ends at
   "Received — waiting for Exchange X to post".
3. The kit finalizes (`finalize_tx`) and posts. The wallet shows confirmations from the chain.

#### 12.6 Timing, failure and duplicates

| Situation | What happens | The user sees |
|---|---|---|
| Exchange down when the user pays | The I2 waits on the home relay (7 days). The kit finalizes when it is back; it accepts a late I2 while the slate's TTL has not passed | "Paid — waiting for Exchange X to post", then confirmations |
| Home relay down | The outbox retries with backoff, collecting backs off; after 24 h `OutboxStuck` | "Exchange X's relay isn't answering" on the contact, then "Couldn't reach Exchange X yet" with Send again |
| User's own relay down or switched | Nothing for this flow uses it | Nothing changes |
| User offline after paying | If the post succeeded nothing more is needed; otherwise the outbox posts on the next open | Same states, later |
| App closed when the request is sent | It waits in the mailbox; push wakes the phone when the home relay has push, else it appears on the next open | The request, later |
| Double click on Deposit | The kit returns the open invoice for the same account, amount and idempotency key within 60 s. Two that still arrive are two requests; the wallet groups same-amount requests from one contact within 10 minutes and asks "Pay both?" before a second payment | One request, or "Exchange X sent 2 requests for 250 EPIC" |
| Invoice expires after payment | The kit finalizes a valid I2 until the TTL height; past it, it sends a signed `withdrawn` and the wallet cancels and releases its inputs | "Exchange X withdrew the request; your funds are unlocked" |
| Withdrawn before payment | The parked invoice is deleted; approving it is refused | "Exchange X withdrew this request" |
| Declined by the user | A signed `declined` to the exchange; the kit marks the deposit declined | "Declined" |
| Exchange posts after the wallet cancelled | If the inputs are still unspent the transaction confirms; refresh shows a cancelled payment whose kernel reached the chain as confirmed | Confirmed |
| Withdrawal while the user switches relay | Nothing changes: the S1 is in the mailbox on the home relay | The withdrawal on next collect |
| Exchange moves its home relay mid-withdrawal | The S1 on the old relay is still collected (7-day drain of both, 8.5); the S2 goes to the new mailbox, and the outbox retries the old one if the new relay does not answer within 30 s | Nothing |

### 13 Reference exchange kit

A Python package (`epic-pairing`, Python 3.11+, MIT or Apache-2.0) that an exchange runs beside
its own `epic-wallet` v4.1.0 owner API. It is the second, independent implementation of this RFC
and generates the test vectors LEPIC checks (14).

#### 13.1 Parts

- `envelope`, `card`, `invite`, `sas`: this RFC, on `cryptography` (X25519, Ed25519,
  ChaCha20-Poly1305, HKDF, HMAC) with HPKE base mode written out and checked against RFC 9180
  Appendix A.2.
- `epicbox`: an Epicbox client (connect, subscribe, drain, `Made`, post) speaking the protocol in
  `docs/compat/epicbox.md`, with the message cipher and ECDSA from `coincurve`, built from what
  `epicbox-py`, the Python relay, already does on the server side.
- `wallet`: a thin owner-API v3 client for `issue_invoice_tx`, `finalize_invoice_tx`,
  `init_send_tx`, `tx_lock_outputs`, `finalize_tx`, `post_tx`, `retrieve_txs`.
- `service`: the flows of section 12 as an async worker with a storage interface (SQLite in the
  example, the exchange's database in production).

#### 13.2 Endpoints and hooks

| Call | What it does |
|---|---|
| `create_invite(account_id)` | Makes the invite of 12.2 and returns the link and QR payload |
| `pairing_status(invite_id)` | Pending, replied (with the SAS), verified, expired |
| `confirm_sas(invite_id)` | The user clicked Confirm on the page |
| `request_deposit(account_id, amount, idempotency_key)` | Issues and sends the sealed invoice; returns the open one for a repeated key |
| `request_withdrawal(account_id, contact_id, amount, idempotency_key)` | Makes, locks and sends the sealed S1 |
| `on_credit(callback)` | Called once per posted deposit with account, amount, slate id and kernel |
| `on_withdrawal_posted(callback)` | Called once per posted withdrawal |
| `revoke_contact(contact_id)` | Removes the pairing; later envelopes from it are dropped |

#### 13.3 Worker

Drains the pairing inbox and the shared customer inbox on its own relay every 5 s (no push
needed: the kit is a server); opens envelopes by fixed hint; dedupes on message id and slate id;
finalizes and posts; delivers to each customer's mailbox on the home relay, which is the
exchange's own relay, so posting is local and a customer's relay switch never matters. Moving
the home relay is a kit command: it starts the new relay, sends each customer one signed update
(8.5) and keeps draining the old relay for 7 days.

#### 13.4 Scale and abuse

- Lookups by fixed hint are indexed; the kit opens at most one envelope per message, and only
  after the hint matched a customer or an open invite.
- Invites: 3 open per account, 15 minutes, one reply each; a replay of a used invite gets status
  02 and nothing else.
- Drop, without opening, messages whose hint matches neither a customer nor an open invite.
- Per customer key: at most 30 messages a minute and 3 contact updates a day; globally a
  configurable ceiling per minute. Over it, messages are acknowledged and dropped and counted.
- A customer who floods is revoked with `revoke_contact`; pairing again needs the logged-in
  account, so the cost of an attack is accounts, which the exchange already rate-limits.
- Rate limits on `create_invite` and `request_deposit` per account and per IP are the exchange's;
  the kit exposes counters.

### 14 Test vectors

`conformance` does not generate these from `epic-wallet` (no upstream implements this RFC). The
kit generates them from fixed inputs (the raw account key, slots, `box_salt`, RNG bytes) and LEPIC checks
them byte for byte; LEPIC also opens what the kit seals and the kit opens what LEPIC seals in the
two-implementation test. Areas under `testdata/vectors/pairing/`:

| File | Content |
|---|---|
| `hpke_rfc9180_a2.json` | RFC 9180 Appendix A.2.1 base-mode vectors, written by the kit's generator from the RFC's values |
| `contact_keys.json` | Raw account key → `root`, `enc_pk`, `sig_pk`, `hint_key`, `box_sk` for slots 0, 1 and 65,535 with fixed `box_salt`s, mainnet and floonet |
| `reply_keys.json` | Slate ids → `reply_pk` |
| `mailbox_keys.json` | Codes → mailbox and sender secrets; the `ctr` loop is tested with an injected curve order, since no real input needs `ctr = 01` (probability about 2^-128) |
| `words.json` | Pairing words and a window → `k`, the rendezvous mailbox secrets, the invite key, and the posted text for a fixed invite and nonce |
| `keycheck.json` | A full key check between two fixed wallets: tags, the 06, the found and restored answers with their proofs, and the not-found answer |
| `envelopes.json` | Each type (01 to 07), anonymous and signed, with fixed RNG: bytes, armored text, hint, opened fields |
| `cards_invites.json` | Card, invite, reply and confirm bytes and their URI forms |
| `sas.json` | Inputs → four bytes → emoji and names |
| `malformed.json` | Each rejection of 3.1, 3.3, 3.5, 6.1 and 7.1 with its typed error |

The SAS table `testdata/sas/emoji-v1.txt` is frozen once released; a change is `emoji-v2` with a
new SAS domain string.

### 15 Threat model

| Threat | What stops it | What remains |
|---|---|---|
| MITM on the invite channel (a chat server swaps keys) | Commitment and SAS (7.5); B checks the commitment | A user who skips the SAS is "Paired, not verified": sealed files still go to the key it got, but it cannot allow that contact's invoices |
| Malicious home relay | It sees only Epicbox-encrypted envelopes between per-contact or throwaway keys; it can drop, delay or replay, not read or forge; replays are deduplicated; the outbox retries | It can deny service to that relationship; it sees which per-contact keys talk and when |
| Leaked or forwarded invite | One reply per invite; A sees the replier's claimed name and the SAS; 24 h default expiry; services bind the invite to a logged-in account | Whoever answers first pairs with an unverified A; A's "Pair with …?" and the SAS reveal it |
| Seed restored into a stock wallet | Sealed messages go only to paired LEPIC contacts, into mailboxes a stock wallet never subscribes; the plain fallback resends the same slate | The stock wallet cannot open sealed files; the sender must use the fallback |
| Replay of a sealed slate or notice | Slates are idempotent on `(slate_id, stage)`; notices on the slate's state; cards on `seq` | none |
| Replay of a pairing reply | One reply per invite; the code is deleted after the first | none |
| Guessing pairing words | Argon2id over the words with a salt that changes every 10 minutes, random nonce, 10-minute expiry, one acknowledged message; the SAS and commitment still decide (7.7) | A party that reads the invite first is in the leaked-invite position |
| A false key check (an impostor re-pairs as a contact, or a MITM of the old pairing interferes) | The check reveals only a tag bound to the new keys; "found" needs a proof by the old key over the check, sent over the new pairing; the restored side adopts the old card only with a proof by its old key; a failed check leaves the old record untouched; one check per pairing and slot within 24 h (7.8) | An impostor learns that the user thought it was the contact |
| A card QR photographed in person | The first collect moves the mailbox to a new `box_salt` (7.4) | The hint key in the shown card links envelopes to that contact |
| Forged invoice | Must arrive in the contact's own mailbox, sealed and signed by that contact, with invoices allowed | A contact you allowed can still request; nothing pays without the PIN |
| Spam or DoS against a service from many paired keys | Each pairing needs a logged-in account and an invite (3 open per account); per-key and global rate limits (13.4); only hint-matched envelopes are opened; revocation | An attacker with many accounts costs the service drains and hint lookups, bounded per message |
| Flood of address or relay updates | None needed for relay switches (8.3); home relay moves only from services, signed, higher `seq` only, 3 a day per contact, 100 an hour in total (8.5) | none |
| Spam into a wallet's contact mailbox | Only the contact knows the mailbox; per-drain read limit and per-contact invoice caps; turning invoices off or removing the pairing stops it | A contact you paired with can annoy you until you remove it |
| Downgrade to plain | Between contacts the sender seals by policy, not by a signal the channel could strip; plain only by the user's "Send as plain"; a plain payload in a contact mailbox is dropped | An attacker who strips the reply key from an unpaired plain S1 gets a plain S2, as today |
| Key reuse and linking | Contact keys and mailboxes share nothing with Epicbox, Tor or proofs; one set per slot | Two installs on one seed that meet in one slot give its two contacts the same keys (2.2). A person's card may carry the ordinary payments address (tag 09), the same for every contact; leave it out to stay unlinkable. A push service links mailboxes registered under one device token (8.6) |
| Compromised phone | Out of scope: it holds the seed | Past sealed messages to it open with the keys from the seed |
| Forward secrecy | Sender side: each envelope uses a fresh HPKE key | A recipient key leak opens past messages to that key (RFC 9180 section 9.7.4); re-pairing rotates |

Secrets never cross the FFI boundary beyond ADR 0014: the app passes invite links, armored text
and file paths in, and receives cards, SAS emoji, labels and states. The invite code inside a link
is the one pairing secret the app sees, because the link reaches the app first; it is not stored by
the app.

### 16 Compatibility

- Stock `epic-wallet` (GUI, CLI) and Epic Pay never receive an envelope, a card, an invite or a
  notice: all go only to paired contacts, and pairing needs LEPIC or the kit.
- A LEPIC S1 or I1 gains `"reply"` in its marker. Stock ignores it. Interop test V-15 proves it for
  `epic-wallet` v4.1.0 over file; Epic Pay is unverified (C-31).
- An older LEPIC peer: no `reply` → plain answers; it cannot open `epiccash://pair` links, so the
  invite expires; it sees a sealed file as "not a slate", and the sender's fallback applies.
- The legacy codecs are not changed. The marked V3 codec writes one more key.
- Wire, store and API effects are breaking for the binding (allowlist calls removed, new calls),
  not for peers.

### 17 UX

#### 17.1 Screens

The app calls the feature Pairing: "Pair", "Pair with Anna", "Paired", "Verified". Copy is
plain and impersonal; the UI never says HPKE, envelope or key, and makes no claim about other
wallets. Labels stay short; an info icon next to a switch opens its explanation. Icons carry the
trust states: Verified (shield with a check), Paired, not verified (outline shield), Keys
changed (shield with a warning), Sealed (lock chip). The app tasks U-25 and U-26 design the
screens, phone and desktop, in the app's themes.

| Flow | Phone | Desktop |
|---|---|---|
| Pair in person | Contacts › Pair › In person: "Show my code" (QR) and "Scan theirs"; "Use words instead" shows pairing words; after both scans, the words check | No camera: "Show my code" with pairing words, and "Enter link or words" |
| Pair online | Contacts › Pair › Invite: expiry 1 h / 24 h / 7 d, then the share sheet with the link; pending invites under Contacts › Pending | The same, with Copy instead of the share sheet |
| Pairing words | Five emoji with their names, laid out as the words check, with a 10-minute countdown; the other side types the names, completed from the table | The same |
| Open an invite | A bottom sheet "Pair with Anna?" with "Name chosen by them · not checked yet", expiry, Pair or Not now; then "Waiting for Anna's wallet…", which can be closed and continues in the background | A dialog with the same content |
| Check the words | Four emoji with their names, large; "They match" (primary), "They don't match" (outline, leads to a warning and Stop pairing), "Skip for now" (Paired, not verified) | The same in a dialog |
| Contact page | Trust badge; switches "Seal payments" and "Allow invoices" (disabled until verified), each with an info icon (for "Seal payments": "Payments and invoices with Anna are encrypted end to end. Only her wallet can read them."); "Delivered via <home relay>", which turns into a notice when the relay does not answer; Remove pairing | The same in the contact panel |
| Keys changed | "Anna's keys changed. This can mean she uses a different wallet now, or someone else is using her name. Check the words again." with Check the words, Keep the old keys, Use the new keys | The same |
| Pair with an exchange | Opened from the exchange's page; the sheet names the site as claimed; the check step offers "Allow invoices from Exchange X", off | Same; the exchange's page shows the same emoji |
| Deposit request | The existing Review invoice layout with "Sealed" and "Verified" chips: "Exchange X requests 250 EPIC", fee, total, Approve with PIN; then a timeline: Paid, Delivered to Exchange X's relay, Posted, confirmations | Same, in the invoices screen |
| Settings › Wallet › Invoices | The paired contacts with an "Allow invoices" switch each (unverified ones greyed with "Check the words first"), and "Pair with a shop or exchange"; no invoice address and no trusted services | Same |
| Help | Topics: what pairing is, why check the words, pairing words, invoices from paired contacts, what a restore does | Same |

Every old invoice-sharing surface goes: the separate invoice address with its QR and copy, "Get
a new invoice address", trusted services by address, and their help topics and tour steps.
Issuing an invoice by file stays.

#### 17.2 Contacts with several addresses

The address book follows the one-per-method rule: an entry holds at most one Epicbox address,
one Link · HTTP address and one Link · Tor address, never a list. Pasting an address detects its
method and shows it as a badge. An unpaired entry's addresses change only when the user edits
them. Invoices go only through pairing, never to an address. A pairing attaches to one entry
(C-21); card tags `0F` and `10` are reserved to carry the Link addresses later (6.1).

## Effort

Estimates, not measurements; one implementer per line unless noted.

| Part | Work | Days |
|---|---|---|
| Keys (K-04) | Root, contact keys, reply keys, mailbox keys, vectors | 1.5 |
| Envelope and armor (X-05) | Seal, open, TLV, hint, armor, file type, fuzz targets | 3 |
| Marker reply key (S-05) | Marked V3 writes `reply`; S1 over file marked; interop check | 1 |
| Store (D-04) | Four tables, migration, drop allowlist and invoice-address state, backup export | 2 |
| Mailboxes and collecting (E-15) | `drain_mailbox_once` over several keys, Tor routing, backoff, the collecting schedule, push for contact mailboxes | 3 |
| Pairing engine (W-28) | Cards, invites, reply, confirm, SAS, state machine, events | 4 |
| Sealed send, reply and fallback (W-29) | File, paste and mailbox paths, attribution, the plain fallback | 3 |
| Contact invoice trust and outbox (W-30) | Invoices and withdrawals through contact mailboxes, sealed notices, home relay moves, outbox, auto-cancel, retire the invoice address | 4 |
| FFI and binding (U-24) | Calls, events, error codes from 56, regenerate both halves | 2 |
| Vectors and kit (G-07, XK-01) | Python kit with HPKE, Epicbox client, owner API, worker, vectors | 6 |
| End to end (V-15) | Two LEPIC wallets and the kit against `epic-wallet` on the local chain; floonet once | 3 |
| App, phone and desktop (U-25, U-26) | Pairing, SAS, contact trust, invoices settings, deposit request, outbox states | 6 |
| Review | A security review of the envelope, pairing and invoice changes before release | 2 |

About 7.5 weeks of single-agent work, about 3 calendar weeks with four lanes in parallel. The
critical path is K-04 → X-05 → W-28 → W-30 → U-24 → U-25 and V-15.

## Open decisions

| # | Question | Recommendation |
|---|---|---|
| OD-P1 | Invite links: `epiccash://` only, or also an `https://` universal link (needs a domain; the payload stays in the `#fragment`, never sent to the server) | `epiccash://` plus the pasteable code now; universal link later |
| OD-P2 | Register contact mailboxes for push when the home relay runs LEPIC's push service (8.6); the push service then links them by device token | Yes, on by default, with "Wake for contacts" to turn it off |
| OD-P3 | A signed `withdrawn` for a paid invoice cancels automatically (11.4), changing ADR 0016's "host offers a cancel" | Yes: the contact's key is authenticated and the inputs are reusable |
| OD-P4 | Exchange kit in Python beside `epic-wallet`, in its own private repository, with `cryptography` and `coincurve` installed in its virtualenv | Yes |

## References

- RFC 9180 Hybrid Public Key Encryption, sections 5.1.1, 6, 7.1.4, 9.7, Appendix A.2.
- RFC 8032 EdDSA; RFC 7748 X25519; RFC 5869 HKDF; RFC 4648 base64url.
- S. Vaudenay, "Secure Communications over Insecure Channels Based on Short Authenticated
  Strings", CRYPTO 2005 (the commitment-based SAS).
- Signal safety numbers; Matrix SAS verification (emoji SAS in practice).
- LEPIC: RFC 0001; ADRs 0003, 0004, 0005, 0012, 0014, 0016 (and its amendments), 0021, 0025;
  `docs/compat/epicbox.md`; `docs/compat/wfeh.md`.
