# 0054 epic1 over carriers: derived slots and a short link

Status: proposed; superseded in part by [ADR 0062](0062-the-address-decides-the-protocol.md):
section 4 (the mailbox pool, pool bits, shared mailbox list) and section 6 (the drain schedule of link
slots); superseded in part by
[ADR 0063](0063-the-epic1-address-carries-its-own-mailbox.md): section 1 (the proof key in the
address), section 2 (slots derived per mailbox, `epic1-box/1`, the reply tag), section 3 (the
link with `t`, `p` and `r`), section 4 (posting to 2 mailboxes, answering on 2), section 5 (the reply
route of tag `09`) and section 6 (link tags, their bounds and restore); the post states of section
8 are built through the outbox of ADR 0062
Date: 2026-11-10

Builds on: ADR 0030, 0033, 0047, 0051, 0052 (with its revision 7, numbered epic1 addresses);
RFC 0002; RFC 0003. Section numbers like "RFC 0003 5.14" refer to RFC 0003 with numbered epic1
addresses (ADR 0052 revision 7).

## Context

RFC 0003 puts the transport of an epic1 payment in the link: `epic:epic1…?epicbox=<mailbox>@<domain>`,
with up to three entries (RFC 0003 5.14). The payer's first message names a reply slot, an
Epicbox address on the payer's mailbox (envelope tag `09`, tail record `02`; RFC 0003 5.6, 5.10).
Link slots come from two numbered index spaces of the seed, 50 on screen used in turn and 32
printed (RFC 0003 5.2).

That model ties each link to Epicbox and to named mailboxes:

- A link carries a 52-character slot and a mailbox host per entry. One entry puts the code at QR
  version 16 at level H (RFC 0003 5.14, "Size of the codes").
- Mailbox hosts in links are hosts from untrusted input on every payment (RFC 0003 5.14, O-17).
- A second carrier (Nostr, a direct endpoint) needs a new link field and a new slot scheme.
- The user sees mailbox names in links and prompts.
- On-screen link slots come from a ring of 50, so a busy payee reuses a slot whose link is
  still live.

The owner's goal: epic1 payments as independent of the delivery method as practical. Epicbox now,
perhaps Nostr later. Epicbox details hidden from the user. Robust, with as little linking by mailboxes
as practical without a complex design, and few rough edges.

epic1 mode is LEPIC to LEPIC. In it the wallet pays and is paid through epic1 links, epic1
addresses and paired contacts. The classic index-0 Epicbox address is only received on, so
payments from stock wallets still reach the balance.

## Decision

### 1. Three layers

| Layer | What it holds | Names a transport |
|---|---|---|
| Identity | The epic1 address: proof key and seal key (RFC 0003 5.13), numbered per account (ADR 0052 revision 7). Contacts (RFC 0002). | No |
| Sealing | Every message is one RFC 0002 envelope, sealed and padded (RFC 0003 5.4, 5.7). The first message of a payment carries, inside the seal, a one-time reply key (tag `03`), a reply tag and the mailboxes the payer watches (tag `09`, section 5). | No |
| Carriers | One interface: post an envelope to a slot on a mailbox; watch a set of slots on a mailbox. Epicbox is the first carrier. Nostr is a later one. Direct HTTP/Tor is an extra carrier between contacts, its endpoint exchanged inside seals and never in links. | Yes, only here |

A carrier takes envelope bytes and a slot reference (carrier, mailbox, slot key). It knows
nothing of slates, addresses or contacts. The wallet layer derives slots (section 2), picks
mailboxes (section 4), deduplicates what comes back and decides what happens to each message
(section 8). The interface lives with the methods of ADR 0051; its Rust names are fixed in the
code. Keys cross the interface as suite-tagged bytes, not as fixed 32-byte arrays, so a second
seal suite does not change it.

### 2. Slots are derived, never listed

No link and no message names a slot. Both sides compute it from what they already share:

```
mailbox_in = "epic1-box/1"          11 bytes, ASCII
           ‖ net                    1  (00 mainnet, 01 floonet)
           ‖ class                  1  (below)
           ‖ key                    32 (an X25519 public key, below)
           ‖ tag                    10 (below)
           ‖ carrier                1  (01 Epicbox; 02 Nostr, reserved; others reserved)
           ‖ len(relay id)          1  (1 to 128)
           ‖ relay id               len bytes (section 4)
box_sk     = SHA-256(mailbox_in ‖ ctr)     ctr u8 from 00, the first value that gives a valid
                                           secp256k1 secret (non-zero, below the group order)
```

| class | Used for | key | tag |
|---|---|---|---|
| `00` | A link | The epic1 seal key of the address index | The link tag (section 3) |
| `01` | A bare address, no tag | The epic1 seal key of the address index | 10 zero bytes |
| `02` | A reply | The payer's one-time reply key (`reply_pk`, RFC 0003 5.2) | The reply tag |
| `03` | A paired contact | The receiver's per-contact `enc_pk` (RFC 0002 2.1) | The period tag of the contact (section 7) |

- **Mailbox id**: the stable name of a mailbox in the derivation (section 4), in the canonical mailbox
  form: the host in lower case, no trailing dot, then `:port` only when the port is not the
  carrier's default (443 for Epicbox). The host follows `relay-domain` of RFC 0003 Appendix B.2
  and is one type in the code (section 9).
- **Epicbox**: `box_sk` is the slot's secret. Its public key with the network's version bytes is
  the Epicbox address (`docs/compat/epicbox.md` "Addresses"). It answers the mailbox's challenge,
  receives at the address and does the Epicbox ECDH.
- **Nostr** (later ADR): `box_sk` as a BIP-340 key; the slot is a filter on its public key.
- **Reply tag**: the first 10 bytes of `BLAKE2b-256(key = seed, msg = "lepic-wallet reply tag v1"
  ‖ be32(account) ‖ net ‖ slate_id)`. The context is 22 bytes. It is rebuilt from the slate id,
  as the reply key is, so a second install on the same seed can collect the reply.
- **Inputs are fixed-width except the mailbox id, which is length-prefixed**, so ADR 0033 rule 4
  holds. `epic1-box/1` is prefix-free with `epic-seal/1`, `epic-tx/1` and `epic-check/1` (rule 3).
  It is a hash domain, not a signature tag, so rule 2's `lepic/` prefix does not apply.
- **One slot per mailbox.** The mailbox id is an input, so each mailbox sees a different slot key
  for the same link, and two mailboxes cannot match their slots by key. This also keeps the
  Epicbox rule that a key subscribes at one mailbox only (`docs/compat/epicbox.md` "Signatures"): a
  challenge signature from one mailbox's slot key is useless at another.
- Anyone who holds the inputs can compute `box_sk`. For a link that is anyone who holds the link;
  section 11 says what that allows.
- Vectors come before code (section 13).

ADR 0033 gains, on acceptance: the hash domain `epic1-box/1` (tags table), the seed label
`lepic-wallet reply tag v1`, the label `lepic-wallet link tag v1` if O-1 is accepted, and the contact
box secret of section 7. The class "Epicbox slot keys" in its recorded exception covers derived
slot keys in place of the reply slot, post key and link slot keys.

**Post keys.** The Epicbox `from` key of a post is a fresh random secp256k1 key per post. Nothing is
received at it, so nothing needs rebuilding. A per-slate key would show two mailboxes the same `from`
for one payment.

### 3. The link

```
epic:<epic1 address>?[a=<amount>&][p=<pool>&][r=<relay>&]t=<tag>
https://<pay host>/<pay path>#<epic1 address>?[a=<amount>&][p=<pool>&][r=<relay>&]t=<tag>
```

- **Tag**: 10 bytes, written as exactly 16 characters of the bech32 alphabet
  (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`), the bytes split into 5-bit groups, most significant first
  (80 bits, no padding). How the bytes are made is O-1. A tag is never issued for a second link.
- **Order.** Writers put `t` last, after `a`, `p` and `r`. A link cut or wrapped by a chat app
  then loses characters of the tag, and the 16-character rule refuses it; an amount cut short
  cannot slip through with a whole tag after it. Readers accept the keys in any order.
- **Parsing.** A `t` that is not exactly 16 characters from the bech32 alphabet rejects the whole
  link. The address checksum does not cover the tag, so this rule is what catches a cut link. A
  repeated `t`, `a`, `p` or `r` rejects the link. An epic1 whose version the reader does not know
  is refused as an unknown version, whatever its length.
- **Case.** The whole link is read case-insensitively: scheme, keys, address and tag are folded to
  lower case before decoding. Text links are written in lower case. QR codes are written in upper
  case, so the address and the tag go in alphanumeric segments.
- **`a`**: the amount in EPIC, decimal, as `amount` in the shipped parser. Optional.
- **`p`**: one bech32 character, 5 bits, most significant first: bit `i` is set when the payee
  watches the shipped default mailbox at position `i` of the default list (section 4). Writers
  always write it. A payer that reads it posts only to mailboxes it names, unless `r` is present.
- **No memo.** Memos and labels travel inside the seal. `message`, `note`, `memo` and `label` in an
  epic1 link are ignored.
- **No mailbox hosts**, with one exception: `r=<relay>` (one at most, `relay-domain` with optional
  port) when the payee watches none of the shipped defaults (`p` is `q`, all bits clear). The payer
  posts to it under the host rule (section 9; RFC 0003 5.14 "Hosts from untrusted input", O-17,
  O-18).
- Unknown keys are ignored. `epicbox=` is not read (O-2).
- **Bare address.** An epic1 with no `t` is payable. Its slot is class `01`: fixed for the
  address, the same trade-off as a printed code (section 11). A payer of a bare address posts to
  every shipped default mailbox.
- **Clickable form** for chat apps that do not link `epic:`: the same payload after `#` of an
  `https` URL. The fragment is not sent to the server. The pay host and path come from the
  built-in configuration (ADR 0030), with `https://epiccash.btlabs.uk/pay` as the shipped value;
  no host is in code. A reader takes the fragment only from a configured pay URL (O-4). Section 10
  states what the page may do.

Sizes, worked by hand from the ISO/IEC 18004 capacity tables, to be checked with an encoder: the
link without amount and pool is 139 characters. Lower case in byte mode: QR version 12 at H, 8 at
M. Upper case in segments (alphanumeric address, byte `?T=`, alphanumeric tag): version 10 at H, 6
at M; a short amount keeps version 10 at H. `&P=x` adds 4 characters. RFC 0003 5.14 gives version
16 at H for one `epicbox=` entry.

### 4. The mailbox pool

- **Pool**: the mailboxes of one carrier in `settings.toml`, 4 or 5 shipped defaults
  (`settings.default.toml`, `[epicbox] servers`; ADR 0030). No host is in code. The first entry
  stays the home mailbox of the classic index-0 address (ADR 0039, 0040).
- **Mailbox id**: each pool entry has an `id`, the mailbox id of section 2. For a shipped default it
  is the canonical form of the entry's host and port in the release that first shipped it, and it
  never changes: when the mailbox moves, the entry keeps its `id` and gets the new host and port. A
  mailbox the user adds takes the canonical form of what the user entered. Two spellings of one
  server (a CNAME, another port) are two mailboxes.
- **The default list is append-only.** Entries are never reordered or removed from the list the
  `p` bits index; a retired default keeps its position with no host. A release test checks that the
  ids and positions of every default ever shipped are unchanged.
- **UI** **[App]**: only Settings › Mailboxes: the list, each mailbox's health, add and remove. Help
  says that fewer mailboxes make delivery weaker. No mailbox name appears in links, payment screens or
  prompts for pool mailboxes.
- **Payer**: posts the sealed first message to 2 mailboxes chosen at random from those the link's `p`
  names, preferring ones in its own pool; to `r` and one pool mailbox when the link has `r`; to every
  shipped default when the link has neither (a bare address, or a writer without `p`). On silence
  it posts the same sealed bytes to another named mailbox (the wait is the app's, as in RFC 0003
  3.2).
- **Payee**: watches every mailbox of its pool, one connection per mailbox, through Tor when Tor is on,
  with a separate circuit per mailbox, within the budget of section 6. It answers a slate id once,
  whatever number of mailboxes it arrived on.
- **Reply**: the payer lists the mailboxes it watches in tag `09` (at most 5), by mailbox id. The payee
  posts the sealed answer to 2 of them at random, preferring those in its own pool, connecting to
  the host its pool holds for that id, or to the id itself when the id is not in its pool. A
  listed mailbox outside the payee's pool is a host from untrusted input (O-17). The payer stores
  the reply route with the payment and drains replies where that route says, whatever its
  settings say later. It finalizes on the first answer that matches its stored slate; copies are
  dropped by slate id and stage.
- **Classic index-0 address**: drained from every mailbox of the pool on unlock, on a forced refresh
  or pull-to-refresh, and every 15 minutes while the wallet runs. Stock senders post through their
  own mailbox, which does not check the destination domain (`docs/compat/epicbox.md` "Receiving a
  slate"), so a payment can wait on any mailbox; draining every pool mailbox is what makes those
  payments arrive. The pool is the user's own list, so the wallet accepts that each pool mailbox
  sees a challenge signed with the index-0 key. Mailboxes named only in links or reply routes are
  never drained with it. The interval is in the built-in configuration (ADR 0030).

### 5. Tag `09` and record `02`: the reply route

Envelope tag `09` (RFC 0003 5.6) and in-person tail record `02` (RFC 0003 5.10) carry the reply
route instead of a reply slot:

```
reply route = reply tag (10)
            ‖ count (u8, 1 to 5)
            ‖ count × ( carrier (u8) ‖ len (u8, 1 to 128) ‖ relay id )
```

The rules on where `09` and `02` are allowed and required stay as RFC 0003 5.9 and 5.10 state
them. The answer goes only to slots derived from the reply route of the slate it answers
(class `02`), never to the Epicbox `from`. A decoder refuses a count of 0 or above 5, a length of
0 or above 128, an unknown carrier and a mailbox id that is not canonical. With 5 mailboxes of 20
characters the value is 121 bytes, 68 more than a reply slot on one 20-character mailbox; the
largest S1 to an epic1 (`L` 724) stays under the 768-byte padding floor (RFC 0003 5.7).

### 6. Lifetime, budget and restore

| Slot | Watched | Drained |
|---|---|---|
| Link tag, on screen or shared | 7 days from issue or last payment, the mailbox's retention (`docs/compat/epicbox.md` "Mailbox retention") | Every cycle for its first hour; every 15 minutes until a day old; then on unlock, forced refresh and pull-to-refresh |
| Printed code | Until the user retires it | Every 15 minutes, and on unlock and refresh |
| Bare address | While the address is issued | As a printed code |
| Reply | Until the slate is finalized, cancelled or past its TTL | Every cycle, at the mailboxes of its stored route |
| Contact | The current period and the one before | Every 15 minutes, and on unlock and refresh |

- **One tag per receive session.** Every share and copy made from one receive screen reuses its
  tag; a new session draws a new one.
- **Live tags per account** are bounded (32 by default). Issuing past the bound stops watching the
  oldest unpaid tag older than a day, or refuses when none is.
- **Subscriptions per cycle** are bounded per mailbox (64 by default); slots past the bound wait
  for the next cycle, newest and replies first.
- **No reuse.** A tag is never issued twice. A printed slot (O-1) is issued to a new code only after
  its retired code has gone 7 days without a payment.
- All values above are in the built-in configuration (ADR 0030).

The payee opens a link or bare-address slot with the seal key of the address index stored with
it, as RFC 0003 5.5 states for link slots. Restore is O-1.

### 7. Paired contacts

A contact slot is class `03`. Its tag is the first 10 bytes of
`HMAC-SHA256(box_secret, "epic1-box/1 period" ‖ be32(period))`, where `period` is the Unix time
divided by the period length. `box_secret` is a 32-byte per-contact secret both sides hold, carried
in the receiver's card (O-3). The receiver watches the current and the previous period, on its home
mailbox only, or on one mailbox of its pool named in its card; never on every pool mailbox. Rotation stops
mailboxes from linking one contact's slot across periods; it does not stop anything section 11
lists. Contacts without `box_secret` keep the shipped slot on the home mailbox (RFC 0002, ADR
0047).

### 8. Delivery states

**Posts.** A post ends in one of three states, stored with the payment:

| State | When |
|---|---|
| posted | The mailbox acknowledged the frame |
| uncertain | The frame was sent and no acknowledgement came (lost connection, timeout) |
| failed | The frame was never sent (no connection, refused before sending) |

An uncertain post counts as posted for every decision that could pay twice: the wallet refuses a
second payment to the same link while one to it is unfinalized, and offers to post the same sealed
bytes again (`post-next`), which is always safe.

**Messages drained from a slot.** Each one ends in one state:

| State | When | Acknowledged |
|---|---|---|
| placed | Opened and stored, or recognised as a copy of something stored | Yes |
| held | Not placeable now: no known key opens it, its slate is not known here, or its account is locked. Another install on the same seed may place it | No; kept with a try counter and the time of the next try |
| dead | Still not placeable after the configured tries and age (at least one mailbox challenge round and the twin-install hold of RFC 0003) | Yes, after it is stored as a dead letter the app can show and export |
| refused | Not an envelope at all (fails decoding or the size rules) | Yes |

Nothing that decodes as an envelope is acknowledged on first sight unless it is placed. An answer
to a send that is cancelled, finalized or already posted is placed against that send (a copy, or a
late answer the send's state decides), never dropped as unknown.

### 9. One mailbox host, one connector

- **One type.** Every mailbox host, from a link `r`, tag `09`, record `02`, the pool or the user's
  settings, is one mailbox host type: `relay-domain` of RFC 0003 Appendix B.2, with an optional
  port, compared and derived in its canonical form (section 2). For Epicbox it follows the
  domain rule of Epicbox addresses, letters, digits and dots, because Epicbox wallets and mailboxes
  refuse any other character in an address; a carrier with a wider rule widens the type for its
  own hosts. Numeric IPv4 shorthand (`127.1`, `0x7f000001`, `2130706433`) is not a mailbox host. A
  settings value that loaded before this type keeps loading and keeps its spelling on the
  carrier's wire. The type is carried unchanged from the parser to the connector. Until it
  exists, each parser applies the same rule and runs the same mailbox host vectors (section 13).
- **One connector.** Every outbound connection (carriers, direct sends) resolves through one
  resolver and classifies the resolved address once: loopback and unspecified addresses are
  refused; local-network addresses follow RFC 0003 O-18 for hosts the user entered and are refused
  for hosts from links, envelopes and reply routes. There is one loopback predicate.
- **Errors to API clients** over TLS name the class of a connection failure, never the resolved
  address or the cause chain.

### 10. The pay page

- The page at the pay URL is static and sends `Content-Security-Policy: script-src 'none'`, or one
  script pinned by hash that never reads `location.hash` beyond handing it to the app.
- The project keeps the pay domain for as long as links that name it can exist.
- The app never fetches the page to read a link: it reads the fragment locally from a configured
  pay URL (O-4).

### 11. Rough edges

- **A link holder can delete messages on Epicbox.** Anyone with a link can derive its slot,
  subscribe, and acknowledge or wear out (three resend rounds) the queued messages. They cannot open
  the envelope or redirect the payment; they can delay it until the payer's TTL frees the coins.
  This is minor for a fresh link shown on screen or sent once. For a printed or widely shared code
  and for a bare address it lasts as long as the code. Printed codes and bare addresses ship on
  Epicbox with this limitation, and the app states it where such a code is made **[App]**. A carrier
  with non-destructive reads (Nostr) is the fix; the `box=` key tweak stays rejected (section 14).
  Period rotation does not help: it only stops mailboxes from linking across periods.
- **Pool mismatch.** A payer posts where the link's `p` says the payee watches; a payee who watches
  no shipped default depends on `r` and on retries.
- **7-day retention.** A payment older than the mailbox's retention is gone; the payer's TTL frees
  the inputs.
- **Phones watch only while the app is open.** Payments wait on the mailboxes until then.
- **One mailbox sees one wallet's slots together.** Slots watched on one connection share an
  IP address or circuit and timing, so that mailbox can group them. Different mailboxes see different
  keys.
- **Index-0 on every pool mailbox** (section 4). A pool mailbox that passes on another pool mailbox's
  challenge can subscribe there with the index-0 signature and drain the classic queue. Accepted for
  the user's own list; it is what lets stock senders' payments arrive from any mailbox.
- **Printed codes and bare addresses are linkable at the mailbox**, as RFC 0003 10.14 says for
  printed codes.

### 12. Engineering rules for this ADR's code

These hold before the first line of carrier code lands.

- **Native state in tables.** Links, tags, payments with their post state and reply route, answers,
  in-person codes, refusals and index counters live in store tables with a schema version and an
  expiry, not as JSON rows under setting prefixes. A row that fails to read is an error, never
  "absent".
- **Rules on the state, not the entry point.** The receipt cap on every arrival the user did not
  start, "finalize only the answer the user picked" for in-person codes, the caller-chosen
  `slate_id` for money-moving API calls over TLS, the host rule and the amount check are enforced
  where every path passes (the engine, or the type every path holds), so a new arrival path cannot
  skip them.
- **Delivery states, not acknowledge-or-hold.** Section 8's states, with try counters and dead
  letters, for every carrier.
- **One fact, one type.** One mailbox host type, one loopback predicate, one `Network`, one error
  kind per engine error mapped once for the CLI and the FFI (with a test that walks every
  variant), and envelope size limits computed from `lepic-seal`'s arithmetic.
- **Seed-wide identity, one issuer.** Everything keyed by an address index or a tag behaves the
  same on every install of one seed; where a counter must be per install, one install issues
  (ADR 0052 revision 7) and the others only receive.
- **Tests where the code runs.** A Linux CI job runs `cargo xtask check`, the Unix CLI tests and a
  reduced interop (two wallets, a local mailbox); the vectors of an issued label are frozen.

### 13. Vectors and fuzzing

Required before code uses each part (ADR 0033 rule 8), from `conformance/` or the pairing kit:

- **Slots**: each class, both networks, a mailbox id with and without a port, a mailbox whose id
  differs from its current host, and a counter value above `00`. The reply tag and the contact
  period tag.
- **Links**: writer output in lower case and in the upper-case QR form, `t` last; reader cases for
  case folding, percent-encoded characters, each repeated key refused, a cut tag, a cut amount
  before a whole tag, every `p` value, `r` present and absent, unknown keys ignored, `epicbox=`
  ignored, an epic1 of an unknown version refused as such, and the BIP-350 valid test string
  `11llll…ludsr8`.
- **Mailbox hosts**: one vector file run against every parser (link `r`, tag `09`, record `02`, pool
  entries, the Epicbox address domain): upper case folded, a trailing dot dropped; hyphens,
  numeric IPv4 shorthand and over-long labels refused; ports with and without the default.
- **Reply route**: encode and decode, and each refusal of section 5.
- **Envelopes**: type `0A` with and without `FE` and with a wrong Padmé length (refused), and an
  X25519 key with bit 255 set or `u ≥ p` (refused).

Fuzz targets: the link reader, the reply route decoder, the mailbox host parser, `seal_tx` and
`seal_padded` round trips, and `seal_open` with type `0A` seeds sealed to the target's own key so
the fuzzer reaches the code after decryption.

### 14. Out of scope

Multi-hop relaying and Dandelion-style hops; mixnets; mailbox lists in links; the `box=` key-tweak
link (rejected: too long); the Nostr carrier's wire detail (its own ADR).

### 15. Migration and build order

This ADR is decided as a whole (O-1 to O-4 and O-6 answered) and accepted before any of its code is
written; code for the transport model stays off `main` until then. Numbered addresses (ADR 0052
revision 7) are the identity layer under it and merge first.

The `epicbox=` link, tag `09` as a reply slot, record `02` as a reply slot and the
reply-slot, post-key and link-slot labels are built on the branch line but in no LEPIC release
(`CHANGELOG.md` "Unreleased"). If no app build that writes them has reached users, they are replaced
outright and nothing reads them; otherwise see O-2.

Placement in ADR 0052 "Steps":

| Step | Change |
|---|---|
| Before 7 | Native state tables, the mailbox host type and the single connector, delivery states (section 12) |
| 7 (payer scans the payee's I1) and 8 (epic1 address and link) | The carrier interface with the Epicbox carrier, derived slots (classes `00`, `01`, `02`), the reply route in tag `09` and record `02`, the new link and its `https` form, the pool with mailbox ids, the subscription budget, the index-0 drain |
| 9 (payer shows an S1 in person) | Uses the reply route as step 7 does |
| New, after 9 | Contacts on class `03` slots, behind a card feature claim (O-3) |
| 10 (direct endpoint) | The direct carrier; between contacts its endpoint travels inside sealed cards, never in a link |
| After 12 | The Nostr carrier, in its own ADR |

### Passages to update on acceptance

These passages describe the link-slot model the code builds today. They change with the code
of this ADR, not before. Accepted ADRs are not rewritten (ADR README): ADR 0052 gets the status
"accepted, epic1 transport rows superseded by 0054". RFC 0003, ADR 0033 (proposed) and the docs
below are edited.

RFC 0003:

- 1 "Purpose and scope", item 6: "a separate epic1 link whose transport fields say how to reach the
  payee (5.14)".
- 2 "Terms": "Carrier" (there it means chat app, e-mail…; rename, for example to "medium"),
  "Mailbox", "Transport field", "Link slot", "Reply slot".
- 3.1 table: the rows "Face to face, payee starts", "Face to face, payer starts", "Paypoint, paypoint
  starts", "Paypoint, payer starts" (throwaway reply slot), "Payment code or link, epic1",
  "Printed (static) epic1 code"; the bullets "Every in-person first code carries… throwaway reply
  slot", "The epic1 holds two keys and nothing else; the transport lives in the link", "A paypoint
  uses a slot on its own domain…".
- 3.2 table row "An epic1 send with no answer" (`epicbox=` entry → another mailbox the link names).
- 4.1 "Rollout", step 8 text. 4.4 rows "Payment link", "In person". 4.6 row "§9 card".
- 5.2 "Epicbox slot keys for payments", whole block (`reply_box_sk`, `post_sk`, `link_box_sk`,
  the two index spaces, "Restore", paypoint domain, the rule-1 paragraph); "One-time reply keys",
  last sentence; "Key separation summary".
- 5.5 "At a link slot" bullet (wording: link or bare-address slot).
- 5.6 tag `09` row. 5.7 the sentence "carries tag `09` beside `03` (56 more bytes…)" and its table.
- 5.9 bullets "Tag `09` (reply slot) is required…", "Reply mailboxes", "An answer (S2, I2) is posted
  only to the slot in tag `09`…".
- 5.10 tail record `02` row.
- 5.13 bullet "Two keys and nothing else", from "A bare epic1 with no link around it…" (a bare
  address is payable); "Decoders refuse mixed case" as it applies inside links.
- 5.14, all of "The epic1 link", "Order", "No answer", "No usable transport", "Transport only",
  "Network", "Pay parameters" (memo), "Paypoints", the mailbox-domain bullet's link part, "No expiry
  parameter. Hosts come from the link", the scope sentence of "Hosts from untrusted input" (an
  `epicbox=` entry → `r` and listed reply mailboxes), "No mixing", "Why O-1 stays dropped" items 1, 3
  and 4, "Size of the codes".
- 5.18 the reply slot in record `02` and its size rows. 6.3, all steps. 6.7 and 6.8, each
  "throwaway reply slot" and post key.
- 7.1 rows "Mailbox of a link slot", "Mailbox of a reply slot"; 7.2 the paragraph "Reply slots
  and post keys are new for every slate…" and "link slots are numbered per account".
- 9 rows "Tail records `01`… `02` reply slot", "Envelope tag `09` reply slot", "Reply slot,
  post key and link slot keys", "link-slot index spaces", "Epicbox mailbox for link and reply
  slots".
- 10 items 3, 13, 14, 15, 17, 18, 20 (`epicbox=` entry), 21 last sentence.
- 11.0 row O-14 (superseded); 11.1 "Retiring a shared link".
- Appendix A rows `reply mailbox v1`, `post key v1`, `link mailbox v1` and the exception text.
- Appendix B.2 `epic1-link`, `transport-param`, `mailbox-address`, the reader rules and "links are
  written and read in lower case, and a mixed-case epic1 is refused".

ADR 0052 (superseded rows, not rewritten): revision 4 rows "epic1 link", "Link slot", "Face to
face, online"; revision 5 rows "Link slots", "Mailbox domains" (link part); revision 6 rows "Link
slots", "epic1 send, no answer"; "Decision" 2, "Discovery" item 1 ("whose transport fields say
where to post"); "Steps" 7 ("the reply slot key under ADR 0033") and 8 ("link slot keys… two
index spaces… `epicbox=` transport fields and envelope tag `09`… the next entry… drains both
link-slot spaces").

ADR 0033: the seed-keyed rows `lepic-wallet reply mailbox v1`, `post key v1`, `link mailbox v1`;
"Recorded exception: Epicbox slot keys", its first sentence; new rows as section 2 lists.

Other docs: `docs/cli.md` "Through an epic1 link" (`epic1 link --printed --epicbox`, `epic1 restore`,
`epic1 answers` "mailbox of the reply slot", `epic1 post-next`, `pay --hosts-ok`) and its API
table (`relays` on `POST /v1/epic1/links`); `docs/api/openapi.json`, the same routes;
`docs/compat/epicbox.md` "Signatures", "the wallet's address key at its own mailbox" (index-0 drain).

## Consequences

- A link shows only the payee, a one-character pool and a 16-character tag. A new carrier or mailbox
  never changes links or addresses.
- The payee holds more connections: one per pool mailbox. The subscription budget keeps the slots
  drained per cycle bounded.
- Mailbox hosts from links are rare (`r` only); pool mailboxes need no prompt.
- A moved default mailbox keeps its mailbox id, so links and replies keep meeting.
- Links issued with `epicbox=` stop working, unless O-2 keeps a reader.
- Every derivation needs vectors before code (section 13).

## Alternatives considered

- **Transport fields in the link** (RFC 0003 5.14 as written): long codes, a new field per carrier,
  mailbox hosts as untrusted input on every payment.
- **A key tweak in the link (`box=`)**: rejected by the owner, too long. It would give printed codes
  a slot only the payee controls; section 11 states the limitation instead.
- **Mailbox lists in links**: longer codes and a host prompt per payment; the pool, `p` and `r` cover
  it.
- **The mailbox host string as the derivation input**: any change of host or port splits payer and
  payee; the stable mailbox id avoids it.
- **The payer posts to every default mailbox**: no `p` needed, but every default mailbox sees every
  payment; kept only for links without `p` and for bare addresses.
- **One slot for all mailboxes**: lets mailboxes match a payment by key, and a challenge signature
  from one mailbox would subscribe at another.
- **Draining index 0 from the home mailbox only**: payments from stock senders on other mailboxes would
  never arrive.
- **Multi-hop relaying, mixnets**: out of scope (section 14).

## Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| O-1 | How link tags are made, and restore. Random tags cannot be found again after a restore from the phrase; a printed code would stop being watched. | On-screen and shared links: 10 bytes from the OS random source, stored; lost on restore, which costs at most 7 days of unpaid links (the payer's TTL frees coins). Printed codes: the first 10 bytes of `BLAKE2b-256(key = seed, msg = "lepic-wallet link tag v1" ‖ be32(account) ‖ net ‖ be32(index) ‖ be32(n))`, `n` from 0 to 31 per address, scanned in full on restore. Alternative: all tags random, printed codes re-printed after a restore. |
| O-2 | Has any app build that writes `epicbox=` links, tag `09` or record `02` as a reply slot reached users? | If none, replace outright. If some, readers take the `epicbox=` form for one release and writers stop at once. |
| O-3 | Contact slots: where `box_secret` comes from, and the period length. | A new 32-byte card field, `Expand(root, "box secret" ‖ be32(slot))`, sent in the next contact update with a feature claim; 7-day periods. Alternative: derive it from `hint_key` (no card change, but a second use of one key). |
| O-4 | The `https` form: which hosts a reader accepts, and what the page shows. | Only the configured pay URLs. The page offers to open the app or install it, and never needs the fragment (section 10). |
| O-6 | Mailbox counts: 2 posts per payment, 5 reply mailboxes at most, 4 or 5 defaults, 32 live tags, 64 subscriptions per mailbox per cycle. | As written; values in the built-in configuration. |
