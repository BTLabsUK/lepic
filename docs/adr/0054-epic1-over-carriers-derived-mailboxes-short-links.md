# 0054 epic1 over carriers: derived mailboxes and a short link

Status: proposed
Date: 2026-11-10

Builds on: ADR 0030, 0033, 0047, 0051, 0052 (with its revision 7, numbered epic1 addresses);
RFC 0002; RFC 0003. Section numbers like "RFC 0003 5.14" refer to RFC 0003 as it stands on
`feat/epic1-indexed-keys` at `ebc09f0a`.

## Context

RFC 0003 puts the transport of an epic1 payment in the link: `epic:epic1…?epicbox=<mailbox>@<domain>`,
with up to three entries (RFC 0003 5.14). The payer's first message names a reply mailbox, an
Epicbox address on the payer's relay (envelope tag `09`, tail record `02`; RFC 0003 5.6, 5.10).
Link mailboxes come from two numbered index spaces of the seed, 50 on screen used in turn and 32
printed (RFC 0003 5.2).

That model ties each link to Epicbox and to named relays:

- A link carries a 52-character mailbox and a relay host per entry. One entry puts the code at QR
  version 16 at level H (RFC 0003 5.14, "Size of the codes").
- Relay hosts in links are hosts from untrusted input on every payment (RFC 0003 5.14, O-17).
- A second carrier (Nostr, a direct endpoint) needs a new link field and a new mailbox scheme.
- The user sees relay names in links and prompts.

The owner's goal: epic1 payments as independent of the delivery method as practical. Epicbox now,
perhaps Nostr later. Epicbox details hidden from the user. Robust, with as little linking by relays
as practical without a complex design, and few rough edges.

epic1 mode is LEPIC to LEPIC. In it the wallet pays and is paid through epic1 links, epic1
addresses and paired contacts. The classic index-0 Epicbox address is only received on, so
payments from stock wallets still reach the balance.

## Decision

### 1. Three layers

| Layer | What it holds | Names a transport |
|---|---|---|
| Identity | The epic1 address: proof key and seal key (RFC 0003 5.13), numbered per account (ADR 0052 revision 7). Contacts (RFC 0002). | No |
| Sealing | Every message is one RFC 0002 envelope, sealed and padded (RFC 0003 5.4, 5.7). The first message of a payment carries, inside the seal, a one-time reply key (tag `03`), a reply tag and the relays the payer watches (tag `09`, section 5 below). | No |
| Carriers | One interface: post an envelope to a mailbox on a relay; watch a set of mailboxes on a relay. Epicbox is the first carrier. Nostr is a later one. Direct HTTP/Tor is an extra carrier between contacts, its endpoint exchanged inside seals and never in links. | Yes, only here |

A carrier takes envelope bytes and a mailbox reference (carrier, relay, mailbox key). It knows
nothing of slates, addresses or contacts. The wallet layer derives mailboxes (section 2), picks
relays (section 4) and deduplicates what comes back. The interface lives with the methods of
ADR 0051; its Rust names are fixed in the code.

### 2. Mailboxes are derived, never listed

No link and no message names a mailbox. Both sides compute it from what they already share:

```
mailbox_in = "epic1-box/1"          11 bytes, ASCII
           ‖ net                    1  (00 mainnet, 01 floonet)
           ‖ class                  1  (below)
           ‖ key                    32 (an X25519 public key, below)
           ‖ tag                    10 (below)
           ‖ carrier                1  (01 Epicbox; 02 Nostr, reserved; others reserved)
           ‖ len(relay)             1  (1 to 128)
           ‖ relay                  len bytes, the canonical relay (below)
box_sk     = SHA-256(mailbox_in ‖ ctr)     ctr u8 from 00, the first value that gives a valid
                                           secp256k1 secret (non-zero, below the group order)
```

| class | Used for | key | tag |
|---|---|---|---|
| `00` | A link | The epic1 seal key of the address index | The link tag (section 3) |
| `01` | A bare address, no tag | The epic1 seal key of the address index | 10 zero bytes |
| `02` | A reply | The payer's one-time reply key (`reply_pk`, RFC 0003 5.2) | The reply tag |
| `03` | A paired contact | The receiver's per-contact `enc_pk` (RFC 0002 2.1) | The period tag of the contact (section 7) |

- **Canonical relay**: the host in lower case, no trailing dot, then `:port` only when the port is
  not the carrier's default (443 for Epicbox). The host follows `relay-domain` of RFC 0003
  Appendix B.2.
- **Epicbox**: `box_sk` is the mailbox's secret. Its public key with the network's version bytes is
  the Epicbox address (`docs/compat/epicbox.md` "Addresses"). It answers the relay's challenge,
  receives at the address and does the Epicbox ECDH.
- **Nostr** (later ADR): `box_sk` as a BIP-340 key; the mailbox is a filter on its public key.
- **Reply tag**: the first 10 bytes of `BLAKE2b-256(key = seed, msg = "lepic-wallet reply tag v1"
  ‖ be32(account) ‖ net ‖ slate_id)`. The context is 22 bytes. It is rebuilt from the slate id,
  as the reply key is, so a second install on the same seed can collect the reply.
- **Inputs are fixed-width except the relay, which is length-prefixed**, so ADR 0033 rule 4 holds.
  `epic1-box/1` is prefix-free with `epic-seal/1`, `epic-tx/1` and `epic-check/1` (rule 3). It is
  a hash domain, not a signature tag, so rule 2's `lepic/` prefix does not apply.
- **One mailbox per relay.** The relay is an input, so each relay sees a different mailbox key for
  the same link, and two relays cannot match their mailboxes by key. This also keeps the Epicbox
  rule that a key subscribes at one relay only (`docs/compat/epicbox.md` "Signatures"): a
  challenge signature from one relay's mailbox key is useless at another.
- Anyone who holds the inputs can compute `box_sk`. For a link that is anyone who holds the link;
  section 8 says what that allows.
- **Vectors are required** before code uses the derivation (ADR 0033 rule 8): each class, both
  networks, a relay with and without a port, and a counter value above `00`. They are not written
  with this ADR.

ADR 0033 gains, on acceptance: the hash domain `epic1-box/1` (tags table), the seed label
`lepic-wallet reply tag v1`, the label `lepic-wallet link tag v1` if O-1 is accepted, and the contact
box secret of section 7. The class "Epicbox mailbox keys" in its recorded exception covers derived
mailbox keys in place of the reply mailbox, post key and link mailbox keys.

**Post keys.** The Epicbox `from` key of a post is a fresh random secp256k1 key per post. Nothing is
received at it, so nothing needs rebuilding. A per-slate key would show two relays the same `from`
for one payment.

### 3. The link

```
epic:<epic1 address>?t=<tag>[&a=<amount>][&r=<relay>]
https://<pay host>/<pay path>#<epic1 address>?t=<tag>[&a=<amount>][&r=<relay>]
```

- **Tag**: 10 bytes, written as exactly 16 characters of the bech32 alphabet
  (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`), the bytes split into 5-bit groups, most significant first
  (80 bits, no padding). Fresh per link: a new tag per receive session, per share or copy, and per
  printed code. How the bytes are made is O-1.
- **Parsing.** A `t` that is not exactly 16 characters from the bech32 alphabet rejects the whole
  link. The address checksum does not cover the tag, so this rule is what catches a link cut or
  wrapped by a chat app. A repeated `t`, `a` or `r` rejects the link.
- **Case.** The whole link is read case-insensitively: scheme, keys, address and tag are folded to
  lower case before decoding. Text links are written in lower case. QR codes are written in upper
  case, so the address and the tag go in alphanumeric segments.
- **`a`**: the amount in EPIC, decimal, as `amount` in the shipped parser. Optional.
- **No memo.** Memos and labels travel inside the seal. `message`, `note`, `memo` and `label` in an
  epic1 link are ignored.
- **No relays**, with one exception: `r=<relay>` (one at most, `relay-domain` with optional port)
  when the payee's pool shares no relay with the shipped default list (section 4). The payer posts
  to it under the host rule (RFC 0003 5.14 "Hosts from untrusted input", O-17, O-18).
- Unknown keys are ignored. `epicbox=` is not read (O-2).
- **Bare address.** An epic1 with no `t` is payable. Its mailbox is class `01`: fixed for the
  address, the same trade-off as a printed code (section 8).
- **Clickable form** for chat apps that do not link `epic:`: the same payload after `#` of an
  `https` URL. The fragment is not sent to the server. The pay host and path come from the
  built-in configuration (ADR 0030), with `https://epiccash.btlabs.uk/pay` as the shipped value;
  no host is in code. A reader takes the fragment only from a configured pay URL (O-4).

Sizes, worked by hand from the ISO/IEC 18004 capacity tables, to be checked with an encoder: the
link without amount is 139 characters. Lower case in byte mode: QR version 12 at H, 8 at M. Upper
case in segments (alphanumeric address, byte `?T=`, alphanumeric tag): version 10 at H, 6 at M; a
short amount keeps version 10 at H. RFC 0003 5.14 gives version 16 at H for one `epicbox=` entry.

### 4. The relay pool

- **Pool**: the relays of one carrier in `settings.toml`, 4 or 5 shipped defaults
  (`settings.default.toml`, `[epicbox] servers`; ADR 0030). No host is in code. The first entry
  stays the home relay of the classic index-0 address (ADR 0039, 0040).
- **UI** **[App]**: only Settings › Relays: the list, each relay's health, add and remove. Help
  says that fewer relays make delivery weaker. No relay name appears in links, payment screens or
  prompts for pool relays.
- **Payer**: posts the sealed first message to 2 relays chosen at random from its pool, preferring
  relays on the shipped default list; to `r` and one pool relay when the link has `r`. On silence
  it posts the same sealed bytes to another pool relay (the wait is the app's, as in RFC 0003 3.2).
- **Payee**: watches every relay of its pool, one connection per relay, through Tor when Tor is on,
  with a separate circuit per relay. It answers a slate id once, whatever number of relays it
  arrived on.
- **Reply**: the payer lists the relays it watches in tag `09` (at most 5). The payee posts the
  sealed answer to 2 of them at random, preferring those in its own pool. A listed relay outside
  the payee's pool is a host from untrusted input (O-17). The payer finalizes on the first answer
  that matches its stored slate; copies are dropped by slate id and stage.
- **Classic index-0 address**: drained from every pool relay on unlock, on a forced refresh or
  pull-to-refresh, and every 15 minutes while the wallet runs. Stock senders post through their
  own relay, which does not check the destination domain (`docs/compat/epicbox.md` "Receiving a
  slate"), so a payment can wait on any relay. The interval is in the built-in configuration
  (ADR 0030).

### 5. Tag `09` and record `02`: the reply route

Envelope tag `09` (RFC 0003 5.6) and in-person tail record `02` (RFC 0003 5.10) carry the reply
route instead of a reply mailbox:

```
reply route = reply tag (10)
            ‖ count (u8, 1 to 5)
            ‖ count × ( carrier (u8) ‖ len (u8, 1 to 128) ‖ canonical relay )
```

The rules on where `09` and `02` are allowed and required stay as RFC 0003 5.9 and 5.10 state
them. The answer goes only to mailboxes derived from the reply route of the slate it answers
(class `02`), never to the Epicbox `from`. With 5 relays of 20 characters the value is 121 bytes,
68 more than a reply mailbox on one 20-character relay; the largest S1 to an epic1 (`L` 724) stays under the
768-byte padding floor (RFC 0003 5.7).

### 6. Lifetime and restore

| Mailbox | Watched |
|---|---|
| Link tag, on screen or shared | 7 days from issue or last payment, the relay's retention (`docs/compat/epicbox.md` "Relay retention"); the value is in the built-in configuration |
| Printed code | Until the user retires it |
| Bare address | While the address is issued |
| Reply | Until the slate is finalized, cancelled or past its TTL |
| Contact | The current period and the one before |

The payee opens a link or bare-address mailbox with the seal key of the address index stored with
it, as RFC 0003 5.5 states for link mailboxes. Restore is O-1.

### 7. Paired contacts

A contact mailbox is class `03`. Its tag is the first 10 bytes of
`HMAC-SHA256(box_secret, "epic1-box/1 period" ‖ be32(period))`, where `period` is the Unix time
divided by the period length. `box_secret` is a 32-byte per-contact secret both sides hold, carried
in the receiver's card (O-3). The receiver watches the current and the previous period. Rotation
stops relays from linking one contact's mailbox across periods; it does not stop anything section 8
lists. Contacts without `box_secret` keep the shipped mailbox on the home relay (RFC 0002, ADR 0047).

### 8. Rough edges

- **A link holder can delete messages on Epicbox.** Anyone with a link can derive its mailbox,
  subscribe, and acknowledge or wear out (three resend rounds) the queued messages. They cannot open
  the envelope or redirect the payment; they can delay it until the payer's TTL frees the coins.
  This is minor for a fresh link shown on screen or sent once. It is a real issue for a printed or
  widely shared code, and for a bare address. Period rotation does not help: it only stops relays
  from linking across periods. A carrier with non-destructive reads (Nostr), or a later relay change,
  is the fix.
- **Pool mismatch.** A payer whose pool shares no relay with the payee's posts where nobody reads.
  Shipped defaults overlap; a user who removes them depends on `r` and on retries.
- **7-day retention.** A payment older than the relay's retention is gone; the payer's TTL frees
  the inputs.
- **Phones watch only while the app is open.** Payments wait on the relays until then.
- **One relay sees one wallet's mailboxes together.** Mailboxes watched on one connection share an
  IP address or circuit and timing, so that relay can group them. Different relays see different
  keys.
- **Index-0 on every pool relay.** Draining the classic address from every pool relay signs that
  relay's challenge with the index-0 key at each. A pool relay that relays another pool relay's
  challenge can subscribe there and drain the classic queue (O-5).
- **Printed codes and bare addresses are linkable at the relay**, as RFC 0003 10.14 says for
  printed codes.

### 9. Out of scope

Multi-hop relaying and Dandelion-style hops; mixnets; relay lists in links; the `box=` key-tweak
link (rejected: too long); the Nostr carrier's wire detail (its own ADR).

### 10. Migration and rollout

The `epicbox=` link, tag `09` as a reply mailbox, record `02` as a reply mailbox and the
reply-mailbox, post-key and link-mailbox labels are built on the branch line but in no LEPIC release
(`CHANGELOG.md` "Unreleased"). If no app build that writes them has reached users, they are replaced
outright and nothing reads them; otherwise see O-2.

Placement in ADR 0052 "Steps":

| Step | Change |
|---|---|
| 7 (payer scans the payee's I1) and 8 (epic1 address and link) | Ship together with this ADR: the carrier interface with the Epicbox carrier, derived mailboxes (classes `00`, `01`, `02`), the reply route in tag `09` and record `02`, the new link and its `https` form, the pool, the index-0 drain. Numbered addresses (ADR 0052 revision 7, in progress on `feat/epic1-indexed-keys`) are the identity layer under it and land first. |
| 9 (payer shows an S1 in person) | Uses the reply route as step 7 does. |
| New, after 9 | Contacts on class `03` mailboxes, behind a card feature claim (O-3). |
| 10 (direct endpoint) | The direct carrier; between contacts its endpoint travels inside sealed cards, never in a link. |
| After 12 | The Nostr carrier, in its own ADR. |

### Passages to update after `feat/epic1-indexed-keys` merges

Accepted ADRs are not rewritten (ADR README). ADR 0052 gets the status "accepted, epic1 transport
rows superseded by 0054". RFC 0003, ADR 0033 (proposed) and the docs below are edited.

RFC 0003:

- 1 "Purpose and scope", item 6: "a separate epic1 link whose transport fields say how to reach the
  payee (5.14)".
- 2 "Terms": "Carrier" (now means chat app, e-mail…; rename, for example to "medium"), "Relay",
  "Transport field", "Link mailbox", "Reply mailbox".
- 3.1 table: the rows "Face to face, payee starts", "Face to face, payer starts", "Paypoint, paypoint
  starts", "Paypoint, payer starts" (throwaway reply mailbox), "Payment code or link, epic1",
  "Printed (static) epic1 code"; the bullets "Every in-person first code carries… throwaway reply
  mailbox", "The epic1 holds two keys and nothing else; the transport lives in the link", "A paypoint
  uses a mailbox on its own domain…".
- 3.2 table row "An epic1 send with no answer" (`epicbox=` entry → another pool relay).
- 4.1 "Rollout", step 8 text. 4.4 rows "Payment link", "In person". 4.6 row "§9 card".
- 5.2 "Epicbox mailbox keys for payments", whole block (`reply_box_sk`, `post_sk`, `link_box_sk`,
  the two index spaces, "Restore", paypoint domain, the rule-1 paragraph); "One-time reply keys",
  last sentence; "Key separation summary".
- 5.5 "At a link mailbox" bullet (wording: link or bare-address mailbox).
- 5.6 tag `09` row. 5.7 the sentence "carries tag `09` beside `03` (56 more bytes…)" and its table.
- 5.9 bullets "Tag `09` (reply mailbox) is required…", "Reply relays", "An answer (S2, I2) is posted
  only to the mailbox in tag `09`…".
- 5.10 tail record `02` row.
- 5.13 bullet "Two keys and nothing else", from "A bare epic1 with no link around it…" (a bare
  address is now payable); "Decoders refuse mixed case" as it applies inside links.
- 5.14, all of "The epic1 link", "Order", "No answer", "No usable transport", "Transport only",
  "Network", "Pay parameters" (memo), "Paypoints", the relay-domain bullet's link part, "No expiry
  parameter. Hosts come from the link", the scope sentence of "Hosts from untrusted input" (an
  `epicbox=` entry → `r` and listed reply relays), "No mixing", "Why O-1 stays dropped" items 1, 3
  and 4, "Size of the codes".
- 5.18 the reply mailbox in record `02` and its size rows. 6.3, all steps. 6.7 and 6.8, each
  "throwaway reply mailbox" and post key.
- 7.1 rows "Relay of a link mailbox", "Relay of a reply mailbox"; 7.2 the paragraph "Reply mailboxes
  and post keys are new for every slate…" and "link mailboxes are numbered per account".
- 9 rows "Tail records `01`… `02` reply mailbox", "Envelope tag `09` reply mailbox", "Reply mailbox,
  post key and link mailbox keys", "link-mailbox index spaces", "Epicbox relay for link and reply
  mailboxes".
- 10 items 3, 13, 14, 15, 17, 18, 20 (`epicbox=` entry), 21 last sentence.
- 11.0 row O-14 (note it is superseded); 11.1 "Retiring a shared link".
- Appendix A rows `reply mailbox v1`, `post key v1`, `link mailbox v1` and the exception text.
- Appendix B.2 `epic1-link`, `transport-param`, `mailbox-address`, the reader rules and "links are
  written and read in lower case, and a mixed-case epic1 is refused".

ADR 0052 (superseded rows, not rewritten): revision 4 rows "epic1 link", "Link mailbox", "Face to
face, online"; revision 5 rows "Link mailboxes", "Relay domains" (link part); revision 6 rows "Link
mailboxes", "epic1 send, no answer"; "Decision" 2, "Discovery" item 1 ("whose transport fields say
where to post"); "Steps" 7 ("the reply mailbox key under ADR 0033") and 8 ("link mailbox keys… two
index spaces… `epicbox=` transport fields and envelope tag `09`… the next entry… drains both
link-mailbox spaces").

ADR 0033: the seed-keyed rows `lepic-wallet reply mailbox v1`, `post key v1`, `link mailbox v1`;
"Recorded exception: Epicbox mailbox keys", its first sentence; new rows as section 2 lists.

Other docs: `docs/cli.md` "Through an epic1 link" (`epic1 link --printed --epicbox`, `epic1 restore`,
`epic1 answers` "relay of the reply mailbox", `epic1 post-next`, `pay --hosts-ok`) and its API
table (`relays` on `POST /v1/epic1/links`); `docs/api/openapi.json`, the same routes;
`docs/compat/epicbox.md` "Signatures", "the wallet's address key at its own relay" (index-0 drain).

## Consequences

- A link shows only the payee and a 16-character tag. A new carrier or relay never changes links or
  addresses.
- The payee holds more connections: one per pool relay, plus one per relay for a code on screen.
- Relay hosts from links are rare (`r` only); pool relays need no prompt.
- Links issued with `epicbox=` stop working, unless O-2 keeps a reader.
- Every derivation needs vectors before code (ADR 0033 rule 8).

## Alternatives considered

- **Transport fields in the link** (RFC 0003 5.14 as written): long codes, a new field per carrier,
  relay hosts as untrusted input on every payment.
- **A key tweak in the link (`box=`)**: rejected by the owner, too long.
- **Relay lists in links**: longer codes and a host prompt per payment; the pool and `r` cover it.
- **One mailbox for all relays**: lets relays match a payment by key, and a challenge signature
  from one relay would subscribe at another.
- **Multi-hop relaying, mixnets**: out of scope (section 9).

## Open questions for the owner

| # | Question | Recommendation |
|---|---|---|
| O-1 | How link tags are made, and restore. Random tags cannot be found again after a restore from the phrase; a printed code would stop being watched. | On-screen and shared links: 10 bytes from the OS random source, stored; lost on restore, which costs at most 7 days of unpaid links (the payer's TTL frees coins). Printed codes: the first 10 bytes of `BLAKE2b-256(key = seed, msg = "lepic-wallet link tag v1" ‖ be32(account) ‖ net ‖ be32(index) ‖ be32(n))`, `n` from 0 to 31 per address, scanned in full on restore. Alternative: all tags random, printed codes re-printed after a restore. |
| O-2 | Has any app build that writes `epicbox=` links, tag `09` or record `02` as a reply mailbox reached users? | If none, replace outright. If some, readers take the `epicbox=` form for one release and writers stop at once. |
| O-3 | Contact mailboxes: where `box_secret` comes from, and the period length. | A new 32-byte card field, `Expand(root, "box secret" ‖ be32(slot))`, sent in the next contact update with a feature claim; 7-day periods. Alternative: derive it from `hint_key` (no card change, but a second use of one key). |
| O-4 | The `https` form: which hosts a reader accepts, and what the page shows. | Only the configured pay URLs. The page offers to open the app or install it, and never needs the fragment. |
| O-5 | Draining index 0 from every pool relay lets a pool relay that forwards another relay's challenge drain the classic queue there. | Accept for the pool, which is the user's own list; drain non-home relays only, never relays from links. |
| O-6 | Relay counts: 2 posts per payment, 5 reply relays at most, 4 or 5 defaults. | As written; values in the built-in configuration. |
