# 0052 Epic compatibility at the edge, a native protocol between LEPIC wallets

Status: accepted
Date: 2026-11-09

Builds on: ADR 0002, 0003, 0012 (RFC 0001), 0016, 0017, 0033, 0044, 0050, 0051; RFC 0002.
Specification: [RFC 0003](../rfcs/0003-epictx-native-slates.md), EPICTX / native slates (byte
detail; its section numbers are cited below).

## Decisions (the project owner, 2026-11-08)

| Item | Answer |
|---|---|
| Isolation (Decision, part 1) | Approved: rename, `legacy` feature, CI build with legacy off. |
| Rollout (Steps 6 to 12) | Approved: paired-contact mailboxes, then direct HTTP/Tor, then Epicbox payments addresses, then flip the defaults one release later. Reordered under O-12 (revision 3): contacts, then in-person QR codes and the epic1 address, then direct HTTP/Tor. The in-person work is split in revision 6 (Steps below). |
| Native slate, RFC 0001 / OD-5 (part 2) | Adopt RFC 0001 `lepic.v1` with the amendments: a TLV extension tail (BOLT 1 odd/even rules at first; the envelope's rule since O-5, revision 3); the Epic block header version in the slate header; each listener advertises its own key (the onion key on the onion, ADR 0044); a spec freeze with vectors and fuzz targets before native is on by default. |
| Native endpoint and discovery (part 2) | Advertise in the `check_version` answer and pin peers seen speaking native (trust on first use). No well-known probe, no separate port. |
| Review before native is on by default | Internal: a reviewer worker, the RFC 9180 vectors, LEPIC's own vectors and fuzz targets for slate, envelope and armour. No external review at first; under O-12 an external review of the specification comes before the codec is written. |
| Slate data format and legacy handling | `lepic.v1` aligned to grin V4 (explicit kernel-features byte, u16 header version, a TLV tail under the envelope's rule (O-5), Epic magic and version, a 1:1 JSON view for tools); self-contained replies kept; legacy handled as "Slate formats and legacy handling" below states. |

Second-page decisions: the project owner, 2026-11-08.

Third-page decisions: the project owner, 2026-11-08. These amend RFC 0001 before the freeze:

| Item | Answer |
|---|---|
| Ours vs grin | Our own format. The binary layout follows grin V4, and grin's armour code is ported with credit (NOTICE, `upstream.toml`). No age, no slatepack markers. |
| Sealing layer | One envelope: a sealed slate is an RFC 0002 envelope. RFC 0001 pack mode 1, its `epic-slate-pack/1` info string and its reply-address field are dropped; the pack stays for plain slates only. The seal code moves out of `lepic-contact` into a crate both use. |
| Seal key | A dedicated X25519 key derived under ADR 0033 (`lepic-wallet seal key v1`), separate from proof keys; no signing key is converted. Each listener advertises its own seal key; this replaces "the onion key on the onion" in the RFC 0001 amendment above. |
| Post-quantum | The suite byte is in place now. X-Wing comes later as suite `02`, once draft-ietf-hpke-pq is an RFC and the code under it has an audit, and before NIST's 2030 deprecation. |
| Padding | Padmé with a 768-byte floor (256 at first; 768 since O-6, revision 5), inside the seal, as TLV `FE` of zero bytes before the signature; receivers check the zeros. |
| Names | The EPICTX family: text markers `BEGINEPICTX.` / `ENDEPICTX.`, `.epictx` files, "transaction text" for users. Readers keep accepting `BEGINEPICSEALED.`. The codec id `lepic.v1` stays. |

EPICTX-page decisions: the project owner, 2026-11-08:

| Item | Answer |
|---|---|
| Grin-style age recipients | No. No age stanzas and no converted keys, for reading or writing. Tools get a CLI command that opens an EPICTX with the wallet's keys and prints the 1:1 JSON view. |
| Files | One extension, `.epictx`, for every step; the stage is read from inside. A reply file is named after the file it answers: the received file's stem, then `-reply`, then `.epictx`. `2d32dd23.epictx` gets the reply `2d32dd23-reply.epictx`, whatever the stem is. Text markers are `BEGINEPICTX.` / `ENDEPICTX.` for every slate; other envelope bodies (pairing, notices) keep `BEGINEPICSEALED.`. |
| The `epic1` address | It carries both keys: the payment-proof key (signs payment proofs) and the seal key (locks the message), kept apart to avoid key reuse. About 115 characters in bech32m. Two keys and nothing else: no mailbox or domain (revision 4). It is for people who are not contacts; contacts already have keys from pairing. Envelopes sealed to an address key carry a zero hint. An account has numbered epic1 addresses, index 0 first; the index is not in the address (revision 7). |
| A file to an unknown receiver | The legacy marked V3 file with a one-time reply key (RFC 0002 §5), as shipped. The reply is sealed only when the receiver is a LEPIC wallet; a stock wallet ignores the marker and answers with a plain V3 S2 as today. EPICTX files go only to receivers whose key is known, so every EPICTX file is sealed. |

User-facing choices: the project owner, 2026-11-08:

| Item | Answer |
|---|---|
| Payment link and QR | ~~The Epicbox address first and the epic1 in an extra `native=` field.~~ Replaced by the transport model (revision 3): two separate links, never mixed. |
| Receive screen | One QR code with the plain Epicbox link; "Copy address" copies the Epicbox address. The epic1 has its own code under "More", labelled for LEPIC wallets. Both means two codes (revision 3). |

Defaults 1–6 (advert seal key per listener, EPICTX replies to marked legacy files, envelope body
type, media type `application/vnd.lepic.epictx`, one fixed epic1 address per account, base64url
text): answered with the revision 2 items below, default 1 as changed by O-10 and default 2
withdrawn by O-3.

## Revision 7 (2026-11-10): numbered epic1 addresses

The project owner agreed the direction on 2026-11-10. Each item in the first table is
**[Decided]**; RFC 0003 writes them in (its sections 5.2, 5.5, 5.13 and 6.3).

| Item | Answer |
|---|---|
| Address index | An account has many epic1 addresses: numbered, per shop, per invoice, one-off. Index 0 is the address earlier builds show: its seal key and epic1 proof key derive as before. Indexes 1 and above use the labels `lepic-wallet epic1 seal key v1` and `lepic-wallet epic1 indexed proof key v1` with `be32(index)` at the end of their context (ADR 0033). The onion, web and Epicbox seal keys do not change. The address format does not change: version `01`, two keys, 115 characters, no index inside. |
| Receiving | No static hint: a hint the sender can derive from the address is the same on every message to it, so a relay, or anyone who knows the address, could pick out every payment to it. Envelopes to an epic1 keep the zero hint. A link mailbox is recorded with the address index it was issued for, and opened with that index's key. Files, transaction text and the direct listener use trial decryption over the issued indexes, the most recent payment's index first, stopping at the first key that opens; the direct listener does so only where the host switched epic1 on for that socket kind (off for the onion and the web socket by default), and otherwise answers such an envelope as one no key opens. No per-message hint either. |
| Wallet state | The highest index issued per account, and the index each payment came to. A restore tries 50 indexes past the highest one known. A restored install issues no new address until the host makes it the one that issues, so two installs on one phrase do not hand the same index to two payers; until then each payment it opens moves its window. LEPIC sets no limit on addresses; the app sets policy. |
| API | The wallet, the CLI and `serve` issue the next address, give the address at an index, and list the issued ones. A received transaction shows its index. |

Proposed with it, and **[Decided]** by the owner on 2026-11-10 as proposed (RFC 0003 11.0):

| # | Item | Answer |
|---|---|---|
| O-19 | The index on every seal key kind | The index only for the epic1 kind, every other key unchanged: the onion, web and Epicbox seal keys and pinned adverts stay as earlier builds derive them, and epic1 index 0 keeps its keys. |
| O-20 | epic1 envelopes in files and text | Opened by trial, as the receive decision lists, beside the link mailbox route of RFC 0003 6.3. |
| O-21 | Accounts tried | Every account of the wallet for a file or the direct listener; the account whose key opens receives. |
| O-22 | First address after a restore | After the gap of 50, then in order. |

## Revision 6 (2026-11-09): in-person answers, invoices, hosts, link mailboxes

The project owner decided these on 2026-11-09. Each item is **[Decided]**. RFC 0003 writes them in
(its sections 3.2 and 6.7 to 6.10).

The owner rule behind several answers: LEPIC is the core. Limits, prompts and policy live in the
consumer (the wallet app), never in LEPIC. LEPIC reports facts and acts when the consumer says
so; the specification marks the app's expected behaviour **[App]**.

| # | Answer |
|---|---|
| O-16 | Rewritten. LEPIC never finalizes an in-person answer by itself, in either direction. It closes the code on the first answer, reports every answer with its check code (four digits from `SHA-256("epic-check/1" ‖ receiver public excess)`), reports when a second answer has the same code as the first, and finalizes only when the consumer calls finalize. **[App]**, to explore in the wallet app: confirm with one tap ("Does Bob's phone show 4821?"); when two answers share a code, cancel both and show a new code with a new reply key; the hold and the late-answer warning are optional. The "no extra tap" goal is withdrawn. Check-code grinding is a known weakness (specification 6.7, 10.19). |
| O-15 | Withdrawn: the invoice window is removed. A paypoint asks for money only as "paypoint starts": the till shows its I1 and the payer scans it. No invoice is pushed to a receive code. A sticker over a printed code stays a residual risk; the merchant's domain claim (ADR 0043) is shown larger than the message (specification 6.8, 6.10, 10.21). |
| O-17 | Hosts and relays from untrusted input (a scanned code, a link, a reply record). LEPIC reports to the consumer the host, whether it is in the configured relay list and its address class (public, local network); it posts only when the consumer says so, through Tor when Tor is configured; it refuses loopback itself (a safety rule, not a policy); it never shows or decides a prompt. **[App]** The prompts are wallet policy: show an unknown relay and accept or reject it, only for relays not in the user's list; answer through Tor when available; one prompt for a local-network address. The same split applies to a changed seal key at a pinned peer (O-10), a slate too large to seal (O-9) and an epic1 send with no answer (specification 3.2, 5.14). |
| O-18 | Decided as proposed. Loopback is refused on the resolved address; a local-network address (RFC 1918, link-local, CGNAT, unique-local, `.local`) is allowed after one app prompt that shows the address; any port. The relay-domain grammar admits IPv4 literals, and Appendix B's reader rules state the host rule (specification 5.14, Appendix B). |
| Link mailboxes | Printed and on-screen codes get separate index spaces: the link mailbox context gains a `kind` byte (11 bytes). On-screen codes take a new index per receive session or share, 50 used in turn; printed codes up to 32, fixed for life. Restore scans both spaces in full (specification 5.2). |
| epic1 send, no answer | An accepted epic1 post is not final. The app shows a waiting state with "Cancel and unlock" from the start; after some minutes it asks LEPIC to post the same sealed S1 to the next `epicbox=` entry. The TTL stays 24 hours (specification 5.14). |
| Wording | This ADR: padding floor 768 everywhere; EPICTX armour for files and copy-paste only, in-person codes raw or binary in `ur:epic-slate`; one step numbering shared with the specification (Steps below). |
| Unknown relays | The unknown-relay prompt is kept, only for relays not in the user's list, and the answer goes through Tor when the user has Tor; written as the O-17 split. |
| Known weaknesses | The specification's list covers check-code grinding, hosts from untrusted input, covered sticker codes; the window race is dropped with the window. |
| Scope | The in-person work is split into four steps: (a) contacts; (b) the payer scans the payee's I1 in person; (c) epic1 links and `.epictx` files; (d) the payer shows an S1 in person, only after the check-code confirmation is designed and reviewed. O-12's order stays in front. |

Still open: the items left open after revision 5 below.

## Revision 5 (2026-11-08): answers to revision 4

The project owner, after revision 4. Each item is **[Decided]** (owner, 2026-11-08); RFC 0003 writes them in. Revision 6 changes O-15, O-16, the link-mailbox rules and the unknown-relay row.

| # | Answer |
|---|---|
| O-6 | Padding floor 768 bytes. Padding is inside the seal, so it never changes an in-person QR code: the first in-person code is raw (specification 5.7). |
| O-15 | Withdrawn in revision 6 (the invoice window is removed). Was: replaces "a second invoice needs pairing". Up to 3 invoices from non-contacts in one window reach the approval screen, each its own; from the second on the screen says "Another invoice arrived — check with the seller."; none is ever paid without the PIN; further invoices in that window are uninvited and need pairing. Contacts with "Allow invoices" keep the shipped rule (6.10). |
| O-16 | Rewritten in revision 6 (LEPIC never finalizes an in-person answer by itself). Was: the payer's wallet closes the code on the first answer and holds 5 seconds before finalizing. The check code is used only on a conflict, a second, different answer within the hold: the wallet finalizes neither, both phones show the check code (four digits from `SHA-256("epic-check/1" ‖ receiver public excess)`) and the payer picks the match. An answer after finalizing gives "Another phone answered this code". The payee's phone shows the check code after it posts. No extra tap in the normal case (6.7). |
| Link mailboxes | Replaced in revision 6 by separate index spaces (revision 6). Was: restore scans `n` with a gap of 50 past the last mailbox found holding a message, extending while hits are found (BIP 44 style). A code shown only on screen is watched 7 days (the relay's retention), then dropped; a printed code until the user retires it (5.2). |
| Default TTLs | A send to an epic1: 24 hours, 1,440 blocks. An in-person request (S1, I1): the app chooses; LEPIC falls back to 30 blocks and refuses a TTL of 10 blocks or fewer (the margin). Epic targets one block a minute (`BLOCK_TIME_SECONDS = 60`); a time is rounded up to a whole block (5.13, 5.18). |
| ADR 0033 exception | Approved: the rule-1 exception for the class "Epicbox mailbox key". Epicbox requires the mailbox key both to sign and to do ECDH, the shipped mailbox keys already do, and every slate is sealed again inside with HPKE to a dedicated X25519 key. (specification Appendix A). |
| Unknown reply relays | Kept in revision 6 as the app's prompt, with the LEPIC and app split (O-17) and the answer through Tor when the user has Tor. Was: the payee's wallet shows the relay the payer named and asks its user to accept or reject it before connecting, only when that relay is not in the user's relay list (settings); listed relays connect without asking (5.9, 10.15). |
| Relay domains | Hyphens allowed: letters, digits, dots and hyphens, no hyphen at either end of a label, in the epic1 link, tag `09` and record `02`. Only LEPIC wallets read those, so no stock wallet breaks; a stock wallet just cannot name such a relay itself. The plain Epicbox link keeps the shipped grammar (Appendix B). |

Still open after revision 5 (revision 6 keeps these): pin expiry and clearing; a real test of Stack Wallet and Epic Pay refusing epic1
links; the native-slate carrier over Epicbox payments addresses; the frame count at which an
in-person I2 offers fewer coins; how a user retires a shared link; the `lepic.v1` codec of the
Python test kit (specification 11.1).

## Revision 4 (2026-11-08): answers to revision 3, the link model and one scan

The project owner, after revision 3:

| # | Answer |
|---|---|
| O-13 | Every face-to-face and paypoint first code carries a one-time reply key, and every reply is sealed to it. |
| O-14 | Replaced by the link model below. `via=`, the relay extension with its `epic-box/1` challenge, and the third-key alternative are dropped. |
| O-15 | Withdrawn in revision 6. A paypoint may push an invoice to an address just shown, while the code is on screen and 2 minutes after. One invoice reaches an approval screen and is never paid by itself (up to 3 since revision 5). |

The link model and in-person flow, the project owner (specification 3.1, 5.13, 5.14, 6.7):

| Situation | How |
|---|---|
| epic1 address | Two keys only: the proof key and the X25519 seal key, version byte first, 115 characters. No mailbox, no domain. |
| epic1 link | Transport lives in the link, one field per method: `epic:epic1…?epicbox=<mailbox address>@<domain>&amount=5&message=…`. Fields may repeat; the sender tries them in order, at most 3. `onion=` and `nostr=` are later fields (`nostr=` a note only). |
| Link mailbox | Transport only, never shown as the payee, and may be a throwaway per link. A swapped mailbox only makes delivery fail. Paypoints use their own domain. Stock wallets refuse epic1 links. |
| Face to face, online | One scan. The payer shows S1 with the reply key and a throwaway reply mailbox (a fresh Epicbox key from the seed per payment); the receiver scans and posts the sealed S2 to that mailbox; the payer's wallet finalizes by itself. The payer confirms the amount once; the receiver answers by itself. |
| Face to face, offline | The sealed S2 as an animated QR code (6 frames). Animated codes are the private face-to-face replacement for transaction files. |
| Printed static code | Allowed. Its relay can link every payment made to its one mailbox (not on chain); codes shown on screen rotate the mailbox. Listed as a weakness. |
| Earlier answers | Unchanged: no age; `.epictx` with the no-clash rule; O-3, O-4, O-5, O-7, O-8, O-9, O-10, O-11, O-12 as in revision 3; invoices and files by who started them; the default receive code is the plain Epicbox link and the epic1 code sits under "More"; one code never mixes the two. |

Added by the specification and proposed, answered in revision 5 above:

| # | Item | Proposal |
|---|---|---|
| O-6 | Padding floor | Unchanged: recommended 768. It matters for sealed messages in mailboxes and files, where the relay sees sizes; it never changes a QR code. |
| O-15 part | A second invoice in the same window | Needs a pairing. Proposed by the specification's author, not confirmed. |
| O-16 | Two answers to one in-person code | The raw first code shows its reply key and mailbox, so an onlooker can race the real receiver. Close the code on the first answer, hold finalizing a few seconds, ask with a check code on both phones if a second answer comes, warn if one comes later. |
| ADR 0033 | Three new labels and an exception | `reply mailbox v1`, `post key v1`, `link mailbox v1` (secp256k1), and a recorded rule-1 exception for the class "Epicbox mailbox key" (specification Appendix A). |

## Revision 3 (2026-11-08): answers to revision 2, and the transport model

The project owner, 2026-11-08, on the revision 2 items:

| # | Answer |
|---|---|
| O-1 | Dropped. The transport model below puts no epic1 beside an Epicbox address in any link or code, so there is nothing to bind. Revision 3's first proposal (a signed link, `bind=`) is withdrawn with it. |
| O-2 | Keep `.epictx`, and make sure the stock kind cannot be confused with ours. Nothing on our side writes the stock kind, so nothing is renamed. Rule: LEPIC and the app write `.epictx` only as `BEGINEPICTX.` text and never into a `saved_txs` folder; readers decide by content (armour, stock hex, JSON), and a stock record is shown as "not a payment file". |
| O-3, O-4, O-5, O-7, O-11 | Accepted as proposed. O-7 holds in person by showing the native slate raw, with nothing around it; whatever only old wallets need stays in the legacy code. |
| O-6 | Not decided. Under the transport model no sealed S1 is shown as a QR code, so the floor matters only for sealed messages and files. Recommended: 768. |
| O-8 | A key of its own. |
| O-9 | Ask the user, and offer fewer coins or combining coins first. The wallet checks before it stores anything, then offers: use fewer, larger coins (a largest-first selection); combine coins first (a send to self, shipped), then pay; send unsealed where the method has a plain form; cancel. |
| O-10 | Always ask. |
| O-12 | The order in Steps below. |

The transport model, the project owner, 2026-11-08 (specification 3.1):

| Situation | How |
|---|---|
| Face to face, two phones | ~~LEPIC to LEPIC, a new native form: the `lepic.v1` S1 raw in a QR code, then the S2 raw. Two scans. No contacts assumed and no contact case for now; being there is the trust. The S1 is one code; the S2 takes 5 animated frames.~~ Replaced in revision 4: one scan online, the reply sealed. |
| Paypoint (shows codes and scans back) | Both existing flows: the payer starts (S1, S2) or the paypoint starts (I1, I2). The first code always carries a one-time reply key, and every reply is sealed to it. At most two scans (one online, revision 4). A hacked paypoint is out of scope. |
| Payment QR (scan and send) | A prefilled send over Epicbox (Epicbox's encryption in transit), or sealed to an epic1 and posted to its mailbox. Finalized later, within the TTL. |
| One code, one identity | No code serves both legacy and LEPIC. The default receive code is the plain Epicbox link, which LEPIC reads too. The epic1 is a separate code under "More". Replaces "Payment link and QR" above. |
| epic1 route | ~~The epic1 link may name its mailbox server, `epic:epic1…?via=<server>`: a route, never shown as identity. Without it, the default server from settings.~~ Replaced in revision 4 by transport fields. The host lives in the link, not in the epic1 string (kept). |
| Invoices | Who started it decides. An invoice the payer scans in person needs no pairing. An invoice pushed uninvited (Epicbox, a link) needs a pairing, as RFC 0002 §11 ships. |
| Files | Paired contact: sealed (EPICTX). Stranger, first message: plain marked legacy V3 with a one-time reply key. A LEPIC stranger's reply: sealed. Stock wallets: nothing sealed. |

Proposed in revision 3 (answered in revision 4 above):

| # | Item | Proposal |
|---|---|---|
| O-13 | Reply key in a payer's in-person S1 | The payer's phone cannot tell a friend's phone from a paypoint. Every S1 shown as a code carries a reply key, so every reply is sealed: the face-to-face S2 takes 6 frames instead of 5, and the S1 stays one code. Alternative: the user picks "Pay a terminal" first. |
| O-14 | Where epic1 mailboxes live | A stock Epicbox server holds mailboxes only for secp256k1 keys, and an epic1 has none. Proposed: an extension on servers that offer it, our relay first: mailboxes named by X25519 keys (the epic1 seal key, a payer's reply key), anonymous posts of one envelope, collection by answering a challenge sealed with its own `info` (`epic-box/1`). Alternative: a third, secp256k1 key in the epic1 (about 168 characters instead of 115). |
| O-15 | A paypoint pushing an invoice to an address the customer just showed | A short window: while the receive code is shown and two minutes after, one invoice from any sender reaches an approval screen and is never paid on its own. Alternatives: the same with a one-time code in the shown link; or not supported, the paypoint shows its own invoice code. |

## Revision 2 (2026-11-08)

Changes proposed to the EPICTX specification draft. RFC 0003 has the byte detail. Revisions 3 to 6
above record the answers.

Proposed in revision 2:

| # | Item | Proposal |
|---|---|---|
| O-1 | `native=` in links | A LEPIC payer uses it only when that epic1 is already bound to the link's Epicbox address (a contact card, or a message from that Epicbox address whose Epicbox signature verified). Otherwise it pays over Epicbox. Nothing in the link binds the two, so a genuine Epicbox address beside someone else's epic1 would otherwise pay that someone. |
| O-2 | File extension | `.epicslate` instead of `.epictx`: stock `epic-wallet` already writes `saved_txs/<uuid>.epictx` files of another kind. |
| O-3 | Default 2 | Withdrawn. The answer to a marked legacy file stays a sealed V3 S2 (envelope type `01`), and the marker gets no new field. |
| O-4 | Text markers | `BEGINEPICTX.` only for native (`0A`) slates. Sealed V3 slates keep `BEGINEPICSEALED.` and `.epicsealed`, as shipped, because older LEPIC builds read only those. |
| O-5 | Slate tail | The envelope's extension rule (`u8` type, `u16` length, below `0x80` critical) instead of BOLT 1 odd/even, so the stack has one rule. |
| O-6 | Padding floor | 768 bytes instead of 256, so every S1 has one size. |
| O-7 | Plain pack | Dropped, with `BEGINEPICSLATE.`: a native slate travels only inside an envelope. The Epicbox carrier is decided at step 8. |
| O-8 | epic1 proof key | A key of its own under ADR 0033 (`lepic-wallet epic1 proof key v1`), not index 0, which is also the previous onion (ADR 0044). One per epic1 address index since revision 7. |
| O-9 | Slate too large to seal | Refuse with a clear error and offer the plain legacy form; never fall back by itself. |
| O-10 | Default 1 | A changed seal key at a pinned address asks on every kind of address; no error from a pinned peer falls back to legacy by itself; pins are kept per sending account and origin. |
| O-11 | Defaults 3–6 | Confirm. |
| O-12 | Order | Merge and release the ADR 0051 work; the step 2 rename as its own release; external review of the specification before step 3; build step 5 only and measure; then the epic1 address and files; the direct endpoint after them. |

Applied in the specification, within the decisions:

- The slate carries a network byte, the kernel-features byte, the u16 header version (it must
  match the consensus table at the slate's height) and the tail at fixed positions; the `LOCK`
  flag bit is retired because the features byte carries the same fact. Unknown ignorable tail
  records are kept verbatim, so `encode(decode(x)) == x` holds; replies never copy them.
- The seal key's context is `be32(account) || net || kind` (epic1, onion listener, web listener).
  epic1 addresses at index 1 and above use a label of their own (revision 7).
- Envelopes sealed to an epic1 or a listener key use their own HPKE `info`; shipped envelopes keep
  theirs.
- An anonymous `0A` is taken only as an S1 or as the answer to a slate this wallet started; an
  anonymous I1 is refused.
- The advertised key is chosen by the socket that accepted the connection, never by `Host`.
- The binding size limit of a sealed slate is the 65,535-byte TLV body; `/v1/peer/slates` takes at
  most 68 KiB.
- `/v1/peer` has no feature bits in protocol 1; the marker's bits stay claims without parity.
- Every send to an epic1 sets a TTL (24 hours by default, revision 5).

## Context

The project owner asked why LEPIC keeps the `lepic-foreign` crate and Epic's names, and whether the API can
serve old Epic wallets as an isolated legacy part while everything new uses a proper protocol.

### What the wire fixes

Stock `epic-wallet` v4.1.0 is the grin-wallet 3.x design, frozen: foreign API version 2, V2 and
V3 JSON slates, no slatepack, no compact slates (`libwallet/src/slate_versions/mod.rs:33-45` at
`845b3fc`; `grep -ri slatepack` finds nothing). Exchanges deposit over HTTP(S) and users send over
Epicbox (https://devdocs.epiccash.com/integrations/exchanges/). These bytes are fixed for as long
as anyone runs it:

| Surface | Fixed on the wire | Source |
|---|---|---|
| HTTP path | `POST <base>/v2/foreign`, the sender appends `v2/foreign`; default port 3415 | epic `impls/src/adapters/http.rs:171`; LEPIC `crates/lepic-foreign/src/url.rs:12`, `server.rs:52` |
| JSON-RPC | 2.0 envelope; `check_version`, then `receive_tx` with `[slate, null, null, null]`; answers wrapped in `result.Ok` / `result.Err` | epic `http.rs:115-215`; LEPIC `rpc.rs:216-260, 389-445` |
| Version answer | `foreign_api_version` >= 2 and `supported_slate_versions` holding `"V3"` or `"V2"`. The sender reads only these two keys through `Value::get`, so extra keys in the answer are ignored | epic `http.rs:26-73` |
| Slates | V2 and V3 JSON; V2 refuses payment proofs. Unknown top-level keys are accepted and dropped on rewrite | epic `http.rs:173-186`; `docs/compat/epicbox.md` facts 2, "Ordinary sends" |
| Tor | the same HTTP body to `http://<onion>.onion/v2/foreign`, port 80; the onion is a v3 address from an ed25519 key | epic `impls/src/adapters/mod.rs:91-106`, `controller/src/command.rs:1354`; LEPIC `crates/lepic-tor/src/transport.rs:40` |
| Mining | the Epic node calls the wallet's `build_coinbase` on `/v2/foreign` | `docs/compat/foreign-api.md`; ADR 0048 |
| Epicbox | relay protocol 3.0.0 frames; `key@domain` addresses matched by an anchored pattern; secp256k1 ECDH + ChaCha20-Poly1305 message cipher; stock sends V2 and acknowledges only payloads that parse as a slate | `docs/compat/epicbox.md`; epic `impls/src/adapters/epicbox.rs:258-269` |
| File | V3 JSON (ADR 0015) | |

What the wire does not fix: crate, module and type names, the internal slate model, how the API
document groups the endpoint, and every LEPIC-to-LEPIC exchange. The engine already works on a
version-free `Slate` (ADR 0002) and the legacy codecs are frozen in `lepic_slate::codec::legacy`
(`docs/rules.md:147`). So most of the legacy shape is already at the edge; what is not:

- **Names.** "Foreign" is grin's word for "the API strangers call". It names a crate, settings,
  FFI items (75 mentions in `lepic-ffi`) and an endpoint in ADR 0050.
- **Stored ids.** The `transport` and `codec` columns hold `http`, `tor`, `epicbox`, `file`,
  `legacy-v2`, `legacy-v3` (`crates/lepic-store/src/sqlite/schema.rs:30, 58, 79, 117`). These are
  data in every installed wallet; they are never renamed.
- **LEPIC-to-LEPIC traffic still rides legacy bytes.** Between two LEPIC wallets an S1 is a V2
  JSON slate plus `"lepic":{"version":1,"f":<bits>}` (`crates/lepic-epicbox/src/marker/`); pairing
  envelopes wrap V3 JSON (RFC 0002). The native slate of RFC 0001 / ADR 0012 is specified and not
  built; OD-5 is still open.
- **No native direct protocol.** Over HTTP and Tor a LEPIC wallet talks to another LEPIC wallet
  exactly as stock does: plain V2 JSON over the legacy HTTP shape, with no sealing, schema or error
  codes of its own to build on.

### Prior art

Full notes with links are kept outside the repository.

- Grin dropped V2/V3 in 4.0.0, added V4 compact slates and slatepack, and removed HTTP(S) sending
  in 5.0.0 (grin-rfcs 0012, 0015, 0019). It kept `foreign_api_version` at 2 throughout: API shape
  and slate format are two separate version axes (grin-wallet `impls/src/adapters/tor.rs:110-170`
  at `f097811`). Grin could break compatibility because it controlled the one wallet everyone ran.
  Epic cannot: stock epic-wallet is not ours and exchanges run it.
- MWC is the precedent for this ADR: it kept V2/V3 and HTTP/MQS and added V3B and slatepack, with
  the sender taking the first of SP > V3B > V3 > V2 from `supported_slate_versions`
  (mwc-wallet `impls/src/adapters/http.rs:360-372` at `bc3b680`).
- BIP 324: try the new transport, fall back to v1, and state the downgrade risk. BOLT 9: feature
  bits where odd is optional and even is required. multistream-select: a protocol id per endpoint,
  several on one host.

## Decision

Two layers with one boundary between them.

### 1. Epic compatibility becomes a named, isolated layer

- **One name: "Epic v4 compatibility" (legacy).** Everything that exists only because stock
  `epic-wallet` speaks it moves under a `legacy` name:
  - `lepic-foreign` is renamed `lepic-legacy-rpc` (the `/v2/foreign` JSON-RPC server and client).
  - `lepic_slate::codec::legacy` becomes the crate `lepic-legacy-slate` (V2/V3 JSON, unchanged
    bytes, still frozen). The LEPIC marker codecs (`crates/lepic-epicbox/src/marker/` on `main`)
    move next to it: they exist only because legacy slates carry LEPIC facts.
  - In `lepic-methods` (ADR 0051), each of `http`, `tor` and `epicbox` has a `legacy` dialect
    module that depends on these crates, behind a cargo feature `legacy`, on by default.
- **Epic's names stay only where bytes are.** JSON-RPC method names, `foreign_api_version`,
  `supported_slate_versions`, `/v2/foreign`, V2/V3 field names: kept inside the legacy crates.
  Rust types, settings keys added from now on, FFI items added from now on and the API document
  use LEPIC's words (`payment listener`, `legacy endpoint`).
- **Stored ids and the existing FFI never change.** `http`, `tor`, `epicbox`, `file`,
  `legacy-v2`, `legacy-v3` stay as stored strings. Existing settings keys and FFI items keep
  their names; a new name is added beside an old one and the old one stays until the app drops
  it in its own release.
- **The proof of isolation is a build.** CI builds `lepic-wallet`, `lepic-methods` and the native
  crates with `legacy` off. That build has to compile and pass its tests, so nothing in the core
  can lean on a legacy shape again. The shipped builds keep `legacy` on.
- **The API document tags it.** `POST /v2/foreign` stays in the OpenAPI document (ADR 0050) under
  a `legacy` tag, described as Epic v4 compatibility with its fixed wire format.

### 2. A native protocol between LEPIC wallets

- **Native slate: RFC 0001 `lepic.v1`**, as ADR 0012 proposes (OD-5), amended as decided above:
  compact binary slate, explicit stage, self-contained replies. A sealed slate is an RFC 0002
  envelope with body type `0A` (default 3, decided), sealed to the receiver's seal key: a contact's key, an
  epic1 address's seal key or a listener's advertised key. Its text form is EPICTX
  (`BEGINEPICTX.`), for files and copy-paste only; in-person codes carry the slate raw or the
  binary envelope in `ur:epic-slate` (revision 6). One codec id `lepic.v1`, stored like the legacy ids.
- **Native direct endpoint on the payment listener**, beside `/v2/foreign`, on the same port and
  onion, in ADR 0050's style:
  - `GET /v1/peer`: what this wallet speaks, as JSON: `{"protocol":1, "formats":["lepic.v1"],
    "network":"mainnet", "key":"<seal key>"}`. The key is the seal key of the listener that
    accepted the connection (one for the onion, one for the plain web address, never the epic1
    key), chosen by socket and never by the `Host` header, so the advert does not link the onion
    to the web listener or to the payments identity.
  - `POST /v1/peer/slates`: body `application/vnd.lepic.epictx` (default 4), the binary envelope of
    type `0A` sealed to the advertised key, at most 68 KiB. `200` answers with the reply envelope,
    sealed to the sender's one-time reply key. Errors are RFC 9457 problem details with
    a closed list of codes: `not_ready` (503, `Retry-After`), `refused` (422), `too_large` (413),
    `rate_limited` (429), `unsupported_format` (415). A repeated slate returns the same reply.
  - Invoices are not taken here: an I1 needs the payer's consent, so it travels only between
    paired contacts (RFC 0002) or in a code the payer scans (specification 6.8, 6.10).
  - The body is opaque bytes in the OpenAPI document; its layout is RFC 0002's envelope around
    RFC 0001's slate. On plain HTTP the HPKE seal gives what plain `/v2/foreign` never had: a
    passive observer sees no amounts.
- **Versioning.** Two axes, as grin did: `protocol` (the endpoint's shape, path `/v1`, additive
  only, a break is `/v2`) and `formats` (slate encodings). Protocol 1 has no feature bits. If a
  later protocol adds them, they are a field of their own with BOLT 9 rules from bit 0 (odd
  optional, even required; a wallet refuses a peer that claims an even bit it does not know). The
  existing marker bits (`crates/lepic-epicbox/src/marker/features.rs`) keep their meaning as
  claims without parity.
- **Discovery, cheapest first:**
  1. *What the sender already knows.* A paired contact's card names its formats and keys. An
     epic1 address names the receiver's seal key; it arrives in its own link, whose transport
     fields say where to post (revision 4), never beside an Epicbox address as a payee. A
     listener seen speaking native is pinned per sending account and origin.
  2. *The version call it already makes.* A LEPIC listener adds
     `"lepic":{"protocol":1,"formats":["lepic.v1"],"path":"/v1/peer","seal":"<64 hex>"}` to its `check_version`
     answer. Stock senders read only their two keys (epic `http.rs:26-73`) and LEPIC's own
     decoder ignores unknown keys (`crates/lepic-foreign/src/rpc.rs:484-487`), so neither
     changes behaviour. A LEPIC sender that sees it posts to `/v1/peer/slates`; one that does not
     falls back to `receive_tx`. No extra round trip.
  3. *Epicbox.* A new marker bit `NATIVE_SLATES` (bit 7). A native slate goes to a payments address only
     when the peer claimed it and is "LEPIC lately" (ADR 0016's rule), because a stock listener
     never acknowledges a non-slate and loses its queue to one.
- **Downgrade.** On plain HTTP an attacker can strip the advert; the sender then sends legacy,
  which is today's behaviour, no worse. A peer known to speak native (rule 1) is not downgraded
  silently: a missing advert or any error from `/v1/peer/slates` stops the send and LEPIC reports it
  to the consumer, as HSTS does for HTTPS; it never retries over `/v2/foreign` by itself. A
  different seal key at a pinned address means a different wallet; the send stops and LEPIC
  reports it (O-10). The wallet app asks its user (O-17). Over Tor the onion
  authenticates the listener, so the advert cannot be stripped.
- **Where it fits ADR 0051.** The method stays how a slate travels (`http`, `tor`, `epicbox`,
  `file`); the dialect (legacy or native) is per transaction, chosen before the engine encodes,
  and recorded as the codec id already is. That needs two additive fields in the port, nothing
  else:
  - `Sending.peer: Option<PeerFormats>`, filled by `lepic-methods` from the contact record or the
    probe, before `Wallet::send`. The engine passes it to `encode_new`; the method picks
    `lepic.v1` or legacy. The S1 is stored with its bytes before delivery, as now.
  - `SenderFacts.format`, so `encode_reply` answers in the format it was asked in (it already
    answers in the shape of the S1).
  - A resend uses the stored bytes, so a transaction keeps its first format for its whole life.

### Slate formats and legacy handling (decided 2026-11-08)

Research notes are kept outside the repository. Grin V4, Beam and Tari all stopped sending the sender's
inputs in the first message and name the stage in each message; RFC 0001 already does both.
Decided: keep lepic.v1, aligned to grin V4 where RFC 0001 differs without reason
(explicit kernel-features byte, u16 block header version, a TLV tail under the envelope's rule (O-5,
revision 3; first decided as odd/even), Epic-specific
magic and version, a 1:1 JSON view for tools and the API only). Keep self-contained replies.

- Accept V2/V3 JSON on every method, marked or not, for good; `lepic.v1` once shipped.
- Emit: to stock or unknown peers, V2 on Epicbox, V2 (V3 after step 12) on HTTP/Tor, V3 in
  files; to older LEPIC builds, marked V2/V3; to native peers, `lepic.v1`. A reply uses the
  format of its request.
- Convert only at the edge: wire to `Slate` to wire, never format to format.
- Store the exact wire bytes per stage with their codec id (`slates`, schema.rs:55-61);
  no conversion at rest; `lepic.v1` is a new codec id with no migration.

### What is left behind, and when

| Item | Now | Later | Never |
|---|---|---|---|
| Receiving V2/V3 over `/v2/foreign` and Tor | | | kept: exchanges and stock users send it |
| `build_coinbase` on `/v2/foreign` | | | kept while the Epic node calls it |
| Epicbox 3.0.0 frames and the message cipher | | | kept while public relays speak it |
| Decoding V2 slates | | | kept: old wallets and files |
| "Foreign" in names, types, new settings, new FFI, the API doc | renamed (step 3) | old FFI and settings names, when the app stops using them | |
| Legacy code in the core | behind `legacy`, proven by the no-legacy build | | |
| Sending V2 S1 to an HTTP/Tor listener that offers V3 | | send V3 (it carries payment proofs and TTL), with the flip of defaults (step 12) | |
| V2 JSON as the S1 between LEPIC wallets | | native once both sides claim it | |
| LEPIC marker on legacy slates | | stays for peers on older LEPIC builds; no new fields are added to it | |
| Plain-JSON `/v2/foreign` between two LEPIC wallets | | native endpoint by default | |
| HTTP(S) send to stock listeners, grin-5.0-style | | | not removed: Epic exchanges depend on it |

### Existing installs

The rule: an installed BT Wallet keeps every address, contact, pending transaction and setting
working across the update, and keeps talking to older BT Wallet builds and to stock wallets.

- Stored `transport` and `codec` strings never change; the rename is code only.
- Saved addresses (`http(s)://`, onions including the previous onion of ADR 0044, Epicbox
  addresses) keep their form and meaning. The native endpoint sits behind the same address.
- A transaction in flight at the update finishes in the format it started in (resends use stored
  bytes; replies follow `SenderFacts`).
- Older LEPIC builds never see native bytes: they do not advertise, so they get legacy. The
  native advert is a key they already ignore.
- The FFI keeps its items; `bridge.sha256` changes only when the app adds new ones in its own
  release. The crate rename touches imports in hashed FFI files (methods spec, appendix), so it
  ships through the binding re-pin flow, or with a re-export shim named `lepic_foreign`.
- Native keys are derived from the seed under ADR 0033 namespaces, so a restore brings them back
  with no migration.
- Default off for one release: the endpoint is served and the advert sent, but senders use native
  only with `native_direct = true` in the host policy (ADR 0036) until the interop and acceptance
  runs cover it; then the default flips.

## Steps

One numbering, shared with the specification (its 4.1) since revision 6. Each step ships alone;
none changes legacy bytes (vectors, conformance, epic-wallet interop and smoke pass unchanged).
Revisions 2 to 5 above keep the step numbers of their time: the methods refactor is now step 2,
old steps 2 to 5 are steps 3 to 6, old step 6 is split into steps 7 to 9, and old steps 7 to 9
are steps 10 to 12.

1. **Decide.** OD-5 and the items of the second, third and EPICTX pages were decided on
   2026-11-08 (above), the defaults and revision 2 items with revision 3, O-13 to O-15 with
   revision 4, O-6, O-16, the TTLs, the link-mailbox rules, unknown relays, relay domains and the
   ADR 0033 exception with revision 5, and the revision 6 items, O-18 included, on 2026-11-09. Before step 6 ships, the ADR 0033 rows and the approved exception are written
   into ADR 0033. The `lepic-methods` lead keeps `Sending` and `SenderFacts` open to additive
   fields (asked 2026-11-08). No code.
2. **Methods refactor:** merge and release the ADR 0051 work.
3. **Isolate and rename**, as its own release: `lepic-foreign` → `lepic-legacy-rpc`,
   `codec::legacy` → `lepic-legacy-slate`, marker codecs beside it, `legacy` feature, CI
   no-legacy build, API `legacy` tag. Backend, one worker. Done: the no-legacy build passes, the
   bridge gate passes or is re-pinned in the binding flow, stored ids unchanged.
4. **External review, then the native slate codec** (RFC 0001 X-02): `lepic.v1` in a crate of its
   own, with the amended header and the envelope-rule tail at the specification's positions,
   vectors, fuzz target, conformance against the G-03 cases. Backend. Done: round trip of every
   vector stage, including kept unknown tail records; sizes as the specification states.
5. **Seal code and envelope type `0A`**: the seal code in a crate both use, per-class HPKE
   `info`, `FE` padding (floor 768), the too-large check, reported to the consumer (O-9).
   Backend. Done: envelope vectors, a test at the 65,535-byte body limit.
6. **(a) Native in paired-contact mailboxes.** Only LEPIC reads mailboxes, so no stock wallet
   can see it; the sealed envelope carries `lepic.v1` when both cards claim native slates.
   Backend. Done: acceptance pairing run with both formats; an older build peer gets V3 JSON.
   Then measure before going on.
   Built on `feat/native-contacts`, unmerged. Lead decisions: a wallet claims bit 7
   `NATIVE_SLATES` in its pairing only while native slates are on (`native_direct`), so that
   with them off the pairing and contact-update feature word is the one older builds write
   (every build with the codec still reads native slates whatever it sends; a contact paired
   while native was off learns the claim at the next pairing or contact update);
   `native_direct` is a `WalletConfig` value, default `false`, because the contact send path
   reads its policy there and the binding keeps it off for the release; native goes over the
   contact mailbox only, not over private pairings, and a stored slate sealed again to copy as
   text keeps type `01`. An answer
   takes its kernel excess from the participants' public excesses (the body of a native proposal
   is not carried).
7. **(b) The payer scans the payee's I1 in person**, face to face and at a paypoint ("paypoint
   starts"): a raw `lepic.v1` I1 with the reply-key and reply-mailbox tail records, the I2
   sealed and posted to the reply mailbox (one scan) or shown as animated codes offline,
   `ur:epic-slate` payload version 2, the reply mailbox key under ADR 0033, the host rule (O-17,
   O-18). No race and no invoice window. Backend, then the app; no relay change (stock Epicbox
   3.0.0 holds every mailbox). Done: a face-to-face and a paypoint run, online and offline.
8. **(c) The epic1 address and link, and `.epictx` files between contacts** (X-03): seal keys,
   the epic1 proof key and the link mailbox keys under ADR 0033 with their two index spaces
   (revision 6), the armour, `.epictx` files with the no-clash rule, the epic1 link with `epicbox=`
   transport fields and envelope tag `09`, the waiting state and the next entry. Done: key,
   mailbox and armour vectors; restore gives the same address and drains both link-mailbox
   spaces in full; a stock wallet refuses an epic1 link; a stock `saved_txs` file is shown as
   "not a payment file".
9. **(d) The payer shows an S1 in person**, face to face and at a paypoint, only after the
   check-code confirmation is designed in the app and reviewed: LEPIC closes the code on the
   first answer, reports every answer with its check code and finalizes only on the consumer's
   call (O-16). Done: two phones pay each other in one scan online and with an animated reply
   offline; two answers with the same code are reported as such.
10. **Native direct endpoint:** a wire crate `lepic-peer` (server and client, no wallet), the
    `check_version` advert, the native dialect in `lepic-methods` `http` and `tor`, the two port
    fields, OpenAPI entries. Backend, then a reviewer (several crates). Done: interop
    `http_epic_wallet_sends` and `serve_http_epic_wallet_sends` unchanged; new LEPIC-to-LEPIC runs
    over HTTP and Tor in native; a LEPIC 0.3.x peer falls back to legacy.
11. **Native over Epicbox payments addresses** when "LEPIC lately" and the bit is claimed.
    Backend. Done: acceptance with a stock listener on the same relay shows no lost queue.
12. **Flip defaults** one release later: native on between LEPIC wallets; V3 instead of V2 to
    listeners that offer V3. The app updates its wording (`Direct (legacy)` versus `Direct`).

## Consequences

- The core no longer depends on Epic's shapes; the no-legacy build keeps it that way.
- Epic compatibility is kept whole and never shrinks on the receive side; the parts that can go
  later are LEPIC's own sending choices.
- Two direct protocols live on the payment listener; its limits (ADR 0017) apply to both.
- A crate rename and a new dialect touch the FFI imports and the methods port; both are additive
  or shimmed, so ADR 0051's steps do not have to be redone.

## Alternatives considered

- **Keep the layout, document it.** No work, but "foreign" stays the core's word and nothing stops
  legacy shapes from leaking back into the engine.
- **Native only, grin 5.0-style.** Removes HTTP(S) to stock wallets. Breaks exchange deposits and
  every stock user; refused by the existing-installs rule.
- **A separate method id for native (`lepic-direct`).** The user would pick a protocol, and one
  address would need two entries. The dialect belongs to the peer, not to the user's choice.
- **Native as JSON instead of binary slates.** Readable, but the slate grows back to legacy size,
  QR and paste lose, and encryption makes the body opaque anyway.
- **A separate port for the native endpoint.** One more thing to open, publish and firewall; the
  onion would need a second port. Paths on one listener cost nothing.
- **Advert in the Epicbox address** (RFC 0001 C-B). The anchored address pattern rejects it in
  stock wallets.
