# RFC 0003 EPICTX: native slates and sealing between LEPIC wallets

Status: Accepted for implementation (2026-11-09)
Date: 2026-11-09
Decision record: ADR 0052. Amends RFC 0001 (section 4 lists what it supersedes). Builds on RFC 0002's
sealed envelope.
Audience: implementers and reviewers, including those who have not seen LEPIC before.
Built so far: the sealed envelope it reuses is shipped. Nothing in section 5.10 onwards (native
slate, EPICTX text, epic1 address, advert) is built yet.

## How to read this document

Every normative statement carries one of these marks:

| Mark | Meaning |
|---|---|
| **[Decided]** | Agreed by the project owner on 2026-11-08, or on 2026-11-09 where the text says so. Recorded in ADR 0052. This includes the defaults D1–D6, the owner items O-2 … O-18 (O-15 withdrawn), and the transport model of section 3.1. |
| **[Proposed — not yet confirmed]** | Put to the project owner and not yet answered: O-19 … O-22 (11.0), on indexed epic1 addresses. |
| **[App]** | Expected behaviour of the wallet app, not a LEPIC rule. LEPIC is core only: it reports facts to its consumer and acts when the consumer calls it; limits, prompts and policy live in the consumer (3.2). Marked "to explore in the wallet app" where the design is not settled. |
| **[Shipped]** | On LEPIC `main` at commit `078eadb7`, with the path given. |
| **[Unmerged]** | On the feature branch `feat/wallet-methods` only at `c100d2bc` (the wallet methods refactor); may still move or change. |
| **[Specified]** | Written in an RFC, an ADR or this document, not built. |
| **[Reasoning]** | The author's own reasoning or arithmetic, not checked against a source or code. |
| **[Open]** | Not decided and not proposed. Listed again in section 11. |

Source documents, all in the LEPIC repository (Apache-2.0). Shipped code and accepted documents
are cited at `main` `078eadb7`. RFC 0001, RFC 0002, ADR 0012 and ADR 0044 read the same at the
feature-branch commit `c100d2bc`. ADR 0033 differs there (it adds the unreleased `api tls v1`
row), and ADRs 0050 and 0051 exist only there:

- RFC 0001 `docs/rfcs/0001-lepic-slate-v1.md` — native slate `lepic.v1`. Status: draft, not
  adopted. Several parts are superseded by the decisions here; section 4 says which.
- RFC 0002 `docs/rfcs/0002-contact-pairing.md` — contact pairing and the sealed envelope. Status:
  accepted, shipped.
- ADR 0012 `docs/adr/0012-native-slate-format.md` — proposes RFC 0001. Status: proposed.
- ADR 0033 `docs/adr/0033-key-and-domain-registry.md` — registry of seed-derived keys and tags.
  Status: proposed; the shipped labels are in code at `main`. The new labels of this
  specification are in Appendix A.
- ADR 0044 `docs/adr/0044-the-onion-has-its-own-key.md` — the onion key. Status: accepted, shipped.
- ADR 0050 (proposed) and ADR 0051 (accepted) — the wallet methods refactor and its follow-up.
  **[Unmerged]**: both exist only on `feat/wallet-methods`. They move the marker and the transport
  code this specification builds on (5.16, 9).
- ADR 0052 `docs/adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md` — "Epic
  compatibility at the edge, a native protocol between LEPIC wallets". Status: accepted. Its
  decision tables are reproduced in section 4.
- Stock wallet: `epic-wallet` v4.1.0 (EpicCash/epic-wallet on GitHub).
- Host app ("BT Wallet", Flutter) at commit `2492270c8`, for link and file naming.

Section numbers like "RFC 0002 §3.1" refer to those documents.

---

## 1 Purpose and scope

Epic Cash is a Mimblewimble chain. A payment is an interactive transaction: the sender and the
receiver exchange a "slate" in two or three rounds (S1 → S2 → finalize, or invoice I1 → I2 →
finalize) before the sender (or invoice issuer) posts it. The slate travels over one of several
methods: Epicbox (a relay protocol), direct HTTP(S) or Tor to a listener, or a file or pasted
text.

LEPIC is a Rust wallet library. It must stay byte-compatible with stock `epic-wallet` v4.1.0,
which speaks V2/V3 JSON slates over `POST /v2/foreign`, Epicbox 3.0.0 and files (ADR 0052,
"What the wire fixes").

This specification covers what LEPIC adds between LEPIC wallets:

1. A compact binary slate, `lepic.v1` (RFC 0001 as amended).
2. Sealing that slate to the receiver with HPKE, inside the RFC 0002 envelope.
3. Its text and file form, the EPICTX family (`BEGINEPICTX.`, `.epictx`).
4. A public `epic1` address that carries a payment-proof key and a seal key.
5. Discovery: an advert in the existing `check_version` answer, pinned on first use.
6. Payment codes and links: the plain Epicbox link that stock wallets read, and a separate epic1
   link whose transport fields say how to reach the payee (5.14).
7. Slates in QR codes between two LEPIC wallets in the same place: face to face and at a
   paypoint, one scan online and an animated QR code offline.

Out of scope: Mimblewimble transaction validity, the Epicbox relay protocol and its message
cipher, Tor, the pairing ceremony itself (RFC 0002 §7, shipped), invoice trust (RFC 0002 §11),
the device, and a hacked paypoint. These are named where they bound a claim.

## 2 Terms

| Term | Meaning |
|---|---|
| Slate | The partial transaction two wallets pass between them. Stages S1, S2, S3 (send) and I1, I2, I3 (invoice). |
| Legacy slate | V2 or V3 JSON as stock `epic-wallet` writes it. |
| Marked slate | A legacy V3 (or V2) slate with an extra top-level `"lepic":{…}` key that stock wallets drop (RFC 0002 §5). |
| `lepic.v1` | The native binary slate codec id (RFC 0001 §1–4). Stored like the legacy codec ids. |
| Envelope | The RFC 0002 sealed envelope: an HPKE base-mode ciphertext with a 16-byte header (RFC 0002 §3). |
| EPICTX | An envelope whose body is a slate, in its text form (`BEGINEPICTX.`) or file form (`.epictx`). "Transaction text" in the app. |
| Contact | A wallet paired through RFC 0002. Each side holds per-contact keys for the other. |
| Seal key | A dedicated X25519 key that envelopes to a non-contact are sealed to. |
| Proof key | The Ed25519 key that signs payment proofs, at BIP32 index `m/<a>/1/0`. |
| epic1 address | A bech32m string with the proof key and the seal key. |
| Epicbox address | `<52 base58 chars>[@<domain>[:<port>]]`, a secp256k1 key derived from the BIP32 key at `m/<a>/1/0` (BLAKE2b-256 of its secret, `docs/compat/epicbox.md` "Addresses"). |
| Listener | A wallet's HTTP endpoint, on a plain web address or a Tor onion. |
| Advert | LEPIC's extra key in the `check_version` answer of a listener. |
| Carrier | Whatever moves a file or text: chat app, e-mail, cloud drive, QR code. |
| Relay | An Epicbox server. |
| In person | Both wallets in the same place, passing QR codes by camera. |
| Paypoint | A shop terminal that shows QR codes and scans them back. |
| Transport field | A parameter of an epic1 link that says how to deliver to the payee, one per method: `epicbox=<mailbox address>@<domain>` now, others later. Never shown as the payee (5.14). |
| Link mailbox | The Epicbox mailbox named in an epic1 link's `epicbox=` field. Transport only; it may be a throwaway per link (5.2, 5.14). |
| Reply key | A one-time X25519 key in a first slate; every reply to that slate is sealed to it (5.2, 5.10). |
| Reply mailbox | A throwaway Epicbox address, fresh per payment, carried with the reply key; the other side posts its sealed reply there (5.2, 5.10). |
| Animated QR | A sequence of QR frames that a camera reads as one message (5.18). The private face-to-face replacement for transaction files. |
| Stock wallet | `epic-wallet` v4.1.0, the GUI built on it, Stack Wallet, Epic Pay. |
| `H(x)` | SHA-256. `HKDF` is HKDF-SHA256 (RFC 5869). `||` is concatenation. Integers are big-endian. `net` is one byte, `00` mainnet, `01` floonet (RFC 0002 "Specification"). |

## 3 Overview

Two layers with one boundary (ADR 0052 "Decision"):

- **Legacy at the edge.** Everything stock `epic-wallet` speaks stays byte for byte: `/v2/foreign`
  JSON-RPC, V2/V3 JSON, Epicbox 3.0.0, V3 files. It moves behind a `legacy` cargo feature. A CI
  build with the feature off proves the core does not depend on it.
- **Native between LEPIC wallets.** `lepic.v1` slates, sealed in RFC 0002 envelopes, over the
  same methods: paired-contact mailboxes first, then in-person codes where the payer scans the
  payee's I1, then the epic1 address and link, then the payer showing an S1, then direct HTTP/Tor,
  then Epicbox payments addresses (4.1, O-12; ADR 0052 "Steps", same numbers).

The engine works on a version-free slate model. Encoding happens at the edge, per transaction,
chosen before the slate is built. Stored slates keep their exact wire bytes and codec id. No
format-to-format conversion happens (ADR 0052 "Slate formats and legacy handling").

### 3.1 Which way a payment goes — **[Decided]** (owner, 2026-11-08; one-scan and link model after draft 3; finalizing in person and invoices from draft 6, 2026-11-09)

| Situation | What travels | Sealed | Scans |
|---|---|---|---|
| Face to face, payee starts | Bob's phone shows a `lepic.v1` I1, raw, with a one-time reply key and a throwaway reply mailbox. Alice scans it and approves with her PIN; her wallet seals the I2 to the reply key and posts it. Bob's wallet finalizes (6.7). An onlooker who films the code can only pay Bob | The reply | One online, two offline |
| Face to face, payer starts | Alice's phone shows a `lepic.v1` S1, raw, with a one-time reply key and a throwaway reply mailbox. Bob scans it; Bob's wallet seals the S2 to the reply key and posts it to that mailbox over Epicbox. Alice's LEPIC reports every answer with its check code and finalizes only the answer her app chooses (6.7) | The reply | One online, two offline |
| Paypoint, paypoint starts | The till shows an I1 with a one-time reply key and the paypoint's mailbox on its own domain. The payer scans it and approves with the PIN; the payer's wallet seals the I2 to the reply key and posts it (6.8) | The reply | One online, two offline |
| Paypoint, payer starts | The face-to-face payer-starts flow: the payer's S1 with reply key and reply mailbox; the paypoint posts the sealed S2, or shows it as an animated code offline (6.8) | The reply | One online, two offline |
| Payment code or link, Epicbox | The plain Epicbox link; the payer sends over Epicbox and finalises later, within the TTL (6.9) | Epicbox's own encryption, in transit | One |
| Payment code or link, epic1 | A separate epic1 link `epic:epic1…?epicbox=<mailbox>@<domain>&…`; the payer seals the S1 to the epic1 seal key and posts it to the link mailbox; the payee seals the S2 to the payer's reply key and posts it to the payer's reply mailbox (6.3) | Yes, both ways | One |
| Printed (static) epic1 code | As above, with a fixed link mailbox. The relay can link all payments to that mailbox (10.14) | Yes | One |
| File to a paired contact | EPICTX (`0A`) or sealed V3 (6.1) | Yes | — |
| File to a stranger, first message | Marked legacy V3 with a one-time reply key (6.4) | No | — |
| File reply from a LEPIC stranger | Sealed V3 to that reply key (6.4) | Yes | — |
| File to or from a stock wallet | Legacy V3 (6.5) | No | — |

- In person is LEPIC to LEPIC only, with no contacts assumed. A contact case is not supported for
  now.
- In person, the native slate goes in the code as it is, with nothing around it. That is how O-7
  holds: there is no plain pack, and whatever only old wallets need stays in the legacy code
  (5.10, 5.18).
- **Every in-person first code carries a one-time reply key, and every reply is sealed to it**
  (O-13). The code also carries a throwaway reply mailbox, so one scan is enough when both phones
  are online. Without a network the reply comes back as an animated QR code: animated QR is the
  private face-to-face replacement for transaction files. A hacked paypoint is out of scope (7.3).
- **LEPIC never finalizes an in-person answer by itself** (O-16 as rewritten, draft 6). Anyone in
  view can read a raw first code and answer it. LEPIC closes the code on the first answer, reports
  every answer to its consumer with its check code, and finalizes only when the consumer calls
  finalize for the answer it chose. The confirmation step ("Does Bob's phone show 4821?") is
  wallet-app behaviour **[App]** (6.7). The draft 5 goal of no extra tap is withdrawn.
- **The payer scanning the payee's code comes first.** The payee shows an I1 and the payer scans
  it: a filmed I1 can only be paid to the payee, so there is no race. It ships in rollout step 7;
  the payer showing an S1 waits for step 9, after the confirmation step is designed in the app and
  reviewed (4.1).
- **One code never serves both legacy and LEPIC.** The receive screen shows the plain Epicbox link,
  which LEPIC reads too. The epic1 has its own code under "More". A user who wants both shows two
  codes. This replaces the user-facing choice "Payment link and QR" (C1: the Epicbox address first,
  the epic1 inside as `native=`), and with it O-1's binding, because no code mixes the two (5.14).
- **The epic1 holds two keys and nothing else; the transport lives in the link** (O-14 as
  replaced). An epic1 link carries one field per delivery method, `epicbox=<mailbox>@<domain>`
  today; the field may repeat and the payer tries the entries in order. The mailbox is transport,
  never shown as the payee, and may be a throwaway per link. Everything is sealed to the epic1 seal
  key, so a swapped mailbox can only make delivery fail. Stock wallets refuse epic1 links. This
  replaces draft 3's `via=` route hint and its epic1-mailbox options (5.14).
- A paypoint uses a mailbox on its own domain. The payer's reply mailbox is a throwaway Epicbox
  address per payment, derived from the seed (5.2).
- **Invoices: who started it decides.** An invoice the payer scans in person (face to face,
  paypoint) needs no pairing. An invoice pushed uninvited (Epicbox, a link) needs a pairing with
  "Allow invoices" on (RFC 0002 §11, shipped). Files keep their shipped handling. No invoice is
  ever pushed to a receive code: draft 5's invoice window (O-15) is removed (6.10).
- The padding floor is 768 bytes (O-6). It matters for sealed messages in mailboxes and files
  (5.7). Padding is inside the seal, so it never changes an in-person code: the first in-person
  code is raw, and every sealed reply shown offline is larger than 768 bytes already.

### 3.2 LEPIC and the wallet app — **[Decided]** (owner, 2026-11-09)

LEPIC is core only. It reports facts to its consumer (the wallet app, or any other program built
on it) and acts when the consumer calls it. Limits, prompts and policy live in the consumer. LEPIC
never shows a prompt and never decides one. Where this document describes what the user sees, it
is the expected app behaviour, marked **[App]**.

| Situation | LEPIC | Wallet app **[App]** |
|---|---|---|
| Answers to an in-person code (6.7) | Closes the code on the first answer; reports every answer with its check code, and says when a second answer has the same check code as the first; finalizes only the answer the consumer names | Asks the payer to confirm the check code before finalizing; on two answers with one check code, cancels both and shows a new code with a new reply key (to explore in the wallet app) |
| A relay or host from untrusted input (5.14 "Hosts from untrusted input") | Reports the host, whether it is in the configured relay list, and its address class (public or local network); posts only when the consumer says so, through Tor when Tor is configured; refuses loopback itself, as a safety rule | Asks about relays not in the user's list and about local-network addresses, and says when the answer goes through Tor |
| A pinned peer changes its key or drops its advert (5.15) | Stops the send and reports what changed; never retries over legacy by itself | Asks the user with the plain message of 5.15 |
| A slate too large to seal (5.17) | Refuses with an error that names the choices | Offers fewer coins, combining coins first, unsealed where the method has a plain form, or cancel |
| An epic1 send with no answer (5.14 "Order") | Keeps the sent S1; posts the same sealed S1 to the next `epicbox=` entry when the consumer asks; cancels and unlocks on request | Shows a waiting state with "Cancel and unlock" from the start, and moves to the next entry after some minutes of silence |

---

## 4 Decisions log

All rows below are **[Decided]** on 2026-11-08 unless marked otherwise.

### 4.1 Architecture and rollout

| Item | Decision |
|---|---|
| Isolation | Rename the legacy crates (`lepic-foreign` → `lepic-legacy-rpc`, `codec::legacy` → `lepic-legacy-slate`), a `legacy` cargo feature on by default, a CI build with `legacy` off. Stored ids (`http`, `tor`, `epicbox`, `file`, `legacy-v2`, `legacy-v3`) never change. |
| Rollout | One step numbering, shared with ADR 0052 "Steps". O-12's order stays in front, and the in-person work is split into steps 7 to 9 (owner, 2026-11-09). Step 1: decide (no code). Step 2: merge and release the methods refactor (ADR 0051). Step 3: the crate rename as its own release. Step 4: an external review of this specification, then the `lepic.v1` codec. Step 5: the seal code and envelope type `0A`. Step 6: (a) native in paired-contact mailboxes, measured before going on. Step 7: (b) in person, the payer scans the payee's I1 (face to face and at a paypoint): no race and no invoice window. Step 8: (c) the epic1 address and its link, and `.epictx` files between contacts. Step 9: (d) the payer shows an S1 in person (face to face and at a paypoint), only after the check-code confirmation is designed in the app and reviewed. Step 10: direct HTTP/Tor endpoint. Step 11: Epicbox payments addresses. Step 12: flip the defaults one release later. Native sending is off by default for one release (`native_direct = true` host policy to enable). |
| Native slate | Adopt RFC 0001 `lepic.v1` with amendments: an extension tail (O-5: the envelope's TLV rule, replacing the BOLT 1 odd/even rule decided first); the Epic block header version in the slate header; each listener advertises its own key; a spec freeze with vectors and fuzz targets before native is on by default (5.10). |
| Discovery | An advert in the `check_version` answer, and pinning of peers seen speaking native (trust on first use). No well-known probe, no separate port. |
| Review before default-on | Internal review (a reviewer, RFC 9180 vectors, LEPIC vectors, fuzz targets for slate, envelope and armour), and an external review of this specification before the codec is written (O-12). |
| Data format | `lepic.v1` aligned to grin V4: an explicit kernel-features byte, a u16 header version, a TLV tail (the envelope's rule, O-5), Epic magic and version, a 1:1 JSON view for tools. Replies stay self-contained. Draft 2 adds a network byte and fixes every position (5.10). |

### 4.2 Legacy handling (ADR 0052 "Slate formats and legacy handling")

| Item | Decision |
|---|---|
| Accept | V2/V3 JSON on every method, marked or not, permanently. `lepic.v1` once shipped. |
| Emit | To stock or unknown peers: V2 on Epicbox, V2 on HTTP/Tor (V3 from step 12, the flip of defaults), V3 in files. To older LEPIC builds: marked V2/V3. To native peers: `lepic.v1`. A reply uses the format of its request. |
| Convert | Only at the edge: wire → slate model → wire. Never format to format. |
| Store | Exact wire bytes per stage with their codec id. No conversion at rest. `lepic.v1` is a new codec id with no migration. |
| Left behind | Nothing on the receive side is ever removed: `/v2/foreign` V2/V3, `build_coinbase`, Epicbox 3.0.0, V2 decoding. HTTP(S) send to stock listeners stays (exchanges depend on it). |

### 4.3 Cryptography and format

| Item | Decision |
|---|---|
| Ours vs grin | Our own format. The binary layout follows grin V4. Grin's armour code is ported with credit. No age, no slatepack markers. |
| One envelope | A sealed slate is an RFC 0002 envelope. RFC 0001 pack mode 1, its `epic-slate-pack/1` info string and its reply-address field are dropped. The RFC 0001 pack is dropped as well (O-7): a native slate travels inside an envelope, or raw in an in-person QR code with nothing around it (3.1, 5.18). The seal code moves out of `lepic-contact` into a crate both use. Draft 2 gives the two new key classes their own HPKE `info` inside the same envelope (5.4). |
| Seal key | A dedicated X25519 key, ADR 0033 label `lepic-wallet seal key v1`, separate from proof keys. No signing key is converted to X25519. Each listener advertises its own seal key. |
| Post-quantum | The suite byte exists now. X-Wing comes later as suite `02`, once draft-ietf-hpke-pq is an RFC and the code under it has an audit, and before NIST's 2030 deprecation of classical ECC. |
| Padding | Padmé with a 768-byte floor (O-6, owner after draft 4; was 256), inside the seal, as TLV `FE` of zero bytes before the signature (`FF`). Receivers check the zeros. Under the transport model it matters only for sealed messages and files; it never changes a QR code (5.7). |
| Names | The EPICTX family: markers `BEGINEPICTX.` / `ENDEPICTX.`, `.epictx` files, "transaction text" for users. Readers keep accepting `BEGINEPICSEALED.`. The codec id `lepic.v1` stays. `.epictx` is kept (O-2) with the no-clash rule of 5.12. |
| age recipients | No. No age stanzas and no converted keys, for reading or writing. Tools get a CLI command that opens an EPICTX with the wallet's keys and prints the 1:1 JSON view. |

### 4.4 Files, addresses, links

| Item | Decision |
|---|---|
| File extension | One extension, `.epictx`, for every stage. The stage is read from inside. Stock `epic-wallet` already writes `.epictx` files of another kind; the owner kept the extension (O-2) and asked for a rule that keeps the two apart (5.12). |
| Reply file name | The received file's stem, then `-reply`, then `.epictx`: `2d32dd23.epictx` → `2d32dd23-reply.epictx`, whatever the stem. |
| Text markers | `BEGINEPICTX.` / `ENDEPICTX.` for native (`0A`) slates only (O-4; first decided for every slate). Sealed V3 slates, to contacts and as answers to marked legacy files, keep `BEGINEPICSEALED.` and `.epicsealed` as shipped, because older LEPIC builds read only that. Other envelope bodies (pairing, notices) keep `BEGINEPICSEALED.` (5.11). |
| epic1 address | Carries both keys: the proof key and the seal key, kept apart to avoid key reuse. About 115 characters in bech32m. For people who are not contacts; contacts have keys from pairing. Envelopes sealed to an address key carry a zero hint. The proof key is an epic1 key of its own, not the index-0 key (O-8, 5.2). An account has many epic1 addresses, numbered from 0; the number is not in the address (5.13). Two keys only: no mailbox key and no domain inside (O-14 as replaced). Shown as its own code and link, never inside an Epicbox link (3.1, 5.14). |
| Unknown receiver | A legacy marked V3 file with a one-time reply key (RFC 0002 §5), as shipped. The reply is sealed only when the receiver is a LEPIC wallet. A stock wallet ignores the marker and answers with a plain V3 S2. EPICTX files go only to receivers whose key is known, so every EPICTX file is sealed. |
| Payment link | Two separate links, never mixed (3.1): the app's plain `epic:<epicbox address>?…` link, which stock wallets read, and an epic1 link `epic:epic1…?epicbox=<mailbox>@<domain>&…` for LEPIC wallets, whose transport fields (one per method, repeatable, at most 3 used) say how to deliver. No expiry in links. Hosts come from the link, never from code. RFC 0001 §9's card form, the first decision's `native=` parameter, draft 3's first proposal `bind=` (O-1), draft 3's `via=` route hint and its epic1-mailbox options are all dropped (5.14). |
| Receive screen | One QR code with the plain Epicbox link. "Copy address" copies the Epicbox address. The epic1 has its own code and copy button under "More", labelled for LEPIC wallets. Both means two codes. Replaces C1 (3.1). |
| In person | LEPIC to LEPIC. The first code is a raw `lepic.v1` slate with a one-time reply key and a throwaway reply mailbox (O-13); the reply is sealed to the reply key, posted to the mailbox online (one scan) or shown as an animated code offline (two scans). Face to face and paypoint use the same codes (3.1, 5.18, 6.7, 6.8). |

### 4.5 Defaults D1–D6 — **[Decided]** (2026-11-08, after draft 2: D1 as revised by O-10, D2 withdrawn by O-3, D3–D6 by O-11)

| # | Default |
|---|---|
| D1 Advert | A `seal` key (64 hex) next to the formats in the `lepic` key of the `check_version` answer. One seal key per listening address (onion, plain web) and account, never the epic1 seal key, derived from the seed (5.2). The key is chosen by the socket that accepted the connection, never by the `Host` header (5.15). Pinned on first use, keyed on the normalised origin and the sending account. A different key later means a different wallet or account, on every kind of address: LEPIC stops and reports, and the app asks the user, always (O-10, 3.2; draft 1 accepted a change silently over an onion or HTTPS). No error from a pinned-native peer falls back to legacy unless the consumer calls the legacy send. |
| D2 Replies to marked legacy files | **Withdrawn (O-3).** Draft 1: the marker of a legacy file also lists `lepic.v1` and a LEPIC receiver answers with a `lepic.v1` body. Draft 2 keeps the shipped answer (a sealed V3 S2, envelope type `01`) and the marker frozen (6.4). |
| D3 Envelope body type | `0A`, fixed in the vectors (5.6). |
| D4 Media type | `application/vnd.lepic.epictx`. |
| D5 epic1 per account | Numbered epic1 addresses per account and network, derived from the seed; index 0 is the account's first address (5.2, 5.13). |
| D6 Alphabet | base64url, as `BEGINEPICSEALED.` today. base58 only if the chat paste test (11.2) shows breakage. |

### 4.6 What these decisions supersede in RFC 0001

| RFC 0001 text | Now |
|---|---|
| D1 K-A: the address is the proof key alone; K-C (both keys) rejected as "about 115 characters, too long" | epic1 carries both keys (4.4). The proof key is an epic1 key of its own, not index 0 (O-8). |
| D4 E-B: the proof key converted to X25519 decrypts packs (§"Security and privacy", "Key reuse") | Dedicated seal key; no conversion (4.3). |
| §5 pack, both modes, and §6 HPKE with `epic-slate-pack/1` | Dropped; the RFC 0002 envelope seals (4.3, O-7). |
| §7 armour `BEGINEPICSLATE.`, base58 | Dropped (O-7). EPICTX markers for native slates; base64url (D6). |
| §8 address version `00` = one key | Two-key layout, version `01` (5.13). |
| §9 card `epic:<native>?epicbox=…` | Two separate links, `epic:<epicbox>?…` and `epic:epic1…?epicbox=<mailbox>@<domain>…` (4.4, 5.14). The `epicbox=` field survives, with another meaning: in RFC 0001 it named the payee's Epicbox address beside the native one; here it names a mailbox that is transport only and never an identity. |
| §10 capability record learned from a pack's reply address, bound by the Epicbox relay signature | Not needed: no code carries an epic1 beside an Epicbox address (3.1, 5.14); an advert key is pinned per origin (5.15). |
| No header version, no network byte, no TLV tail; trailing bytes rejected (§2, §4) | Network byte, kernel-features byte, u16 header version and an extension tail (envelope TLV rule) at fixed positions; the `LOCK` flag bit is retired (5.10). |
| §4 `encode(decode(x)) == x` | Kept, with the rules that make it hold for the tail (5.10). |

---

## 5 Wire and format detail

### 5.1 Conventions

From RFC 0002 "Specification" and RFC 0001 §1. Integers unsigned big-endian. ASCII strings in
quotes have no terminator. `HKDF-Expand(prk, info, L)` uses its first argument directly as PRK.
Commitments and secp256k1 public keys are 33-byte compressed points; Schnorr signatures 64 bytes;
Ed25519 keys 32 bytes, signatures 64 bytes; a range proof is 675 bytes.

### 5.2 Keys and derivation

**Funds and index-0 keys** — **[Shipped]**, upstream-defined (ADR 0033 "BIP32 paths"):

- `m/<a>/1/0` (secp256k1; the address secret is BLAKE2b-256 of the BIP32 secret at that path,
  `docs/compat/epicbox.md` "Addresses"). Its public key is the Epicbox address. The same secret bytes are the
  Ed25519 seed of the **proof key**. This index also serves Epicbox ECDH and the relay challenge
  signature. It is ADR 0033's recorded exception to "one key per purpose", kept for stock
  compatibility (ADR 0033 "Recorded exception: index 0"; ADR 0012 decision table, D1).

**ADR 0033 namespace keys** — **[Shipped]** construction (ADR 0033 "The namespace"):

```
k = BLAKE2b-256(key = seed, msg = "lepic-wallet <purpose> v<n>" || context)
```

- `seed` is the BIP39 entropy. A 32-byte result is an Ed25519 seed or an X25519 secret directly.
- Rule 1: a key that signs never encrypts or does ECDH. Rule 4: no label is a prefix of another
  label followed by its context; contexts are fixed-width or length-prefixed. Rule 8: every entry
  has a vector under `testdata/vectors/keys/`.
- Existing namespace keys: `lepic-wallet onion key v1` (Ed25519, the onion and the proof key
  for slates that arrive over the onion, ADR 0044; empty context), `device link key v1`,
  `seed check v1`, `peer tag v1`, store keys, `listing key v1`. `api tls v1` is **[Unmerged]**.

**Seal keys** — **[Decided]** label; context **[Specified]** here (draft 2):

```
seal_sk = BLAKE2b-256(key = seed, msg = "lepic-wallet seal key v1" || be32(account) || net || kind)   (X25519)
seal_pk = X25519(seal_sk, 9)
```

- `kind` (u8): `00` the epic1 address, `01` the onion listener, `02` the plain web listener, `03`
  the Epicbox payments address (5.15) **[Specified]**. Other values are reserved. The context is
  fixed-width (6 bytes), so ADR 0033 rule 4 holds. This key is the same in every build: the
  address index (5.13) is not in it (O-19).
- `net` is in the context so that one seed shows different seal keys on mainnet and floonet, as
  the contact root does (`info = "root" || net`). **[Reasoning]** HPKE `info` already separates the
  networks cryptographically; the byte is there for unlinkability across networks.
- The 32-byte output is used as the X25519 secret; X25519 clamps it (RFC 7748). Keyed BLAKE2b-256
  as a PRF is the shipped ADR 0033 construction.
- One listener seal key per listener kind, account and network (D1). The listener that accepted a
  connection decides which key is advertised and used (5.15).
- One Epicbox seal key per account and network. It is separate from the epic1 seal key (`00`),
  so a peer that holds both keys cannot tell that a payments address and an epic1 belong to one
  wallet.
- Vectors under `testdata/vectors/keys/` (rule 8) before any code uses the key.

**epic1 seal key at an address index** — context **[Specified]** (O-19):

```
index 0:   epic1_seal_sk = seal_sk with kind 00 (above)
index ≥ 1: epic1_seal_sk = BLAKE2b-256(key = seed, msg = "lepic-wallet epic1 seal key v1" || be32(account) || net || be32(index))   (X25519)
```

- `index` (u32) is the number of the epic1 address within the account (5.13). Index 0 is the
  account's first address and keeps the kind-`00` seal key of earlier builds, so that address
  does not change. The context of the new label is fixed-width (9 bytes); neither label is a
  prefix of the other followed by its context, so ADR 0033 rule 4 holds.
- One epic1 seal key per address index, account and network (D5).
- Vectors: `pairing/epic1_seal_keys.json` (indexes 0, 1, 2 and 2³²−1; index 0 equals the
  kind-`00` key in `pairing/seal_keys.json`).

**epic1 proof key** — **[Decided]** (O-8, 2026-11-08); context **[Specified]**:

```
index 0:   proof_sk = BLAKE2b-256(key = seed, msg = "lepic-wallet epic1 proof key v1" || be32(account) || net)   (Ed25519 seed)
index ≥ 1: proof_sk = BLAKE2b-256(key = seed, msg = "lepic-wallet epic1 indexed proof key v1" || be32(account) || net || be32(index))   (Ed25519 seed)
```

- `index` is the epic1 address index, as in the epic1 seal key. Index 0 keeps the key of earlier
  builds. The contexts are fixed-width (5 and 9 bytes).
- Signs the receiver's payment proof for a slate that came to the epic1 address `index`, the
  rule ADR 0044 set for the onion: "a proof is signed with the key of the address the slate came
  to". A slate that came to an epic1 address and asks for a proof to another key, including the
  proof key of another index, is refused with `ForeignProofAddress`.
- Reason: the index-0 Ed25519 key is also the previous onion that the GUI wallet, stock
  `epic-wallet` and LEPIC up to 0.3.1 published (ADR 0044). Putting it in epic1 would link that
  onion to the epic1 and, through the payment link, to the Epicbox address: the link ADR 0044
  removed. A key of its own removes the last new public use of index 0.
- The sender's own proof address in a proof stays the payment-proof key at index 0 (ADR 0044,
  unchanged). **[Reasoning]** The receiver learns it, as with every proof today.
- Vectors: `keys/epic1_proof_key_seed32`, `keys/epic1_proof_key_seed16` (index 0) and
  `keys/epic1_indexed_proof_key_seed32`, `keys/epic1_indexed_proof_key_seed16` (indexes 1, 2 and
  2³²−1).

**Epicbox mailbox keys for payments** — **[Decided]** use (owner, after draft 3: a throwaway reply
mailbox per payment, transport in the link); labels and contexts **[Specified]** (draft 4,
Appendix A):

```
reply_box_sk = BLAKE2b-256(key = seed, msg = "lepic-wallet reply mailbox v1" || be32(account) || net || slate_id || ctr)    secp256k1
post_sk      = BLAKE2b-256(key = seed, msg = "lepic-wallet post key v1"      || be32(account) || net || slate_id || role || ctr)   secp256k1
link_box_sk  = BLAKE2b-256(key = seed, msg = "lepic-wallet link mailbox v1"  || be32(account) || net || kind || be32(n) || ctr)   secp256k1
```

- Each is an ordinary Epicbox address: the 33-byte compressed public key with the network's
  version bytes, base58check (`docs/compat/epicbox.md` "Addresses"). `ctr` is a u8 from `00`; the
  first value that gives a valid secp256k1 secret is used, as for `box_sk` and the listing key.
  `slate_id` is the 16-byte slate id; `role` is `00` for the party that started the slate and `01`
  for the party that answers it. `kind` is `00` for a code shown on screen and `01` for a printed
  code (draft 6). Contexts are fixed-width (22, 23 and 11 bytes), so rule 4 holds.
- **Reply mailbox** (`reply_box_sk`): the payer's (or invoice issuer's) throwaway mailbox for one
  payment. Its address goes with the reply key in the first slate (tail record `02` raw, envelope
  tag `09` sealed; 5.6, 5.10). Like the reply key it is rebuilt from the slate id, so nothing new
  is stored and a second install on the same seed that holds the slate can drain it.
- **Post key** (`post_sk`): the Epicbox `from` key of every post to another party's mailbox (an S1
  to a link mailbox, an S2 or I2 to a reply mailbox), one per slate and role. It plays the part of
  RFC 0002's `pfrom_sk` for pairing mailboxes: the relay checks a signature, so a post needs some
  key, and a fresh one ties no Epicbox address of the poster to the payment. Nothing is ever
  received at it.
- **Link mailbox** (`link_box_sk`): the mailbox an epic1 link names in `epicbox=` (5.14).
  **[Decided]** (owner, 2026-11-09); detail **[Specified]** (draft 6).
  Printed and on-screen codes have their own index spaces, told apart by `kind`:
  - *On screen* (`kind` `00`): a new `n` per receive session, and per share or copy of the link;
    showing the same session again, or drawing it again, keeps its `n`. `n` runs `0 … 49` and then
    wraps to `0`, so the watched set is capped at 50 mailboxes. The wallet drains each one used in
    the last 7 days, the relay's retention (`docs/compat/epicbox.md` "Relay retention"); only the
    one on screen is live (10.18).
  - *Printed* (`kind` `01`): one `n` for the code's life, `n` in `0 … 31`. A printed code is
    watched until the user retires it (how a user retires one is **[Open]**, 11.1). A 33rd printed
    code needs one retired first.
  - The wallet stores every `n` it issued.
- Restore **[Specified]** (draft 6): after a restore from the phrase the wallet drains all 50
  on-screen and all 32 printed link mailboxes. Both spaces are small and scanned in full, so
  nothing the relay still holds is missed. This replaces draft 5's gap of 50 over one shared
  space, which lost a printed code with no recent payment once more than 50 on-screen codes came
  after it (10.17). **[Reasoning]** With a ring, an on-screen mailbox is used again after 50
  sessions; the relay can link those two sessions (10.14).
- A link mailbox is never the index-0 key (the derivations differ), so a link never names the
  wallet's Epicbox payments address and does not tie the epic1 to it.
- A paypoint may name a mailbox on its own domain, derived the same way; the domain is
  configuration, not part of the key.
- ADR 0033 rule 1 ("a key that signs never encrypts or does ECDH"): an Epicbox mailbox key must
  sign the relay's challenge, `Made` and `PostSlate`, and the Epicbox message cipher does ECDH with
  it. The shipped mailbox keys (`box_sk`, the pairing mailbox, the listing key) already do both;
  only the listing key has a recorded exception (ADR 0033 "Recorded exception: the listing key").
  **[Decided]** (owner, 2026-11-08) one recorded exception for the class "Epicbox mailbox key". Reason:
  Epicbox requires the mailbox key both to sign and to do ECDH, the shipped mailbox keys already
  do both, and every slate it carries is sealed again inside with HPKE to a dedicated X25519 key.
  Its ECDH output goes only into Epicbox's own message cipher and its signatures only over Epicbox
  texts. The text to write into ADR 0033 is in Appendix A.

**Contact keys** — **[Shipped]** (RFC 0002 §2.1–2.2), `lepic-wallet-contacts`:

```
id   = m/<a>/2/0
raw  = derive_key(0, id, SwitchCommitment::None)
root = HKDF(salt = "epic-contact/1", ikm = BLAKE2b-256(raw), info = "root" || net)     32 bytes
enc_sk   = HKDF-Expand(root, "enc"  || be32(slot), 32)                  X25519
sig_sk   = HKDF-Expand(root, "sig"  || be32(slot), 32)                  Ed25519 seed
hint_key = HKDF-Expand(root, "hint" || be32(slot), 32)
box_sk   = HKDF-Expand(root, "box"  || be32(slot) || box_salt || ctr, 32)   secp256k1, first valid ctr
```

`slot` is a u32 per pairing, below 65,536 for wallets; `box_salt` is 16 random bytes per pairing.
Vector: `testdata/vectors/pairing/contact_keys.json`.

**One-time reply keys** — **[Shipped]** (RFC 0002 §2.3), `crates/lepic-wallet-contacts/src/key_schedule.rs:243`:

```
reply_sk = HKDF-Expand(root, "reply" || slate_id, 32)     X25519, slate_id = 16 bytes
```

Nothing is stored; the key is rebuilt from the slate id. A second install on the same seed can
open the answer. The same keys serve the reply key of every in-person first code (tail record
`01`, 5.10, O-13) and of an S1 sent to an epic1 (envelope tag `03`) **[Specified]**. Vector
(shipped): `testdata/vectors/pairing/reply_keys.json`. The reply mailbox that travels with the key is a
secp256k1 key of its own (above): an Epicbox address cannot be an X25519 key.

**Key separation summary** — **[Reasoning]** from the rows above: proof keys sign only; seal keys
decrypt only; contact keys are per pairing; reply keys, reply mailboxes and post keys are per
slate; link mailboxes are per link. Epicbox mailbox keys sign and do ECDH inside the Epicbox
protocol only (the exception above). The one shared secret is index 0 (Epicbox address, Epicbox
ECDH, the payment-proof key, the previous onion), inherited from stock. No new protocol in this
document publishes or uses index 0 (O-8).

### 5.3 Envelope layout, byte by byte — **[Shipped]** (RFC 0002 §3.1), `crates/lepic-contact/src/envelope.rs`

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `89 45 53 45` |
| 4 | 1 | version | `01` |
| 5 | 1 | network | `net` (`00` mainnet, `01` floonet) |
| 6 | 1 | suite | `01` base or `41` PSK (see 5.4 for the registry) |
| 7 | 1 | flags | `00`; any other value is rejected |
| 8 | 8 | hint | 5.5 |
| 16 | `Nenc(suite)` | enc | HPKE encapsulated key; 32 bytes for suites `01` and `41` |
| 16 + `Nenc` | n + 16 | ciphertext | inner content (5.6) and the 16-byte AEAD tag |

- AAD = bytes 0–15 (magic to hint).
- Whole envelope at most 1 MiB (`MAX_ENVELOPE_LEN`, `envelope.rs:31`). The binding limit for a
  slate envelope is lower: 5.17.
- **[Specified]** `Nenc` is a function of the suite. The shipped decoder splits 32 bytes before it
  checks the suite (`envelope.rs`, `ENC_LEN`); that is correct for `01` and `41` and must change
  before suite `02` exists: read the suite byte, look up `Nenc`, then split.
- Decoding rejects truncation, trailing bytes, an unknown version, suite or flag, and the other
  network, before any allocation larger than the input.
- Opening failure is one typed error that does not say which step failed.

### 5.4 HPKE — **[Shipped]** for suites `01` and `41`; new `info` **[Specified]** (draft 2)

- RFC 9180, single-shot. Mode base (`SealBase` / `OpenBase`) for every envelope except private
  pairing, which uses mode PSK (`epic-private/1`, `crates/lepic-contact/src/private.rs`). Auth and
  AuthPSK modes are not used.
- Suite registry (envelope byte 6):

| Byte | Mode | KEM | KDF | AEAD | `Nenc` | Status |
|---|---|---|---|---|---|---|
| `01` | base | `0x0020` DHKEM(X25519, HKDF-SHA256) | `0x0001` HKDF-SHA256 | `0x0003` ChaCha20-Poly1305 | 32 | **[Shipped]** |
| `41` | PSK, `psk_id = "epic-private/1"` | as `01` | as `01` | as `01` | 32 | **[Shipped]** (`SUITE_PSK`, `private.rs:31`) |
| `02` | base | `0x647a` X-Wing (ML-KEM-768 + X25519) | `0x0001` | `0x0003` | 1,120 | **[Decided]** as a slot, not specified |
| `42` | PSK | as `02` | as `02` | as `02` | 1,120 | **[Reasoning]** reserved by the same rule: bit `0x40` means PSK mode |

  Every other value is refused before any key operation.
- `info` is a function of the recipient key's class. Shipped classes keep theirs; the two classes
  this document adds get their own. Draft 3's third row, `"epic-box/1"` for a route server's
  mailbox challenge, is withdrawn with the epic1 mailbox it served (5.14):

| Recipient key class | `info` | Status |
|---|---|---|
| Contact keys, one-time reply keys, pairing keys, any body type | `"epic-seal/1" \|\| net \|\| suite` (13 bytes) | **[Shipped]** |
| epic1 seal key | `"epic-tx/1" \|\| net \|\| suite \|\| 00` (12 bytes) | **[Specified]** |
| Listener seal key (onion or web) | `"epic-tx/1" \|\| net \|\| suite \|\| 01` (12 bytes) | **[Specified]** |
| Epicbox seal key (kind `03`, 5.15) | `"epic-tx/1" \|\| net \|\| suite \|\| 02` (12 bytes) | **[Specified]** |

  The opener knows the class of each candidate key (5.9), so it never guesses an `info`.
  `"epic-tx/1"` is a new label because ADR 0033 rule 3 wants new HPKE `info` labels prefix-free,
  and `"epic-seal/1"` would be a prefix of an `"epic-seal/1 tx"`. **[Reasoning]** Why: reusing one
  `info` was safe only because every key class comes from a different derivation; nothing
  cryptographic said which class an envelope was meant for. A future bug that let one X25519
  secret serve two classes would make envelopes cross-interpretable. A per-class `info` costs
  nothing, and nothing installed changes.
- Ephemeral key: `DeriveKeyPair(ikm)` with 32 bytes from the caller's RNG (RFC 9180 §7.1.3). A
  fixed RNG gives identical envelopes across implementations (used for vectors).
- The sender rejects a recipient key that is all zeros or of small order
  (`EncPublicKey::from_bytes`, `crates/lepic-contact/src/keys.rs`). Every X25519 key this document
  adds (epic1 seal key, advert seal key, reply key in a tail record) is decoded through that same function.
- Library: Rust `hpke` 0.14.1, `default-features = false` (`Cargo.toml:70`), pinned in the lock
  file; `cargo deny` refuses wildcard versions. Calls:
  `hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, SealKem>` and `single_shot_open`.
  To be re-evaluated (hpke-rs with libcrux, aws-lc-rs) when suite `02` is due.
- Known-answer test: RFC 9180 Appendix A.2.1 at `testdata/vectors/pairing/hpke_rfc9180_a2.json`.
  New: vectors for both `epic-tx/1` classes.

**Suite `02`** — X-Wing (draft-connolly-cfrg-xwing-kem-11; public key 1,216 B, ciphertext
1,120 B). The header and AAD rules are unchanged; `enc` grows to 1,120 bytes (the `Nenc` rule in
5.3). An epic1 address cannot carry a 1,216-byte key; a post-quantum epic1 is a new address
version and is **[Open]**.

### 5.5 Hint — **[Shipped]** except the zero hint

| Recipient | hint (8 bytes) | Source |
|---|---|---|
| Contact | `HMAC-SHA256(key = hint_key, enc)[0..8]` | RFC 0002 §3.2 |
| Service with `fixed-hint` cap | `H("epic-seal/1 fixed" || hint_key)[0..8]` (links envelopes to that service) | RFC 0002 §3.2 |
| One-time reply key | `HMAC-SHA256(key = H("epic-seal/1 reply" || reply_pk), enc)[0..8]` | RFC 0002 §3.2 |
| Pairing reply | `invite_id = H("epic-pair/1 id" || code)[0..8]` | RFC 0002 §2.4, §3.2 |
| epic1 seal key | `00 00 00 00 00 00 00 00` | **[Decided]** (owner, 2026-11-10) |
| Listener seal key (advert) | `00 00 00 00 00 00 00 00` | **[Specified]** (draft 2): one rule for both new classes, no new hint rule |
| Epicbox seal key | `00 00 00 00 00 00 00 00` | **[Specified]** (5.15): the same rule |

A recipient computes candidate hints for its live keys and opens only with matching keys
(RFC 0002 §3.4 step 2). A zero hint means "try the epic1 seal keys, or the seal key of the
listener that received it".

**How an envelope to an epic1 address is opened** **[Decided]** (owner, 2026-11-10). The
envelope carries the zero hint whatever address index it was sealed to. There is no hint derived
from the address and no per-message hint.

- At a link mailbox: the wallet records which address index each link mailbox it issues belongs
  to (6.3), and opens with that index's seal key only.
- Everywhere else (a file, transaction text, the direct listener): trial decryption over the
  epic1 seal keys the wallet issued, each account in turn. The index of the account's most recent
  payment is tried first, then index 0, then the rest from the highest index down. The first key
  that opens is the address the slate came to; the wallet records that index with the
  transaction, and it is tried first next time.
- The direct listener tries epic1 seal keys only where the host switched it on for that socket
  kind, onion or web; the switch is off for both by default. With it off, an envelope sealed to
  an epic1 gets the answer of an envelope no key opens, so whoever holds an epic1 cannot tell
  from the answer whether a listener is that wallet.

**[Reasoning]** A hint the sender can derive from the address is the same on every message to it,
so a relay, or anyone who knows the address, could pick out every payment to it.

The cost is no cheap "not for me" filter: each key tried is one X25519 and one failed AEAD over
the envelope. A test opens a file sealed to the key tried last among 1,001
(`trial_decryption_finds_the_address_tried_last_among_a_thousand_and_one`,
`crates/lepic-wallet/tests/epic1.rs`). In a release build (`opt-level = "s"`, without LTO) on a
desktop x86-64 CPU it derives the 1,001 keys in 1.5 ms and opens at the last one in 0.13 s, about
0.13 ms per key tried; a debug build is about 70 times slower.

**[Reasoning]** The reply-key hint is computable by anyone who saw `reply_pk` in a plain marked
S1 or a raw in-person code. A carrier or onlooker that saw the S1 can therefore link the sealed S2
to it. This leaks nothing it did not already have (it saw the S1). The relay of a reply mailbox
sees the same link anyway: the mailbox exists for that one payment.

### 5.6 Inner content (TLV) — **[Shipped]** (RFC 0002 §3.3)

Each field is `tag (u8) || length (u16) || value`. Tags strictly increasing, no repeats. Unknown
tags below `0x80` are rejected. `0x80`–`0xFE` are ignored if unknown. `FF` is the signature and
comes last.

| Tag | Name | Value | Notes |
|---|---|---|---|
| `01` | type | u8 | `01` slate (V3 JSON), `02` notice, `03` pairing reply, `04` confirm, `05` contact update, `06` key check, `07` key check answer, `09` contact check, `40` app payload. Every other value is refused. `08` is avoided because the reference kit refuses it (`envelope.rs:78-81`). **`lepic.v1` slate: `0A` — [Decided] (D3).** |
| `02` | body | bytes, at most 65,535 | Per type. For `0A` **[Specified]**: the raw `lepic.v1` slate bytes (5.10), not an RFC 0001 pack. |
| `03` | reply key | 32 | X25519 key the answer is sealed to, for an anonymous envelope |
| `04` | purpose | u8 | `01` payment … `05` request between people |
| `05` | reference | 1–64 B UTF-8 | A service's reference; never trusted for crediting |
| `06` | expires | u64 seconds | Advisory |
| `07` | card | bytes | The sender's contact card (RFC 0002 §6) |
| `08` | sender key | 32 | Sender's Ed25519 `sig_pk` for this contact; required with `FF` |
| **`09`** | **reply mailbox** | **34–161** | **[Specified]** (draft 4). The Epicbox mailbox the answer is posted to: a 33-byte compressed secp256k1 key, then the ASCII `domain[:port]` of its relay (1–128 bytes in all; the domain is `relay-domain` of Appendix B.2: letters, digits, dots and hyphens, no hyphen at either end of a label; port 1–65535; 128 is LEPIC's limit, Epicbox sets none). Only with `03`, only in an anonymous S1 or I1 of type `0A`. Unknown to shipped builds, which refuse it (it is below `0x80`); that is intended, since only native readers get a `0A`. Tag `09` is unused at `main` (the envelope test refuses it). |
| `80` | sent at | u64 seconds | In every signed slate, notice and payload. Refused if over 30 days old or a day ahead |
| `81`, `82`, `83` | address proof, feature word, domain claim | | ADR 0034, 0041, 0043 |
| **`FE`** | **padding** | **zero bytes, at most 65,535** | **[Decided]**, not built (5.7) |
| `FF` | signature | 64 | Ed25519 by `sig_sk` (5.8) |

Rules (RFC 0002 §3.3): `FF` without `08` is refused; `08` without `FF` counts as unsigned. An
Ed25519 key of small order is refused before verification. Anonymous envelopes never attribute to
a contact record, even when they open with a contact key.

**[Reasoning]** Because `FE` sits in the ignored range, a LEPIC build that predates padding skips
it. Only new readers check the zeros.

**[Specified]** (draft 2) Readers that know `FE` must find it whatever its position among the
extensions. The shipped field list keeps only the first 8 extension fields and skips the rest
unread (`EXTENSION_SLOTS`, `crates/lepic-contact/src/tlv.rs`); `FE` is therefore read into a slot
of its own, not into the extension slots. The zero check need not be constant-time: the bytes are
the sender's, checked after the AEAD.

**[Specified]** (draft 2) A TLV value has a `u16` length and a tag may not repeat, so the body of
an envelope is at most 65,535 bytes. That is the binding size limit of every sealed slate (5.17).
`Writer::field` returns `FieldTooLong` past it (tested in `crates/lepic-contact/tests/envelope.rs`);
callers must handle it as section 5.17 says.

### 5.7 Padding — **[Decided]** rule; input length **[Specified]** (draft 2); floor 768 **[Decided]** (O-6, owner, 2026-11-08)

Padmé (Nikitin et al., PETS 2019) above a floor. For a length `L`:

```
E = floor(log2 L); S = floor(log2 E) + 1; z = E - S; mask = 2^z - 1
padme(L) = (L + mask) & ~mask
target   = max(FLOOR, padme(L))
```

- `L` is the length of the inner content with every field, the 3-byte `FE` header and the `FF`
  field (when signed) included; `FE`'s value is `target - L` zero bytes. `FE` is always written in a
  slate envelope (types `01` and `0A`) by builds that know it, even with an empty value, so a
  slate envelope has one encoding. Readers check the zeros when `FE` is present and do not require
  it (older senders). Vectors fix the result.
- `FLOOR` is 768 **[Decided]** (owner, 2026-11-08) (O-6; drafts 2 to 4 had 256). Reason: with 256, an S1
  without a proof pads to 256 and one with a proof to 272, and a sender message moves it further,
  so a carrier learns "proof requested" and roughly the message length. The largest S1 (lock, TTL,
  proof and a full 256-byte message) is 600 bytes of inner content anonymous and 713 signed (656
  anonymous with a reply mailbox, draft 4); the 768 floor makes every S1 one size. Padmé applies
  above the floor.
- Padmé leaks O(log log M) bits of the length with at most 12% overhead (the paper). HPKE does not
  hide length (RFC 9180 §9.7.6).

Sizes, **[Reasoning]** arithmetic from RFC 0001's size table plus the 4 bytes draft 2 adds to the
slate header (5.10), anonymous envelopes; an S1 carries tag `03`, an S2 does not:

| Slate | `lepic.v1` bytes | `L` | Floor 256 (draft 4): inner / envelope / text chars | Floor 768 (decided): inner / envelope / text chars |
|---|---|---|---|---|
| S1 plain | 153 | 198 | 256 / 320 / 432 | 768 / 832 / 1,115 |
| S1 with proof | 217 | 262 | 272 / 336 / 454 | 768 / 832 / 1,115 |
| S1 largest | 555 | 600 | 608 / 672 / 902 | 768 / 832 / 1,115 |
| S2 plain | 992 | 1,002 | 1,024 / 1,088 / 1,456 | same |
| S2 with proof | 1,120 | 1,130 | 1,152 / 1,216 / 1,627 | same |
| I2 | 1,026 | 1,036 | 1,088 / 1,152 / 1,542 | same |

An S1 to an epic1 (draft 4) always has a TTL and carries tag `09` beside `03` (56 more bytes of
`L` with a 20-character relay domain):

| S1 to an epic1 | `lepic.v1` bytes | `L` | Floor 256 (draft 4): inner / envelope / text chars | Floor 768 (decided): inner / envelope / text chars |
|---|---|---|---|---|
| With TTL | 161 | 262 | 272 / 336 / 454 | 768 / 832 / 1,115 |
| With TTL and proof | 225 | 326 | 336 / 400 / 539 | 768 / 832 / 1,115 |
| Largest | 555 | 656 | 672 / 736 / 987 | 768 / 832 / 1,115 |

"Text chars" is the
base64url payload with its 4-byte checksum, without the markers. A signed contact envelope adds
tags `08`, `80` and `FF` (113 bytes) to `L`.

**The floor and QR codes** **[Reasoning]**. Padding is inside the seal, so it never changes the
size of an in-person code: the first in-person code is raw. Under the transport model (3.1) no
sealed S1 is shown as a QR code: in person the first code is raw, and a payment code carries an address, not a slate.
The only sealed slates shown as codes are in-person replies shown offline (S2, I2), and every reply
is larger than 768 bytes already, so the floor never changes a code. It matters for sealed S1s and
I1s in mailboxes and files, where 512 more bytes cost nothing a user sees. The relay of a link
mailbox sees the size of every Epicbox message, so there the floor is what hides "proof requested"
and the message length. Slates in codes are in 5.18.

**O-6: 768** **[Decided]** (owner, 2026-11-08), so that every sealed S1 has one size and its length says
nothing about a proof or a message.

### 5.8 Signature — **[Shipped]** (RFC 0002 §3.3)

```
msg = "epic-seal/1 sig" || header (16 bytes) || recipient X25519 public key || every inner field before FF, as encoded
sig = Ed25519(sig_sk, msg)
```

The recipient key binds the signature to one recipient, so a contact cannot re-seal a signed
message to a third party. Signed between paired contacts; anonymous otherwise. Padding (`FE`) is
before `FF`, so it is signed.

`enc` is not in the signed input. A third party cannot move a ciphertext to another `enc`: the
HPKE key schedule binds `enc` (DHKEM `kem_context = enc || pkR`), so the AEAD fails. For
contact-hint envelopes the hint, `HMAC(hint_key, enc)`, is in the signed header, so `enc` is bound
in effect. For zero-hint and fixed-hint envelopes the *recipient* can re-seal a signed plaintext
under a fresh `enc` to itself; that is harmless, because the recipient key is in the signed input
and nobody else can open the result.

### 5.9 Opening rules — **[Shipped]** (RFC 0002 §3.4); type `0A` rules **[Specified]** (draft 2)

1. Decode the header. Reject another network, an unknown version or suite.
2. Find candidate keys by hint. None means "not for this install". A zero hint selects the seal
   key of the epic1 address index the link mailbox it came from belongs to, or the accepting
   listener's seal key (endpoint). A zero-hint envelope from a file, transaction text or the
   direct listener (where the host switched epic1 on for that socket kind) is tried with the
   issued epic1 seal keys in the order of 5.5.
3. `OpenBase` (or `OpenPSK` for suite `41`) with each candidate, with the `info` of that key's
   class (5.4). Failure with all is "cannot open".
4. Decode the TLV. If `FF` is present, verify with `08`'s key. A signed envelope opened with a
   contact slot's key is attributed to that slot's record only if its peer `sig_pk` equals `08`.
5. Hand the body to its type's handler. For `0A`, the `lepic.v1` decoder (5.10), then the rules
   below, then the engine.

For type `0A`, normative:

- The slate's network byte (5.10) must equal the envelope's `net`; otherwise refuse.
- An anonymous `0A` (no `FF`) is taken only as an S1, or as the S2 or I2 that answers a slate this
  wallet started (matched on the stored slate id and stage, RFC 0001 §11). An anonymous I1 is
  refused: an invoice needs the payer's consent. Native invoices travel sealed between paired
  contacts, or raw in an in-person code the payer scans (5.18). There is no exception: draft 5's
  invoice window (O-15) is removed (owner, 2026-11-09; 6.10). An invoice is never paid
  automatically. (Legacy V3 I1 files keep their shipped handling.)
- Tag `09` (reply mailbox) is required in an anonymous S1 that arrives at a link mailbox, and
  refused in every other envelope. **[Specified]** Without it the answer has nowhere to go: an
  epic1 sender has no other address.
- Reply relays **[Decided]** (owner, 2026-11-09; 3.2): the relay named in tag `09` or record `02`
  is a host from untrusted input. Before LEPIC posts an S2 there, it reports the host, whether it
  is in the configured relay list, and its address class, and posts only when the consumer says so
  (5.14 "Hosts from untrusted input"). **[App]** The wallet app posts to a relay in the user's own
  relay list (settings) without asking. Any other relay is shown to the user, who accepts or
  rejects it; when the user has Tor, the app says the answer goes through Tor. Rejected, nothing
  is posted (in person the answer can still be shown as a code, 6.7).
- An answer (S2, I2) is posted only to the mailbox in tag `09` (or tail record `02`) of the slate
  it answers, through the relay that mailbox names, from a post key (5.2). It is never posted to
  the `from` of the Epicbox message that carried the request: only the `from` key is authenticated,
  its domain is not (`docs/compat/epicbox.md` "Receiving a slate"), and a post key receives
  nothing.
- A signed `0A` from a contact follows the contact's shipped rules (RFC 0002 §11 for invoices).
- An anonymous `0A` never attributes to a contact record, even when it opens with a contact key.

### 5.10 Native slate `lepic.v1` — **[Specified]** (RFC 0001 §1–4 as amended); positions **[Specified]** (draft 2); tail rule **[Decided]** (O-5)

RFC 0001 §2 with the decided amendments (4.1 "Native slate", "Data format") at fixed positions.
Draft 2 adds the network byte (4.1) and retires the `LOCK` flag bit in favour of
the decided kernel-features byte. **[Reasoning]** One fact, one encoding: RFC 0001 derived the
kernel features from `LOCK`; with an explicit features byte the flag would be a second encoding of
the same fact, so it goes.

Fixed header, 51 bytes (RFC 0001: 47):

| Offset | Field | Size | Rule |
|---|---|---|---|
| 0 | magic | 4 | `89 45 53 4C` |
| 4 | version | 1 | `01` |
| 5 | network | 1 | `00` mainnet, `01` floonet. Any other value is refused. Inside an envelope it must equal the envelope's `net` (5.9). |
| 6 | stage | 1 | S1 `01`, S2 `02`, S3 `03`, I1 `04`, I2 `05`, I3 `06` |
| 7 | flags | 1 | bit 0 reserved, must be zero (was `LOCK`); bit 1 `TTL`, bit 2 `PROOF`, bit 3 `SENDER_MESSAGE`, bit 4 `RECEIVER_MESSAGE`; bits 5–7 must be zero |
| 8 | kernel features | 1 | `00` Plain, `02` HeightLocked (`lepic-primitives` kernel constants). `01` Coinbase and every other value are refused: a slate never builds a coinbase kernel. |
| 9 | header version | 2 | u16, Epic block header version; rule below |
| 11 | id | 16 | slate UUID |
| 27 | amount | 8 | u64 atomic units |
| 35 | fee | 8 | u64, zero at I1 |
| 43 | height | 8 | u64 |

Then, in this order, with no padding:

| Field | Size | Present |
|---|---|---|
| lock_height | 8 | exactly when kernel features are `02`; must be non-zero |
| ttl_cutoff_height | 8 | exactly when `TTL` |
| offset | 32 | always |
| sender participant | 66, + 64 signed, + 2 + n + 64 with message | by stage (RFC 0001 §3) |
| receiver participant | same | by stage |
| payment proof | 64, + 64 at S2/S3 | exactly when `PROOF`; never in the invoice flow |
| input count, inputs | 2 + 34 each | always (count may be zero) |
| output count, outputs | 2 + 709 each | always |
| kernel excess, kernel signature | 33 + 64 | final stages (S3, I3) |
| extension tail | rest of the input | zero or more records, below |

Participant: public blind excess (33), public nonce (33), partial signature (64) when RFC 0001 §3
says the party has signed, then, when its message flag is set, message length (u16, at most 256),
the UTF-8 message and the message signature (64). Input and output features: `00` plain, `01`
coinbase. Range proof: 675 bytes.

**Header version rule** **[Specified]**, **[Reasoning]**. The writer sets the block header
version that the consensus table gives for the slate's `height` on the slate's network: today 6
below the first hard fork, 7 from it (mainnet 9,000,000, floonet 25,800;
`crates/lepic-wallet/src/send.rs`, `block_header_version`, which legacy slates already use). A
reader refuses a slate whose header version is not the one its own table gives for that
`height`, and a slate whose `height` falls in a range its table does not cover. It is not
compared with the reader's own chain tip, and it has no other effect. Reason: the value is then a
pure function of fields already in the slate, so it adds no second encoding, and a reader built
before a future fork refuses a slate it could not complete correctly.

**Extension tail** — **[Decided]** (O-5). The envelope's rule (5.6): `u8` type, `u16` length,
value; types strictly increasing; an unknown type below `0x80` refuses the slate, `0x80` and above
is ignored. It replaces the BOLT 1 odd/even rule decided first (BigSize fields, even critical).
**[Reasoning]** Both rules are equally expressive. The envelope rule is already shipped and
fuzzed, has a fixed width (so no minimal-encoding rule is needed), and leaves one parser rule and
one fuzz corpus for the whole stack. Further:

- Protocol 1 defines two tail records, **[Specified]** (`01` draft 3, `02` draft 4, for 3.1):

  | Type | Name | Value | Allowed in |
  |---|---|---|---|
  | `01` | reply key | 32 bytes, an X25519 public key, decoded through `EncPublicKey::from_bytes` | Required in an S1 or I1 shown raw in an in-person code (5.18, O-13). Refused at every other stage, and in any slate inside an envelope, where the reply key is the envelope's tag `03`: one fact, one encoding. |
  | `02` | reply mailbox | 34–161 bytes: a 33-byte compressed secp256k1 key, then ASCII `domain[:port]` of 1–128 bytes in all, the domain a `relay-domain` (Appendix B.2; hyphens allowed) (the value of envelope tag `09`, 5.6) | Only with `01`, under the same rule; the envelope's tag `09` carries it otherwise. Optional: without it the answer can only be shown as an animated code (offline flow, 6.7). |

  A slate in an envelope has an empty tail in protocol 1.
- **[Reasoning]** An in-person code is the one carrier where the slate travels with nothing
  around it (O-7), so the reply key and mailbox ride in the slate's own tail there, and in the
  envelope everywhere else.
- A record of a known type must have exactly its defined form.
- Unknown ignorable records are kept, verbatim and in order, in the decoded slate, and written
  back unchanged by `encode`. So `encode(decode(x)) == x` holds for every accepted input
  (RFC 0001 §4: "ignore" would otherwise drop them).
- A reply never copies the request's unknown records. A responder writes only records it knows.
  The engine contract's comparison (RFC 0001 §11) covers known fields only.
- Truncation inside a record, or a length running past the end of the input, refuses the slate.

**Decoding** (RFC 0001 §4, amended). A decoder refuses, with a typed error, before any allocation
larger than the input: input over the bound below; wrong magic or version; a network other than
`00`/`01`; a bad stage; a reserved flag bit; kernel features other than `00`/`02`; a header
version that breaks the rule above; HeightLocked with a zero lock height; `PROOF` in the invoice
flow; a message flag for an absent party or for the initiator at S2 or I2; truncation; a tail that
breaks its rule; weight over `MAX_TX_WEIGHT`; bad input or output features; points that do not
parse; a proof address that does not decompress (decoded through the shipped functions); a message over 256 bytes or not UTF-8; the same commitment twice; anything
`Slate::from_parts` rejects. The responder checks a minimum fee (RFC 0001 §4). An S1 or S2
that carries no inputs, which is what a native proposal is (it holds no inputs or outputs), has
unknown input counts, so the check bounds the weight from below: the fee is at least one base
fee. The sender's own finalize check and the node enforce the real minimum on the final
transaction. A slate with an input, and every I1, I2, S3 and I3, is checked as before.

**Bound.** `MAX_WIRE_SLATE_LEN` (8 MiB, `crates/lepic-slate/src/codec/mod.rs:13`) stays the
codec's own bound. Every carrier of a `lepic.v1` slate in this specification is an envelope body,
which is at most 65,535 bytes (5.6, 5.17), so in practice that is the limit. **[Reasoning]** A
`lepic.v1` I2 reaches 65,535 bytes at roughly 1,900 payer inputs.

Engine contract (RFC 0001 §11), unchanged: the initiator checks that the reply repeats id, amount,
the kernel features and lock height, offset, its own public excess and nonce, the proof addresses
(and fee, height, TTL in the send flow); it takes the responder's participant data, proof
signature and every input and output not already stored; an entry with a stored commitment must
be identical. Draft 2 adds: the reply's network and header version equal the request's.

A 1:1 JSON view exists for tools and the API only, never on the wire (4.1). It shows the network,
the kernel features and the header version as fields, and unknown tail records as type and hex.

**Pack** — dropped, **[Decided]** (O-7). RFC 0001 §5's pack (magic `89 45 50 4B`) and the
`BEGINEPICSLATE.` armour are not built. A native slate travels inside an envelope, or raw in an
in-person code (5.18): the slate's own bytes, nothing around them. Whatever only old wallets need
stays in the legacy code. Native slates to Epicbox payments addresses
(step 11) travel in an envelope too (5.15) **[Specified]**. Reason: with
the network byte in the slate, the pack's only remaining field was the mode, always `00`, and every
carrier this specification defines is an envelope.

### 5.11 Armour — **[Shipped]** for `BEGINEPICSEALED.`; EPICTX **[Decided]**; which bodies get which marker **[Decided]** (O-4); alphabet **[Decided]** (D6)

Shipped form (RFC 0002 §3.5, `crates/lepic-contact/src/armor.rs`):

```
BEGINEPICSEALED. <payload>. ENDEPICSEALED.
payload = base64url-nopad( envelope || H(H(envelope))[0..4] )
```

EPICTX form:

```
BEGINEPICTX. <payload>. ENDEPICTX.
```

Same payload rule under D6. Framing (RFC 0001 §7, RFC 0002 §3.5):

- Split on the first three periods. Header and footer match with optional `>`, spaces, tabs and
  line breaks around them (RFC 0001 header regex `^[>\n\r\t ]*BEGINEPICSLATE[>\n\r\t ]*$`,
  adapted). Whitespace and `>` inside the payload are removed.
- Encoders wrap the payload at 76 characters (`armor.rs`, `LINE_LEN`).
- At most 96 KiB of text (`MAX_ARMOR_LEN`, `armor.rs:9`), checked before decoding. **[Reasoning]**
  The largest envelope a slate can fill (67,648 bytes, 5.17) is 90,203 characters of payload plus
  line breaks, about 91.4 KiB, so the bound holds.
- A wrong checksum is its own typed error ("damaged on the way").
- New readers accept both markers for every body type. The marker never decides how the content
  is read; the envelope's type does.
- **[Reasoning]** The 4-byte double-SHA-256 checksum is for transcription errors only; the AEAD
  provides integrity.

Which marker a writer uses. The first decision put `BEGINEPICTX.` on every slate. Shipped LEPIC
builds already write sealed slates as `BEGINEPICSEALED.` text and `.epicsealed` files: to paired
contacts (`contact_seal_slate`, `crates/lepic-wallet-contacts/src/sealed.rs`) and as the answer to
a marked legacy file (`SealedAnswer::Sealed`, same file). Those builds read only
`BEGINEPICSEALED.`. If a new build wrote `BEGINEPICTX.` around a type-`01` (V3) slate, an older
LEPIC sender or contact could not read the answer. Decided under O-4:

| Envelope body | Marker and file | Why |
|---|---|---|
| Type `0A`, `lepic.v1` slate | `BEGINEPICTX.`, EPICTX file (5.12) | Only builds that read native slates produce or need it. |
| Type `01`, V3 slate | `BEGINEPICSEALED.`, `.epicsealed`, as shipped | Readable by every LEPIC build that can open the envelope. |
| Every other type | `BEGINEPICSEALED.`, as shipped and decided | |

The base58 alternative (RFC 0001 §7: 15-character words, 16 KiB bound because base58 decoding is
quadratic) comes back only if base64url fails the chat paste test (D6, 11.2). A 16 KiB bound would not hold the largest
slate envelope (5.17), so base58 would also need a lower slate limit.

### 5.12 Files and media type

| Item | Value | Mark |
|---|---|---|
| EPICTX file | Armoured `BEGINEPICTX.` text, UTF-8, any stage. Never binary. Extension `.epictx`, kept under O-2 with the no-clash rule below. | **[Decided]** |
| Reply name | `<stem of received file>-reply.epictx` | **[Decided]** |
| Name of a new send | **[Reasoning]** the app's current pattern, first 8 characters of the slate id: `<id8>.epictx` (`app/lib/src/slate_files.dart`, `sendFileName`) | not decided |
| Sealed envelope file | `.epicsealed` (`SEALED_FILE_EXTENSION`, `armor.rs`). Holds any sealed envelope, including sealed V3 slates to contacts and sealed answers to marked legacy files. Draft 1 said it held only non-slate bodies; that was wrong. | **[Shipped]** |
| Legacy files | `<id8>.tx`, answer `<id8>.response` or `<loaded name>.response` | **[Shipped]** (app) |
| HTTP media type | `application/vnd.lepic.epictx` for the binary envelope body (5.15) | **[Decided]** (D4) |

Names never decide how a file is read; content does (`slate_files.dart`, `uniqueFileName`).

Under the transport model (3.1) EPICTX files go only between paired contacts. A file to a
stranger is the marked legacy V3 with a one-time reply key, and a LEPIC stranger's answer is a
sealed V3 (`.epicsealed`, 6.4). An S1 for an epic1 goes to its mailbox, not into a file (6.3).

**The other `.epictx`** — **[Shipped]** upstream fact. Stock `epic-wallet` v4.1.0 (and the GUI
wallet on it) stores each transaction it sends in `wallet_data/saved_txs/<uuid>.epictx`
(`impls/src/backends/lmdb.rs:403-414`, `libwallet/src/internal/selection.rs:144`). The content is
the binary transaction (`ser_vec`, protocol version 1) as lowercase hex: no marker, no JSON, no
line breaks. The owner API's `stored_tx` field names the file. These are the wallet's own records
for reposting, never meant to be sent to anyone.

What can be renamed on our side: nothing needs to be. LEPIC and the app write no file of that
kind. LEPIC only reads the `stored_tx` name during the GUI-wallet import
(`crates/lepic-store/src/legacy/`, `MAX_STORED_TX_CHARS`), and the app's only mention of
`saved_txs` is a test of that import (`app/test/legacy_wallets_test.dart`). The stock name is
upstream's and cannot change.

**No-clash rule** — **[Decided]** (O-2: keep `.epictx`); rule **[Specified]** (draft 3):

1. LEPIC and the app write a file named `*.epictx` only with armoured `BEGINEPICTX.` text (5.11).
   They never create, or write into, a directory named `saved_txs`.
2. A reader decides by content, never by name or folder. After skipping whitespace and `>`:
   - `BEGINEPICTX.` or `BEGINEPICSEALED.` → armour (5.11), then the envelope.
   - Otherwise, if the trimmed content is only hex digits, of even length → a stock saved
     transaction. It is refused with its own error, and the app says: "This is a record another
     Epic wallet keeps of a transaction it sent. It is not a payment file." Nothing else happens:
     it is not decoded, imported or posted.
   - Otherwise `{` → the legacy JSON slate rules (shipped).
   - Anything else → "not a payment file".
3. **[Reasoning]** The cases cannot overlap. Armour starts with `BEGIN`, and `G`, `I` and `N` are
   not hex digits; stock content is only `0-9a-f`; JSON starts with `{`. A marker-less EPICTX
   does not exist (armour is required in files), and binary content is never valid in an EPICTX
   file.
4. The app's file read bound (1 MiB, `maxSlateFileBytes`) applies before the check.
5. File associations: an operating system may offer BT Wallet for a stock saved transaction.
   That is harmless under rule 2: the app shows the message and stops.

No owner question remains from this: nothing on our side clashes once rule 1 holds, and the stock
file is told apart by its first bytes.

### 5.13 epic1 address — **[Decided]** content (two keys, O-14 as replaced); layout **[Specified]** (draft 2), Appendix B

RFC 0001 §8 base, amended:

- bech32m (BIP 350), human-readable part `epic` (mainnet) or `tepic` (floonet).
- Data, 65 bytes: version `01` (1), proof key (32, Ed25519), seal key (32, X25519, 5.2).
  **[Reasoning]** Version `00` meant RFC 0001's one-key form, which never shipped; `01` keeps it
  unambiguous. Proof key first matches the RFC 0001 form, whose data began with that key.
- Proof key: the dedicated epic1 proof key (5.2, O-8), not the index-0 payment-proof key.
- Length: 65 data bytes = 104 characters; with `epic1` and the 6-character checksum, 115
  characters (116 for `tepic1`). **[Reasoning]** arithmetic.
- Decoders refuse mixed case, a bad checksum, an unknown version, a proof key that does not
  decompress or is weak, a small-order seal key, and the other network's prefix (RFC 0001 §8).
  Keys are decoded through the shipped functions (`EncPublicKey::from_bytes`, the `sig_key`
  checks), with no new lists.
- `epic-wallet` rejects an `epic1` string both as an Epicbox address and as a proof address
  (RFC 0001 §8), so it cannot be mistaken for either.
- Length limit: BIP 173 caps segwit addresses at 90 characters. The Rust `bech32` crate applies
  that cap only in its segwit API from 0.11 on; its generic `encode::<Bech32m>` allows up to
  1,023 characters (re-check on the version added, the workspace has none today). The
  chance that random errors pass the checksum stays near 2⁻³⁰. A typo that survives gives a wrong
  seal key: nobody can open the S1, and the sender's inputs stay locked until cancel or TTL; no
  coins are lost.
- **Every send to an epic1 sets a TTL** (`TTL` flag and `ttl_cutoff_height`), so locked inputs
  come back by themselves. **[Specified]**. The default TTL is 24 hours, 1,440 blocks
  **[Decided]** (owner, 2026-11-08). Epic's target is one block a minute (`BLOCK_TIME_SECONDS = 60`,
  `crates/lepic-wallet/src/chain.rs`); a TTL in time is turned into blocks at that rate, rounded up
  to a whole block, and `ttl_cutoff_height` is the wallet's chain height plus that count. Real
  block times vary, so the time is a target: slow blocks make it longer, fast ones shorter.
- Numbered addresses per account and network (D5) **[Decided]** (owner, 2026-11-10). The address
  at index `n` holds the epic1 proof key and the epic1 seal key at index `n` (5.2). Index 0 is the
  account's first address and the address every earlier build shows. The index is not in the
  address: a payer cannot tell two addresses of one account apart from two accounts, and the
  format stays version `01`, 115 characters.
- The wallet issues addresses in order and keeps, per account, the highest index it issued, the
  highest index a payment came to, the index of the most recent payment, and the index of each
  payment. Coins never depend on it; it only says which seal keys to try.
- A wallet rebuilt from the recovery phrase does not know how far it issued. It tries 50 indexes
  past the highest one it knows, and its first new address after the restore comes after those
  50, so it does not hand out an address it may have given out before. A payment found in the
  gap moves the gap past it, until the account issues its first new address.
- LEPIC sets no limit on how many addresses an account issues; the app sets any policy. The
  wallet, the CLI (`address`, `new-address`, `addresses`) and `serve` issue the next address,
  give the address at an index, and list the issued ones. An index past the highest issued is
  refused (`AddressNotIssued`); an account at index 2³²−1 issues no more (`NoAddressLeft`). A
  received transaction shows the index it came to.
- **Two keys and nothing else** **[Decided]** (O-14 as replaced, owner after draft 3). No mailbox
  key, no domain, no transport of any kind: the epic1 says who is paid and what to seal to. How to
  reach the payee lives in the link (5.14), so a new transport, relay or domain never changes the
  address. A bare epic1 with no link around it identifies a payee but cannot be paid: the app says
  "This address has no way to deliver. Ask for a payment link."
- Shown and shared as its own code and link, never inside an Epicbox link (3.1, 5.14).
- The example in RFC 0001 §8 (`epic1qzcrepxh77qm2dkfve5djwehw6x8sy4hv3yuz740p2w3rgqrc0rnwal22fe`,
  from vector `slates/send_file_payment_proof_s1_v3`) is the old one-key form. No two-key vector
  exists yet; the vectors come with the codec.

### 5.14 Payment links — **[Decided]** two separate links (3.1) and transport in the link (O-14 as replaced, owner after draft 3); grammar **[Specified]** (draft 4)

Shipped link builder: `EpicUri.build` in `app/lib/src/scan/scan_router.dart:620-636` writes
`epic:<address>` then `amount`, `message`, `label`, `method`, `direct`. The parser
(`scan_router.dart:440-530`) reads `amount`, `message`/`note`/`memo`, `label`, `method`, `direct`,
`require`, `min`, and skips every other key (`:529`). Values longer than `maxUriValueLength` are
flagged (`:27`).

Two links, never mixed. The grammar is in Appendix B (ABNF, RFC 5234). In short:

```
epic:<Epicbox address>[@<domain>[:<port>]]?amount=5&message=Dinner                  shipped, unchanged
epic:epic1<110 chars>?epicbox=<52 base58>@<domain>[:<port>]&amount=5&message=Dinner  LEPIC only
```

Examples (placeholders, not real addresses):

```
epic:<52 base58 chars>@relay.example?amount=5&message=Dinner
epic:epic1<110 bech32 chars>?epicbox=<52 base58 chars>@relay.example&amount=5&message=Dinner
epic:epic1<110 bech32 chars>?epicbox=<52 base58 chars>@pay.shop.example&epicbox=<52 base58 chars>@relay.example
```

**The Epicbox link** is the shipped one. Stock wallets and LEPIC pay it over Epicbox (6.9). It is
the default receive code.

**The epic1 link** **[Decided]**:

- The address part is the epic1 alone (5.13): two keys, the payee shown to the user.
- **Transport fields.** One field per delivery method; today `epicbox=<mailbox address>@<domain>[:<port>]`,
  where the mailbox is an Epicbox address (52 base58 characters) and the domain is required. A
  field may repeat, and several methods may appear. Later methods are new field names (`onion=`
  is the obvious next one; `nostr=` is a note only, not specified). A reader that does not know a
  field ignores it.
- **Order.** The payer tries the transport entries it can use in the order they appear, at most
  three; writers write at most three. **[Specified]** "Tries" means: post the sealed S1 to the
  first; if the relay cannot be reached or refuses the post, the next. Each post goes through the
  host rule below ("Hosts from untrusted input").
- **No answer** **[Decided]** (owner, 2026-11-09); detail **[Specified]**
  (draft 6). Draft 5 made an accepted post final, which left a payer whose payee never drains that
  relay waiting until the TTL with the coins locked. Now LEPIC keeps the sent S1 and, when the
  consumer asks, posts the same sealed S1 to the next `epicbox=` entry. The S1 is sealed once, so
  every copy is the same bytes, and the receipt is idempotent: the payee answers one slate id once
  and the payer finalizes on the first S2 that matches its stored slate (RFC 0001 §11), so a copy
  in a second mailbox cannot cause a second payment. On request LEPIC cancels the slate and
  unlocks the coins. The 24-hour TTL is kept. **[App]** From the post on, the app shows a waiting
  state with "Cancel and unlock". After some minutes with no answer it asks LEPIC to post to the
  next entry (the wait is to explore in the wallet app).
- **No usable transport.** A link with no transport field the reader can use is "cannot pay this
  code". There is no default relay from settings for an epic1: a mailbox the payee did not name
  is one nobody reads.
- **Transport only.** The mailbox is never shown as the payee, never stored as a contact or an
  address, and never paid as an Epicbox address: a LEPIC reader never sends a plain slate to an
  `epicbox=` value, and a payee never answers a plain slate that arrives at a link mailbox
  (it acknowledges and drops it). The mailbox may be a throwaway per link (5.2, `link mailbox`).
- **Network.** The mailbox's Epicbox version bytes must name the epic1's network (`epic1` with a
  mainnet mailbox, `tepic1` with a floonet one); a field that breaks this is not usable.
- **Pay parameters.** `amount`, `message` (and its aliases `note`, `memo`) and `label` as in the
  shipped parser. `method`, `direct`, `require` and `min` have no meaning in an epic1 link and are
  ignored.
- **Stock wallets refuse epic1 links** as an unknown address (`epic-wallet` rejects `epic1`
  strings, 5.13); the app labels the code for LEPIC wallets. Stack Wallet and Epic Pay are assumed
  to refuse it the same way, not tested (**[Open]**, 11.1).
- **Paypoints** name a mailbox on their own domain. The payer's wallet trusts that domain for
  nothing but delivery.
- **Relay domains may contain hyphens** **[Decided]** (owner, 2026-11-08): `relay-domain` in Appendix B.2,
  letters, digits, dots and hyphens, no hyphen at either end of a label. Epicbox upstream allows
  only `[a-zA-Z0-9.]` in an address's domain (`docs/compat/epicbox.md` "Addresses"). Only LEPIC
  wallets read epic1 links, tag `09` and record `02`, so this breaks no stock wallet; a stock wallet
  just cannot name such a relay in its own address. The relay does not check the destination's
  domain (`docs/compat/epicbox.md`, after "Message format"). The plain Epicbox link keeps the
  shipped grammar.
- No expiry parameter. Hosts come from the link, never from code.

**Hosts from untrusted input** — LEPIC part **[Decided]** (owner, 2026-11-09, O-17); address
classes **[Decided]** (owner, 2026-11-09, O-18).
It covers every host LEPIC would connect to because of input it did not configure: an `epicbox=`
entry, tag `09` (5.6), record `02` (5.10) and the direct HTTP/HTTPS endpoint of an address (5.15).
A relay or host from the configured relay list or the user's settings is not covered.

- **LEPIC** (O-17). Before it posts to such a host, LEPIC reports to the consumer the host, whether
  it is in the configured relay list, and its address class (below). It posts only when the
  consumer says so, and posts through Tor when Tor is configured. It never shows or decides a
  prompt.
- **Loopback is refused by LEPIC itself.** This is a safety rule, not a policy: a code must not
  reach services on the payer's own device. Refused: `localhost` and names under it,
  `127.0.0.0/8`, `::1`, and IPv4-mapped forms of these. The check is made on the resolved address
  at connect time, not only on the name, so a name that resolves to loopback (DNS rebinding) is
  refused too.
- **Address classes** **[Decided]** (owner, 2026-11-09, O-18), the class LEPIC reports, again
  on the resolved address: *local network* for RFC 1918 (`10/8`, `172.16/12`, `192.168/16`),
  link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`), unique local (`fc00::/7`) and names
  ending in `.local`; *public* for the rest. Any port is allowed. **[Reasoning]** A shop may run a
  wallet or relay on its own Wi-Fi, so local addresses have a use; the danger is the payer's own
  device, which loopback covers.
- **[App]** The wallet app connects to a host in the user's relay list without asking. Any other
  relay is shown to the user, who accepts or rejects it, and the app says when the post goes
  through Tor. A local-network host gets one prompt that shows the address: "This code connects to
  a local network address 192.168.1.20. Continue?" (to explore in the wallet app).

This replaces draft 3's `via=` route hint, its epic1 mailbox extension on route servers (with the
`"epic-box/1"` challenge), and the alternative of a third key in the epic1.

**No mixing** **[Specified]**. No parameter of either link is read as a second address. A LEPIC
reader ignores a `native=` parameter, or any epic1, inside an Epicbox link, and pays the Epicbox
address as a stock reader does. Inside an epic1 link, `epicbox=` is transport (above), never an
address. One QR code never carries both kinds of link.

**Why O-1 stays dropped, and why the link does not let a user check one identity and pay another** **[Reasoning]**.
The risk is a code with two identities: a genuine address beside someone else's key, where the user
checks one and pays the other. The epic1 link now carries an Epicbox address again, as a mailbox,
so the case is checked afresh:

1. *Swap the mailbox, keep the epic1.* Everything posted to the mailbox is sealed to the epic1's
   seal key (5.4, 5.9). The attacker who owns the swapped mailbox receives an envelope it cannot
   open, and cannot answer for the payee: an S2 must be built by the holder of the epic1's keys to
   finalise into a payment to them, and the payer only takes an S2 that answers its own stored
   slate. The payment does not happen; the TTL frees the inputs (5.13). The attacker learns that
   someone sent something of that size at that time, and the payer's IP address if it holds the
   relay. Delivery fails; no money moves to the attacker.
2. *Swap the epic1, keep the mailbox.* The payee shown to the user changes. That is a whole-address
   swap, caught (or not) by the user's check exactly as with any address today (7.1).
3. *Mailbox of a third party.* Same as 1: nobody but the epic1's holder can open the S1.
4. *A wallet that pays the mailbox as an address.* This is where the risk would come back: a reader
   that treated `epicbox=` as the payee would pay an address the user never checked. Hence the
   rules above (never pay it, never show it, never answer a plain slate at a link mailbox) and a
   conformance test for each. Stock wallets do not read the link at all.

So the identity that is paid is the identity that is shown, and the transport field can only
decide whether delivery works. **[Reasoning]** This depends on the payer sealing to the epic1 and
never falling back to a plain form; an epic1 has no plain form (5.17).

**Size of the codes** **[Reasoning]**, computed with the `segno` encoder. Level H with the app's
mark in the middle (`MarkedQr`, `app/lib/src/ui/theme/brand.dart`), byte mode, a 20-character
relay domain, a 52-character mailbox and `&amount=5&message=Dinner`; in brackets without amount and
message. Level M is given for printed codes without a mark:

| Code | Characters | QR version at H | at M |
|---|---|---|---|
| Epicbox link, the default receive code | 102 (78) | v10, 57 × 57 (v8) | v6 (v5) |
| epic1, no transport (cannot be paid) | 144 (120) | v12 (v11) | v8 (v7) |
| epic1 link, one `epicbox=` | 226 (202) | v16, 81 × 81 (v15) | v11 (v10) |
| epic1 link, two `epicbox=` | 308 (284) | v18 (v18) | v13 (v12) |
| epic1 link, three `epicbox=` | 390 (366) | v21 (v20) | v15 (v15) |

Each `epicbox=` entry adds 82 characters with a 20-character domain. One entry is the default; a
second is for a paypoint that wants a fallback relay. Draft 3's `via=` link was v13 at H; the
transport entry costs three versions, because a mailbox is an Epicbox address.

### 5.15 Advert and native direct endpoint — **[Decided]** shape (ADR 0052 "Native direct endpoint"); seal key and pinning **[Decided]** (D1 as revised by O-10); rest **[Specified]** (draft 2)

`check_version` answer of a LEPIC listener, extra key:

```json
"lepic": {"protocol": 1, "formats": ["lepic.v1"], "path": "/v1/peer", "seal": "<64 hex>"}
```

- Stock senders read only `foreign_api_version` and `supported_slate_versions`
  (`epic-wallet` `impls/src/adapters/http.rs:26-73`), so the extra key changes nothing for them.
  LEPIC's decoder ignores unknown keys (`crates/lepic-foreign/src/rpc.rs:484-487`).
- `seal`: the seal key of the listener that accepted the connection (5.2, kind `01` onion,
  `02` web). It never equals the epic1 seal key, so the advert does not link the listener to the
  epic1 or Epicbox identity.
- **Key by socket.** The key is chosen from the socket that accepted the connection, never from
  the `Host` header or any other request field. Today the onion forwards to its own loopback port
  or Unix socket (`crates/lepic-tor/src/listen.rs`), so the onion and the web listener are
  different sockets. **[Specified]** This is an invariant, with a test: a request to the web
  socket naming the onion in `Host` gets the web key, and the reverse. If both listeners ever
  share one socket, the onion's key may not be advertised on it.

Endpoints on the same socket as `/v2/foreign`:

- `GET /v1/peer` → `{"protocol":1,"formats":["lepic.v1"],"network":"mainnet","key":"<seal key>"}`.
  Protocol 1 has no feature bits here (see versioning below).
- `POST /v1/peer/slates`: body the binary envelope (type `0A`, hint zero) sealed to the advertised
  key, media type `application/vnd.lepic.epictx` (D4). **[Specified]** binary, because the endpoint is not a text carrier.
  Body limit 68 KiB (69,632 bytes), the largest slate envelope rounded up (5.17); larger bodies get
  `too_large` before they are read in full.
- `200` returns the reply envelope, sealed to the sender's reply key (tag `03` of the request) with
  the one-time reply-key hint (5.5). **[Specified]**
- Errors are RFC 9457 problem details: `not_ready` 503 (`Retry-After`), `refused` 422,
  `too_large` 413, `rate_limited` 429, `unsupported_format` 415. A repeated slate returns the
  same reply.
- Invoices (I1) are not taken here: they need the payer's consent, and arrive only from paired
  contacts, or in a code the payer scans (5.9, 6.10).
- The endpoint's host comes from an address the user entered or scanned, so it follows the host
  rule of 5.14 ("Hosts from untrusted input"): loopback refused, the address class reported.
- Versioning: `protocol` is the endpoint shape (additive; a break is `/v2`); `formats` lists
  codecs. **[Specified]** (draft 2) The endpoint carries no feature bits in protocol 1.
  If a later protocol adds them, they are a field of their own, numbered from bit 0 with BOLT 9
  parity (even required, odd optional; a peer claiming an unknown even bit is refused). They are
  never the marker's bits (5.16), which are claims without parity. Draft 1 put BOLT 9 parity on
  "new bits" of a shared field, under which the marker's bit 0 would read as "required".

Pinning (D1 as revised; **[Decided]**, O-10: always ask the user; the asking is the app's, 3.2):

- The first successful native exchange pins the listener's seal key. The pin's key is the sending
  account and the normalised origin: scheme, lowercased host, port (the scheme's default made
  explicit), or the onion name. The path is not part of it.
- A different key later at a pinned origin is treated as "the payee changed", on every kind of
  address, onion and HTTPS included. Reason: listener seal keys are fixed per seed,
  account and listener, so a new key means a different wallet or account, not a routine rotation.
  LEPIC stops the send and reports the change to the consumer. **[App]** The wallet app asks the
  user, with the plain message "This address now answers with a different wallet." Draft 1
  accepted a change silently over an onion or HTTPS.
- A pinned-native peer is never downgraded to legacy by LEPIC. That covers a missing advert and
  every failure of `POST /v1/peer/slates` (a 415, a 503, a reset, a timeout): LEPIC stops and
  reports; none of them falls back to `/v2/foreign` by itself, because on plain HTTP an attacker
  can produce all of them. A legacy send happens only when the consumer calls it. **[App]** The app
  offers to retry or to send the legacy way, and says that the legacy way is not sealed.
- **[Open]** Pin expiry, and how a user clears a pin.

Epicbox (step 11): marker bit `NATIVE_SLATES` (bit 7, a claim like bits 0–6). A native
slate goes to a payments address only when the peer claimed the bit and is "LEPIC lately"
(ADR 0016), because a stock listener acknowledges only payloads that parse as a slate and can lose
its queue to one (ADR 0052, "Discovery" 3).

The carrier **[Specified]** (step 11):

- A wallet with native slates on puts bit 7 in the marker of every legacy slate it sends over
  Epicbox, and the public key of its Epicbox seal key (5.2, kind `03`) in the marker's `reply`
  field. With native slates off, the marker is as before: no bit 7 and no `reply`.
- A wallet with native slates on keeps the claim and the key per address from the latest marked
  slate. A later marked slate without the claim, or a claim whose key does not decode (5.4),
  clears it.
- A send goes native only when native slates are on, the peer is "LEPIC lately" and its latest
  marked slate claimed bit 7 with a valid key. The S1 is an envelope of type `0A` with the zero
  hint, sealed to that key under the Epicbox `info` (5.4), with tag `03` naming a reply key for
  this slate. It is armoured `BEGINEPICTX.` and posted to the payments address. Every other send is
  V2 or V3 JSON as before.
- A receiver always tries its Epicbox seal key on a `BEGINEPICTX.` text at its payments address.
  The S2 is a type `0A` envelope sealed to the request's tag `03` key and posted to the sender's
  payments address.
- Refused, with nothing stored: an envelope that does not open, a tampered envelope, and a native
  I1 to a payments address (invoices need a pairing, 6.10).

**[Reasoning]** Why this carrier:

- An envelope, because the plain pack is dropped (O-7).
- The key travels in a field the marker already has (`reply`, 5.16), so the marker gains no field
  and stock wallets ignore it as they ignore the rest of the marker.
- The key is kind `03`, separate from the epic1 seal key (`00`), so a payments address and an epic1
  of one wallet cannot be linked through a shared key.

### 5.16 LEPIC marker on legacy slates — **[Shipped]** (RFC 0002 §5), `crates/lepic-epicbox/src/marker/` on `main` (moved to `crates/lepic-transport/src/marker/` **[Unmerged]**)

```json
"lepic": {"version": 1, "reply": "<64 hex of reply_pk>"}
```

- Written as the last top-level key of a V3 S1 or I1 by `MarkedV3JsonCodec`. On Epicbox the
  marker carries feature bits (`"f"`, `marker/features.rs`): bit 0 `MARKER`, 1 `PAIR_REQUESTS`,
  2 `ADDRESS_PROOF`, 3 `STATUS_NOTICES`, 4 `DEVICE_FORWARDING`, 5 `NAME_SERVICE`, 6
  `APP_PAYLOADS`, 16–31 the host profile. These are claims; there is no even/odd rule.
- Stock `epic-wallet` drops unknown top-level keys (vector `slates/malformed_unknown_top_level_key`).
- A LEPIC receiver of a marked plain S1/I1 with a valid `reply` answers sealed and anonymous, with
  a V3 body (envelope type `01`), over the same channel. Over Epicbox it answers as before (the
  Epicbox cipher covers it).
- A malformed or small-order `reply` is ignored; the answer goes plain.
- The reply key authenticates nothing (RFC 0002 §5).
- **Frozen.** No new field is added (ADR 0052 table). Draft 1's D2 (a format list here, so the
  answer could be `lepic.v1`) is withdrawn (O-3, decided): it broke "a reply uses the format of its
  request", made the engine compare a native reply with a stored V3 request, and hid little,
  because the S1 was plain and the S2 is already sealed.

### 5.17 Bounds summary

| Object | Bound | Where |
|---|---|---|
| Armoured text | 96 KiB, before decoding | `armor.rs:9` |
| Envelope | 1 MiB | `envelope.rs:31` |
| **Envelope body (any sealed slate)** | **65,535 bytes**, the `u16` TLV length; this is the binding limit | `tlv.rs`, `Writer::field` → `FieldTooLong` |
| `FE` padding value | at most 65,535; at the largest body Padmé adds 1,840–2,039 zero bytes, depending on the other tags (1,891 for a signed envelope with tag `03`) | 5.7 |
| Largest slate envelope | 67,648 bytes (body 65,535, padded inner 67,584) **[Reasoning]** | 5.7 arithmetic |
| `POST /v1/peer/slates` body | 68 KiB (69,632) | 5.15 |
| Slate (any codec) | 8 MiB `MAX_WIRE_SLATE_LEN`, plus `MAX_TX_WEIGHT` on counts | `lepic-slate/src/codec/mod.rs:13` |
| Participant message | 256 B UTF-8 | RFC 0001 §2 |
| Legacy slate file read by the app | 1 MiB | `slate_files.dart`, `maxSlateFileBytes` |

**[Shipped]** fact: the 65,535 limit already applies to sealed V3 slates (type `01`). A V3 JSON
slate with a few hundred inputs cannot be sealed to a contact today: `Writer::field` returns
`FieldTooLong`, and no caller in `lepic-wallet` or `lepic-wallet-contacts` handles it.
**[Reasoning]** A `lepic.v1` I2 reaches the limit at roughly 1,900 payer inputs, so native raises
the ceiling a long way but does not remove it.

**When a slate is too large to seal** — **[Decided]** (O-9: ask the user, and offer fewer coins
or combining coins first; the asking is the app's, 3.2); flow **[Specified]** (draft 3).

The check runs when the wallet builds its slate (an S1, or the I2 of a payer), before anything is
stored or locked, as `TooHeavy` does today (`crates/lepic-ffi/src/api/error.rs`). LEPIC reports
it to the consumer and never falls back by itself; each choice below is a call the consumer makes.
**[App]** The app says "This payment needs too many coins to send sealed." and offers, in this
order:

1. **Use fewer coins.** Shown only when it works: the wallet selects again, largest coins first,
   and offers the result if it fits the limit. Today's strategies are `Smallest` and `All`
   (`crates/lepic-wallet/src/selection.rs:26`); this needs a third, used only for this offer.
   **[Specified]**
2. **Combine coins first.** A consolidation: a send to self that merges the smallest coins into
   one (`Wallet::send_to_self` with `SelfInputs::All`, shipped,
   `crates/lepic-wallet/src/self_send.rs`; the app's outputs screen already offers "Consolidate").
   It is a transaction of the wallet with itself, so no slate leaves the wallet and the seal limit
   does not apply. The fee and the weight limit do, and one consolidation spends at most 500
   coins (`max_outputs`), so a wallet with more may need several. The app shows the fee, posts
   it, and says the payment can go once the new coin has its confirmations; the user then sends
   the payment again. **[Reasoning]** Merging links those coins on chain, as spending them
   together in the payment would.
3. **Send unsealed**, where the method has a plain form: plain V3 to a contact (RFC 0002 §9.3,
   6.1 step 7), `/v2/foreign` to a listener (6.2). The app says it is not sealed. An epic1 has no
   plain form; there the choices are 1, 2 and cancel.
4. **Cancel.**

In person (5.18) the same check applies to every reply, since every reply is sealed (O-13). Online
the reply goes to a mailbox and the seal limit is the only bound. Offline an I2's animated code
grows by one frame for about every six payer inputs; the frame count at which the app offers fewer
or combined coins is **[Open]**.

Tests at the limit (65,535 and 65,536) for both body types. **[Reasoning]** An automatic fallback
would let a sender's coin count decide whether a payment is sealed, without the user knowing.
With the default 500-input selection window a `lepic.v1` slate rarely reaches the limit; a sealed
V3 slate (type `01`) reaches it with a few hundred inputs.

### 5.18 Slates in QR codes — **[Decided]** form (3.1, O-13, one scan online); framing **[Specified]** (drafts 3 and 4)

- In person, the first code carries the `lepic.v1` slate as it is (5.10): no pack, no armour, no
  envelope around it. Its tail always holds the one-time reply key (record `01`) and, when the
  showing wallet is online, its throwaway reply mailbox (record `02`) (O-13).
- Every reply is the binary envelope (type `0A`, anonymous, reply-key hint, 5.5) sealed to that
  reply key. Online it is posted to the reply mailbox over Epicbox (6.7); offline it is shown as
  an animated code. **Animated QR is the private face-to-face replacement for transaction files**:
  the reply is sealed, and nothing is left behind in a chat or a download folder.
- Framing: the app's QR transport `ur:epic-slate` (ADR 0025), animated, with fountain parts. Its
  payload today is deflated slate JSON, and its readers refuse anything else
  (`docs/compat/ur-epic-slate.md` "Payload"). **[Specified]** Payload version 2: the CBOR map
  `{1: 2, 2: <bytes>}`, the bytes being a `lepic.v1` slate (magic `89 45 53 4C`) or an envelope
  (magic `89 45 53 45`). The reader tells them apart by the fourth byte. Nothing is compressed:
  the slate is binary and an envelope is ciphertext. The UR layer is the transport the app already
  uses for every slate code; it adds no field to the slate.
- One code when the payload is at most 360 bytes (version 15 at L at most); longer payloads are
  animated 200-byte frames (version 11 at L, 6 frames a second, as shipped). **[Specified]** (draft
  4; draft 3 had 300.) The shipped encoder makes one code only up to 200 bytes; 360 keeps a
  first code with a TTL, a reply key, a reply mailbox and a short message as one static code
  (360 bytes are 752 characters of the 758 that v15 at L holds, checked with `segno`).
- Accepted from the camera only. A raw `lepic.v1` slate in a file, pasted text, a mailbox or an
  HTTP body is refused: everywhere else a native slate travels inside an envelope (5.10).
  **[Specified]**
- A raw I1 the payer scans is an invoice the payer started: no pairing is needed (3.1), and
  nothing pays without the user's approval (PIN).
- No payment proof in person **[Reasoning]**: the sender of an S1 does not know the receiver's
  proof key before the first scan, and the invoice flow has no proofs (5.10).
- Every in-person S1 and I1 sets a TTL, so a walk-away frees the inputs. **[Specified]** The
  expiry is the app's choice **[Decided]** (owner, 2026-11-09, replacing 15 blocks of 2026-11-08): the app
  passes its own TTL in blocks. LEPIC keeps the 10-block margin (the payer stops paying 10 blocks before the
  cutoff, 5.13), refuses a TTL at or under it, and falls back to 30 blocks for a caller that passes none
  (the CLI, tests).

Sizes, **[Reasoning]**: bytes from the 5.10 layout (the codec is not built, so these are computed,
not measured), a 20-character relay domain in record `02`, codes from the shipped UR framing
(bytewords, two characters a byte, CRC32), versions at level L in alphanumeric mode, computed with
`segno`:

| Code | Bytes | Frames | Version of each frame | As one code |
|---|---|---|---|---|
| S1 or I1 with TTL and reply key, offline (no record `02`) | 196 | 1 | v11 (61 × 61) | — |
| S1 or I1 with TTL, reply key and reply mailbox | 252 | 1 | v13 (69 × 69) | — |
| the same with a 6-character message | 324 | 1 | v15 (77 × 77) | — |
| the same with a 256-byte message | 574 | 3 | v11 | v20 |
| S2 sealed (offline reply) | 1,088 | 6 | v11 | v28 |
| I2 sealed, one payer input (offline reply) | 1,152 | 6 | v11 | v29 |
| I2 sealed, 10 inputs | 1,408 | 8 | v11 | v33 |
| I2 sealed, 50 inputs | 2,880 | 15 | v11 | does not fit |

Today, measured (`docs/compat/ur-epic-slate.md` "Worked example", the `send_file_plain`
vectors): a V3 S1 is 2,426 bytes of JSON and 7 frames; its S2 is 4,248 bytes and 12 frames.

So every first code with a message of up to about 40 bytes is one static code, and online that is
the only code; a longer message makes the first code animated (3 frames at 256 bytes). An offline reply needs
6 frames for an S2 and 6 and up for an I2, one more for about every six payer inputs. A reply as
one code would be version 28 or more, too dense to read from a phone screen with another phone.
**[Reasoning]** Draft 3's raw S2 and I2 rows are gone: no reply travels raw (O-13).

---

## 6 Flows

Each flow states what is shipped. "Seal to K" means build an envelope with recipient key K. Section
3.1 says which flow serves which situation; in person is 6.7 and 6.8, payment codes are 6.3 and
6.9, files are 6.1 and 6.4.

### 6.1 Paired contact (step 6)

Shipped today with V3 JSON bodies (RFC 0002 §9). Native adds type `0A`.

1. Sender A has contact B's card: `enc_pk`, `sig_pk`, `hint_key`, mailbox, caps (RFC 0002 §6.1).
2. A builds the S1. If both cards claim native slates, the body is `lepic.v1` (type `0A`);
   otherwise V3 JSON (type `01`).
3. A seals to B's `enc_pk`, hint `HMAC(hint_key, enc)[0..8]`, signed with A's `sig_sk` for B,
   tags `08`, `80`, padding `FE`, `FF`.
4. A posts it to B's contact mailbox on B's home relay (an Epicbox mailbox keyed per contact), or
   writes it as a file or text: `BEGINEPICTX.` for type `0A`, `BEGINEPICSEALED.` for type `01`
   (5.11, O-4).
5. B opens it (5.9), attributes it to A's record, runs the engine, and seals the S2 back to A's
   per-contact key, signed, on the same channel, in the request's format.
6. A checks the S2 against its stored S1 (RFC 0001 §11), finalizes and posts the transaction.
7. If B cannot open sealed messages, A's app offers "Send as plain instead": the same stored
   slate in plain V3, never a second transaction (RFC 0002 §9.3).
8. A slate too large to seal (5.17) is not stored; the app offers fewer coins, combining coins
   first (a send to self), plain V3, or cancel (O-9).

### 6.2 Direct HTTP or Tor peer — **[Specified]**

Step 10 (O-12: after contacts, in person and epic1).

1. A calls `check_version` on B's listener, as stock does.
2. No `lepic` key and no pin for this origin → legacy `receive_tx` with V2 (V3 from step 12).
   Stop. No `lepic` key but a pin → stop and report; the app asks (5.15).
3. `lepic` key present: A compares `seal` with any pin for this origin and account (5.15). A
   different key → stop and report, on every kind of address; the app asks (D1, O-10).
4. A builds a `lepic.v1` S1 and seals it to the advertised key, anonymous, zero hint, with tag
   `03` = A's reply key for this slate.
5. A posts the binary envelope to `/v1/peer/slates`.
6. B opens it with the seal key of the socket that accepted it, runs the engine, seals the S2 to
   `03`, returns it in the `200` body. An envelope that key does not open is tried with B's
   issued epic1 seal keys (5.5); one that opens is a payment to that epic1 address and index, and
   its proof is signed with that index's epic1 proof key.
7. A opens with its reply key, checks the S2, finalizes, posts.
8. Any error or reset at step 5 or 6 from a pinned peer → stop and report; the app asks; never a
   silent legacy retry (5.15).
9. If A wants a payment proof, the receiver address in the slate must be B's proof key for that
   listener: the onion key on the onion (ADR 0044), the index-0 proof key otherwise. B refuses a
   proof for another key (`ForeignProofAddress`).
10. A slate too large to seal (5.17): fewer coins, combine first, `/v2/foreign` unsealed, or
    cancel (O-9).

### 6.3 epic1 link — **[Decided]** model (O-14 as replaced); detail **[Specified]** (draft 4)

Step 8, after the payee-shows-I1 codes (4.1).

1. B's wallet issues a link for one of its epic1 addresses, index 0 unless B picks another it
   issued (5.13): it takes the next link-mailbox index `n` (5.2), writes
   `epic:<B's epic1>?epicbox=<link mailbox>@<B's relay>` with amount and message if set, and
   stores `n` with the address index. A code shown on screen gets a new `n` per receive session, and per share or copy;
   a printed code keeps one from its own index space (5.2, 10.14). B's wallet watches each issued mailbox: live while its code is on screen, by
   draining otherwise (one socket per live address, one draining socket for the rest:
   `docs/compat/epicbox.md` facts 4 and 6).
2. A scans or opens the link from B's "More" screen, a message or a web page. A's app shows B's
   epic1 as the payee, never the mailbox. A link with no usable transport field is "cannot pay
   this code" (5.14).
3. A builds a `lepic.v1` S1 with a TTL (5.13), optionally with `PROOF` and the proof key of B's
   epic1 as receiver address (O-8). Too large to seal: fewer coins, combine first, or cancel (5.17).
4. A seals it to the seal key in B's epic1: anonymous, zero hint, tag `03` = A's reply key for this slate,
   tag `09` = A's reply mailbox for this slate on A's own relay (5.2), padding to the floor (5.7).
5. A posts the armoured envelope (`BEGINEPICTX.` text as the Epicbox plaintext, as contact
   mailboxes carry armour, RFC 0002) to the first usable `epicbox=` entry, from A's post key for
   this slate (5.2). The relay comes from the link, so the host rule applies (5.14 "Hosts from
   untrusted input"). If that relay cannot be reached or refuses, A tries the next entry, at most
   three (5.14). A then watches its reply mailbox. **[App]** A's app shows a waiting state with
   "Cancel and unlock" from the start; after some minutes with no answer it has LEPIC post the
   same sealed S1 to the next entry (5.14 "No answer").
6. B drains the link mailbox, opens the envelope with the seal key of the address index stored
   with that mailbox (5.5, 5.9), records the index with the transaction, and runs the engine. A
   proof is signed with that index's epic1 proof key. B seals the S2 to tag `03` (reply-key hint), and posts it to the mailbox in tag `09`,
   through the relay that tag names, from B's post key for this slate. That relay is a host from
   untrusted input: LEPIC reports it with its relay-list flag and address class and posts only
   when B's app says so; the app asks B about a relay not in B's own relay list (5.9, 10.15). B
   never answers to the Epicbox `from` (5.9). An S1 that came to two mailboxes is answered once.
   When the engine refuses the S1 because its amount is not the one the link issued, B seals a
   `declined` Notice (type `02`, anonymous, JSON body with `slate_id` and `reason` `amount`) to
   the same reply key and posts it armoured (`BEGINEPICSEALED.`) to the same mailbox, but only
   to a relay in B's own relay list; ADR 0045.
7. A collects the reply mailbox. An S2 (`BEGINEPICTX.`) is opened with the reply key, checked
   against the stored S1, finalized and posted, whenever both have been online. A sealed
   envelope is opened with the same key and accepted only as a `declined` Notice for this slate
   while the send is `sent` with no S2: A cancels the send, frees its inputs and reports the
   refusal once. If B never answers, the TTL frees A's inputs (24 hours by default, 5.13), or A
   cancels and unlocks earlier.
8. An anonymous I1 sealed to an epic1 is refused (5.9). There is no invoice window (6.10).

### 6.4 Unknown receiver (no key known) — **[Shipped]**, unchanged

1. A writes a marked V3 S1 file (`<id8>.tx`) with `"lepic":{"version":1,"reply":"<reply_pk>"}`.
2. Stock receiver: ignores the marker, answers a plain V3 S2 (`<name>.response`). A finalizes.
3. LEPIC receiver: answers an anonymous envelope, type `01`, V3 S2 body, sealed to `reply_pk`, as
   `BEGINEPICSEALED.` text or a `.epicsealed` file (shipped; kept, O-4).
4. The S1 is plain: the carrier reads it, including the sender's inputs and change outputs (V3
   carries them).
5. Draft 1's D2 (a `lepic.v1` answer here) is withdrawn (5.16, O-3).
6. A stock wallet's own `saved_txs/*.epictx` records are not payment files; readers tell them
   apart by content (5.12).

### 6.5 Stock wallet interoperability — **[Shipped]**, unchanged

- Stock sender → LEPIC listener: `/v2/foreign` V2/V3 as today.
- LEPIC sender → stock listener: no advert → legacy.
- Epicbox to a stock payments address: V2 JSON as today; no native without the marker bit.
- Files to stock: marked V3; answers plain.
- Links: stock readers pay the Epicbox link as today, and refuse an epic1 link as an unknown
  address (5.14).
- Stock wallets never receive an envelope, card, invite or notice (RFC 0002 §16).

### 6.6 Exchange

Two cases.

- **Stock exchange** (runs `epic-wallet`): deposits and withdrawals over HTTP(S) `/v2/foreign` and
  Epicbox, V2/V3. Unchanged. **[Shipped]**
- **Exchange using the RFC 0002 reference kit** (a paired service, RFC 0002 §12–13): pairing bound
  to a logged-in account; `fixed-hint` cap; deposits are invoices (I1) the user's wallet takes from
  the service's mailbox, sealed and signed; withdrawals are S1s to the user. Shipped with V3
  bodies. Native type `0A` would follow when both claim native slates. **[Open]** The kit is
  Python (RFC 0002 OD-P4) and would need its own `lepic.v1` codec.

### 6.7 Face to face, two phones — **[Decided]** model (3.1, O-13, O-16 as rewritten in draft 6); detail **[Specified]** (drafts 4 and 6)

LEPIC to LEPIC, no contacts assumed. Two directions, in two rollout steps (4.1): the payee shows an
I1 and the payer scans it (step 7); the payer shows an S1 and the payee scans it (step 9, only
after the check-code confirmation below is designed in the app and reviewed).

**LEPIC's part, both directions** **[Decided]** (owner, 2026-11-09).
LEPIC accepts and processes raw in-person codes and their answers. It never finalizes an
in-person answer by itself:

- It closes the code on the first answer that checks against the stored slate (RFC 0001 §11).
- It reports every answer to the consumer with its check code, four digits from
  `SHA-256("epic-check/1" || receiver public excess)` (Appendix A). **[Specified]** (draft 5) The
  four digits are the first 4 bytes of the hash read as a big-endian number, modulo 10,000,
  written with leading zeros; the excess is the 33-byte compressed point.
- When a later answer has the same check code as the first, it reports that too.
- It finalizes only when the consumer calls finalize for the answer it chose.

**Payee starts (step 7).** Online, one scan:

1. Bob, receiving, enters the amount. His wallet builds a `lepic.v1` I1 with a TTL (5.18), tail
   record `01` (his one-time reply key) and record `02` (his throwaway reply mailbox on his relay,
   5.2), stores it and shows it as one static code.
2. Alice scans it. Her wallet shows the amount and Bob's message and pays only on her approval
   (PIN). It builds the I2, seals it to the reply key (type `0A`, anonymous, reply-key hint) and
   posts it, armoured, to the reply mailbox from her post key for this slate (5.2). The relay is a
   host from untrusted input (5.14 "Hosts from untrusted input"): LEPIC reports it, and Alice's app
   asks her about a relay that is not in her own relay list; rejected, the I2 is shown as a code
   (step 4).
3. Bob's LEPIC opens the I2, checks it against the stored I1 and reports it. **[App]** Bob's app
   finalizes (I3) the first I2 and posts it: whoever sent it, it pays Bob.
4. Offline, two scans: Alice's phone shows the sealed I2 as an animated code (6 frames with one
   input, 5.18) and Bob scans it.

**[Reasoning]** An onlooker who films Bob's I1 can only pay Bob. If its I2 comes first, Bob is paid
by the onlooker and Alice's I2 is a second answer that is never finalized; Alice's inputs are freed
by the TTL or when she cancels. Nobody loses money, so no confirmation is needed in this direction.

**Payer starts (step 9).** Online, one scan:

1. Alice, paying, enters the amount and confirms it once. Her wallet builds a `lepic.v1` S1 with a
   TTL and no proof (5.18), with tail records `01` and `02`. It stores the S1, locks her inputs,
   subscribes to the reply mailbox on a socket of its own, and shows the S1 as one static code.
2. Bob scans it. His wallet shows the amount and Alice's message; receiving needs no approval
   beyond the scan. LEPIC builds the S2 and seals it to the reply key. Before posting it reports
   Alice's relay (host rule, 5.14); Bob's app posts at once to a relay in Bob's own relay list, and
   otherwise shows its domain and asks Bob to accept or reject it, through Tor when Bob has Tor
   (5.9, 10.15). Rejected, the answer is shown as a code (step 5). After posting, Bob's screen
   shows the check code and offers "Show code instead". Bob's phone shows its check code only
   after it has posted.
3. Alice's LEPIC receives the S2, opens it with the reply key, checks it, closes the code and
   reports the answer with its check code. It finalizes only when her app says which answer.
4. **[App]** (to explore in the wallet app) Alice's app asks her to confirm the check code before
   finalizing: "Does Bob's phone show 4821?", one tap. Yes: the app has LEPIC finalize that answer
   and post it. No: nothing is finalized and the app waits for the next answer, or Alice cancels.
   When two answers share one check code, the app cancels both and shows a new code with a new
   reply key and reply mailbox for the same payment. A short hold before the question and the
   warning "Another phone answered this code" for a later answer may stay as extras. Draft 5's
   goal of no extra tap in the normal case is withdrawn.

Offline fallback, two scans:

5. If either phone has no network, Bob's phone shows the sealed S2 as an animated code (6 frames,
   5.18), and Alice scans it. A first code built offline has no record `02`; Bob's wallet then
   shows the animated code at once. **[App]** An answer Alice scanned from the phone in front of
   her comes from that phone; whether the app still asks the question is to explore in the wallet
   app.
6. If Alice's code has closed before an S2 arrives, her wallet drains the reply mailbox until the
   TTL (the app's choice, 30 blocks by default, 5.18). If no S2 ever comes, Alice cancels, or the TTL frees her
   inputs.

Onlookers: anyone who films the first code learns the amount, the message, the requester's keys,
its reply key and its reply mailbox (7.1). The reply is sealed, so they do not learn the other
side's output from it.

**Why the payer confirms** **[Reasoning]** The reply key and mailbox are
in a raw code, so an onlooker who films Alice's S1 can build an S2 of its own, seal it to the same
key and post it to the same mailbox, perhaps before Bob. Draft 5 finalized the first answer after a
5-second hold and showed the check code only when a second answer came within the hold, so an
onlooker who answered first and alone was paid. With the confirmation:

- An onlooker that answers before Bob has posted cannot know Bob's code, which his phone shows only
  after posting. It can choose its own excess and so its own code, but must guess Bob's: 1 in 10⁴.
- An onlooker that waits to see Bob's code, and grinds an excess to match it, arrives after Bob
  with the same code. LEPIC reports the match and the app cancels both.
- The code is 4 digits and the receiver picks its excess, so the code alone is no proof of who
  answered; the order above is what bounds the guess (10, "Check-code grinding").

### 6.8 Paypoint — **[Decided]** model (3.1, O-13, one scan); detail **[Specified]** (draft 4)

A shop terminal that shows codes and scans back. The first code always carries a one-time reply
key (tail record `01`, 5.10; key from 5.2), and the reply is sealed to it. The paypoint's mailbox
is on its own domain. One scan online, two offline. A hacked or impostor paypoint is out of scope
(7.3).

Paypoint starts (invoice), rollout step 7. This is the only way a paypoint asks for money
(owner, 2026-11-09):

1. The paypoint shows an I1 with a TTL, tail record `01` (its reply key) and record `02` (a
   mailbox on the paypoint's own domain; a LEPIC paypoint derives it as a reply mailbox, 5.2):
   one code.
2. The payer scans it: an invoice the payer started by scanning, so no pairing is needed (6.10).
   The wallet shows the amount and the shop's message and pays only on the user's approval (PIN).
3. The payer's wallet builds the I2, seals it to the reply key and posts it to the paypoint's
   mailbox from a post key; offline, it shows it as an animated code (6 frames with one input, one
   more for about every six inputs, 5.18).
4. The paypoint opens it, checks, finalizes (I3) and posts. As in 6.7, LEPIC reports the I2 and
   the paypoint's software finalizes the first one, which pays the paypoint whoever sent it.

Payer starts, rollout step 9: exactly 6.7 "Payer starts", with the check-code confirmation. The
payer's phone cannot tell a friend's phone from a terminal, so it shows the same S1, with reply
key and reply mailbox. The paypoint scans it, posts the sealed S2 to the reply mailbox (or shows
it as an animated code), shows its check code, and the payer's app asks the payer to confirm it
before finalizing.

No invoice is pushed to an address the customer shows: draft 5's invoice window is removed
(6.10).

### 6.9 Payment code or link over Epicbox — **[Shipped]**; native carrier **[Specified]** (5.15)

1. B's receive screen shows the plain Epicbox link (3.1, 5.14), with an amount and a message if B
   set them.
2. A scans or opens it, and the app fills in the send. A sends over Epicbox to B's address: V2
   JSON as today, or native once step 11 is on and B is "LEPIC lately" with the bit
   claimed (5.15). Epicbox encrypts it between the two wallets.
3. B answers when it is online. A finalizes when the S2 arrives, under the shipped expiry rules.

### 6.10 Invoices: who started it — **[Decided]** (3.1; owner, 2026-11-09)

| How the invoice arrives | Rule |
|---|---|
| The payer scans it in person (face to face, paypoint) | No pairing needed. Paid only on approval (PIN). (6.7, 6.8) |
| Pushed uninvited: Epicbox, a mailbox, a link | Needs a pairing with "Allow invoices" on, the contact verified (RFC 0002 §11, shipped). An address-based invoice path was removed (RFC 0002 §11.5). |
| A file the user opens | The shipped handling, unchanged (RFC 0002 §11.5: "issuing by file is unchanged"). |

No invoice is ever pushed to a receive code. Draft 5's invoice window (O-15: up to 3 invoices from
non-contacts at the code on screen and for 2 minutes after) is removed. A paypoint asks for money
only by showing its own I1, which the payer scans and approves with the PIN (6.8). Uninvited
invoices from non-contacts are refused as before; contacts with "Allow invoices" keep the shipped
rule. **[Reasoning]** The window let anyone who saw a code, or knew a
fixed Epicbox address, put invoices on the payer's approval screen at the moment the payer
expected one; a scanned I1 comes only from the screen the payer is facing.

**Covered sticker codes** **[Reasoning]** (residual risk, 10). A printed code can be covered by
another sticker. The payer then pays whoever printed the top one. As with any QR payment, the
payer checks the amount and the merchant before entering the PIN. **[App]** Where the payee has a
merchant domain claim (ADR 0043), the app shows it larger than the payee's message, so a message
cannot pose as the merchant.

---

## 7 Threat model

Assumptions: the device and seed are not compromised (RFC 0002 §15 "Compromised phone": out of
scope). HPKE base mode is IND-CCA2 for the recipient. Ed25519 is EUF-CMA. Mimblewimble partial
signatures and payment proofs bind the parties to a transaction (RFC 0001 "Security and
privacy").

### 7.1 Per party

| Party | Can learn | Can do | Cannot do |
|---|---|---|---|
| **Carrier** (chat, e-mail, drive) of an EPICTX | Network byte, suite, version, hint, `enc`; padded size (5.7); timing. A zero hint says "sealed to an address or listener key". With the 768 B floor (O-6) every sealed S1 is one size, so the size no longer says whether an S1 asks for a proof or how long its message is. For a reply-key hint: links the S2 to the S1 only if it saw the S1's `reply_pk`. | Drop, delay, replay (deduplicated on `(slate_id, stage)`). Seal its own anonymous S1 to a public epic1 key (spam). | Read amounts or keys; modify (AEAD with header as AAD); forge a signed contact envelope; get an anonymous invoice paid (5.9). |
| **Carrier** of a marked legacy file (6.4) | The whole V3 S1: amount, sender inputs and change outputs, `reply_pk`. | Replace `reply_pk` and read the S2 (RFC 0002 §5: no worse than before). Answer as the receiver with its own S2, so the sender pays the carrier, unless the sender required a payment proof to a key it trusts. **[Reasoning]** | Make a stock receiver answer sealed. |
| **Whoever hands the payer a link or code** | — | Replace the whole address, Epicbox link or epic1 link, as with any address today; the user's check of the address catches it as it does now. Replace only the `epicbox=` mailbox with its own: it then receives an S1 it cannot open, sees the payer's post key, IP address and timing, and can drop the S1, which the TTL frees (5.14, 7.1). | Mix two identities in one code: no code carries both an Epicbox address and an epic1 (3.1), and a link mailbox is never shown, paid or answered as an address (5.14). Open an S1 posted to its mailbox. |
| **Onlooker** in person (a camera, someone in the queue) | The raw first code: amount, messages, the requester's public keys, its reply key and its reply mailbox with the relay's domain. Replies are sealed. | Post its own answer to the reply mailbox before the real receiver. LEPIC never finalizes it by itself; it reports it with its check code, and the payer's app asks the payer to confirm the code shown on the receiver's phone (O-16 as rewritten, 6.7, 10.16, 10.19). Pay a filmed I1 itself (the payer loses nothing). Post junk to the reply mailbox. **[Reasoning]** | Read or change a sealed reply; complete a slate the payer did not store (RFC 0001 §11). |
| **Relay of a link mailbox** (the payee's relay, or a paypoint's own domain) | Which link mailbox receives messages, when, their sizes, the poster's IP address and post key. Through a printed code's single mailbox it links every payment made with that code (10.14). | Drop, delay, replay, deny service. | Open envelopes (sealed to the epic1's seal key); find the epic1 from the mailbox (neither is derived from the other). |
| **Relay of a reply mailbox** (named by the payer) | That one mailbox got an answer, when, its size, the answerer's IP address and post key (10.15). LEPIC reports the relay before it posts; the payee's app connects to a relay outside its user's relay list only after the user accepts it, through Tor when the user has Tor (5.9, 5.14). | Drop, delay, replay; the payer's TTL frees the inputs. | Open the answer (sealed to the reply key). |
| **Relay** (Epicbox), payments addresses and contacts | Epicbox addresses or per-contact mailbox keys, timing, sizes of Epicbox-encrypted payloads. | Drop, delay, replay, deny service (RFC 0002 §15). | Read or forge envelopes. |
| **Exchange** as paired service | What a party to the transaction learns: amounts, its own outputs, the user's account binding, the user's payments address if the card carries it. Its `fixed-hint` links its envelopes. | Send invoices if the user allowed it; spam its own mailbox within limits. | Spend without the user's PIN; reuse its address proof elsewhere (a designated-verifier MAC, ADR 0034). |
| **Network observer**, plain HTTP | Today: the whole V2 JSON slate. Native: the advert (formats, seal key), IP addresses, envelope size and timing. | — (passive) | Read amounts in a native exchange. |
| **Network observer**, Tor or HTTPS | Tor or TLS metadata. | — | Read the advert or the slate. |
| **Active MITM on first contact**, plain HTTP | Everything. | Strip the advert → legacy, as today. Replace the seal key → it opens the S1 and can answer as the receiver; the wrong key is pinned. **[Reasoning]** Without a payment proof bound to a key the sender got elsewhere, the sender cannot tell. | Get past a pin silently: a changed key, a missing advert or an error from a pinned peer makes LEPIC stop and report, and the app ask (5.15). |
| **Active MITM**, onion | — | Deny service. | Impersonate: the onion address authenticates the listener (ADR 0052 "Downgrade"). |
| **Active MITM**, HTTPS | — | With a mis-issued certificate, the plain-HTTP row applies on first contact. | Change a pinned key silently (D1 stops and reports on HTTPS too, O-10). |
| **MITM on the channel that delivers a link or epic1** | — | Replace the whole link or address, as with any address today; or only a transport field, which makes delivery fail (5.14). | Make the payer pay anyone but the epic1 the link shows. |
| **MITM on pairing invites** | — | Swap keys. | Pass the commitment and SAS check (RFC 0002 §7.5). An unverified pairing cannot authorize invoices. |

### 7.2 Properties claimed

- **Confidentiality** of native slates against carriers, relays and passive observers (HPKE).
- **Integrity** of header and content (AEAD with header as AAD; signature for contacts).
- **Sender authentication** only between paired contacts (signature over header, recipient key
  and fields). Anonymous envelopes authenticate nothing; the slate proves itself by answering a
  stored slate or by its partial signatures (RFC 0002 §3.3). Anonymous invoices are refused;
  there is no invoice window (6.10).
- **Recipient binding** of signatures (recipient key in the signed input).
- **Network separation**: `net` in the envelope header, HPKE `info`, contact root, seal-key
  context, the slate's own network byte, and the address prefix.
- **Key-class separation**: shipped envelopes, epic1-sealed envelopes and listener-sealed
  envelopes use different HPKE `info` strings (5.4), so an envelope opens only under the key class
  it was sealed for.
- **Sender-side forward secrecy** only: fresh ephemeral per envelope. A leak of a recipient's
  static key opens every past message to it (RFC 9180 §9.7.4; RFC 0002 §15 "Forward secrecy").
  All static keys come from the seed.
- **Replay**: idempotent on `(slate_id, stage)`; signed contact messages also carry `80` sent-at.
- **Unlinkability**: listener seal keys differ from the epic1 key and from each other and are
  chosen by socket, so an advert does not link an onion to a web listener or to an Epicbox
  identity. The epic1 carries no index-0 key (O-8), so it does not link the previous onion
  (ADR 0044). No link or code puts the epic1 and the Epicbox address together (3.1); a user who
  shows both codes links them for whoever sees both. Reply mailboxes and post keys are new for
  every slate, and link mailboxes new for every receive session or share shown on screen (5.2), so a relay
  cannot join payments by mailbox, except through a printed code or an on-screen index used again
  after 50 sessions (10.14). No mailbox key is the index-0 key.
- **epic1 addresses of one account**: each index has its own proof key and seal key, and the
  address carries no index, so two addresses of one account look like two wallets to whoever holds
  both. Envelopes to them all carry the zero hint, so a relay or carrier cannot sort payments by
  address (5.5). What still joins them: link mailboxes are numbered per account, not per address
  (5.2), and they all sit on the payee's relay; the payee's answers come from the payee's IP
  address; and a payment proof names the address it was signed for, as any proof does.
- **Length hiding**: Padmé buckets above the 768 B floor (5.7, O-6): every sealed S1 is one size,
  so its length shows neither "proof requested" nor the message length. This concerns sealed
  slates only; no sealed S1 is shown as a code (5.7).
- **Delivery cannot redirect payment**: an epic1 link's transport fields decide where a sealed S1
  is posted, never who can open it or who is paid; answers go only to the sealed reply mailbox,
  never to the Epicbox sender (5.9, 5.14).
- **No downgrade between contacts**: sealing is policy, not a strippable signal (RFC 0002 §15).
  No silent downgrade for pinned direct peers (5.15).

### 7.3 Not claimed

- Anonymity of the sender towards the receiver in a transaction (they build it together).
- Protection of plain legacy flows (6.4, 6.5) beyond today.
- Post-quantum confidentiality until suite `02` exists. Recorded envelopes could be opened later
  ("harvest now, decrypt later"); that exposes amounts and the transaction graph, not funds.
  NIST IR 8547: ECC deprecated after 2030, disallowed after 2035.
- Recipient-side forward secrecy.
- Confidentiality of the first in-person code, face to face or at a paypoint (3.1, 5.18). Its
  replies are sealed (O-13).
- That the first answer to an in-person code comes from the intended receiver: anyone who read
  the code can answer it. LEPIC does not finalize any in-person answer by itself, and the
  app's check-code confirmation bounds the race to a 1-in-10⁴ guess (O-16 as rewritten, 6.7,
  10.19).
- Hiding the payee's IP address from a relay the payer named (10.15).
- Protection against a hacked or impostor paypoint (3.1), or a printed code covered by another
  sticker (6.10, 10.21).

---

## 8 Compatibility and migration

From ADR 0052 "Existing installs" and RFC 0002 §16.

- **Stock wallets** see nothing new except an ignored `lepic` key in `check_version` answers and
  ignored marker keys. They refuse an epic1 link as an unknown address (5.14).
- **Older LEPIC builds** do not advertise, so they get legacy. They skip `FE` padding (ignored
  range). They read `BEGINEPICSEALED.` but not `BEGINEPICTX.`, and do not know type `0A` (refused
  as malformed). Senders therefore use `0A` and `BEGINEPICTX.` only for peers that claimed native.
  Under O-4, sealed V3 slates keep `BEGINEPICSEALED.`, so an older LEPIC sender can still read a
  new receiver's sealed answer to its marked file.
- **Installed wallets**: stored `transport` and `codec` strings, saved addresses (including the
  previous onion of ADR 0044) and settings keep their meaning. A transaction in flight at an
  update finishes in its starting format (resends use stored bytes). Native keys come from the
  seed, so a restore needs no migration. Pins are new data and start empty.
- **FFI**: existing items keep their names; new names are added beside them.
- **Default off** for one release: endpoint served and advert sent, native sending only with the
  host policy switch, until interop and acceptance runs cover it.
- **Readers keep accepting** `BEGINEPICSEALED.` permanently.
- **RFC 0001's freeze**: vectors and fuzz targets before native is on by default. After the freeze
  a change is a new codec id or a tail record.

---

## 9 Implemented vs specified

Paths are in the LEPIC repository at `main` `078eadb7` unless marked otherwise.

| Part | Status | Where |
|---|---|---|
| RFC 0002 envelope, HPKE base and PSK (suite `41`), signed/anonymous, opening rules | **[Shipped]** | `crates/lepic-contact/src/{envelope,tlv,hint,keys,private}.rs` |
| `BEGINEPICSEALED.` armour, `.epicsealed`, 96 KiB bound, typed checksum error | **[Shipped]** | `crates/lepic-contact/src/armor.rs` |
| Contact keys, reply keys | **[Shipped]** | `crates/lepic-wallet-contacts/src/key_schedule.rs` |
| Sealed slates to contacts and sealed answers to marked files | **[Shipped]** | `crates/lepic-wallet-contacts/src/sealed.rs` |
| Marker with reply key, `MarkedV3JsonCodec`, feature bits | **[Shipped]** at `crates/lepic-epicbox/src/marker/`; moved to `crates/lepic-transport/src/marker/` **[Unmerged]** | bit 7 `NATIVE_SLATES` claimed in a pairing only while `native_direct` is on **[Unmerged]** (`feat/native-contacts`, step 6) |
| Native slates in paired-contact mailboxes (6.1, step 6): `lepic.v1` in type `0A` when `native_direct` is on and the contact claims bit 7, replies in the request's format, `BEGINEPICTX.` text | **[Unmerged]** `feat/native-contacts`, off by default (`native_direct = false`) | `crates/lepic-wallet-contacts/src/native.rs`, `crates/lepic-wallet/tests/contact_native.rs` |
| ADR 0033 namespace construction, onion key | **[Shipped]** | `lepic_wallet::namespace` |
| `api tls v1` namespace key | **[Unmerged]** | `feat/wallet-methods` only (ADR 0033 row "unreleased") |
| Methods refactor (ADR 0050, 0051) | **[Unmerged]** | `feat/wallet-methods` at `c100d2bc`; `crates/lepic-methods/` exists only there |
| Vectors | **[Shipped]** | `testdata/vectors/pairing/` (`hpke_rfc9180_a2.json`, `contact_keys.json`, `reply_keys.json`, `envelopes.json`, `malformed.json`, …), `testdata/vectors/keys/` |
| HPKE dependency | **[Shipped]** `hpke` 0.14.1 | `Cargo.toml:70` |
| Onion on its own socket | **[Shipped]** | `crates/lepic-tor/src/listen.rs` |
| `lepic.v1` codec | **[Specified]**, no code | RFC 0001 §1–4, ADR 0012, 5.10 here |
| Amendments (network, kernel features, header version, tail) | **[Specified]** here at fixed positions; not yet in RFC 0001 | 5.10 |
| Plain pack | Dropped (O-7); RFC 0001 §5 to be amended | 5.10 |
| Tail records `01` reply key and `02` reply mailbox | **[Specified]** (drafts 3 and 4), not built | 5.10 |
| Envelope tag `09` reply mailbox | **[Specified]** (draft 4), not built; tag unused at `main` | 5.6 |
| Reply mailbox, post key and link mailbox keys | Labels and contexts **[Specified]** (draft 4, Appendix A), not built, no vectors | 5.2 |
| Type `0A`, padding `FE`, `BEGINEPICTX.`, EPICTX file and its no-clash rule | **[Decided]** (D3, O-2, O-4), not built | 5.6, 5.11, 5.12 |
| Slates in QR codes: `ur:epic-slate` payload version 2 (raw `lepic.v1` or an envelope), one code up to 360 bytes; one scan online, the sealed reply animated offline | Model **[Decided]** (3.1, O-13), framing **[Specified]**, not built | 5.18, 6.7, 6.8 |
| Invoice window | Removed in draft 6 (owner, 2026-11-09); never built | 6.10 |
| In-person answers: closed on the first, each reported with its check code, finalized only on the consumer's call; the app's check-code confirmation | LEPIC part implemented **[Unmerged]** on `feat/in-person-invoice` (invoice codes) and `feat/in-person-send` (send codes): `crates/lepic-wallet-contacts/src/in_person.rs`, `lepic in-person`, `/v1/in-person/…`; app part **[App]**, to explore in the wallet app | 6.7 |
| Hosts from untrusted input: report host, relay-list flag and address class; post on the consumer's word, through Tor when configured; loopback refused on the resolved address | **[Decided]** (O-17), address classes **[Decided]** (O-18); implemented for in-person posts **[Unmerged]** on `feat/in-person-invoice`: `lepic_transport::host_rule`, `Connector::connect_untrusted` in `crates/lepic-epicbox/src/session.rs` | 5.14 |
| epic1 send with no answer: the same sealed S1 to the next entry on request, cancel and unlock | **[Decided]** (owner, 2026-11-09), not built | 5.14, 6.3 |
| Default TTLs (epic1 send 24 hours, in person the app's choice, fallback 30 blocks), link-mailbox index spaces, restore and watch time, hyphens in relay domains | **[Decided]** (after drafts 4 and 5), not built | 5.2, 5.9, 5.13, 5.14, 5.18 |
| Per-class HPKE `info` | **[Specified]** (draft 2), not built | 5.4 |
| Seal key `lepic-wallet seal key v1`, and `lepic-wallet epic1 seal key v1` for epic1 indexes 1 and above | **[Decided]** label, context **[Specified]**; the index label implemented **[Unmerged]** on `feat/epic1-indexed-keys`: `crates/lepic-wallet/src/namespace.rs`, vectors `pairing/seal_keys.json`, `pairing/epic1_seal_keys.json` | 5.2 |
| epic1 proof key, and `lepic-wallet epic1 indexed proof key v1` for indexes 1 and above | **[Decided]** (O-8), context **[Specified]**; the index label implemented **[Unmerged]** on `feat/epic1-indexed-keys`, vectors `keys/epic1_proof_key_seed32`, `keys/epic1_proof_key_seed16`, `keys/epic1_indexed_proof_key_seed32`, `keys/epic1_indexed_proof_key_seed16` | 5.2 |
| Numbered epic1 addresses: issue, list, address at an index; zero hint, link mailbox to index, trial decryption elsewhere; index per payment; restore gap of 50 | **[Decided]** (owner, 2026-11-10); implemented **[Unmerged]** on `feat/epic1-indexed-keys`: `crates/lepic-wallet/src/epic1_index.rs`, `crates/lepic-wallet-contacts/src/epic1.rs`, `sealed.rs`, `direct.rs`, `lepic address`, `new-address`, `addresses` | 5.5, 5.13, 6.3 |
| epic1 two-key address | **[Decided]**, layout **[Specified]**, not built; `bech32` not in workspace dependencies | 5.13 |
| `check_version` advert, `/v1/peer`, pinning | **[Specified]**, not built | 5.15 |
| Two separate links, the epic1 link with transport fields, the receive screen | **[Decided]** (3.1, O-14 as replaced), grammar **[Specified]** (Appendix B), not built | 5.14; app `app/lib/src/scan/scan_router.dart` |
| Epicbox relay for link and reply mailboxes | Protocol **[Shipped]** (Epicbox 3.0.0); no relay change needed | `docs/compat/epicbox.md` |
| Handling of `FieldTooLong` when sealing | Not handled today; flow **[Decided]** (O-9), not built; a largest-first selection strategy is needed | 5.17 |
| Consolidation (send to self) | **[Shipped]** | `crates/lepic-wallet/src/self_send.rs` |
| CLI JSON view of an EPICTX | **[Decided]**, not built | — |
| Fuzz targets for slate, envelope, armour | Required before default-on | — |

---

## 10 Known weaknesses

1. **First contact over plain HTTP is unauthenticated.** An active attacker can strip the advert
   or substitute the seal key. Native is no worse than legacy here, but a substituted key is then
   pinned. Only a payment proof to a key obtained elsewhere detects a fake receiver.
2. **No recipient-side forward secrecy.** Static seal keys, contact keys and listener keys open
   every past envelope to them. All derive from the seed.
3. **Anonymous envelopes authenticate nothing.** Anyone with an epic1 link can post S1s to its
   mailbox, and anyone who saw a reply mailbox can post to it. Rate limits exist for the listener
   (ADR 0017) and services (RFC 0002 §13.4); a mailbox has only the relay's caps, and a relay holds a
   queue for a bounded time (`docs/compat/epicbox.md` "Relay retention"), so a flood can crowd a
   real message out of the bounds. Anonymous invoices are refused, with no exception
   (6.10).
4. **The marked legacy file is plain.** Carriers read the S1 and can swap the reply key. Accepted
   in RFC 0002 §5.
5. **Index 0 serves several purposes** (Epicbox address, Epicbox ECDH, proof key, previous onion),
   inherited from stock. Nothing new uses it (O-8).
6. **The first in-person code is readable.** It is raw: an onlooker learns the amount, the
   messages, the requester's public keys, the reply key and the reply mailbox with its relay's
   domain. Replies are sealed (O-13).
7. **epic1 exceeds bech32's 90-character segwit limit.** Random errors still pass the checksum
   with probability near 2⁻³⁰; a surviving typo loses no coins, and the TTL frees the inputs.
8. **Single-maintainer HPKE crate**, no paid audit (rust-hpke README "Audit history", SECURITY.md).
   The 0.15 line turns `mlkem` on by default and clamps X25519 private keys on serialisation; the
   KAT files are not in the crate tarball, so LEPIC vendors RFC 9180 A.2. Kept for suite `01`;
   re-evaluated when suite `02` is due.
9. **Size leak** is reduced to Padmé buckets, not removed. With the 768 B floor (O-6) every sealed
   S1 is one size; larger slates (S2, I2) leak about log log of their size (5.7).
10. **Sealed slates have a 65,535-byte body limit**, which a V3 slate with a few hundred inputs
    already passes; today the error is not handled. In the decided flow (5.17) LEPIC reports it and
    the app offers fewer or combined coins.
11. **Two kinds of `.epictx` file** exist on users' disks: stock wallets' own records and EPICTX.
    Readers tell them apart by content (5.12).
12. **Pinning has no recovery story yet** for a legitimate change beyond "LEPIC stops and
    reports, the app asks the user", and no expiry.
13. **The relay of a link mailbox sees** which mailbox receives payments, when, their sizes, and
    from which IP address payers post (5.14), as an Epicbox relay sees an Epicbox address today.
    A paypoint's own domain sees the same for its customers.
14. **Printed static codes are linkable at the relay.** A printed epic1 code keeps one link mailbox
    for its life, so its relay can link every payment made through it (not on chain: the chain
    sees nothing of the mailbox). On-screen codes take a new mailbox per receive session or share;
    their 50 indexes are used again in turn, so the relay can link two sessions 50 apart. A shop
    that minds this prints a new code from time to time (at most 32 printed codes are live).
15. **The payer chooses the relay the payee answers through.** The reply mailbox names its relay,
    so the payee's wallet connects where the payer says, and that relay learns the payee's IP
    address and timing. A LEPIC payee posts over Tor when its user chose Tor; otherwise this is the
    exposure of paying an Epicbox address today, with the roles swapped. LEPIC reports the relay
    with its relay-list flag before posting; the payee's app asks its user before it connects to a
    relay that is not in the user's relay list, and says when the answer goes through Tor (5.9,
    5.14). So the exposure to an unknown relay needs a tap; a user who accepts takes it.
16. **Two answers to one in-person code** (O-16 as rewritten). The reply key and mailbox are
    public in the raw code, so an onlooker can race the real receiver. Draft 5's 5-second hold
    finalized a first answer that came alone, so an onlooker who answered first was paid without
    a question. Now LEPIC never finalizes an in-person answer by itself:
    it reports each with its check code and finalizes the one the consumer names, and the payer's
    app asks the payer to confirm the code on the receiver's phone first (6.7). What is left is
    item 19, and a payer who taps "Yes" without looking. In the payee-starts direction an onlooker
    can only pay the payee.
17. **Restore finds what the relay still holds.** The on-screen (50) and printed (32) link
    mailboxes are scanned in full after a restore (5.2), so no index is missed. An S1 older than the
    relay's retention window (7 days) is no longer there, and its sender's TTL frees the inputs. Draft 5's gap of
    50 over one shared index space could miss a printed code; the separate spaces remove that
    (owner, 2026-11-09).
18. **One live mailbox per connection.** A relay serves one mailbox at a time on a connection, so
    each mailbox watched live needs its own connection (`docs/compat/epicbox.md` fact 4); the
    others are drained in turn. A wallet with many issued
    links drains slowly, so answers can come late; the TTL bounds the cost. The watched set is
    capped at the 50 on-screen and 32 printed link mailboxes (5.2).
19. **Check-code grinding.** The check code is 4 digits and the receiver picks its own excess, so
    anyone can make an S2 with any code it likes. The code proves nothing alone; the order bounds
    it. The receiver's phone shows its code only after it posts, so an onlooker answering first
    must guess it, 1 in 10⁴, and the payer confirms before finalizing. An onlooker that waits to
    see the code and grinds a match arrives second with the same code; LEPIC reports the match and
    the app cancels both and shows a new code (6.7). The cost is a retry, not a loss.
20. **Hosts from untrusted input.** An `epicbox=` entry, tag `09`, record `02` or a direct
    endpoint makes the wallet connect to a host someone else chose: it learns the wallet's IP
    address and timing (15), and could point at services on the local network. LEPIC refuses
    loopback on the resolved address, reports the host's class, and posts only on the consumer's
    word; the app asks for unknown relays and local-network addresses (5.14). The address classes
    are decided (O-18). A user who accepts a local-network prompt lets the code
    reach that host on any port.
21. **Trial decryption has no cheap filter.** A file, transaction text or a payment at the
    direct listener sealed to an epic1 is tried with every issued seal key of every account, each
    one X25519 and one failed AEAD, until one opens (5.5). The order puts the most recent payment's
    index and index 0 first. A wallet that issues very many addresses pays for each key on every
    such envelope, and anyone can post envelopes that open with none (item 7's spam). A payment
    through a link mailbox is opened with one key.
22. **An address handed out before a restore, past the gap, is not found.** A restored wallet
    tries 50 indexes past the highest one it knows (5.13). An address issued beyond that before
    the restore is no longer tried, and its first new address may be one handed out before. A
    payment to it is not found until the wallet issues that far.
23. **Covered sticker codes.** A printed code can be covered by another sticker, and the payer then
    pays whoever printed it. The payer's checks are the amount and the merchant shown before the
    PIN, as with any QR payment; a merchant domain claim (ADR 0043), where there is one, is shown
    larger than the message (6.10).

Draft 5's item on invoices racing in the invoice window is gone with the window (6.10).

## 11 Open questions

### 11.0 Items for the project owner

Owner items O-1 … O-18 and their answers. All are decided or withdrawn; O-18 was decided on
2026-11-09. The defaults D1–D6 are in 4.5.

| # | Item | Recommendation | Section |
|---|---|---|---|
| O-1 | When a LEPIC payer uses `native=` from a link | **Dropped** (3.1): no code carries both identities, so nothing needs binding; `native=` and `bind=` go | 5.14 |
| O-2 | EPICTX file extension | **Decided:** keep `.epictx`, with the no-clash rule (write only armour, never into `saved_txs`, read by content) | 5.12 |
| O-3 | Default D2 | **Decided:** withdrawn; the shipped sealed V3 answer and the frozen marker stay | 5.16, 6.4 |
| O-4 | Which sealed slates use the EPICTX markers | **Decided:** native (`0A`) only; sealed V3 slates keep `BEGINEPICSEALED.` / `.epicsealed` | 5.11 |
| O-5 | Extension rule of the slate tail | **Decided:** the envelope's rule (`u8`, `u16`, below `0x80` critical) | 5.10 |
| O-6 | Padding floor | **[Decided]** (owner, 2026-11-08): 768 bytes. It matters for sealed S1s and I1s in mailboxes and files, where a relay or carrier sees every size; padding is inside the seal, so it never changes a QR code | 5.7 |
| O-7 | Plain pack and `BEGINEPICSLATE.` | **Decided:** both dropped; in person the slate goes raw, with nothing around it (3.1) | 5.10, 5.18 |
| O-8 | epic1 proof key | **Decided:** a key of its own under ADR 0033 | 5.2 |
| O-9 | Slate too large to seal | **Decided:** LEPIC reports, the app asks; offer fewer coins, combining coins first (a send to self), unsealed where possible, or cancel | 5.17 |
| O-10 | D1 pinning | **Decided:** always ask the user (LEPIC stops and reports; the app asks, 3.2) | 5.15 |
| O-11 | D3–D6 | **Decided:** confirmed | 4.5 |
| O-12 | Work order | **Decided:** the order of 4.1, kept in front of the work; the in-person and link work is split into steps 7, 8 and 9 | 4.1 |
| O-13 | Reply key in an in-person first code | **Decided:** every face-to-face and paypoint first code carries a one-time reply key, and every reply is sealed to it. With it goes a throwaway reply mailbox: one scan online; offline the sealed reply as an animated code. The payer confirms the amount once and the receiver answers by itself. Draft 6: finalizing is no longer automatic in person (O-16 as rewritten) | 3.1, 5.10, 5.18, 6.7, 6.8 |
| O-14 | Where epic1 mailboxes live | **Decided, replaced by the link model:** the epic1 holds two keys only; the transport lives in the link, one field per method (`epicbox=<mailbox>@<domain>`, repeatable, tried in order, at most 3). The mailbox is transport only, may be a throwaway per link, and a swapped one only makes delivery fail. Stock wallets refuse epic1 links. `via=`, the relay extension and the third-key alternative are dropped | 5.2, 5.13, 5.14, 6.3 |
| O-15 | A paypoint pushing an invoice to an address the customer just showed | **Withdrawn** (owner, 2026-11-09): the invoice window and its 3-invoice rule are removed. A paypoint asks for money only by showing its own I1, which the payer scans. No invoice is pushed to a receive code; uninvited invoices from non-contacts are refused; contacts with "Allow invoices" keep the shipped rule | 6.8, 6.10 |
| O-16 | Two answers to one in-person code | **[Decided]**, rewritten (owner, 2026-11-09). LEPIC accepts and processes raw in-person codes in both directions and never finalizes an in-person answer by itself: it closes the code on the first answer, reports every answer with its check code (and when a second has the same code as the first), and finalizes only the answer the consumer names. **[App]** The app asks the payer to confirm the check code first ("Does Bob's phone show 4821?"); on two answers with one code it cancels both and shows a new code with a new reply key; the hold and the late-answer warning may stay as extras (to explore in the wallet app). Draft 5's 5-second hold with no extra tap is withdrawn | 3.1, 6.7, 10.16, 10.19 |
| O-17 | LEPIC and the app, for hosts and relays from untrusted input (new in draft 6) | **[Decided]** (owner, 2026-11-09). LEPIC is core only: before posting to a host from untrusted input it reports the host, whether it is in the configured relay list, and its address class; it posts only when the consumer says so, through Tor when Tor is configured; it refuses loopback itself; it never shows or decides a prompt. The prompts (unknown relay, local network, "through Tor") are the app's. The same split applies to every place where draft 5 had LEPIC ask | 3.2, 5.9, 5.14, 5.15, 5.17 |
| O-18 | Address classes of the host rule | **[Decided]** (owner, 2026-11-09, text as proposed): loopback refused on the resolved address; private and local-network addresses (RFC 1918, link-local, CGNAT, ULA, `.local`) allowed after one app prompt that shows the address; any port | 5.14, Appendix B |
| O-19 | The index field on every seal key kind | **[Proposed — not yet confirmed]** The index only for the epic1 kind, every other key unchanged: the onion, web and Epicbox seal keys and the adverts peers pinned stay as earlier builds derive them. epic1 index 0 keeps the kind-`00` seal key and the epic1 proof key of earlier builds; indexes 1 and above use `lepic-wallet epic1 seal key v1` and `lepic-wallet epic1 indexed proof key v1`, each with a fixed-width context (rule 4). Alternative: `be32(index)` in the context of every kind, which changes the onion, web and Epicbox seal keys | 5.2 |
| O-20 | epic1 envelopes in files and transaction text | **[Proposed — not yet confirmed]** 6.3 sends an S1 to an epic1 through the link mailbox; the owner's receive decision also opens files and text sealed to an epic1, by trial (5.5). Keep both: a wallet opens an epic1 file it is handed. Alternative: link mailboxes only | 5.5, 6.3 |
| O-21 | Accounts tried for a file or the direct listener | **[Proposed — not yet confirmed]** Every account of the wallet, each in its own trial order, and the account whose key opens receives it. Alternative: the active account only, which is cheaper and refuses a file to another account | 5.5 |
| O-22 | The first address after a restore | **[Proposed — not yet confirmed]** It comes after the gap (index 51 on a wallet that knew only index 0), and later ones follow on, so no address handed out before the restore within the gap is handed out again. Alternative: continue from the highest index known and accept that a payer may hold the same address as someone else | 5.13 |

### 11.1 Still open

- **Pin expiry** and how a user clears a pin (5.15).
- **Stack Wallet and Epic Pay** on an epic1 link: assumed to refuse it as an unknown address, not
  tested (5.14).
- **The frame count** at which an in-person I2 offers fewer coins (5.17).
- **Retiring a shared link**: how a user retires a printed or shared code, beyond "watched until
  retired" (5.2, 6.3).
- **Suite `02`** (X-Wing, `enc` 1,120 bytes) and a post-quantum epic1 key; suite `42`
  (X-Wing with PSK) **[Reasoning]** (5.4).
- **The Python reference kit** would need its own `lepic.v1` codec (6.6).
- **Name of a new send file** (5.12).
- **The largest-first selection strategy** for O-9's "use fewer coins" (5.17).

Questions that were open earlier are decided and recorded in the decision log (section 4) and in
11.0.

### 11.2 Already listed in the sources

- RFC 0001 "Open points": per-transaction native addresses (privacy), deferred.
- RFC 0002 OD-P1: `https://` universal links for invites.
- Chat paste test for base64url (Telegram, Discord, WhatsApp, Signal) before the freeze (D6).

## 12 References

- RFC 9180, HPKE: https://www.rfc-editor.org/rfc/rfc9180.html (§7.1.3 DeriveKeyPair, §7.1.4
  validation, §9.7.4 forward secrecy, §9.7.6 length)
- draft-ietf-hpke-hpke (RFC 9180bis): https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/
- draft-ietf-hpke-pq: https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
- X-Wing, draft-connolly-cfrg-xwing-kem-11: https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.txt
- NIST IR 8547: https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf
- Padmé / PURBs, PETS 2019: https://petsymposium.org/popets/2019/popets-2019-0056.pdf
- HPKE KCI in Auth mode, eprint 2020/1499: https://eprint.iacr.org/2020/1499
- Ed25519/X25519 key reuse, eprint 2021/509: https://eprint.iacr.org/2021/509
- rust-hpke: https://github.com/rozbb/rust-hpke (README audit history, SECURITY.md, CHANGELOG)
- RFC 8032 EdDSA; RFC 5869 HKDF; RFC 4648 base64url; RFC 9457 problem details; RFC 3986 URI;
  RFC 5234 ABNF
- BIP 173 bech32, BIP 350 bech32m, BIP 321 URI scheme: https://github.com/bitcoin/bips
- BOLT 1 (TLV parity), BOLT 9 (feature bits), BOLT 11: https://github.com/lightning/bolts
- Grin RFC 0012 compact slates, RFC 0015 slatepack: https://github.com/mimblewimble/grin-rfcs
- age v1: https://age-encryption.org/v1
- epic-wallet v4.1.0: https://github.com/EpicCash/epic-wallet (`impls/src/adapters/http.rs`,
  `impls/src/backends/lmdb.rs`, `libwallet/src/internal/selection.rs`)

---

## Appendix A — ADR 0033 registry rows (proposed)

Rows to add to ADR 0033 "The table" when the codec lands, in its column format. None is built; no
vector exists yet (rule 8: vectors before code). `be32` is a big-endian u32, `net` the network
byte, `ctr` a u8 counter from `00` until the secret is valid for its curve.

Seed-keyed labels, `BLAKE2b-256(key = seed, label ‖ context)`:

| Label ‖ context | Type | Purpose | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| `lepic-wallet seal key v1` ‖ be32(account) ‖ net ‖ kind | X25519 | Opens envelopes sealed to the epic1 address at index 0 (`kind` 00), the onion listener (01), the plain web listener (02) or the Epicbox payments address (03) (5.2, 5.15) | `lepic-wallet::namespace` | none | proposed | `pairing/seal_keys.json` |
| `lepic-wallet epic1 seal key v1` ‖ be32(account) ‖ net ‖ be32(index) | X25519 | Opens envelopes sealed to the epic1 address `index`, index 1 or above (5.2, 5.13) | `lepic-wallet::namespace` | none | proposed | `pairing/epic1_seal_keys.json` |
| `lepic-wallet epic1 proof key v1` ‖ be32(account) ‖ net | Ed25519 (the 32 bytes are the seed) | The proof key in the epic1 address at index 0; signs payment proofs for slates that came to it (O-8, 5.2) | `lepic-wallet::namespace` | none | proposed | `keys/epic1_proof_key_seed32`, `keys/epic1_proof_key_seed16` |
| `lepic-wallet epic1 indexed proof key v1` ‖ be32(account) ‖ net ‖ be32(index) | Ed25519 (the 32 bytes are the seed) | The proof key in the epic1 address `index`, index 1 or above (O-8, 5.2, 5.13) | `lepic-wallet::namespace` | none | proposed | `keys/epic1_indexed_proof_key_seed32`, `keys/epic1_indexed_proof_key_seed16` |
| `lepic-wallet reply mailbox v1` ‖ be32(account) ‖ net ‖ slate_id(16) ‖ ctr | secp256k1 | Throwaway Epicbox mailbox for the answer to one slate; its address goes with the reply key (5.2, 5.6 tag `09`, 5.10 record `02`). Exception class "Epicbox mailbox key" | `lepic-wallet::namespace` | none | proposed | `keys/reply_mailbox_*` (to write) |
| `lepic-wallet post key v1` ‖ be32(account) ‖ net ‖ slate_id(16) ‖ role ‖ ctr | secp256k1 | Epicbox `from` key of every post to another party's mailbox for one slate; `role` 00 initiator, 01 responder. Nothing is received at it. Exception class "Epicbox mailbox key" | `lepic-wallet::namespace` | none | proposed | `keys/post_key_*` (to write) |
| `lepic-wallet link mailbox v1` ‖ be32(account) ‖ net ‖ kind ‖ be32(n) ‖ ctr | secp256k1 | Mailbox named by `epicbox=` in an epic1 link; `kind` 00 on screen (`n` 0–49, new per receive session or share, used in turn), 01 printed (`n` 0–31, fixed per code) (5.2, 5.14). Exception class "Epicbox mailbox key" | `lepic-wallet::namespace` | none | proposed | `keys/link_mailbox_*` (to write) |

Context widths: seal key 6, epic1 seal key 9, epic1 proof key 5, epic1 indexed proof key 9, reply mailbox 22, post key 23, link mailbox 11
bytes (10 in draft 5, before the `kind` byte), each fixed, so rule 4 holds. No label is a prefix of another label.

Tags and domains:

| Tag | Used with | Covers | Owner | First | Status | Vector |
|---|---|---|---|---|---|---|
| `epic-tx/1` ‖ net ‖ suite ‖ `00`, `01` or `02` (HPKE info) | HPKE | Envelopes sealed to an epic1 seal key (`00`), a listener seal key (`01`) or an Epicbox seal key (`02`) (5.4) | `lepic-contact` | none | proposed | `envelopes/epictx_*` (to write) |
| `epic-check/1` | SHA-256 over tag ‖ the receiver's public excess | The check code: the receiver's phone shows it after it posts; LEPIC reports it with every answer to an in-person code, and the payer's app asks the payer to confirm it before finalizing (O-16 as rewritten, 6.7) | `lepic-wallet` | none | proposed (O-16 decided) | none yet |

Recorded exception to add, beside "index 0" and "the listing key". **[Decided]** (owner,
2026-11-08): approved for the class "Epicbox mailbox key". 

> **Epicbox mailbox keys.** The reply mailbox, post key and link mailbox keys sign Epicbox texts
> (`Subscribe`, `Made`, `PostSlate`) and do the Epicbox message ECDH, as the relay protocol
> requires of any address key. Their ECDH output goes only into Epicbox's message cipher and their
> signatures only over Epicbox texts. Every slate they carry is sealed again inside with HPKE to
> an X25519 key that does nothing else, so a break of the outer layer reveals the envelope, not
> the slate. The shipped mailbox keys (`box_sk`, the pairing mailbox, the listing key) already
> sign and do ECDH the same way. Approved by the project owner on 2026-11-08.

## Appendix B — epic1 v1 layout and link grammar

### B.1 epic1 v1

```
epic1 address  = hrp "1" data checksum          ; bech32m, BIP 350, lower case only
hrp            = "epic" (mainnet) / "tepic" (floonet)
data (65 B)    = version(1) = 0x01
               ‖ proof key(32)  Ed25519 public key, the epic1 proof key at the address index (5.2)
               ‖ seal key(32)   X25519 public key, seal key kind 00 at the same index (5.2)
characters     = 65 × 8 / 5 = 104 data characters + 6 checksum + "epic1" = 115 (tepic1: 116)
```

Nothing else is in the address: no mailbox, domain, transport or index (5.13). Version `00` is RFC 0001's
one-key form and is refused; any version above `01` is refused until defined.

### B.2 Links (ABNF, RFC 5234)

```
link            = epicbox-link / epic1-link

; shipped, unchanged (scan_router.dart)
epicbox-link    = "epic:" ["epicbox://"] epicbox-address [ "?" e0-param *( "&" e0-param ) ]
epicbox-address = 52base58char [ "@" domain [ ":" port ] ]       ; shipped charset, below
e0-param        = pay-param / ( "method" / "direct" / "require" / "min" ) "=" value / other-param

; LEPIC only
epic1-link      = "epic:" epic1-address [ "?" e1-param *( "&" e1-param ) ]
epic1-address   = ( "epic1" / "tepic1" ) 110bech32char        ; 104 data + 6 checksum
e1-param        = transport-param / pay-param / other-param
transport-param = "epicbox=" mailbox-address                  ; may repeat; read at most 3
mailbox-address = 52base58char "@" relay-domain [ ":" port ]  ; domain required;
                                                              ; domain [":" port] at most 128 octets
                                                              ; onion=, nostr=: other-param until defined
pay-param       = ( "amount" / "message" / "note" / "memo" / "label" ) "=" value
other-param     = key "=" value                               ; ignored by readers

domain          = 1*128( ALPHA / DIGIT / "." )                ; Epicbox upstream's characters
relay-domain    = label *( "." label )                        ; LEPIC only: epic1 link, tag 09,
                                                              ; record 02; hyphens allowed
label           = ( ALPHA / DIGIT ) [ *( ALPHA / DIGIT / "-" ) ( ALPHA / DIGIT ) ]
                                                              ; no hyphen at either end of a label;
                                                              ; four decimal labels are an IPv4
                                                              ; literal (host rule, below)
port            = 1*5DIGIT                                    ; 1-65535
key             = 1*( ALPHA / DIGIT / "_" / "-" )
value           = *( unreserved / pct-encoded )               ; RFC 3986
; unreserved, pct-encoded: imported from RFC 3986 §2.3, §2.1
base58char      = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
                                                              ; Bitcoin alphabet: no 0, I, O, l
bech32char      = DIGIT / %x61-7A                             ; a superset of the bech32 alphabet;
                                                              ; the decoder checks it (below)
```

Quoted strings in RFC 5234 are case-insensitive; links are written and read in lower case, and a
mixed-case epic1 is refused (B.1).

Reader rules beside the grammar (5.14): a mailbox whose Epicbox version bytes name the other
network is not usable; `method`, `direct`, `require` and `min` in an epic1 link are ignored; an
epic1 link with no usable `epicbox=` is "cannot pay this code"; no parameter of either link is ever
read as a second payee. `bech32char` is written loosely; the decoder checks the bech32 alphabet
(`qpzry9x8gf2tvdw0s3jn54khce6mua7l`) and the checksum. `domain` in the plain Epicbox link keeps
Epicbox upstream's characters (`docs/compat/epicbox.md` "Addresses"). `relay-domain` adds the
hyphen **[Decided]** (owner, 2026-11-08), so a relay on a domain with a hyphen can be named in an
epic1 link, tag `09` and record `02`. Only LEPIC wallets read those, so no stock wallet breaks; a
stock wallet just cannot name such a relay in its own address. `relay-domain` is ABNF over
characters: as elsewhere in the grammar, ALPHA matches either case.

Host rule beside the grammar (5.14 "Hosts from untrusted input"; LEPIC part **[Decided]**, O-17;
classes **[Decided]**, O-18). It applies to every `relay-domain` in an epic1
link, tag `09` and record `02`, and to the host of a direct endpoint. The grammar admits names and
IPv4 literals; an IPv6 literal cannot be written, and an IPv6 address is reached only through a
name. After resolving, LEPIC refuses loopback (`localhost` and names under it, `127.0.0.0/8`,
`::1`, IPv4-mapped forms), whatever the name; any other address is reported to the consumer as
public or local network (RFC 1918, link-local, CGNAT, unique local, names ending in `.local`). A
private IPv4 literal is allowed, and the app asks once before it is used. Any port 1–65535 is
allowed.
