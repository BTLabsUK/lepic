# ADR 0063: The epic1 address carries its own slot

Status: accepted; in §1 the numbered addresses (index 1 and up), §7 (a link per address, the link id, the amount check, the 256 bound, the
restore gap), the `POST /addresses` and link id lines of §8, and in §9 "an open link's address"
and the reason `amount` for an address superseded by 0066 (one address per account; a request
link only fills in the Send screen); §4 (the own mailbox first in the list, the post to every
mailbox, the single answering mailbox and the default-host notice) and §11 superseded by 0065;
in §9 the payer's cancel on `declined` superseded by 0067 §4: the payer erases a declined send
Date: 2026-11-18

Terms: this record uses the glossary of 2026-11-19 (ADR 0066): a mailbox is a server that runs
Epicmail, and a slot is the box of one key on a mailbox.

## Context

ADR 0062 made the address decide the protocol and put native mail on push. Its epic1 address
holds two keys: an Ed25519 proof key and an X25519 seal key. A payment to a bare address goes to
the payee's index-0 slot on the payee's own mailbox, and a link reaches the payee through a link
slot: one of 50 on-screen slots (a ring) or 32 printed ones per account, written in the link
as an `epicbox=` entry with a mailbox host.

Building it showed four costs:

- The mailbox is part of the payment code. A link names a host, so the payer must trust or confirm it
  (`hosts_ok`, `RelayNotConfirmed`), and a link breaks when the payee moves mailbox.
- The link slot ring and the printed slots are state with their own failure modes
  (a full set of printed slots, slot reuse, a link number never issued) and their own restore
  rounds. The open set that replaces them refuses with `TooManyOpen` and `AddressNotIssued`.
- The proof key signs nothing. epic1 pay asks for no payment proof
  (`send.payment_proof_recipient = None`), yet the receive path still derives an epic1 proof key,
  and the address carries 32 bytes for it.
- Services make a one-off order address per request (ADR 0058, `POST /addresses` with `id`). With
  links that carry `http`/`tor` entries and link ids, the same service gets the same answer with
  instant feedback, through one path.

The owner's goals for the address: complete alone, easy to carry, delivery a separate layer that
can change without a new address, no mailbox name in a link, a QR code or a payment screen, and
mailboxes chosen in the wallet's settings.

## Decision

### 1. The address carries a seal key and a delivery key

```
data    = version (01) || seal key (32) || delivery key (33)          66 bytes
address = bech32m(hrp, data)      hrp "epic" (mainnet) or "tepic" (floonet)
length  = 117 characters on mainnet, 118 on floonet
```

- Seal key: X25519 public key, derived as today (`epic1_seal_key`, RFC 0003 §5.2): index 0 is the
  account's `SealKeyKind::Epic1` key, index 1 and up use `lepic-wallet epic1 seal key v1`. HPKE
  suite 01 and the info string for key class 00 are unchanged.
- Delivery key: compressed secp256k1 public key, prefix 02 or 03, a point on the curve. It comes
  from the seed under a new registry label `lepic-wallet epic1 delivery key v1` (ADR 0033),
  context `account (u32 BE) || net || index (u32 BE)`, with the counter rule RFC 0003 §5.2 uses for
  secp256k1 slot keys. One label for every index, 0 included.
- The version byte stays 01: this ADR changes the layout under it and no version number. An
  address of the earlier layout (65 bytes, 115 characters) fails the length check. There is one
  address format and one decoder.
- Each numbered address has its own two keys, so each has its own slot.

### 2. No proof key; receipts are dropped for epic1

- The address carries no signing key. epic1 payments carry no payment proof.
- The labels `lepic-wallet epic1 proof key v1` and `lepic-wallet epic1 indexed proof key v1` are
  retired. Under ADR 0033 rule 6 they are never reused.
- The receive path stops deriving an epic1 proof key. A slate that arrives at an epic1 address and
  asks for a payment proof is refused.
- One key is not used for both signing and sealing. A later receipt key can travel in pairing, or
  come with a later address version.

### 3. The slot of an address is its delivery key

- The Epicbox slot of an address is its delivery key, the same on every mailbox. No mailbox name
  goes into any key derivation. Both wallets know the slot from the address; no link carries it.
- The payee attaches every slot it watches with mux/1 on every mailbox in its list. Ownership is
  proven as today, by a secp256k1 signature over the socket challenge. The mailbox needs no change.
- The link slot ring (50), the printed link slots (32), their label
  `lepic-wallet link mailbox v1` and their settings rows are removed. The label is retired.
- A later method that needs its own secp256k1 key gets a child key of the delivery key, defined
  when that method is added.

### 4. Mailboxes come from settings, and the payer posts to all of them

- The wallet's mailbox list is its own mailbox followed by its other configured mailboxes, shipped as
  defaults in the signed release and editable by the user. One notice tells the user when an
  update changes a default host. A mailbox without mux/1 is listed as not usable for epic1.
- A private mailbox works only when both sides list it. A link cannot point a payer to a mailbox.
- Payer, bare address or link without entries: posts the same sealed envelope to the payee's
  slot on every mailbox in its own list. Each mailbox holds at most one copy.
- Payee: answers a payment once, on the mailbox it read it from, and acknowledges every copy. A
  repeat that arrives after the answer's post failed or ended gets the same answer bytes again
  (as `answer_again` does today); it is never taken twice.
- Once the answer arrives, the payer cancels its copies on the other mailboxes (`txcancel/1`,
  ADR 0060). A mailbox older than 3.1.0 keeps its copy until it expires. Every copy carries one
  transaction id, derived from the payer's post key, the payment id and the stage, so the
  cancel needs nothing stored.
- No new retry, no mailbox-to-mailbox copying. The core moves to the next route only when a post fails,
  and the host may ask for a resend (ADR 0062).

### 5. The reply route is a typed list

Envelope tag 09 changes from one slot key and mailbox host to:

```
reply route = count (u8) || count × ( method (u8) || len (u8) || value )
```

- Method 01 `epicbox`: the value is a one-time reply slot key (33 bytes), nothing else. The
  payee posts the answer to the mailbox it read the payment from; the payer watches the reply slot
  on every mailbox it posted to.
- A payment that arrived over `http` or `tor` is answered in the same request and needs no reply
  route.
- A reader skips entries of an unknown method. A count of 0, a value of the wrong length for a
  known method, or bytes left over is malformed.

### 6. Links carry `http` and `tor` entries only

```
epic:<address>[?amount=<n>][&message=<text>][&http=<host[:port]>][&tor=<onion>]
```

- At most 3 route entries, limits on length and values as ADR 0062 §3.
- `epicbox=` is neither written nor read. A reader reports it with the other ignored parameters.
- A link with entries is paid through its entries only, in link order. The slot is not tried.
  When no entry answers, the payment fails with a clear message.
- A link without entries is paid as a bare address (§4).
- `http` is HTTPS only, to the native endpoint `POST /api/v1/inbox`, answered in the same request.
  `tor` is a v3 onion, port 80, the same endpoint, through the wallet's own Tor. A local-network
  host is refused unless it is on the wallet's own list (ADR 0062).
- Paying an `http` link shows the host on the confirm screen. There is no consent prompt.
- The epic1 web and onion listener switches are the only gates for serving the native endpoint.

### 7. A link is an address with an amount, and its id is the address index

> Superseded by ADR 0066: an account has one epic1 address, and a link is that address with an
> amount or a message that fill in the payer's Send screen. Nothing below in this section is built.

- Each link takes its own address index; the link id is `<account>.<index>`. This replaces the
  ids `<account>.<screen|printed>.<n>` of ADR 0058 §4 and its settings row `epic1.taken.<tx id>`
  names the new id.
- The payee knows the link of a payment from the address that opened it: the slot it came to,
  or for `http` and `tor` the key that opened the envelope.
- The amount check applies to a link with an amount and to an invoice. A bare address, or a link
  without an amount, takes any amount.
- The payee tries and watches only open ones: the addresses of open links, plus the account's
  public address. A retired link's address is neither tried nor watched.
- Bound: 256 open links per account, the slots of one mux/1 socket.
- Restore watches the delivery slots of indexes 0 to the highest known index plus 101 (50
  past the first address the account would issue, itself 50 past the highest known) while
  the account is in its restore gap (rebuilt from the phrase, no address issued since), and of
  the open addresses only otherwise. A payment opens an address only in the gap, within the
  bound.

### 8. Payment requests travel only between verified contacts

> Amended by ADR 0068: an invoice the payer opens (scan, file, invoice link) needs no pairing, and
> an in-person request is no longer limited to verified contacts. Pushed invoices stay as written.

- A payment request (an invoice) sent by slot goes only to a contact whose pairing is
  verified, and is taken only from a contact the payer verified and allowed to send invoices
  (RFC 0002 11.5; allow is per contact, off by default, set by the payer). A contact known by
  address alone sends and receives none.
- A pairing is verified by a proof made when the wallets met in person, by a domain proof, or by
  comparing the words. Wallets that did not meet compare the words.
- A contact that is paired and not verified gets no dead end. Issuing to it fails with
  `NotVerified` before anything is stored, and each host answers that error with the words
  comparison. A request that arrives from such a contact is answered with a refusal, so the
  issuer learns it at once.
- An in-person request stays, between verified contacts: the proof made in person verifies them.
- A request file stays and works for anyone, sealed or plain. It is never paid by itself: no
  setting, import or default action pays one. Paying takes a deliberate step by the payer, after
  the wallet has shown the amount and who asks. A host built on the core keeps this rule: the
  core's pay calls are single calls and the host asks first.
- One-off order addresses for strangers are removed: `POST /addresses` with `id`. A plain new
  address without an `id` stays. Shops and exchanges use links with `http` or `tor` entries and
  link ids.
- No invoice or pair request travels inside an epic1 payment or to an epic1 address. Contacts
  come by invite code only; a pair request sent to an address is removed.

### 9. Refusing what was not asked for

> ADR 0066: there are no open links. With the switch on, the epic1 address takes nothing; only
> invoices are asked for. The reason `amount` stays for invoices only.

- With `refuse_unsolicited_payments` on (ADR 0045), the public address takes nothing. Only asked-for
  payments are taken: payments to an open link's address and payments of an invoice.
- Over `http` and `tor` a refused payment fails at once. At the slot the payee seals a declined
  notice to the payment's reply key, and the payer cancels and frees its inputs. ADR 0067 §4 (note
  of 2026-11-19): a declined send never happened; the payer erases it and frees its inputs.
- The declined notice carries a reason: `amount` for a known request paid with the wrong amount,
  `declined` for any other refusal. A service that reads no mailbox cannot send it; a payment posted
  to its slot ends at its deadline.
- Separate payments to one address are never blocked while another waits.

### 10. QR codes are written in upper case

- A bare address is written `EPIC:EPIC1…` in upper case, so the code uses alphanumeric mode: level
  H, version 8 (49 × 49). The reader accepts an address that is all lower case or all upper case
  and refuses mixed case.
- A link with parameters is written in lower case.

### 11. Pairing mail goes to every mailbox

- The pairing reply, the confirmation, the pairing status notices and the unpaired notice go
  through the one outbox. Each is posted to its slot on every usable mailbox in the sender's
  list, as a payment is, and is posted again by the outbox's schedule until it is taken or ends.
- The mailbox named in an invite or a contact card is a hint. The sender also posts there when it
  is not in its list, so a wallet that reads only that mailbox is still reached. The invite and
  the card do not change on the wire (RFC 0002).
- Each side watches its pairing and contact slots on the same mailboxes. A copy read twice is
  applied once.
- A copy is deleted when its reader takes it. Pairing mail carries no transaction id, so no copy
  is cancelled: the copies left expire at the mailbox's retention.

### 12. What stays from ADR 0062

The address decides the protocol, the classic lane, mux/1 for native receiving, the watch set, the
carrier interface, one outbox, "recover funds", the in-person record 02 and `label=`.

## Consequences

- Links and printed codes made by the 2026-11-17 pre-release build (schema 17) stop working. LEPIC is alpha; the owner accepts the break.
  Open link payments of that build end at their deadline. The store is not migrated; rows of the link ring
  and printed slots are no longer read.
- The address is 2 characters longer than before (117 against 115) and has the same QR size in
  upper case.
- epic1 has no receipts until a receipt key is added in pairing or in a later address version.
- One payment can sit on several mailboxes for a short time. Each copy is deleted when read or
  cancelled, and at the latest at the mailbox's retention.
- A payee that shares no mailbox with a payer cannot be paid at its bare address. The payer's
  payment then ends at its deadline and its inputs are freed.
- Code goes: the ring and printed slots, host confirmation for mailboxes, the epicbox link entry, the
  epic1 proof key, one-off order addresses, the block on a second payment to one address, pair
  requests sent to an address, and the pairing messages' own posting and retry loops.
- A pairing no longer depends on one mailbox being up.
- Docs change: `docs/protocols/epic1.md`, `docs/protocols/epictx.md`, RFC 0003 §5.2 and §5.4
  tables, ADR 0058 §4 link ids, `docs/api/README.md`, `openapi.json`, `docs/cli.md`.

## Tests the implementation needs

- Address golden vectors on both networks; a bad delivery key refused; an address of the earlier
  length refused; all upper case accepted; mixed case refused.
- Delivery key golden vectors for several accounts and indexes, including the counter rule; restore
  finds a payment at index k and reads up to index k + 101 from then on.
- Reply route vectors: one entry, several entries, an unknown method skipped, a bad length refused,
  a count of 0 refused.
- Links: `http`, `tor`, both, more than 3 refused, `epicbox=` ignored and reported, a local-network
  host refused.
- On a test mailbox: a bare address paid and answered; the same payment posted to two mailboxes is taken
  once and answered once; payer and payee on different mailboxes of a shared list; the payer's other
  copy cancelled after the answer; an `http` link answered in one request.
- With the refuse switch on: a payment to the public address declined with reason `declined`; a
  link payment taken.
- A second payment to an address with one waiting is taken.
- An invoice to a contact that is paired but not verified is refused before anything is stored;
  one that arrives from such a contact is answered with a refusal.
- A request file is not paid before the payer has seen it and agreed; without a terminal the
  command line refuses unless told to proceed.
- A pairing finishes when the invite's mailbox is down and another mailbox of both lists is up; a
  reply read on two mailboxes pairs once and is confirmed once; a wallet that reads only the
  invite's mailbox gets its reply there.
- A QR round trip in upper case.

## Alternatives considered

- **Keep three keys (proof, seal, delivery).** 168 characters, QR version 10 in upper case.
  Receipts stay possible, but nothing signs one today, and every share carries 51 more characters.
- **One Ed25519 key for receipts and sealing (as Grin's Slatepack does).** As short as dropping
  receipts. Refused: the owner's rule is no key reuse across signing and encryption. Joint security
  is proven in the random oracle model (Thormarker 2021, eprint 2021/509), and libsodium still
  advises distinct keys.
- **A slot key per mailbox.** Both wallets would have to spell the mailbox the same way; an alias or
  a written port gives a different slot and a lost payment. It hides little, since anyone with
  the address can compute every per-mailbox key.
- **Post to the first mailbox, the next only on failure.** No extra copies, but the payment is lost
  when the payee does not read the payer's first mailbox.
- **Keep one-off order addresses for strangers.** One more decision branch for the service API,
  where links with entries and link ids give the same result with instant feedback.

## Related

- Supersedes in part ADR 0062: §3 (the `epicbox` route entry, "printed links with `epicbox=` stay
  valid", the native mailbox setting, notices through the link's slot) and §4 (50 on-screen and
  32 printed links per account), and its tests "a reader of the pre-release build given a link with `http=` or `tor=`
  pays through the `epicbox=` entry" and "an epic1 link slot answers a repeated slate with the
  stored answer".
- Supersedes in part ADR 0058: §4 link ids and the per-request address of the service pattern.
- ADR 0033: one new label, three retired.
- ADR 0045: the refuse switch. ADR 0060: mailbox cancel. RFC 0002: pairing and invoices. RFC 0003:
  sealing and the key table.
