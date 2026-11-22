# ADR 0068: Invoices the payer opens need no pairing

Status: accepted
Date: 2026-11-21

## Terms

This record uses the glossary of ADR 0065: Epicmail is the protocol, a mailbox is a server that
runs it, a slot is the box of one key on a mailbox. A checkout request is an in-person invoice
code that a shop's `lepic serve` issues for one order, signed for the shop's domain. An invoice
link is that code as `epiccash://invoice/1/<code>`.

## Context

Two rules about invoices disagreed:

- RFC 0003 §6.10 said an invoice the payer scans in person needs no pairing.
- ADR 0063 §8 said an invoice goes only between verified contacts, and kept in-person requests
  only "between verified contacts".

The code did the first. A shop made the conflict matter. A web shop wants the invoice flow
without pairing: the shop builds the request for one order, the buyer approves once, and the
shop's server finalizes and posts. LEPIC already has the pieces in the in-person code (RFC 0003
§6.7 to §6.9), but `lepic serve` could not issue one, nothing finalized without a person picking
the answer, a code opened only from a scan, and a code did not say which shop made it.

The owner decided on 2026-11-21: the shop issues a checkout request as a link and a QR; the
amount is fixed by the shop; the shop's domain is signed into the request and shown to the
buyer; the buyer approves once, with no account and no pairing.

## Decision

### 1. The invoice rule

- **Pushed.** An invoice that arrives through a mailbox is taken only from a paired, verified
  contact that the payer allowed to send invoices. Any other is refused before it is stored.
- **Opened by the payer.** An invoice the payer opens (a camera scan, a file, an invoice link)
  needs no pairing. Nothing is stored and no input is held until the payer approves, after the
  wallet has shown the amount, the fee, the expiry, who asks (a checked domain, or that the
  requester is unknown) and where the answer goes. No setting, import or link pays one by
  itself.
- **Addresses.** No invoice is sent to an address or taken at one.

### 2. Links need a checked domain

A request signed for a domain carries a claim (RFC 0003 §5.20, record `F0`). The wallet checks
it against `https://<domain>/.well-known/epic-wallet.json` (ADR 0043). Three results:

| Result | Link | Scan |
|---|---|---|
| Checked | Paid after approval, domain shown | Paid after approval, domain shown |
| No claim, or the file cannot be fetched | Refused | Opens with a caution that the requester is unknown |
| False claim (bad signature, key not listed) | Refused | Refused |

A false claim is refused in the CLI and in the app. The caution on a scan is shown by the app.
LEPIC builds the verdict; the host fetches the file and decides how to show it.

### 3. Serve may finalize the first valid answer

An issuer may ask, per request, that its `lepic serve` finalize the first answer that passes the
checks, and post. The option is `finalize: "first"`; the default is `"manual"`, which keeps the
rule of RFC 0003 §9 that a person picks the answer.

With `first`, serve finalizes at most one answer per code, never falls back to a second, and does
so once across a crash or restart. Before an answer is stored or counted, the node must show its
inputs unspent; a node that cannot be reached means the answer is not counted and is tried again
on the next take.

### 4. Two reply routes from the start

The code names the slot (record `01`, `02`, as today) and may also name the shop's own host (new
record `0x81`, DIRECT_ROUTE: `http` or `tor` entries). The buyer's wallet posts the sealed answer
to the slot and to each direct entry. A direct post is accepted or refused in the same request
(`/api/v1/inbox`, RFC 0003 §5.15), so a refusal reaches the buyer at once.

In Tor-only mode the direct route goes over Tor too: only `tor` entries are used and `http`
entries never are. Nothing falls back to clearnet.

### 5. The signed request

A new last tail record `0xF0`, REQUEST_CLAIM, holds the shop's domain key, the time, a signature
and the domain. The signature covers the whole code (RFC 0003 §5.20). Both new records are at or
above `0x80`, so a reader that does not know them passes over them and pays through the slot as
before. Both are allowed only on an I1.

## Consequences

- RFC 0003 §3.2 "LEPIC never finalizes an in-person answer by itself" becomes: LEPIC finalizes
  an in-person answer by itself only when the request asked for it, in serve. The library calls
  stay single calls and the consumer asks. §9 "Finalizing" changes the same way.
- Threat model (RFC 0003 §7.3): "that the first answer to an in-person code comes from the
  intended party" stays unclaimed, and with `first` the first valid answer wins. The order is
  paid by whoever answers first, with a valid transaction for the shop's amount; no coins move
  to anyone else. Someone who holds an order's code can answer first and then spend the same
  inputs elsewhere: the shop's order then needs a new code. The same holds for inputs already
  spent in a transaction still in the node's pool: the check reads the chain's unspent outputs,
  so the answer passes, the post fails and the request ends `expired`. It costs the sender a fee
  for each code. A pool check before finalizing would narrow this; it is left for later. The
  shop keeps codes inside the buyer's session.
- The domain proof says who controls the domain's HTTPS. It stops a code swapped by a script or
  a relayed page. It does not stop someone who can change the domain's own files, and a
  look-alike domain passes the check for its own name, so the review shows the full domain.
- A copied code shown to someone else can only make them pay that shop's order.
- Old wallets ignore records at or above `0x80` and read the code as a plain in-person invoice
  without a domain. An app from before this change ignores an `epiccash://invoice/...` link: its link reader takes
  only the `pair` and `device-link` hosts (checked on app main 76af9dd8d).
- The reply mailbox carries a signed code that is larger. A long message may no longer fit one
  QR, and the code becomes an animated one.
- ADR 0063 §8 is amended: an in-person request needs no pairing; the proof made in person was
  never the only way to open one.
- A serve answers many open codes through one reply slot per account, matched by hint.

## Alternatives considered

- **A request link and a guide (design 1).** A payment link `epic:<address>?amount=…&http=…` with
  a guide for shops. It works today but the buyer's wallet finalizes and posts, which is what the
  shop wants to leave, the payer can change the amount, and nothing ties the link to the shop.
- **A shop contact (design 3).** The checkout link is a pairing invite from a proven domain, and
  the request follows by push. It needs more taps on the first purchase, leaves a lasting
  contact per buyer at each shop, lets the shop push requests to every past buyer, and runs into
  the pairing limits of the core (64 pending invites, a watched slot per contact).
- **Keep ADR 0063 §8 as written.** In-person requests only between verified contacts. It would
  end the paypoint, which pairs with nobody.

## Related

- ADR 0043: the domain proof and the well-known file.
- ADR 0063 §8: payment requests between verified contacts. Amended here.
- ADR 0065: the glossary words.
- RFC 0003 §3.2, §5.15, §5.20, §6.10, §7.3 and §9.
