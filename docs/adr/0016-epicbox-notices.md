# 0016 LEPIC notices over Epicbox, sent only to proven peers

Status: accepted
Date: 2026-10-05

## Context

Invoices over Epicbox (ADR 0003 and ADR 0004 amendments, `docs/compat/epicbox.md`) leave each side
guessing about the other: the payer does not learn that its payment was pushed or that the issuer
withdrew the invoice, and the issuer does not learn that the payer declined. A slate cannot say
any of this, and no slate stage exists for it.

A stock `epic-wallet` `v4.0.2` listener sends `Made` only for a payload that parses as a V3 or V2
slate (fact 3 in `docs/compat/epicbox.md`). Anything else stays pending on the relay and is
delivered again, so one payload that is not a slate holds back every later message to that
address. LEPIC must therefore never send one to a peer that might run stock software.

## Decision

A notice is a JSON object, not a slate:

```
{"lepic":1,"type":"declined","slate_id":"<uuid>"}
{"lepic":1,"type":"withdrawn","slate_id":"<uuid>"}
{"lepic":1,"type":"posted","slate_id":"<uuid>","excess":"<66 hex>"}
```

- `lepic` is the format version, a number. A slate written by LEPIC carries an object under
  `lepic` (the marker), and a stock slate carries nothing there, so a number tells a notice from a
  slate before any slate decoding.
- At most 512 bytes. A longer notice-shaped payload is acknowledged and dropped.
- A notice of another version or an unknown type is acknowledged and ignored. Unknown keys are
  ignored. A known type with a missing or invalid field is acknowledged and dropped.
- `declined` goes from the payer to the issuer, from the invoice address the payer holds now, to
  the address the user allowed. `withdrawn` goes from the issuer to the payer when the issuer
  cancels the invoice or it expires. `posted` goes from the issuer to the payer once the paid
  invoice was pushed, with the kernel excess. Both go to the address the invoice was issued to.

Capability proof, kept per peer key in the store:

- A peer is proven to run LEPIC once an I1 it sent with the marker was parked, an I2 with the
  marker answering an invoice this wallet issued was finalized, or it sent a notice that was
  accepted. A marked I2 proves both the key it came from and the key the invoice went to, since
  only a wallet reading that address could answer it and a stock wallet does not pay invoices
  over Epicbox.
- A peer that sent an issued I1 back unchanged is recorded as not supporting invoices.
- A notice goes only to a peer proven to run LEPIC. Without proof, nothing is sent.

Receiving:

- A notice is accepted only from the recorded counterparty of its slate: for `posted` the
  issuer of an invoice this wallet paid, with the excess this wallet's payment implies; for
  `withdrawn` the sender of a parked invoice or the issuer of a paid one; for `declined` the
  address an issued invoice went to. Anything else is acknowledged and dropped.
- A notice is advisory. It never moves funds, cancels or unlocks anything. `withdrawn` deletes an
  unpaid parked invoice, which holds nothing; for a paid invoice it raises an event, and the host
  offers the user a cancel. `posted` and `declined` raise events only.
- On the invoice address, the prefilter admits the senders of invoices the wallet holds as well
  as the allowlist, so their notices arrive after a sender was removed from the allowlist.

Sending is best effort: a notice that cannot be delivered is logged and not retried. Nothing
depends on it arriving.

## Consequences

- No relay or wire change. Stock wallets never see a notice, and an older LEPIC build drops one
  as an undecodable slate and acknowledges it.
- A payer that rotated its invoice address after an invoice arrived declines from the new
  address, and the issuer drops that notice. The invoice still expires as ADR 0003's amendment
  describes.
- The marker is covered by the Epicbox signature over `str` and by no slate signature, so it
  proves a capability of the sending key and nothing about the slate.
- New notice types are added under version 1 as new `type` values; peers that do not know them
  ignore them.

## Alternatives considered

- Notices as a new slate stage or a field in a slate: a stock listener would act on or reject a
  slate it cannot finalize, and the legacy codecs are frozen.
- Sending notices to every peer and relying on stock to skip them: fact 3 shows stock never
  acknowledges them, which blocks the peer's address.
- Retrying undelivered notices from an outbox: the information is advisory and the state each
  side keeps is enough; a retry queue would add storage for no change in what funds do.
