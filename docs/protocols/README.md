# Protocols

A LEPIC wallet moves a slate to the other party by one of the methods below. The address decides
the format: to a classic address it writes V2 or V3 JSON; to an epic1 address it sends the native
slate `lepic.v1`, sealed in an envelope. These guides are for developers who build on LEPIC or
talk to it: what each method sends, which formats it reads and writes, and the constants and
errors in the code. The normative byte layouts are in the [RFCs](../rfcs/).

## Methods and formats

| Method | Reads | Writes |
|---|---|---|
| File or paste | V2 and V3 JSON by version, `BEGINEPICTX.` and `BEGINEPICSEALED.` armor | V3 JSON; a sealed armor to a contact or a reply key |
| Epicbox, classic address | V3 then V2 by shape | V2 for a new slate, a reply in the shape it answers |
| Epicbox, epic1 mailboxes | `lepic.v1` in a type `0A` envelope | The same |
| Epicbox, contact and pairing mailboxes | The envelopes of [Pairing](pairing.md) | The same |
| HTTP foreign API `/v2/foreign` | V3 then V2 by shape | V2 for a new slate, a reply in the shape it answers |
| Tor | As HTTP, at `<onion>:80` | As HTTP |
| epic1 link entry, `/api/v1/inbox` over HTTP or Tor | `lepic.v1` in a type `0A` envelope | The same, as the answer |
| In person (QR) | A raw `lepic.v1` proposal; UR `epic-slate` | A slate envelope, posted or shown back |

## Guides

| Guide | Covers |
|---|---|
| [EPICTX](epictx.md) | Native slates, the slate envelope, armors, reply keys, in-person codes, legacy at the edge |
| [epic1](epic1.md) | The epic1 address, links and their transports, paying a link |
| [Payment proofs](epic1-receipt.md) | The proof a payee of an epic1 payment signs: fields, signature, how anyone verifies it |
| [Pairing](pairing.md) | Invite, reply, confirm, SAS, private pairings, contact mailboxes, sealed slates, contact invoices, key checks, domain proof, relay moves |
| [Epicbox](epicbox.md) | Addresses, encryption, frames, listening and draining, the classic lane, messages that cannot be taken yet |
| [Epicbox mux/1](epicbox-mux.md) | The optional push extension: one socket for many mailboxes, tokens to resume, acknowledgements without signatures |
| [Delivery](delivery.md) | How native mail travels: the relay list, the watch set, reading by push, the outbox, what the host calls |
| [Tor](tor.md) | The onion service and its key, the tor process, SOCKS5, Epicbox and the node over Tor |
| [HTTP](http.md) | The foreign JSON-RPC API and the epic1 inbox |
| [Legacy transactions](../legacy-transactions.md), [epic1 overview](../epic1-overview.md) | Short overviews: what a classic address gets, and how an epic1 payment travels |

## RFCs

| RFC | Specifies |
|---|---|
| [0001](../rfcs/0001-lepic-slate-v1.md) | Slate stages and the framing rules |
| [0002](../rfcs/0002-contact-pairing.md) | Contact pairing, the sealed envelope, contact mailboxes |
| [0003](../rfcs/0003-epictx-native-slates.md) | EPICTX: native slates, epic1, the native endpoint |

The [Epicbox compatibility notes](../compat/epicbox.md) list how other Epicbox clients and relays
behave.
