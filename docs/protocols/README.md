# Protocols

A LEPIC wallet moves a slate to the other party by one of six methods. With a wallet that is not
LEPIC it speaks V2 or V3 JSON. With another LEPIC wallet it can use the native slate `lepic.v1`,
sealed in an envelope. These guides are for developers who build on LEPIC or talk to it: what
each method sends, which formats it reads and writes, and the constants and errors in the code.
The normative byte layouts are in the [RFCs](../rfcs/).

## Methods and formats

| Method | Reads | Writes |
|---|---|---|
| File or paste | V2 and V3 JSON by version, `BEGINEPICTX.` and `BEGINEPICSEALED.` armor | V3 JSON; a sealed armor to a contact or a reply key |
| Epicbox | V3 then V2 by shape; `BEGINEPICTX.` at the payments address | V2 for a new slate, a reply in the shape it answers; native when the peer claimed it |
| HTTP foreign API `/v2/foreign` | V3 then V2 by shape | V2 for a new slate, a reply in the shape it answers |
| Tor | As HTTP, at `<onion>:80` | As HTTP |
| Native direct `/api/v1/inbox` | `lepic.v1` in a type `0A` envelope | The same |
| In person (QR) | A raw `lepic.v1` proposal; UR `epic-slate` | A slate envelope, posted or shown back |

The V2 and V3 JSON a LEPIC wallet writes ends with the `lepic` marker. Another LEPIC wallet reads
it to learn a reply key or a native-slate claim; other wallets ignore it.

## Guides

| Guide | Covers |
|---|---|
| [EPICTX](epictx.md) | Native slates, the slate envelope, armors, reply keys, in-person codes, legacy at the edge |
| [epic1](epic1.md) | The epic1 address, links and their transports, paying a link |
| [Pairing](pairing.md) | Invite, reply, confirm, SAS, private pairings, contact mailboxes, sealed slates, contact invoices, key checks, domain proof, relay moves |
| [Epicbox](epicbox.md) | Addresses, encryption, frames, listening and draining, notices, messages that cannot be taken yet |
| [Tor](tor.md) | The onion service and its key, the tor process, SOCKS5, Epicbox and the node over Tor |
| [HTTP](http.md) | The foreign JSON-RPC API and the native direct endpoint |

## RFCs

| RFC | Specifies |
|---|---|
| [0001](../rfcs/0001-lepic-slate-v1.md) | Slate stages and the framing rules |
| [0002](../rfcs/0002-contact-pairing.md) | Contact pairing, the sealed envelope, contact mailboxes |
| [0003](../rfcs/0003-epictx-native-slates.md) | EPICTX: native slates, epic1, the native direct endpoint |

The [Epicbox compatibility notes](../compat/epicbox.md) list how other Epicbox clients and relays
behave.
