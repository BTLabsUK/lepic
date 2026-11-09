# epic1

An epic1 is a LEPIC wallet's address for good: a proof key and a seal key, in bech32m. A link
to it adds where to deliver a payment (one to three Epicbox mailboxes on named relays) and what
to pay. This guide covers the address, the link, and how a payment travels between payer and
payee. The formats are in [RFC 0003 §5.13, §5.14 and §5.19](../rfcs/0003-epictx-native-slates.md#513-epic1-address),
with the grammar in Appendix B.

| Crate | Holds |
|---|---|
| [`lepic-epic1`](../../crates/lepic-epic1/README.md) | The address, the link, relay hosts and amounts; pure |
| `lepic-wallet-contacts` | Link mailboxes, paying a link, collecting and answering |

## The address

```text
data  = version (01) || proof key (32) || seal key (32)
text  = bech32m("epic", data)   on mainnet: 115 characters
        bech32m("tepic", data)  on floonet: 116 characters
```

- The **proof key** is an Ed25519 key. It signs the payment proofs of slates that came to the
  epic1.
- The **seal key** is the X25519 seal key of kind `00`. Payments to the epic1 are sealed to it.

Both derive from the seed and account, so a restore gives the same epic1. The address carries
no mailbox, relay or transport.

```rust
use lepic_epic1::Epic1Address;

let address = Epic1Address::decode(text, Network::Mainnet)?; // refuses floonet
let any = Epic1Address::decode_any(text)?;                    // network from the prefix
let seal_to = address.seal_key();
assert_eq!(address.encode(), text);
```

A reader decodes in this order and stops at the first error, an `Epic1Error`:

| Step | Variant | Message |
|---|---|---|
| bech32m, lower case, at most 256 characters | `Bech32` | not a bech32m string: … |
| Prefix of the expected network | `WrongNetwork` | address is not a Mainnet epic1 |
| Prefix `epic` or `tepic` | `UnknownPrefix` | address prefix is not epic or tepic |
| 65 data bytes | `Length` | address data has N bytes, expected 65 |
| Version `01` | `Version` | address version 0x02 is not defined |
| Proof key | `ProofKey` | proof key is not a canonical Ed25519 point of large order |
| Seal key | `SealKey` | seal key is of small order |

| Constant | Value |
|---|---|
| `VERSION` | `0x01` |
| `DATA_LEN` | 65 |
| `MAINNET_TEXT_LEN` | 115 |
| `hrp(network)` | `epic` or `tepic` |

## The link

```text
epic:epic1qqqq...example?epicbox=es1qexample...@relay.example.com&amount=1.5&message=Lunch
```

| Key | Meaning |
|---|---|
| `epicbox` | A link mailbox: `<mailbox>@<relay>[:<port>]`. May repeat. |
| `amount` | Decimal EPIC |
| `message`, `note`, `memo` | The payee's message |
| `label` | A label for the payee |

```rust
use lepic_epic1::{Delivery, Epic1Link};

let link = Epic1Link::parse(text)?;
match link.delivery() {
    Delivery::Usable(entries) => { /* try them in order */ }
    Delivery::CannotPay => { /* no usable epicbox entry; there is no default relay */ }
}
for skipped in &link.ignored { /* report each */ }
```

`Epic1Link::parse` reads only `epic:epic1…` and `epic:tepic1…`, and the link's network is the
address's own. A plain Epicbox link `epic:es1…` is `LinkError::NotAnEpic1Link`. The reader:

- refuses a link over `MAX_LINK_LEN`, 2048 bytes (`LinkError::TooLong`);
- reads at most `MAX_TRANSPORTS`, 3, `epicbox` entries, and reports the rest as
  `Skipped::TransportsOverLimit`;
- skips and reports each unusable entry as `Skipped::Transport` with a `TransportFault`;
- reads the first `amount` only, refusing the link when it is not valid (`LinkError::Amount`);
- reads the first `message` (or `note`, or `memo`) and `label` only, and skips a value over
  `MAX_VALUE_LEN`, 256 bytes, or one with control characters (`Skipped::Value`);
- ignores `method`, `direct`, `require`, `min` and unknown keys. No parameter is read as a second
  payee.

| `TransportFault` | Message |
|---|---|
| `Encoding` | value is not percent-encoded UTF-8 |
| `NoRelay` | no `@` between mailbox and relay |
| `Mailbox` | mailbox address: … |
| `Network` | mailbox is not of the epic1's network |
| `Relay` | relay: … (a `RelayHostError`) |

`to_uri` writes the link in lower case: the `epicbox` entries first, then `amount`, `message` and
`label`, with everything outside RFC 3986 unreserved characters percent-encoded.
`EpicboxTransport::new(mailbox, relay, port)` builds an entry, and `to_value(network)` writes it.
An entry with no port connects to 443.

### Amounts

`parse_amount` reads decimal EPIC into base units: `1`, `1.5` and `.25` are valid.
`format_amount` writes the shortest form back.

| `AmountError` | Message |
|---|---|
| `Syntax` | amount is not a decimal number of epic |
| `TooPrecise` | amount has more than 8 decimals |
| `TooLarge` | amount is too large |
| `Zero` | amount is zero |

Signs, exponents, separators and spaces are `Syntax`.

### Relay hosts

A relay from a link, from tag `09` of an envelope or from tail record `02` is untrusted input.
`RelayHost::parse` and `parse_host_port` check its syntax:

- `host[:port]` of at most `MAX_HOST_PORT_LEN`, 128 bytes;
- labels of 1 to 63 letters, digits and hyphens, with no hyphen at either end, lower-cased;
- a last label of digits only makes the host an IPv4 literal: four decimal labels, each at most
  255, without leading zeros. An IPv6 literal cannot be written;
- a port from 1 to 65535.

| `RelayHostError` | Message |
|---|---|
| `Length` | relay host is empty or longer than 128 octets with its port |
| `Label` | relay host has an empty label, a label over 63 octets or a character outside letters, digits, dots and hyphens |
| `Hyphen` | relay host has a hyphen at the end of a label |
| `NotAnAddress` | relay host looks like an IPv4 literal but is not four decimal numbers up to 255 |
| `Port` | relay port is not a number from 1 to 65535 |

The wallet checks the addresses it connects to after resolution. It refuses loopback, and
reports a local-network address to the user. The full list is in
[RFC 0003 §5.14](../rfcs/0003-epictx-native-slates.md#514-payment-links).

## Link mailboxes

A link names link mailboxes: Epicbox addresses derived from the seed, one per link
([RFC 0003 §5.2](../rfcs/0003-epictx-native-slates.md#52-keys-and-derivation)). There are two
kinds, `Epic1LinkKind`:

| Kind | Mailboxes | Use |
|---|---|---|
| `OnScreen` | A ring of 50 | Each link shown takes the next one |
| `Printed` | 32 | A printed link takes the first free one and keeps it until retired |

Each collect drains:

- every on-screen mailbox used within `ON_SCREEN_LIVE_FOR`, 7 days;
- every printed one not retired.

A link names the wallet's own relay unless the caller passes other relays, at most three.

## A payment

**Payer.** `epic1_read` reads the link and stores nothing. `epic1_pay` then:

1. builds an S1 with a TTL of `EPIC1_TTL_BLOCKS`, 1440 blocks, unless the send sets one;
2. seals it with `TxKey::Epic1`, which gives an anonymous envelope with a zero hint. The
   envelope carries tag `03`, the payer's reply key, and tag `09`, a reply mailbox on the
   payer's own relay;
3. armors it `BEGINEPICTX.` and posts it, with a post key of role initiator, to the first usable
   entry.

When that post fails, `epic1_post_next` posts the same bytes to the next entry. The payer must
pass `hosts_ok` to either call: it is the user's consent to the relays the link names.

**Payee.** On collect, the payee:

- drops a message at a link mailbox that is not `BEGINEPICTX.` armor;
- opens the envelope with the epic1 seal key and checks it;
- builds the S2, and signs a payment proof with the epic1 proof key when the S1 asks for one;
- seals the S2 to the reply key and stores it.

The check refuses a signed envelope, a non-zero hint, a missing tag `03` or `09`, and any stage
other than S1. `epic1_answers` lists the stored answers with the relay of each reply mailbox.
`epic1_post_answer` posts one, with a post key of role responder, once the user confirms that
relay. Posting again is safe.

**Payer again.** On collect, the payer opens the answer with the reply key, checks it is the S2
of its stored S1, and finalizes it.

`epic1_restore` reads the link mailboxes of the seed on the wallet's own relay after a restore.
Links named on other relays are not found.

A refusal is an `Epic1Refusal` inside `ContactError::Epic1`:

| Variant | Message |
|---|---|
| `CannotPay` | cannot pay this code |
| `WrongNetwork` | the epic1 is for another network |
| `Signed` | the payment is signed |
| `HintNotZero` | the envelope's hint is not zero |
| `NoReplyKey` | the payment names no reply key |
| `NoReplyMailbox` | the payment names no reply mailbox |
| `WrongStage` | the slate is at a stage this call does not take |
| `OtherSlate` | the answer is for another slate |
| `PrintedFull` | all printed links are in use |
| `NotIssued` | no printed link with that number is in use |
| `NoPayment` | no epic1 payment for this slate |
| `RelayNotConfirmed` | the relay was not confirmed |
| `NoMoreEntries` | no transport of the link is left to try |
| `OwnRelayLocal` | the wallet's relay is on this device |
| `LinkRelay` | a link relay is not usable |
| `TooManyRelays` | a link names at most three relays |
| `Message` | the message does not fit in a link |
| `ProofKey` | the address's proof key is not usable |
| `Finalized` | the payment was finalized already |

## From the CLI

```bash
lepic epic1 address
lepic epic1 link 0.8
lepic epic1 link --printed --epicbox relay.example
lepic epic1 read 'epic:epic1…'
lepic epic1 pay 'epic:epic1…' --hosts-ok
lepic epic1 post-next <SLATE_ID> --hosts-ok
lepic epic1 answers
lepic epic1 post-answer <SLATE_ID> --relay-ok
```

[docs/cli.md](../cli.md#through-an-epic1-link) has every option. Sealing is described in
[EPICTX](epictx.md), and the mailboxes and relays in [Epicbox](epicbox.md).
