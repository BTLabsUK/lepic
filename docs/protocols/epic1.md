# epic1

An epic1 is a LEPIC wallet's address for good: a seal key and a delivery key, in bech32m. The
delivery key is the address's slot on every mailbox. Each account has one. A payment link is the
address as a link. A request link adds an amount, a message or both, and at most three `http` or
`tor` hosts to deliver to instead. This guide covers the address, the links, and how a payment
travels between payer and payee.

Words: a mailbox is a server that runs Epicmail, the mail protocol; a slot is the box of one
key on a mailbox. Code and older records say relay for mailbox and mailbox for slot.

The formats are in [RFC 0003 §5.13, §5.14 and §5.19](../rfcs/0003-epictx-native-slates.md#513-epic1-address),
with the grammar in Appendix B.

| Crate | Holds |
|---|---|
| [`lepic-epic1`](../../crates/lepic-epic1/README.md) | The address, the link, mailbox hosts and amounts; pure |
| `lepic-wallet-contacts` | Paying an address or a link, collecting and answering |

## The address

```text
data  = version (01) || seal key (32) || delivery key (33)
text  = bech32m("epic", data)   on mainnet: 117 characters
        bech32m("tepic", data)  on floonet: 118 characters
```

- The **seal key** is the X25519 seal key of kind `00`. Payments to the epic1 are sealed to it.
- The **delivery key** is a compressed secp256k1 public key, prefix `02` or `03`.

The address is written in lower case. A reader takes it in lower or upper case, so a QR code
can hold it in upper case; mixed case is refused. An epic1 carries no proof key. The payee signs a
payment proof with a key derived in public from the delivery key
([Payment proofs](#payment-proofs)); a slate that asks for a slate-level proof is refused.

Both derive from the seed, the account and the address's index, so a restore gives the same
epic1. The address names no mailbox or transport, and no index. Its delivery key, read as an
Epicbox address, is its delivery slot on any mailbox.

### One address per account

Each account has one epic1 address: index 0, with the keys and the slot described above. Anyone
pays it any number of times, and every payment comes to the same account. No other address of an
account is made, issued, watched or tried. Numbered addresses (index 1 and up) of earlier builds
are not read: a payment sent to one is not taken, and its payer's wallet cancels it at its
deadline. Coins already received at one stay in the wallet, because they come from the seed.

Two accounts on one wallet have two addresses. A user who does not want two payers to know they
pay the same wallet uses a second account.

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
| bech32m, all lower or all upper case, at most 256 characters | `Bech32` | not a bech32m string: … |
| Prefix of the expected network | `WrongNetwork` | address is not a Mainnet epic1 |
| Prefix `epic` or `tepic` | `UnknownPrefix` | address prefix is not epic or tepic |
| 66 data bytes | `Length` | address data has N bytes, expected 66 |
| Version `01` | `Version` | address version 0x02 is not defined |
| Seal key, canonical and not of small order | `SealKey` | seal key is of small order |
| Delivery key, a compressed secp256k1 point | `DeliveryKey` | delivery key is not a compressed secp256k1 point |

| Constant | Value |
|---|---|
| `VERSION` | `0x01` |
| `DATA_LEN` | 66 |
| `MAINNET_TEXT_LEN` | 117 |
| `hrp(network)` | `epic` or `tepic` |

## The links

A payment link is the address as a link: `epic:<address>`. A request link is the same with an
amount, a message or both:

```text
epic:epic1qqqq...example?amount=1.5&message=Lunch
epic:epic1qqqq...example?http=pay.example.com&tor=example...onion&amount=1.5
```

A request link only fills in the payer's Send screen. The payer may change the amount and the
message before paying, and the payer's wallet does not refuse a payment whose amount differs from
the link's. The payee keeps no record of a link: making one stores nothing and derives no key,
and the same fields always give the same text. A payment arrives as a normal payment to the
address with the payer's message; nothing matches it to a link. A shop that wants to tell orders
apart puts the order number in the message and matches payments itself. The message is written by
the payer and proves nothing.

A link names no mailbox, whatever the wallet's list holds.

| Key | Meaning |
|---|---|
| `http` | A host the payment may be posted to over HTTPS: `<host>[:<port>]`, port 443 by default |
| `tor` | An onion the payment may be posted to: `<name>.onion[:<port>]`, port 80 by default |
| `amount` | Decimal EPIC |
| `message`, `note`, `memo` | A message for the payer's Send screen |
| `label` | A label for the payee |

```rust
use lepic_epic1::Epic1Link;

let link = Epic1Link::parse(text)?;
for entry in &link.routes { /* an `http` or `tor` entry, in link order */ }
for skipped in &link.ignored { /* report each */ }
```

`Epic1Link::parse` reads only `epic:epic1…` and `epic:tepic1…`, and the link's network is the
address's own. A plain Epicbox link `epic:es1…` is `LinkError::NotAnEpic1Link`. The reader:

- refuses a link over `MAX_LINK_LEN`, 2048 bytes (`LinkError::TooLong`);
- refuses a link with more than `MAX_TRANSPORTS`, 3, `http` and `tor` entries
  (`LinkError::TooManyEntries`);
- skips and reports each unusable entry as `Skipped::Transport` with a `TransportFault`;
- skips and reports each `epicbox` entry, which links of earlier releases wrote, as
  `Skipped::Epicbox`;
- reads the first `amount` only, refusing the link when it is not valid (`LinkError::Amount`);
- reads the first `message` (or `note`, or `memo`) and `label` only, and skips a value over
  `MAX_VALUE_LEN`, 256 bytes, or one with control characters (`Skipped::Value`);
- ignores `method`, `direct`, `require`, `min` and unknown keys. No parameter is read as a second
  payee.

| `TransportFault` | Message |
|---|---|
| `Encoding` | value is not percent-encoded UTF-8 |
| `Http` | http host: … (a `RelayHostError`) |
| `Onion` | tor value is not an onion name with an optional port |

`to_uri` writes the link in lower case: the `http` and `tor` entries first, then `amount`, `message`
and `label`, with everything outside RFC 3986 unreserved characters percent-encoded. `to_qr` writes
the text of a QR code: the address, the first `http` or `tor` entry and the amount only. A link with
neither an entry nor an amount is written `EPIC:EPIC1…` in upper case, so the code uses
alphanumeric mode: level H, version 8 (49 × 49) for a mainnet address. A link with an entry or an
amount is written in lower case. The reader takes the scheme and the keys in any case, and the
address in all lower or all upper case; an address in mixed case is refused.

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

### Mailbox hosts

A mailbox from a link, from tag `09` of an envelope or from tail record `02` is untrusted input.
`RelayHost::parse` and `parse_host_port` check its syntax:

- `host[:port]` of at most `MAX_HOST_PORT_LEN`, 128 bytes;
- labels of 1 to 63 letters and digits, lower-cased. No hyphens: Epicbox mailboxes apply this rule
  to every address they carry;
- a last label that starts with a digit makes the host an IPv4 literal: four decimal labels,
  each at most 255, without leading zeros. An IPv6 literal cannot be written;
- a port from 1 to 65535.

| `RelayHostError` | Message |
|---|---|
| `Length` | relay host is empty or longer than 128 octets with its port |
| `Label` | relay host has an empty label, a label over 63 octets or a character outside letters, digits and dots |
| `NotAnAddress` | relay host looks like an IPv4 literal but is not four decimal numbers up to 255 |
| `Port` | relay port is not a number from 1 to 65535 |

The wallet checks the addresses it connects to after resolution. It refuses loopback, and
reports a local-network address to the user. The full list is in
[RFC 0003 §5.14](../rfcs/0003-epictx-native-slates.md#514-payment-links).

## The mailbox list

The wallet posts and reads epic1 mail on [its mailbox list](delivery.md#the-mailbox-list): one
list per wallet, for all native mail. [Delivery](delivery.md) has the rules for each kind of
mail, the slots watched and the outbox.

## What is watched

Collect watches the slot of each account's address, and the slots of its contacts, on every
mailbox of the list that offers mux/1 and on every mailbox not yet known; a mailbox known not to
offer it is asked again later. The wallet tries the seal key of index 0 of each account on a
payment that arrives without a slot (a file, transaction text, the native endpoint), and no
other.

A link entry is an `http` host or a `tor` onion. An `http` host on the local network is refused
unless it is in the wallet's mailbox list, on any port; a payer leaves such an entry out.

## A payment

**Payer.** `epic1_read` reads the link and stores nothing. `epic1_pay` then:

1. builds an S1 with a TTL of `EPIC1_TTL_BLOCKS`, 10,080 blocks (7 days), unless the send sets one;
2. seals it with `TxKey::Epic1`, which gives an anonymous envelope with a zero hint. The
   envelope carries tag `03`, the payer's reply key, and tag `09`, the key of a one-time reply
   slot; it names no mailbox;
3. armors it `BEGINEPICTX.` and posts it, with a post key of role initiator, to the first entry
   of the link. An `http` or `tor` entry is posted to that host and answered in the same
   request. A link without such entries goes to the address's delivery slot on the 3 healthiest
   mailboxes of the payer's list at once ([Delivery](delivery.md#where-mail-goes)). The payment counts as posted when any mailbox takes it; the mailboxes
   that did not are tried again on the outbox's schedule until the payment is answered or ends.
   A link with `http` or `tor` entries never falls back to the slot.

The payer's wallet checks before it stores anything that the payee can be reached. If the payer's
list holds no shipped mailbox and the call names none, `epic1_pay` fails with `NoSharedMailbox`:
the payer and the payee need one mailbox in common. The error lists the shipped mailboxes. The
call takes an optional list of mailboxes for that one payment, so a host can ask its user and pay
through them. A payer on the shipped list who pays a payee that reads only a private mailbox gets
no error; the payment ends at its deadline.

Each copy posted to a mailbox carries a transaction id derived from the payer's post key, the
payment id and the stage. The outbox stores which mailboxes took a copy. Once the answer or a
refusal is taken from one mailbox, the payer cancels the copies on the mailboxes that took one,
with that id (txcancel/1), and tries again on the outbox's schedule after a failure while the
payment is open. A copy the payee reads later has its stored answer posted again, the same bytes,
from the same outbox row: a repeat adds no row.
If the wallet stops between storing the answer and the cancels, the copies expire with the
mailbox's retention.
A post of the same payment that a mailbox refuses because the payment was cancelled there, after
the answer was taken, ends quietly.

A post to an entry that is not sent, or that the host refuses, moves on to the next entry at once
with the same bytes. A post that was sent and not answered may have arrived, so the wallet tries
it again on the same entry and moves on only when the host asks: `lepic epic1 post-next` posts the
same bytes to the next entry. `epic1_read` returns `http_host`, the host of the link's first `http`
or `tor` entry, or none for a payment through the slot.

`Epic1Paid` lists the posts in `attempts`, one per mailbox a payment to the slot was taken by. `posted` is
the entry the payment went to. `uncertain` marks a post that may have arrived, in two cases. For a
payment to the slot, no mailbox of the list took it and at least one gave no answer: that mailbox may
still hold it. For a payment on the link's entries, the post on an entry failed after it was sent,
and the next entry may be tried: it is the same payment, so it never pays twice. A second payment to
an address whose first payment waits for its answer is posted as usual; each payment has its own id.

**Payee.** On collect, the payee:

- reads a message at a delivery slot by its armor: `BEGINEPICTX.` as a payment,
  `BEGINEPICSEALED.` as a notice (see Notices). Anything else, a payment armored as a notice
  and a notice armored as a payment are dropped;
- opens the envelope with the seal key of the account's address and checks it;
- takes any amount. It checks none against a link, because it keeps no link;
- with the refuse switch on (`refuse_unsolicited_payments`,
  [ADR 0045](../adr/0045-refusing-slates-nobody-asked-for.md)), refuses every payment to the
  address with reason `declined`. A request link does not make a payment asked for. The reason
  `amount` is no longer sent for a payment to the address; readers still understand it;
- refuses an S1 that asks for a payment proof (`ReceiveError::ForeignProofAddress`), signs
  nothing, and stores a `declined` notice with reason `declined`, posted as the one above;
- builds the S2;
- seals the S2 to the reply key and stores it.

The check refuses a signed envelope, a non-zero hint, a missing tag `03` or `09`, and any stage
other than S1. The answer or refusal is posted, with a post key of role responder, to the reply
slot on the mailbox the payment was read on, and on the 2 healthiest other mailboxes of the
payee's list: 3 mailboxes at most, never the whole list. The payment carries no reply mailbox: the
payer watches its reply slot on every mailbox of its list, so the mailbox the payment was read on
always reaches it. A payment read again on another mailbox is not taken twice; its stored answer
is posted again, with the same bytes and from the same outbox row.
`epic1_answers` lists the stored answers.

**Payer again.** On collect, the payer opens the answer with the reply key, checks it is the S2 of
its stored S1, and finalizes it. For a payment sent by an `http` or `tor` entry, the answer comes in
the same request and the reply slot of tag `09` is not read.

`epic1_restore` reads the slot of each account's address and the slots of its contacts, in one
pass, on every mailbox of the list that answers, and reports the mailboxes it could not read. It
fails only when none could be read. There is no gap, no window and no rounds over indexes: a
restored wallet takes a payment to its address and makes a request link at once.

Two installs on one recovery phrase without a link are unsupported; link the device instead. The
rest of this paragraph says how that setup fails safe. They share the address. A slot has one reader at a time on a mailbox: the
newest attach takes it and the other install is told it was replaced. Whichever install holds the
slot reads the payment and answers it. The other learns of it from the chain: once it is mined,
its refresh and update scan record an incoming entry from another wallet, confirmed, without the
payer's message. The replaced install attaches the slot again when its hold-off (10 minutes)
ends; an open (start, unlock, `epic1_restore`) or a restart takes it back at once. A pull only
retries the reconnect, so two installs that both pull do not trade the slot. Mail not
acknowledged is delivered again to the new reader. If both installs answer one payment, the
twins rules end the answer the payer did not finalize.

A refusal is an `Epic1Refusal` inside `ContactError::Epic1`:

| Variant | Message |
|---|---|
| `CannotPay` | cannot pay this code |
| `WrongNetwork` | the epic1 is for another network |
| `Signed` | the payment is signed |
| `HintNotZero` | the envelope's hint is not zero |
| `NoReplyKey` | the payment names no reply key |
| `NoReplyRoute` | the payment names no reply route |
| `WrongStage` | the slate is at a stage this call does not take |
| `OtherSlate` | the answer is for another slate |
| `NoPayment` | no epic1 payment for this slate |
| `NoMoreEntries` | no transport of the link is left to try |
| `LinkRelay` | making a link: an entry is not usable |
| `TooManyRelays` | making a link: a link carries at most three entries |
| `Message` | the message does not fit in a link |
| `Finalized` | the payment was finalized already |
| `NoSharedMailbox` | the payer's list holds no shipped mailbox and the call names none |
| `NoReceipt` | the payee's answer brings no payment proof (a payment that requires one) |
| `BadReceipt` | the payee's payment proof does not verify (a payment that requires one) |

## Payment proofs

A LEPIC payee signs a payment proof into the S2 of every epic1 payment it takes, with a key
derived from the address's delivery key. It says the owner of the address took this amount in the
transaction whose kernel excess it names, for this slate id. The payer key in it is one-time and
names no payer. The payer keeps the proof if it holds, and finalizes the payment even without one
unless it requires proof (`--require-proof`, `epic1_require_proof`). Stock Epic wallets and LEPIC wallets of 0.6.1 and older sign none.
The byte-level format is [epic1-receipt](epic1-receipt.md).

## Notices

A notice tells the other side of an epic1 payment what happened to it. Each is one outbox row
of no stage on the payment's route, posted by the carrier like any row: on a slot route to
at most 3 usable mailboxes of the mailbox list, with no mailbox transaction id. Nothing else sends a notice
and nothing retries one on its own. Every notice goes out by one send path and is taken by one
intake ([ADR 0067](../adr/0067-one-notice-path.md)).

| Kind | From, to | Where | When |
|---|---|---|---|
| `posted` | payer to payee | the delivery slot of the address paid | the payer finalized the payment and its transaction is posted |
| `cancelled` | payer to payee | the delivery slot of the address paid | the payer cancelled a payment that a mailbox took or may hold |
| `declined` | payee to payer | the reply slot of tag `09`, on the mailbox the payment was read on and the 2 healthiest others of the payee's list | the payee refused the payment |

`posted` and `cancelled` are a type `02` envelope sealed to the seal key of the address paid:
anonymous, hint zero, padded as a slate, no reply route (`seal_epic1_notice`), armored
`BEGINEPICSEALED.`. The body is the
notice JSON of ADR 0016 with the slate id, and for `posted` the kernel excess. The payee opens
what comes to a delivery slot once (`SealedEnvelope::open_epic1`) and tells a slate from a
notice by `TxKind`. `declined` is sealed to the reply key and armored `BEGINEPICSEALED.`.

The payer queues `posted` when it first posts the transaction, so it is queued once. A wallet that
stops between the post and the queuing sends none. A collect queues `cancelled` before it reads the slots and posts it in the same
collect. The cancel of a payment's other copies (`txcancel/1`) names the payment's transaction
id and a notice carries none, so a cancel never removes a notice and either may reach a mailbox
first.

What each kind changes where it is read:

- `posted` is taken only for a payment the address took and answered, still waiting for its
  sender, and only when its excess is the one the payee's own answer implies. The payee keeps
  the time and raises `PaymentPosted`. Confirmations still come from the chain. A `posted` not
  yet sent when its transaction confirms is dropped, and the payee sees the confirmation
  itself.
- `cancelled` is taken only for a payment the address took and answered, still waiting for its
  sender. The payee keeps the time and raises `PaymentCancelled`. The payment stays received;
  the host decides what to do.
- `declined` is taken by the payer only while the payment waits for its answer. The payer keeps
  the time and raises `PaymentDeclined`. The send never happened: the payer erases it and frees
  its inputs, and the event carries the id of a send that no longer exists. A refusal that an
  HTTP or Tor endpoint gives in the same request stays `Undelivered`.

A notice moves no coins. Each event is raised once per payment and kind: a copy read again, on
the same mailbox or another, changes nothing and raises nothing. A notice about a payment the
reader does not hold, or one that confirmed or ended, changes nothing, and nothing is kept for
it. A `cancelled` read before its payment therefore changes nothing; the payment read after it
is answered as usual, and the payer, which cancelled it, drops the answer.

No notice is sent:

- for a payment by an `http` or `tor` entry: the answer or refusal comes in the request;
- by a payee to a payment that names no reply route; no notice falls back to the classic
  Epicbox lane or to an index-0 address;
- `cancelled` for a payment no mailbox took, or one its payee declined;
- `posted` for a payment whose transaction the payer did not post, such as one finalized
  offline.

A notice row ends posted once any mailbox takes it. Otherwise it is tried again with back-off and
fails after `OUTBOX_STUCK_AFTER`, a day. The mailbox's retention removes what nobody reads. The
prune deletes an ended row; a cancelled payment's S1 row and record wait until its `cancelled`
is queued, and go in the collect after. A notice envelope is 832 bytes: the content pads to
`PADDING_FLOOR`, 768 bytes, as a slate's does, far under the mailbox's message limit, which the
carrier checks as for any post. A notice is padded by the same rule as a slate and is always the
floor size, so a slate that pads past the floor differs from it in size.

No pair request and no invoice travel over an epic1 link.

## From the CLI

```bash
lepic epic1 address
lepic epic1 link
lepic epic1 link --amount 0.8 --message Lunch
lepic epic1 link --amount 0.8 --http-host pay.example.com
lepic epic1 read 'epic:epic1…'
lepic epic1 pay 'epic:epic1…'
lepic epic1 post-next <SLATE_ID>
lepic epic1 answers
```

[docs/cli.md](../cli.md#epic1-links) has every option. Sealing is described in
[EPICTX](epictx.md), and the mailboxes, the slots watched and the outbox in
[Delivery](delivery.md).
