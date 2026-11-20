# Direction

This page states where the design of LEPIC is heading. It is drawn from the accepted and proposed
decision records and from the points the specifications leave open. It states intent; the order
and the outcome of each item can change, and none of it describes the code as it is. For the code
as it is, see [Architecture](architecture.md) and the crate READMEs.

## Core and consumer

LEPIC carries the wallet's core functions and its cryptography. Limits, quotas, policy, trust
decisions, prompts and higher-level tools belong to the consumer: the app, a bot or a service that
drives the CLI. Where a decision needs the user, LEPIC stops and reports what it found, and the
consumer decides and calls back. Two examples in the code:

- An in-person code or a payment link's `http` or `tor` entry can name a host. Reading it, LEPIC
  reports each host, whether it is in the wallet's mailbox list and its address class, and refuses
  a loopback host itself. An epic1 link names no mailbox. The consumer shows the report and pays with a second call
  ([RFC 0003](rfcs/0003-epictx-native-slates.md)).
- A contact's request to move its relay is raised as an event. The consumer decides whether to
  apply it ([ADR 0039](adr/0039-the-host-applies-a-relay-move.md),
  [Pairing](protocols/pairing.md)).

Features follow the same split. A limit that the CLI enforces is a mechanism, and the
operator of a service sets its value.

## Native slates between LEPIC wallets

The address decides the protocol ([ADR 0062](adr/0062-the-address-decides-the-protocol.md)).
Between LEPIC wallets a slate is sealed in an EPICTX envelope; Epic Cash's JSON slates and the
reference wallet's protocols stay at the edge, for every wallet that is not LEPIC
([ADR 0052](adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md),
[EPICTX](protocols/epictx.md)). The code that speaks the reference formats sits behind the
`legacy` feature of `lepic-transport` and `lepic-methods`.

- A paired contact gets a V3 slate in a type `01` envelope, signed
  ([RFC 0003 §6.1](rfcs/0003-epictx-native-slates.md#61-paired-contact)).
- An epic1 address or link gets a slate envelope sealed to the address. Each account has one
  epic1 address, and mail goes to the wallet's one list: posted to at most 3 of its mailboxes, read on all of them
  ([ADR 0066](adr/0066-one-address-per-account.md),
  [ADR 0065](adr/0065-mail-goes-where-the-receiver-reads.md),
  [RFC 0003 §5.19](rfcs/0003-epictx-native-slates.md#519-epic1-payments)).
- In person, a proposal is a raw `lepic.v1` code, answered with a slate envelope
  ([RFC 0003 §9](rfcs/0003-epictx-native-slates.md#9-in-person-codes)).
- An Epicbox address, a listener URL or an onion gets V2 or V3 JSON and nothing else
  ([RFC 0003 §6.5](rfcs/0003-epictx-native-slates.md#65-wallets-that-are-not-lepic)). Receiving
  V2 and V3 slates, decoding V2, the Epicbox 3.0.0 frames and HTTPS sends to stock listeners stay,
  for exchanges and for wallets that speak only those formats.

## Records marked proposed

These records are marked `proposed`. The code follows all of them except ADR 0054. ADR 0062 and
ADR 0063 supersede most of ADR 0054; its carrier, router and outbox are built in
`crates/lepic-wallet-contacts/src/delivery/`, and its rotating contact mailbox (section 7) and pay
page (section 10) are not. Accepting them is a decision for the project owner.

| Record | Subject |
|---|---|
| [0012](adr/0012-native-slate-format.md) | The native slate format, specified in [RFC 0001](rfcs/0001-lepic-slate-v1.md) and adopted by ADR 0052 |
| [0024](adr/0024-contact-pairing-and-invoice-trust.md) | Contact pairing, sealed slates and invoice trust |
| [0033](adr/0033-key-and-domain-registry.md) | One registry of seed-derived keys and signature domains |
| [0034](adr/0034-trust-versioning-and-probing.md) | Trust, versioning and probing between Epic wallets |
| [0045](adr/0045-refusing-slates-nobody-asked-for.md) | Refusing slates nobody asked for |
| [0050](adr/0050-one-wallet-api.md) | One wallet API, served by `lepic serve` (its paths and bodies are superseded by ADR 0055) |
| [0054](adr/0054-epic1-over-carriers-derived-mailboxes-short-links.md) | epic1 over carriers: derived mailboxes and a short link; mostly superseded by 0062 and 0063 |
| [0058](adr/0058-service-wallet-api.md) | Serve for service wallets: boosts, webhooks and payment fields |

## Cryptography

The envelope carries a suite byte. Suites `01` and `41` (the same with a pre-shared key) are in
use. A post-quantum suite, X-Wing as
suite `02` (with a PSK variant), and a post-quantum epic1 key are planned once the IETF draft for
post-quantum HPKE is published as an RFC and the code under it has had an audit
([ADR 0052](adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md),
[EPICTX](protocols/epictx.md)).

## Open points in the specifications

These questions are open. Each needs a design before code:

- **Large in-person answers.** The number of animated QR frames at which an in-person I2 offers to
  use fewer coins, and whether a largest-first selection strategy backs that offer.
- **File names.** The name of the file a send writes.
- **Other wallets and epic1 links.** Stack Wallet and Epic Pay are expected to refuse an epic1
  link as an unknown address; this has not been tested.
- **Reference kit.** The Python reference kit needs its own `lepic.v1` codec.
- **Per-transaction native addresses.** A native address is a long-lived key; per-transaction
  addresses are a later option ([RFC 0001](rfcs/0001-lepic-slate-v1.md)).
- **Invite links.** Invites use `epiccash://` links and pasteable codes; an `https://` universal
  link, with the payload in the fragment, is a later option
  ([RFC 0002](rfcs/0002-contact-pairing.md)).
- **Chat apps.** A paste test of base64url codes through common chat apps comes before the
  formats are frozen.
