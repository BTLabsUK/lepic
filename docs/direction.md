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

- An epic1 link or an in-person code can name a relay. Reading it, LEPIC reports each host,
  whether it is in the configured relay list and its address class, and refuses a loopback host
  itself. The consumer shows the report and pays with a second call
  ([RFC 0003](rfcs/0003-epictx-native-slates.md)).
- A contact's request to move its relay is raised as an event. The consumer decides whether to
  apply it ([ADR 0039](adr/0039-the-host-applies-a-relay-move.md),
  [Pairing](protocols/pairing.md)).

Features follow the same split. A limit that the CLI enforces is a mechanism, and the
operator of a service sets its value.

## Native slates between LEPIC wallets

Two LEPIC wallets exchange native `lepic.v1` slates in EPICTX envelopes; Epic Cash's JSON slates
and the reference wallet's protocols stay at the edge, for every wallet that is not LEPIC
([ADR 0052](adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md),
[EPICTX](protocols/epictx.md)). The code that speaks the reference formats sits behind the
`legacy` feature of `lepic-transport` and `lepic-methods`.

- Native slates are off by default: a wallet sends them only with `native_direct` on in its
  `WalletConfig` (`native_direct` in the CLI's [settings](configuration.md)). The intent is to turn them on by default between LEPIC wallets once the interop
  and acceptance runs cover them.
- With that change, a send to an HTTP or Tor listener that offers V3 slates goes as V3 rather than
  V2, since V3 carries payment proofs and a TTL.
- Receiving V2 and V3 slates, decoding V2, the Epicbox 3.0.0 frames and HTTPS sends to stock
  listeners stay, for exchanges and for wallets that speak only those formats.

## Records marked proposed

These records are marked `proposed`. Their designs are in the code; accepting them is a decision
for the project owner.

| Record | Subject |
|---|---|
| [0012](adr/0012-native-slate-format.md) | The native slate format, specified in [RFC 0001](rfcs/0001-lepic-slate-v1.md) and adopted by ADR 0052 |
| [0024](adr/0024-contact-pairing-and-invoice-trust.md) | Contact pairing, sealed slates and invoice trust |
| [0033](adr/0033-key-and-domain-registry.md) | One registry of seed-derived keys and signature domains |
| [0034](adr/0034-trust-versioning-and-probing.md) | Trust, versioning and probing between Epic wallets |
| [0045](adr/0045-refusing-slates-nobody-asked-for.md) | Refusing slates nobody asked for |
| [0050](adr/0050-one-wallet-api.md) | One wallet API, served by `lepic serve` |

## Cryptography

The envelope carries a suite byte. Suites `01` and `41` (the same with a pre-shared key) are in
use. A post-quantum suite, X-Wing as
suite `02` (with a PSK variant), and a post-quantum epic1 key are planned once the IETF draft for
post-quantum HPKE is published as an RFC and the code under it has had an audit
([ADR 0052](adr/0052-legacy-at-the-edge-native-between-lepic-wallets.md),
[EPICTX](protocols/epictx.md)).

## Open points in the specifications

These questions are open. Each needs a design before code:

- **Pins.** When a pinned peer's pin expires, and how a user clears a pin.
- **Shared links.** How a user retires a printed or shared epic1 link or code.
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
