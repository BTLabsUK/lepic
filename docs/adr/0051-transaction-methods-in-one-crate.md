# ADR 0051: Transaction methods in one crate, outside the engine

Status: accepted

## Context

A slate moves over a transaction method: Epicbox, HTTP, Tor or a file. Each method decides how a
slate is encoded, what it may carry, how it is delivered and what a received one says about its
sender. Three consumers move slates: the CLI, the binding and the wallet API of `lepic serve`
(ADR 0050). A method's code written once per consumer drifts apart, and an engine that names one
method cannot take another.

Not everything a method decides can leave the slate builder. A method decides what the slate may
carry: a payment proof addressed to its own key (the Epicbox address key, the onion key), a TTL, the
slate shape. The engine must know those limits before it stores anything, so that a slate the
method cannot carry is refused with nothing locked (ADR 0003). The order of effects also belongs to
wallet state: an S1 is stored with its inputs locked before it is delivered, and a delivery that
fails leaves it for a resend with its first bytes. A received envelope is acknowledged only after
its effect is stored.

## Decision

### The engine knows no method by name

`lepic-wallet` builds, stores, receives, finalizes and posts slates. It reaches a method through
one port, the `Method` trait of `lepic-transport`. It decides:

| Item | Call |
|---|---|
| What the slate may carry (`Carries`) | `carries` |
| How a new slate (S1, I1) and a reply (S2, I2) are encoded | `encode_new`, `encode_reply` |
| What a received slate says about its sender (the marker's claimed features and reply key) | `sender_facts` |
| Padding lengths of a notice; an empty list means the method sends none | `notice_lengths`, `notice_lengths_for` |
| The key an address names, and whether two destinations are one payee | `peer_key`, `same_payee` |
| Whether a delivery failure would repeat | `delivery_is_permanent` |

A method's id is an opaque name stored with the transaction in the `transport` column.

A message a method received goes to the engine through `Wallet::arrived`, with the method that
carried it. The engine records the message id before it applies the slate, settles repeats, and
fails with `Outcome::Hold` or `Outcome::Requeue` when the message is to stay or go back. The method
answers or acknowledges after that.

Notices carry no method. The engine finds the method of a stored payment through `MethodLookup`,
which the consumer hands it in `Ports.methods`. With none, the engine sends no notice. A notice that
arrives is handed to one engine entry, whichever method carried it.

### One crate holds every method

`lepic-methods` holds the registry (`Methods`) and one module per method, each behind a cargo
feature of the same name:

| Feature | Holds |
|---|---|
| `file` | The file method, re-exported from `lepic-transport` |
| `epicbox` | The Epicbox method and transport, with no engine |
| `epicbox-wallet` | The Epicbox inbox loop, listings and drain, which call the engine |
| `http` | The HTTP receiver and dialer, the native peer client and the shared refusal mapping (`http::refuse`) |
| `tor` | The Tor listener and dialer |
| `legacy` | The legacy wire formats each method speaks (ADR 0052) |

A new method is a new module and one `Methods::register` call. The engine calls no method code
other than through the port above, and `lepic-methods` calls the engine in the order of effects
stated in Context.

### Protocol crates are wire libraries

`lepic-epicbox` (relay client, addresses, wire messages), `lepic-legacy-rpc` (the `/v2/foreign`
server and client), `lepic-peer` (the native endpoint) and `lepic-tor` (the tor process, onions,
SOCKS) know no wallet and implement no LEPIC trait. They stay small enough to fuzz and to check
against the reference implementations on their own.

### Consumers ask for a method

`lepic-cli`, `lepic-ffi`, `serve` and its API call `lepic-methods` for anything that moves a slate.
`lepic-wallet-contacts` builds on its Epicbox and HTTP modules.

```
lepic-slate ── lepic-wallet ── lepic-methods ──┬── lepic-epicbox
                                  │            ├── lepic-legacy-rpc
                                  │            ├── lepic-peer
                                  │            └── lepic-tor
              lepic-wallet-contacts, lepic-cli, lepic-ffi
```

`lepic-wallet` depends on `lepic-transport` and not on `lepic-epicbox`. Its tests take
`lepic-epicbox` and `lepic-methods` as dev-dependencies for a mock relay.

### The API

The API's `method` field and `GET /v1/methods` read the registry. The API sends over `epicbox`
and `http` (ADR 0050).

## Consequences

- A method's code exists once, for the CLI, the app and the API alike.
- One refusal mapping serves every consumer.
- The engine's send and receive take the method's port in place of a transport id and a registry.
- The risk is in the order of effects and the marker handling. The adversarial race tests, the
  lifecycle tests and the slate vectors guard it. The wire does not change with the layout.
- The engine keeps one Epicbox-shaped part: the `epicbox_invoice` module. It names the stored id
  `epicbox` (`EPICBOX`) to find the invoices and sends issued over Epicbox, expire them and
  to match a returned I1. A test checks that the constant equals `lepic_methods::epicbox::TRANSPORT_ID`.
- The binding keeps its own `EpicboxSlot`, a `Method` that forwards each call to the current Epicbox
  transport, so that replacing the relay in place does not change the method the engine holds.

## Alternatives considered

- **One crate with the protocols folded in.** Fewer crates, but the relay client, the JSON-RPC
  server and the tor control code become feature-gated modules of a crate that also depends on the
  engine, and can no longer be built, fuzzed and checked against the reference on their own.
- **Keep the layout and move only the Epicbox rules out of `send.rs`.** The smallest change, but
  the HTTP and Tor code stays written once per consumer and the inbox stays in the engine.

## Related

- ADR 0003: transports.
- ADR 0026: Tor behind a cargo feature.
- ADR 0050: the wallet API.
- ADR 0052: legacy at the edge, native between LEPIC wallets.
