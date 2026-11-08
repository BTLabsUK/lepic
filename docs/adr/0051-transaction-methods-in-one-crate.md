# 0051 Transaction methods in one crate, outside the engine

Status: proposed
Date: 2026-11-08

## Context

ADR 0003 gave each transaction method a `Transport` in `lepic-transport`: capabilities
(`Outbound`, `Inbound`, `Exchange`) and a format policy. The engine was to build slates and ask
the method for the rest. In practice the line has moved:

- `lepic-wallet` depends on `lepic-epicbox`. `send.rs` picks the marked V2 codec when the method
  is Epicbox and puts a reply key in the S1 when it is a file; a parked invoice's payment is bound
  by comparing Epicbox keys. The Epicbox inbox loop, notices, listings and invoices over Epicbox
  (`inbox.rs`, `epicbox_notice.rs`, `epicbox_invoice.rs`, `peer_compat.rs`, `inbox/listing.rs`)
  live in the engine.
- HTTP and Tor have no home of their own. The CLI and the FFI each write the HTTP receiver that
  turns a `/v2/foreign` call into a wallet receive (`commands.rs` `HttpReceiver`,
  `session/http.rs` `HttpReceiver`), each map refusals, and each start tor for a send or a
  listener.

So the engine knows about one method, and the code for the other methods is written once per
consumer, with a copy for the API to come.

Not everything a method decides can leave the slate builder. A method decides what the slate may
carry: a payment proof addressed to its own key (the Epicbox address key, the onion key), a TTL,
the slate shape (V2 or V3 JSON, a future slatepack). The engine must know those limits before it
stores anything, so that a slate the method cannot carry is refused with nothing locked (ADR
0003). The order of effects also belongs to wallet state: an S1 is stored with its inputs locked
before it is delivered, and a delivery that fails leaves it for a resend with its first bytes; a
received envelope is acknowledged only after its effect is stored.

## Decision

- **`lepic-wallet` knows no method.** It builds, stores, receives, finalizes and posts slates. It
  defines one port, the method's side of a slate: what the slate may carry, how a new slate and a
  reply are encoded, and what a received slate says about its sender (the LEPIC marker's claimed
  features and reply key). A method's id is an opaque name stored with the transaction, as the
  `transport` column stores it today, so the database does not change.
- **`lepic-methods` holds every method.** It grows out of `lepic-transport` (capability traits,
  registry, format policy, the file method) and takes over:
  - from the engine: the Epicbox inbox loop, notices, listings, invoices over Epicbox, the marker
    codecs and the payee binding;
  - from the CLI and the FFI: the HTTP receiver and dialer, the Tor listener and dialer, refusal
    mapping;
  - one module per method (`file`, `http`, `tor`, `epicbox`), each behind a cargo feature as tor
    is (ADR 0026); new methods (slatepack, QR) are added as new modules.
  It implements the engine's port and calls the engine in the order above.
- **Protocol crates stay wire libraries.** `lepic-epicbox` (relay client, addresses, wire
  messages), `lepic-foreign` (the `/v2/foreign` server and client) and `lepic-tor` (the tor
  process, onions, SOCKS) know no wallet and implement no LEPIC trait. They stay small enough to
  fuzz and to check against the reference implementations on their own.
- **Consumers ask for a method.** `lepic-cli`, `lepic-ffi`, `serve` and its API call
  `lepic-methods` for anything that moves a slate. `lepic-wallet-contacts` builds on its Epicbox
  module.

```
lepic-slate ── lepic-wallet ── lepic-methods ──┬── lepic-epicbox
                                  │            ├── lepic-foreign
                                  │            └── lepic-tor
              lepic-wallet-contacts, lepic-cli, lepic-ffi
```

The move goes in steps, each one shippable:

1. `lepic-methods` from `lepic-transport`, the engine's port, and the send-side rules (codec
   choice, reply key, payee binding).
2. The Epicbox inbox, notices, listings and invoices.
3. One HTTP and one Tor receiver and dialer; the CLI and FFI copies are deleted.
4. The API's method field and `GET /v1/methods` read the registry.

Each step keeps the bytes on the wire: the slate vectors under `testdata/vectors`, the conformance
workspace and the epic-wallet interop scenarios pass unchanged, and the binding's
`bridge.sha256` does not change, which proves the app sees the same FFI.

## Consequences

- A method's code exists once, for the CLI, the app and the API alike.
- `lepic-wallet` loses its dependency on `lepic-epicbox` and the Epicbox modules; its tests no
  longer need a relay.
- The engine's send and receive take the method's port instead of a `TransportId` and a registry.
  Every caller of those changes, in this repository only.
- The risk is in moving the order of effects and the marker handling. The adversarial race tests,
  the lifecycle tests and the vectors are the guard; no step changes behaviour.

## Alternatives considered

- **One crate with the protocols folded in.** Fewer crates, but the relay client, the JSON-RPC
  server and the tor control code become feature-gated modules of a crate that also depends on
  the engine, and can no longer be built, fuzzed and checked against the reference on their own.
- **Keep the layout and move only the Epicbox rules out of `send.rs`.** The smallest change, but
  the HTTP and Tor code stays written once per consumer and the inbox stays in the engine.
