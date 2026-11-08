# 0051 Transaction methods in one crate, outside the engine

Status: accepted
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
- Notices carry no method. The engine resolves the method of each payment from the transport id
  stored with its transaction, through a lookup of methods the consumer hands it in the wallet's
  ports; with no lookup, no notice is sent. The padding lengths of a notice are the method's, and
  a notice that arrives is handed to one engine entry, whichever method carried it.

## Deviations

What shipped differently from the steps as written (2026-11-08):

- The engine keeps one port, `Wallet::arrived(&Arc<dyn Method>, Arrival)`, and the other inbox entries, because the method decides proof key, TTL and slate shape before inputs lock. Engine entries take `&Arc<dyn Method>`, not `&dyn Method`: they encode inside `spawn_blocking`.
- `Ports.methods: Option<Arc<dyn MethodLookup>>`: notices, the sender's posted report and forwarded notices resolve the stored transport id through the consumer's registry. With no registry the engine sends no notice and reads no report.
- `Method::peer_key` returns `Result<String, TransportError>` (default `UnknownDestination`). `notice_lengths()` is required; an empty slice means the method sends no notices and the engine withholds. `IncomingInvoice.sender` and `BouncedInvoice.peer` are `String`s.
- Notices are method-agnostic: `Notice::encode()` is gone in favour of `encode_to(lengths, 0)`, `pair_request_to` and `unpaired_notice_to` take the method's lengths, and one engine entry takes a notice whichever method carried it.
- The engine still holds the stored-id literal `epicbox` in `epicbox_invoice.rs` to match an invoice's expiry and bounce against the method it was issued over. Notices and peer facts stay in the engine (decided 2026-11-08): the engine computes them, the consumer's registry delivers them.
- `Method::delivery_is_permanent` is a provided method (default false); the engine keeps `UnsupportedLocation`, `UnknownDestination` and `InvalidDestination` permanent itself. `arrival_settled` and `prune_arrivals` take the retention as a parameter.
- One refusal mapping, `lepic_methods::http::refuse`. Refusal classes that changed per consumer. CLI: `ReceiveError::Slate` Unavailable to Rejected (intended); `Wallet(UnknownTransaction)` Rejected to Unavailable. FFI, Rejected to Unavailable: `ReceiveError::{Output, Signing, Excess, Codecs, Encode, OpenReceipts}` and `Wallet(WalletError::{UnknownTransaction, MinimumConfirmationsOutOfRange, WalletExists, NoWallet, NetworkMismatch, ForeignDatabase, Store(WrongKey), SecretVault, SecretStore, AppData})` plus any `WalletError` variant not in the FFI's old Unavailable list.
- The shared receiver reports `refused` on every error, so the FFI emits one Refused event (Unavailable) on the path where the session was already dropped.
- The FFI keeps its own `OpenReceipts` arm (same class as `refuse`) and its per-receive method lookup by transport id, ignoring the `method` argument.
- The whole foreign API stays in `lepic-foreign`, re-exported from `lepic_methods::http`. `OnionClientSettings` stays in `lepic-tor`. New edge `lepic-methods -> lepic-keychain`; `lepic-methods` also depends on `lepic-node` and `lepic-crypto`. The FFI keeps `lepic-tor`.
- `lepic-methods` has two features: `epicbox` (the method and transport, no engine) and `epicbox-wallet` (the inbox loop, listing and drain). The FFI keeps its `EpicboxSlot`, since replacing the relay in place would change `settings()` for callers outside the move; tests check that the slot's `peer_key`, `delivery_is_permanent`, `encode_new` and `sender_facts` equal `Epicbox`'s.
- The FFI's peer functions derive the key with `lepic_methods::epicbox::peer_key` and call the engine's key-based entry points, so they work without a relay. `BouncedInvoice` carries `peer_key`.
- `lepic-wallet` keeps `lepic-epicbox` as a dev-dependency for its mock relay, so "its tests no longer need a relay" is not yet true. The `lepic_epicbox::marker` shim was deleted; the marker lives in `lepic-transport`.
- The API sends over `epicbox` and `http` only. `tor` (no tor binary setting in serve) and `file` (no body to hand the slate to) are parked and answer a usage problem. A send over the owner TLS listener needs a `slate_id`; the TLS listener has its own connection cap and a connection age limit (ADR 0050 carries the dated notes).

## Alternatives considered

- **One crate with the protocols folded in.** Fewer crates, but the relay client, the JSON-RPC
  server and the tor control code become feature-gated modules of a crate that also depends on
  the engine, and can no longer be built, fuzzed and checked against the reference on their own.
- **Keep the layout and move only the Epicbox rules out of `send.rs`.** The smallest change, but
  the HTTP and Tor code stays written once per consumer and the inbox stays in the engine.
