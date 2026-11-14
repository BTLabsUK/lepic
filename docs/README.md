# LEPIC documentation

LEPIC is an Epic Cash wallet core in Rust. An app links it and calls it in its own process. These
pages describe how it is built, how to use it from Rust, from the `lepic` command line and through
the FFI, the protocols it speaks, and the decisions behind it.

## Reading order

1. [The repository README](../README.md): what LEPIC is, a quick start and how to build it.
2. [Architecture](architecture.md): the crate layers, the ports the engine calls, and the main
   flows from opening a wallet to finalizing a transaction.
3. The crate READMEs, starting with [lepic-wallet](../crates/lepic-wallet/README.md), the engine.
4. One of the three ways in: [the CLI](cli.md), [the FFI](ffi.md) or the crates directly.
5. [Configuration](configuration.md) for the settings each of them reads.
6. [Protocols](protocols/README.md) for the formats on the wire.
7. [Direction](direction.md) for where the design is heading.

## Crates

Pure crates hold formats, keys and arithmetic and do no I/O. I/O crates talk to a node, a relay,
the disk or Tor. The engine sits on them; the methods and the contact layer sit on the engine, and
the hosts (CLI and FFI) wire everything together. [Architecture](architecture.md#crates) gives the allowed dependencies.

| Layer | Crates |
|---|---|
| Pure | [primitives](../crates/lepic-primitives/README.md), [crypto](../crates/lepic-crypto/README.md), [keychain](../crates/lepic-keychain/README.md), [slate](../crates/lepic-slate/README.md), [legacy-slate](../crates/lepic-legacy-slate/README.md), [native-slate](../crates/lepic-native-slate/README.md), [seal](../crates/lepic-seal/README.md), [contact](../crates/lepic-contact/README.md) |
| I/O | [node](../crates/lepic-node/README.md), [store](../crates/lepic-store/README.md), [transport](../crates/lepic-transport/README.md), [epic1](../crates/lepic-epic1/README.md), [epicbox](../crates/lepic-epicbox/README.md), [peer](../crates/lepic-peer/README.md), [legacy-rpc](../crates/lepic-legacy-rpc/README.md), [tor](../crates/lepic-tor/README.md), [telemetry](../crates/lepic-telemetry/README.md) |
| Engine | [wallet](../crates/lepic-wallet/README.md) |
| Methods | [methods](../crates/lepic-methods/README.md) |
| Contacts | [wallet-contacts](../crates/lepic-wallet-contacts/README.md) |
| Hosts | [lepic-cli](../crates/lepic-cli/README.md), [lepic-ffi](../crates/lepic-ffi/README.md) |

## Using LEPIC

- [CLI](cli.md): the `lepic` command, its commands and flags, and `lepic serve`.
- [FFI](ffi.md): the API an app calls through flutter_rust_bridge, its streams and error codes.
- [Configuration](configuration.md): `config.toml`, `settings.toml` and the settings a host app
  passes through the FFI.
- [Wallet API guide](api/README.md): connecting, conventions, payments, events and errors, for
  integrators.
- [`api/openapi.json`](api/openapi.json): the OpenAPI document of the wallet API (`/api/v1`) that
  `lepic serve` answers. It is written by hand and is the contract.

## Protocols

- [Overview](protocols/README.md): which format and channel is used between which wallets.
- [EPICTX](protocols/epictx.md): native slates between LEPIC wallets and sealed envelopes.
- [epic1](protocols/epic1.md): epic1 addresses and payment links.
- [Pairing](protocols/pairing.md): contacts, mailboxes and invoices between contacts.
- [Epicbox](protocols/epicbox.md): the relay client and the notices LEPIC sends over it.
- [Epicbox mux/1](protocols/epicbox-mux.md): the push extension for many mailboxes on one socket.
- [Tor](protocols/tor.md): the wallet's onion service and reaching the node and relay over Tor.
- [HTTP](protocols/http.md): the foreign API and the native direct endpoint.

The specifications are in [`rfcs/`](rfcs/):
[RFC 0001](rfcs/0001-lepic-slate-v1.md) (native slate `lepic.v1`),
[RFC 0002](rfcs/0002-contact-pairing.md) (contact pairing, with
[its cases](rfcs/0002-contact-pairing-cases.md)) and
[RFC 0003](rfcs/0003-epictx-native-slates.md) (EPICTX).

## Decisions

[The ADR index](adr/README.md) lists every architecture decision record with its status. Each
record states the decision as it holds in the code.

## Compatibility with Epic Cash

LEPIC matches the formats of the reference wallet and node. Each note describes one of them:

- [Legacy slates](compat/legacy-slates.md): the V2 and V3 JSON slates.
- [Slates in QR codes](compat/ur-epic-slate.md): `ur:epic-slate`.
- [Keys and proofs](compat/keys-and-proofs.md): key derivation, payment proofs, kernels and the
  seed file.
- [Transaction and output states](compat/states.md).
- [Node API](compat/node-api.md): the node calls the wallet makes.
- [Foreign API](compat/foreign-api.md): the wallet's foreign API over HTTP.
- [Epicbox](compat/epicbox.md): the relay protocol.
- [epic-wallet database](compat/epic-wallet-db.md): importing a reference wallet's history.
- [App data files](compat/wfeh.md): the `WFEH` file format.
- [The secp256k1-zkp fork](compat/secp256k1-zkp-fork.md).
- Upstream releases [4.1.0](compat/upstream-4.1.0-review.md) and
  [4.1.2](compat/upstream-4.1.2-review.md): what LEPIC takes from each.

## Working on LEPIC

- [CONTRIBUTING](../CONTRIBUTING.md): branches, commit format and the check gate.
- [Rules](rules.md): the project's coding, compatibility and testing rules.
- [Logging](logging.md): log levels, fields and redaction.
- [Budgets](budgets.md): the size and performance limits `cargo xtask budget` measures.
- [Fuzzing](fuzzing.md): the fuzz targets and how to run them.
- [Interop suite](../interop/README.md): tests against the reference wallet, node and relay.
- Notes on the [mobile build](spikes/f-03-mobile-build.md) and the
  [Argon2 parameters](spikes/k-03-argon2.md).
- [SECURITY](../SECURITY.md): how to report a vulnerability.
