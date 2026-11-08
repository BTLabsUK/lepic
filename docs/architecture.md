# Architecture

## TL;DR

LEPIC is a Cargo workspace of small crates arranged in layers: pure, deterministic crates for crypto,
transactions, keys and slates at the bottom; I/O crates for the node, storage and transports in the
middle; the wallet engine above them; and the CLI and mobile bindings on top. Slates have one domain
model and several wire codecs, and each transport declares which codecs it speaks. Dependency edges
between crates are fixed below and checked by `cargo xtask deps-check`.

## Crates

| Crate | Responsibility | I/O |
|---|---|---|
| `lepic-crypto` | Safe boundary over the pinned secp256k1-zkp wrapper: commitments, Bulletproofs, aggregate signatures, ECDSA, ECDH. Validates every length and key before the call. | none |
| `lepic-primitives` | Binary serialization, hashing, transaction, input, output and kernel types, weights and fees, per-network chain parameters. Ported from the node. | none |
| `lepic-keychain` | Mnemonic to seed, BIP32 derivation, identifiers and paths, switch commitments, proof builders and rewind, seed vault formats, the host app's data file format (`docs/compat/wfeh.md`). | none |
| `lepic-slate` | Slate domain model, stages and roles, codec trait, legacy V2 and V3 JSON codecs, codec registry, the `ur:epic-slate` QR form of slate text (ADR 0025). | none |
| `lepic-contact` | Contact pairing formats (RFC 0002): the sealed envelope (HPKE to a contact's X25519 key, signed with its Ed25519 key) and its armor, contact cards, invites, pairing replies and confirms, the SAS. | none |
| `lepic-node` | Node JSON-RPC client for the foreign API, with strict response validation and bounded sizes. | network |
| `lepic-store` | SQLite storage behind repository traits, migrations, encryption of private transaction context, the database file encrypted at rest (ADR 0032). | disk |
| `lepic-transport` | Transport traits, the method port, shared legacy codecs, transport registry, format policy, the file transport. | disk |
| `lepic-epicbox` | Epicbox addresses, message crypto, protocol frames, relay client and its transport. | network |
| `lepic-foreign` | The wallet foreign API over HTTP (ADR 0017): JSON-RPC messages, the client and the `http` transport, the listener. | network |
| `lepic-tor` | Tor on desktop and Android (ADR 0018): onion v3 addresses and the wallet's onion key, a tor child process per wallet driven over its control port, SOCKS5, the `tor` transport. | network, child process |
| `lepic-wallet` | The engine: accounts, output selection, send, receive, finalize, cancel, scan, refresh, transaction state machine, events. | through ports |
| `lepic-wallet-contacts` | Contacts on the engine (RFC 0002): pairing, contact mailboxes, sealed slates, contact invoices, key checks and app payloads. Drives `lepic-wallet` through its public calls and the hooks of `lepic_wallet::extension`. | through ports |
| `lepic-methods` | Transaction methods: the registry of methods and one module per method, each behind a feature. Re-exports the port of `lepic-transport` and the wire crates' transports. | through ports |
| `lepic-telemetry` | Tracing subscribers for CLI and mobile, redaction helpers. | stderr, files |
| `lepic-cli` | The `lepic` binary. | all |
| `lepic-ffi` | LEPIC's FFI API, built with flutter_rust_bridge (ADR 0007). The Flutter binding is a separate repository (ADR 0023). | all |
| `xtask` | Build, check, vector, mobile packaging and release commands. | all |

Outside the product workspace, with their own `Cargo.lock`:

- `conformance/` runs the reference `epic-wallet` and node code to generate golden vectors and to run
  differential tests against LEPIC. It is the only place those crates appear (ADR 0009).
- `fuzz/` holds cargo-fuzz targets.
- `interop/` runs LEPIC against real `epic-wallet` binaries and a local Epicbox relay.

### Feature code kept out of the money core

Contact pairing and its key schedule (RFC 0002) live in `lepic-wallet-contacts` (ADR 0029), the
LEPIC marker of slates sent between LEPIC wallets in `lepic-epicbox` (`marker`), next to the
transport that uses it. What the pure crates keep of LEPIC's own features is the least the
features need from the wallet's keychain:

- `lepic-keychain` `contact_identity`: the plain key at `m/<a>/2/0` that the contact key
  schedule starts from.
- `lepic-keychain` `app_data`: the app's `WFEH` backup file (`docs/compat/wfeh.md`), sealed under
  a key derived from the wallet root.

Nothing in consensus, keys of funds or the slates `epic-wallet` reads depends on them, so a review
of the money core can leave them out.

## Allowed dependency edges

```
lepic-crypto      -> (external only)
lepic-primitives  -> lepic-crypto
lepic-keychain    -> lepic-crypto, lepic-primitives
lepic-slate       -> lepic-crypto, lepic-primitives
lepic-contact     -> (external only)
lepic-node        -> lepic-primitives, lepic-crypto
lepic-store       -> lepic-primitives
lepic-transport   -> lepic-slate, lepic-primitives
lepic-epicbox     -> lepic-transport, lepic-slate, lepic-crypto, lepic-primitives
lepic-foreign     -> lepic-transport, lepic-slate
lepic-tor         -> lepic-foreign, lepic-transport, lepic-slate
lepic-wallet      -> all crates above
lepic-wallet-contacts -> all crates above
lepic-methods     -> lepic-wallet, lepic-transport, lepic-epicbox, lepic-foreign, lepic-tor, lepic-slate, lepic-primitives
lepic-telemetry   -> (external only)
lepic-cli         -> lepic-wallet, lepic-wallet-contacts, lepic-methods, lepic-telemetry, lepic-epicbox, lepic-foreign, lepic-tor, lepic-transport, lepic-node, lepic-store, lepic-keychain, lepic-primitives
lepic-ffi         -> lepic-wallet, lepic-wallet-contacts, lepic-methods, lepic-telemetry, lepic-epicbox, lepic-foreign, lepic-tor, lepic-transport, lepic-node, lepic-store, lepic-keychain, lepic-primitives
```

The block applies to normal and build dependencies. Any crate may take `lepic-telemetry` as a
dev-dependency for its log-capture test helpers, and `lepic-wallet` takes `lepic-wallet-contacts`
as one, so the contact tests run on the engine's own test harness (ADR 0029). Any other edge is a design change and needs an ADR.
`lepic-ffi`'s edge to `lepic-tor` is optional, behind its default `tor` feature (ADR 0026).
Pure crates (`crypto`, `primitives`, `keychain`, `slate`, `contact`) may not depend on Tokio or the filesystem,
read a clock, or create their own randomness.

## Engine and ports

The engine depends on traits, not implementations:

| Port | Implemented by |
|---|---|
| `NodeApi` | `lepic-node`, and a mock node in tests |
| `StoreOpener` (opens the `WalletStore` after unlock, keyed from the seed) | `lepic_wallet::SqliteStores` over `lepic-store`, the CLI's `CliStores`, in-memory stores in tests |
| `Method` (the slate's method: codecs, marker, peer key, delivery) | `lepic-transport::file`, `lepic-methods`, and a loopback in tests |
| `SecretVault` (`exists`, `create`, `unlock` with a password, yielding a `lepic_keychain::SecretStore`) | the CLI's `FileVault` over a `lepic-keychain` vault file on desktop, `lepic-ffi`'s `AppVault` over the platform keystore on mobile, a fast vault in tests |
| `Clock`, `Rng` | real implementations in `lepic-cli` and `lepic-ffi`, fixed ones in tests |

The engine owns no runtime and no globals. `lepic-cli` and `lepic-ffi` create the Tokio runtime and
pass it in.

## Slates, codecs and transports

```
              +---------------------- lepic-slate ----------------------+
 wire bytes   |  Codec (legacy V2 JSON | legacy V3 JSON | future native) |   domain Slate
 <----------> |  detect / decode / encode, lossless or a typed error     | <------------> engine
              +---------------------------------------------------------+
                         ^ chosen by FormatPolicy of the transport
              +----------+-----------+
              |  Transport           |  epicbox: accepts V2, V3; sends V2, V3 for invoices; replies in the inbound shape
              |  (file, epicbox,...) |  file:    accepts V2, V3; writes V3
              +----------------------+
```

- The domain `Slate` is version-free: explicit stage, explicit roles, typed fields. It can hold a
  partial body, so a compact native format does not need the sender's inputs and outputs on the wire.
  A slate decoded from a legacy format keeps its wire origin (codec and legacy header) so a reply can
  echo what the peer sent.
- A codec maps between one wire format and the domain model. Encoding fails with a typed error when
  the format cannot carry something the slate contains. Nothing is dropped silently.
- A transport's `FormatPolicy` lists the codecs it accepts, the codec it sends by default, and the
  reply rule. Adding a method is one transport module plus one registration; adding a format is one
  codec module plus one registration.
- ADRs 0002, 0003 and 0012 hold the reasoning and the native format proposal.

## Main flows

Send, standard flow:

1. The engine selects outputs, builds the S1 slate, stores the private context encrypted, and locks
   the selected outputs, in one store transaction.
2. The transport's policy picks a codec. The codec encodes. The transport delivers.
3. The response arrives, through the Epicbox inbox or a file import. It is detected and decoded with
   a codec the transport accepts, validated against the stored context, finalized, and posted to the
   node. Then it is acknowledged to the relay.

Receive is the mirror: decode S1, validate, add the output and the partial signature, store, reply
through the same transport in the format its policy prescribes for replies, acknowledge.

Every inbound message is idempotent on `(slate_id, stage)`. A relay message is acknowledged only after
its effect is stored or it was rejected for good.

## Mobile shape

A phone suspends the app, so Epicbox runs in two modes: `listen` keeps a connection while the app is
in the foreground, and `drain` connects, processes everything pending, and disconnects. A host
that wants background work schedules a `drain`; BT Wallet schedules none, so messages wait on the
relay until the app opens. Events (balance, transaction stage, sync progress,
transport state) stream to the host through the binding.
