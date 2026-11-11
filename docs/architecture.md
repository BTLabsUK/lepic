# Architecture

LEPIC is an Epic Cash wallet written as a Rust library. It runs inside the process of the app
that uses it: the `lepic` command-line wallet, or BT Wallet through the Flutter binding. It speaks
the wire formats of `epic-wallet` and the Epic node, and adds its own formats for exchanges
between two LEPIC wallets.

This page shows how the workspace is cut into crates, which crate may use which, how slates move
between formats, and what happens in the main flows.

## Layers

```text
 hosts       lepic-cli                     lepic-ffi  ── lepic-flutter (own repository) ── BT Wallet
               │                              │
 contacts    lepic-wallet-contacts ───────────┤
               │                              │
 methods     lepic-methods  (file, http, tor, epicbox)
               │
 engine      lepic-wallet  ── ports: NodeApi, StoreOpener, SecretVault, Clock, SharedRng, MethodLookup
               │
 I/O         lepic-node  lepic-store  lepic-transport  lepic-epicbox  lepic-peer
             lepic-legacy-rpc  lepic-tor  lepic-epic1  lepic-telemetry
               │
 pure        lepic-crypto  lepic-primitives  lepic-keychain  lepic-slate
             lepic-legacy-slate  lepic-native-slate  lepic-seal  lepic-contact
```

- **Pure crates** compute. They take keys, randomness and the time as arguments, and do no I/O.
- **I/O crates** talk to one outside thing each: the node, the database, a relay, a socket, Tor.
- **The engine**, `lepic-wallet`, holds the wallet's rules. It reaches the outside only through
  ports that the host fills in.
- **Methods**, `lepic-methods`, are the ways a slate travels: a file, the HTTP foreign API, Tor,
  Epicbox. Each sits behind a feature of the same name.
- **Contacts**, `lepic-wallet-contacts`, add pairing, contact mailboxes and epic1 payments on top
  of the engine and the methods.
- **Hosts** build the ports, the Tokio runtime and logging, and present the result: a command
  line or a Dart API.

`lepic-epic1` sits with the I/O crates in the edge table because it depends on `lepic-epicbox`
for the network type, but it does no I/O itself.

## Crates

| Crate | Layer | Role |
|---|---|---|
| [`lepic-crypto`](../crates/lepic-crypto/README.md) | pure | Checked boundary over secp256k1-zkp: commitments, range proofs, Schnorr and ECDSA signatures |
| [`lepic-primitives`](../crates/lepic-primitives/README.md) | pure | Transactions, binary serialization, hashing, weights, fees, chain parameters |
| [`lepic-keychain`](../crates/lepic-keychain/README.md) | pure | Mnemonic, BIP32 derivation, output keys, proof builders, seed vault format |
| [`lepic-slate`](../crates/lepic-slate/README.md) | pure | Version-free slate model, the `Codec` trait, the codec registry |
| [`lepic-legacy-slate`](../crates/lepic-legacy-slate/README.md) | pure | V2 and V3 JSON slates as `epic-wallet` writes them, plain or with the LEPIC marker |
| [`lepic-native-slate`](../crates/lepic-native-slate/README.md) | pure | The binary `lepic.v1` slate |
| [`lepic-seal`](../crates/lepic-seal/README.md) | pure | Sealed envelopes, armor, contact cards, domain claims |
| [`lepic-contact`](../crates/lepic-contact/README.md) | pure | Pairing messages, private pairing, key check, SAS, pairing words |
| [`lepic-node`](../crates/lepic-node/README.md) | I/O | Client for the Epic node's foreign JSON-RPC API, and a mock node |
| [`lepic-store`](../crates/lepic-store/README.md) | I/O | Wallet database behind repository traits: SQLite, encrypted at rest, or in memory |
| [`lepic-transport`](../crates/lepic-transport/README.md) | I/O | Transport traits, the method port, format policies, the file method |
| [`lepic-epicbox`](../crates/lepic-epicbox/README.md) | I/O | Epicbox addresses, message crypto, frames and the relay client |
| [`lepic-epic1`](../crates/lepic-epic1/README.md) | I/O (no I/O itself) | The epic1 address and payment link |
| [`lepic-peer`](../crates/lepic-peer/README.md) | I/O | The native direct endpoint `/api/v1/inbox` and its client |
| [`lepic-legacy-rpc`](../crates/lepic-legacy-rpc/README.md) | I/O | The foreign API of `epic-wallet` over HTTP: client and listener |
| [`lepic-tor`](../crates/lepic-tor/README.md) | I/O | Onion service and onion client over a bundled `tor` binary |
| [`lepic-telemetry`](../crates/lepic-telemetry/README.md) | I/O | Tracing subscribers for the hosts, redaction, log capture for tests |
| [`lepic-wallet`](../crates/lepic-wallet/README.md) | engine | The wallet: accounts, refresh, scan, send, receive, invoice, finalize, post |
| [`lepic-methods`](../crates/lepic-methods/README.md) | methods | The method registry and the file, http, tor and epicbox methods |
| [`lepic-wallet-contacts`](../crates/lepic-wallet-contacts/README.md) | contacts | Pairing, contact mailboxes, native slates between contacts, epic1 payments |
| [`lepic-cli`](../crates/lepic-cli/README.md) | host | The `lepic` command-line wallet |
| [`lepic-ffi`](../crates/lepic-ffi/README.md) | host | flutter_rust_bridge API for the app |

`xtask` holds the repository's own tooling; `cargo xtask` with no command lists it. Outside the
workspace sit `conformance/`, `fuzz/`, `interop/`, `console/` and the vendored secp256k1-zkp in
`third_party/`.

## Allowed dependency edges

`cargo xtask deps-check` reads this section. It fails when a crate's real dependencies differ
from the block below, when a pure crate takes a dependency that does I/O, and when a banned crate
appears anywhere in the tree.

```text
lepic-crypto      -> (external only)
lepic-primitives  -> lepic-crypto
lepic-keychain    -> lepic-crypto, lepic-primitives
lepic-slate       -> lepic-crypto, lepic-primitives
lepic-native-slate -> lepic-slate, lepic-crypto, lepic-primitives
lepic-seal        -> (external only)
lepic-contact     -> lepic-seal
lepic-node        -> lepic-primitives, lepic-crypto
lepic-store       -> lepic-primitives
lepic-legacy-slate -> lepic-slate, lepic-crypto, lepic-primitives
lepic-transport   -> lepic-legacy-slate, lepic-slate, lepic-primitives, lepic-crypto
lepic-epicbox     -> lepic-transport, lepic-slate, lepic-crypto, lepic-primitives
lepic-epic1       -> lepic-contact, lepic-epicbox, lepic-crypto, lepic-primitives
lepic-peer        -> lepic-primitives
lepic-legacy-rpc  -> lepic-peer, lepic-transport, lepic-slate
lepic-tor         -> lepic-legacy-rpc
lepic-wallet      -> lepic-contact, lepic-store, lepic-node, lepic-transport, lepic-legacy-slate, lepic-slate, lepic-keychain, lepic-crypto, lepic-primitives
lepic-methods     -> lepic-wallet, lepic-transport, lepic-epicbox, lepic-legacy-rpc, lepic-peer, lepic-legacy-slate, lepic-tor, lepic-node, lepic-slate, lepic-keychain, lepic-crypto, lepic-primitives
lepic-wallet-contacts -> all crates above
lepic-telemetry   -> (external only)
lepic-cli         -> lepic-wallet, lepic-wallet-contacts, lepic-methods, lepic-telemetry, lepic-epicbox, lepic-transport, lepic-node, lepic-store, lepic-keychain, lepic-primitives
lepic-ffi         -> lepic-wallet, lepic-wallet-contacts, lepic-methods, lepic-telemetry, lepic-epicbox, lepic-tor, lepic-transport, lepic-node, lepic-store, lepic-keychain, lepic-primitives
```

The block covers normal and build dependencies. A few dev-dependencies sit outside it, each so a
crate's tests can use a real neighbour:

| Crate | Dev-dependency | Why |
|---|---|---|
| any crate | `lepic-telemetry` | log capture in tests |
| `lepic-wallet` | `lepic-wallet-contacts`, `lepic-methods`, `lepic-epicbox` | contact and Epicbox tests on the engine's own harness (ADR 0029, ADR 0051) |
| `lepic-epicbox` | `lepic-legacy-slate` | vectors that encode the V2 slates a relay carries |
| `lepic-native-slate` | `lepic-legacy-slate` | vectors that decode like their V3 JSON (ADR 0052) |

Any other edge is a design change and needs an ADR.

Some edges are optional:

- `lepic-ffi` → `lepic-tor` is behind the default `tor` feature (ADR 0026).
- `lepic-transport` → `lepic-legacy-slate`, `lepic-methods` → `lepic-legacy-slate` and
  `lepic-methods` → `lepic-legacy-rpc` are behind the default `legacy` feature (ADR 0052).
  `cargo xtask no-legacy` builds the crates that need no legacy crate without it.
- `lepic-wallet` → `lepic-legacy-slate` is not optional: the engine stores slates as V3 JSON.

Pure crates (`crypto`, `primitives`, `keychain`, `slate`, `legacy-slate`, `native-slate`, `seal`, `contact`) may not depend on Tokio or the filesystem,
read a clock, or create their own randomness.

## Ports

The engine names what it needs as traits and generic parameters, and the host supplies them in a
`Ports` value (`crates/lepic-wallet/src/ports.rs`):

| Port | What it gives the engine | Implementations |
|---|---|---|
| `NodeApi` (`lepic-node`) | chain tip, outputs, kernels, push of a transaction | `NodeClient` over HTTP; `MockNode` with the `mock` feature |
| `StoreOpener` | the wallet database, opened or created | `EncryptingSqliteStores`, `SqliteStores`, `EncryptedSqliteStores`; host wrappers in `lepic-cli` and `lepic-ffi` |
| `SecretVault` | the sealed seed, created or unlocked with a password | a vault file in `lepic-cli`; the platform keystore in `lepic-ffi` |
| `Clock`, `SharedRng`, runtime `Handle`, `MethodLookup` | the time, randomness, a Tokio runtime and the methods by name | the host's real ones; fixed ones in tests |

A `Wallet` is `Wallet::new(config, ports)`, where `WalletConfig` carries the network, the name
and every policy value. The library has no defaults for hosts, ports or limits; hosts read them
from `settings.toml` (ADR 0030, ADR 0036). See [Configuration](configuration.md).

Contacts plug into the engine through hooks in `lepic_wallet::extension`: `ReplyKeys`,
`NativeSlates`, `ContactNotices` and `PairRequests`. `lepic-wallet-contacts` installs them; a
wallet without them refuses what they would handle.

## Slates, codecs and methods

A slate is the document two wallets pass back and forth to build one transaction. LEPIC keeps
one version-free model of it, `lepic_slate::Slate` (ADR 0002), and converts at the edge.

```text
 wire bytes ──Codec::decode──▶ Slate ──engine──▶ Slate ──Codec::encode──▶ wire bytes
               ▲                                             ▲
               └──────────── FormatPolicy picks ─────────────┘
```

- A **codec** maps one wire format to and from `Slate`. Codecs never convert into each other.
- A **format policy** (ADR 0003) belongs to a transport and decides which codec reads an
  incoming slate and which writes a new slate or a reply. The engine never names a codec.
- A **method** is a transport plus its policy and what it knows about peers
  (`lepic_transport::method::Method`). The engine looks methods up by `TransportId`.

### Wire formats

| Format | Codec id | Crate | Used for |
|---|---|---|---|
| V2 JSON | `legacy-v2` | `lepic-legacy-slate` | `epic-wallet` peers; standard sends over Epicbox |
| V3 JSON | `legacy-v3` | `lepic-legacy-slate` | `epic-wallet` peers; files; invoice stages over Epicbox; what the engine stores |
| `lepic.v1` | `lepic.v1` | `lepic-native-slate` | between two LEPIC wallets that both claim native slates |

The legacy codecs match `epic-wallet`'s output byte for byte, quirks included, and change only to
fix a mismatch a golden vector shows. See [Legacy slates](compat/legacy-slates.md).

### The LEPIC marker

A LEPIC wallet adds `"lepic":{"version":1}` as the last top-level key of the V2 and V3 JSON
slates it sends over Epicbox, so the peer knows it runs LEPIC. Stock `epic-wallet` ignores the key
and drops it. The marked codecs share the ids `legacy-v2` and `legacy-v3` with the plain ones.

- Over Epicbox the marker carries `f`, the feature bits the wallet claims
  (`lepic_transport::marker::features`). The bit registry only grows.
- A file or paste slate may carry `reply`, an X25519 key for a sealed answer.
- A wallet that takes native slates over Epicbox writes `f` and `reply` together; `reply` is then
  the seal key of its payments address.

### Format policies

| Method | Reads | Writes a new slate | Writes a reply |
|---|---|---|---|
| file (`lepic-transport`) | V2 or V3, by `version_info.version` | V3 (ADR 0015) | V3, next to the input with a `.response` suffix |
| http (`lepic-methods`) | V3 or V2 | V2 | the shape that came in |
| epicbox (`lepic-methods`) | V3 or V2, detected by shape | S1 as marked V2; I1 as marked V3 | the shape that came in; I2 always as marked V3 |

### Native slates

`lepic.v1` is a binary slate with a 51-byte header and an extension tail (RFC 0003). It carries
what the other party needs and nothing else. It travels in two ways:

- between paired contacts, sealed in a type 0A envelope through their mailboxes, when the host
  turns on `WalletConfig::native_direct` and the contact claims `NATIVE_SLATES`;
- over Epicbox to a peer whose marker claimed native slates, through the `NativeSlates` hook.

The engine itself works on V3 JSON. `lepic-wallet-contacts` converts at the edge. See
[EPICTX](protocols/epictx.md).

## Main flows

Each flow is a `Wallet` method that takes the method to use. Every step stores its result before
it returns.

**Send** (standard flow, S1 → S2 → S3). `Wallet::send` selects outputs, builds change with its
range proofs, locks the inputs, stores the transaction and S1, and then delivers S1 through the
method (`Delivery::Deliver`) or writes it for the user to carry (`Delivery::Export`). A stored
send that failed to deliver waits for `Wallet::resend` or `Wallet::cancel`.

**Receive.** `Wallet::receive` decodes S1 with the method's policy, checks it against the chain
tip, adds an output and a partial signature, stores the result and returns S2 in the shape the
policy picks.

**Finalize and post.** `Wallet::finalize` checks S2 against the stored send, completes the
signatures and builds the transaction (S3). `Wallet::post` sends it to the node. A transaction
whose kernel is already on chain counts as posted.

**Invoice** (I1 → I2 → I3). `Wallet::issue_invoice` creates I1 for the payer.
`Wallet::pay_invoice` adds the payer's inputs and signature (I2). `Wallet::finalize_invoice`
completes I3 on the issuer's side, which then posts it.

**Refresh and scan.** `Wallet::refresh` brings outputs and transactions in line with the node's
UTXO set and kernels. A scan rebuilds outputs from the chain after a restore.

**Drain and listen** (Epicbox). The epicbox method's `drain` takes every waiting message once and
returns, for background work on mobile. `listen` holds a relay connection and handles messages as
they arrive, until the host stops it. Both hand each message to the engine's inbox, which decides
what it is: a slate to answer, a reply to finalize, or a notice. A message that fails for a
transient reason stays on the relay for the next attempt.

## Mobile

`lepic-ffi` exposes the engine to Dart with flutter_rust_bridge (ADR 0007). The generated Dart
package lives in its own repository, lepic-flutter (ADR 0023), which records the fingerprint of
the API it was generated from in `crates/lepic-ffi/bridge.sha256`.

- `LepicRuntime` owns one multi-threaded Tokio runtime for the app.
- The seed stays in the platform keystore; the binding passes the sealed vault bytes in and out
  around each engine call (ADR 0014).
- Logs go to a `LogSink` the app implements, or to an on-device `LogRing`.
- Tor is a build feature (ADR 0026). With it, each open wallet runs a bundled `tor` binary as a
  child process.

See [FFI](ffi.md).

## Storage at rest

| What | Where | Protection |
|---|---|---|
| Seed | a vault file (CLI) or the platform keystore | XChaCha20-Poly1305 under an Argon2id key from the password |
| Wallet database | SQLite file in the wallet directory | SQLite3 Multiple Ciphers under a key derived from the seed (ADR 0032) |
| Transaction contexts (blinding factors, nonces) | rows in the database | also sealed with XChaCha20-Poly1305 under a key from the wallet's root key, bound to their row |
| Logs | stderr or a rotating file (CLI); the app's sink or `LogRing` | `LogRing` redacts each record before it reaches the disk |

`EncryptingSqliteStores` copies a plain database into an encrypted one when it opens a directory
that holds one. Every opener of a wallet directory takes one OS lock (`DataDirLock`), so the CLI
and the app never open one database at once.

## No global state

The network, settings, runtime, clock, randomness and paths are values passed in (ADR 0011). Two
wallets on different networks run in one process, and tests run in parallel.

The only process-wide values are immutable: constant tables such as the BIP39 word list, and the
one secp256k1 context in `lepic-crypto`. A host may blind that context once at start with
`lepic_crypto::randomize_context`. Library crates emit `tracing` events and never install a
subscriber; the host installs one from `lepic-telemetry`.

## Related

- [Docs index](README.md)
- [Configuration](configuration.md), [CLI](cli.md), [FFI](ffi.md)
- [Protocols](protocols/README.md): [EPICTX](protocols/epictx.md), [epic1](protocols/epic1.md),
  [Pairing](protocols/pairing.md), [Epicbox](protocols/epicbox.md), [Tor](protocols/tor.md),
  [HTTP](protocols/http.md)
- [Architecture decision records](adr/README.md)
- [Rules](rules.md), [Logging](logging.md)
