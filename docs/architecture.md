# Architecture

LEPIC is an Epic Cash wallet written as a Rust library. It runs inside the process of the program
that uses it: the `lepic` command-line wallet, a Rust program that links the crates, or a Flutter
app (BT Wallet is one) through the binding. It speaks
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
| [`lepic-legacy-slate`](../crates/lepic-legacy-slate/README.md) | pure | V2 and V3 JSON slates as `epic-wallet` writes them |
| [`lepic-native-slate`](../crates/lepic-native-slate/README.md) | pure | The binary `lepic.v1` slate |
| [`lepic-seal`](../crates/lepic-seal/README.md) | pure | Sealed envelopes, armor, contact cards, domain claims |
| [`lepic-contact`](../crates/lepic-contact/README.md) | pure | Pairing messages, private pairing, key check, SAS |
| [`lepic-node`](../crates/lepic-node/README.md) | I/O | Client for the Epic node's foreign JSON-RPC API, and a mock node |
| [`lepic-store`](../crates/lepic-store/README.md) | I/O | Wallet database behind repository traits: SQLite, encrypted at rest, or in memory |
| [`lepic-transport`](../crates/lepic-transport/README.md) | I/O | Transport traits, the method port, format policies, the file method |
| [`lepic-epicbox`](../crates/lepic-epicbox/README.md) | I/O | Epicbox addresses, message crypto, frames and the relay client |
| [`lepic-epic1`](../crates/lepic-epic1/README.md) | I/O (no I/O itself) | The epic1 address and payment link |
| [`lepic-peer`](../crates/lepic-peer/README.md) | I/O | The epic1 inbox endpoint `/api/v1/inbox` and its client |
| [`lepic-legacy-rpc`](../crates/lepic-legacy-rpc/README.md) | I/O | The foreign API of `epic-wallet` over HTTP: client and listener |
| [`lepic-tor`](../crates/lepic-tor/README.md) | I/O | Onion service and onion client over a bundled `tor` binary |
| [`lepic-telemetry`](../crates/lepic-telemetry/README.md) | I/O | Tracing subscribers for the hosts, redaction, log capture for tests |
| [`lepic-wallet`](../crates/lepic-wallet/README.md) | engine | The wallet: accounts, refresh, scan, send, receive, invoice, finalize, post |
| [`lepic-methods`](../crates/lepic-methods/README.md) | methods | The method registry and the file, http, tor and epicbox methods |
| [`lepic-wallet-contacts`](../crates/lepic-wallet-contacts/README.md) | contacts | Pairing, contact mailboxes, slates between contacts, epic1 payments |
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
lepic-peer        -> (external only)
lepic-legacy-rpc  -> lepic-transport, lepic-slate
lepic-tor         -> lepic-legacy-rpc
lepic-wallet      -> lepic-contact, lepic-store, lepic-node, lepic-transport, lepic-legacy-slate, lepic-slate, lepic-keychain, lepic-crypto, lepic-primitives
lepic-methods     -> lepic-wallet, lepic-transport, lepic-epicbox, lepic-legacy-rpc, lepic-legacy-slate, lepic-tor, lepic-node, lepic-slate, lepic-keychain, lepic-crypto, lepic-primitives
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

The legacy inbox (`lepic-wallet`'s `inbox::legacy` and the modules it names) names no native
crate or module, and its own files name no notice (ADR 0062). `cargo xtask legacy-imports` fails
when they do.

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

Contacts plug into the engine through a hook in `lepic_wallet::extension`, `ContactNotices`.
`lepic-wallet-contacts` installs it; a wallet without it refuses what it would handle.

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
| V3 JSON | `legacy-v3` | `lepic-legacy-slate` | `epic-wallet` peers; files; slates between contacts; what the engine stores |
| `lepic.v1` | `lepic.v1` | `lepic-native-slate` | epic1 payments and in-person codes; also read from a contact that sends one |

The legacy codecs match `epic-wallet`'s output byte for byte, quirks included, and change only to
fix a mismatch a golden vector shows. See [Legacy slates](compat/legacy-slates.md).

### Format policies

| Method | Reads | Writes a new slate | Writes a reply |
|---|---|---|---|
| file (`lepic-transport`) | V2 or V3, by `version_info.version` | V3 (ADR 0015) | V3, next to the input with a `.response` suffix |
| http (`lepic-methods`) | V3 or V2 | V2 | the shape that came in |
| epicbox (`lepic-methods`) | V3 or V2, detected by shape | V2 | the shape that came in |

### Native slates

`lepic.v1` is a binary slate with a 51-byte header and an extension tail (RFC 0003). It carries
what the other party needs and nothing else. A wallet writes one for an epic1 payment and an in-person code, sealed in a type 0A envelope
for a payment, and reads one that a paired contact sends through their mailboxes. A new slate to a
contact goes as V3 JSON in a type 01 envelope. An Epicbox payments address, a URL and an onion get a V2
or V3 JSON slate.

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
whose kernel is already on chain counts as posted. Every push is recorded with its outcome:
accepted, refused by the node's pool, or unreachable, which covers any answer the wallet does
not know. While the session is online and before its cutoff, `Wallet::refresh` pushes a
finalized transaction again 1, 2, 4, 8 and 16 blocks after its first five pushes and then every
30 blocks, and a posted one that neither the pool nor the chain holds 10 blocks after the node
last took it. The first push that finds the node unreachable ends them for that refresh. A
finalized send expires at its cutoff only when every recorded push was refused by the node's
pool and neither the pool nor the chain holds its kernel; with no push recorded, or with one
accepted or unreachable, it stays open. `TransactionDetails::expired_reason` then reads
`RejectedByNode`.

**Invoice** (I1 → I2 → I3). `Wallet::issue_invoice` creates I1 for the payer.
`Wallet::pay_invoice` adds the payer's inputs and signature (I2). `Wallet::finalize_invoice`
completes I3 on the issuer's side, which then posts it.

**Refresh and scan.** `Wallet::refresh` brings outputs and transactions in line with the node's
UTXO set and kernels. A scan rebuilds outputs from the chain after a restore.

**Drain and listen** (Epicbox). The epicbox method's `drain` takes every waiting message once and
returns, for background work such as a periodic job or a mobile wake-up. `listen` holds a relay connection and handles messages as
they arrive, until the host stops it. Both hand each message to the engine's inbox, which decides
what it is: a slate to answer, a reply to finalize, or a notice. A message that fails for a
transient reason stays on the relay for the next attempt.

A listener leaves a socket that has gone quiet: when the relay sends no periodic challenge for
`listener_challenge_rounds` of its intervals (3 by default), it opens a fresh socket, which
collects what waits. Several listings of one wallet are drained in one batch
(`drain_epicbox_listings`), and a failed listing does not stop the others.

**Push sessions** (Epicbox `mux/1`, [spec](protocols/epicbox-mux.md)). A relay that offers `mux/1`
pushes mail over one socket that serves many mailboxes, so the host does not have to poll.
`lepic-epicbox` holds the session client and the session service (`sessions`). In
`lepic-methods` the payments listener and in `lepic-wallet-contacts` the contacts collect each
claim their mailboxes on a shared session, one session per relay and group. A session opens
more sockets when the relay caps the mailboxes per socket. Both fall back to their own sockets
when the relay does not offer `mux/1`. The FFI exposes this as "Epicbox sessions".
`lepic serve` uses the sessions too: it attaches its payments address and every live contact
and pairing mailbox (`relay_sockets` picks one session per relay or two), and reads the mail a
relay pushes, or that waited when a session attaches, at most once a second.

**Delivery layer** (`lepic-wallet-contacts`, `delivery`; the outbox posts through it, no host reads
through it yet). The carrier takes the whole watch set from the store and makes the contacts' shared
sessions carry exactly its live rows: it claims each row's mailbox on the session of its relay,
releases what left the set and leaves other owners' claims alone. A row past its expiry is not
claimed, and the pass that finds it removes it from the store. A row whose relay or key does not
resolve is skipped, and each relay is reported on its own: a relay that does not offer `mux/1` gets
its own error and nothing is read from it another way until it is asked again (after 1 minute,
doubling to 1 hour), and mailboxes beyond the per-socket limit that no further socket took are
reported with the limit. The carrier also posts on an Epicbox route:
on the session it holds on the recipient's relay when there is one, else on a short connection, and
once more on a short connection when the session wrote nothing of the post. The carrier posts once;
the outbox decides whether a post is made again. The router hands each message a session pushed to
the handler registered for the class of its row, one message at a time per mailbox and in the order
the relay sent them. It waits on the sessions' queues and on the carrier's watch set, with no timer.
A message is acknowledged only after its handler stored it; a hold, a class with no handler, a panic
or a cancelled run leaves it on the relay, which offers it again.

**Outbox** (`lepic-wallet-contacts`, `delivery::outbox`). Every payment post of the contact engine
is a row of the store's native outbox: one row per route a payment's bytes went to, under the
payment's slate id. The write that makes a payment, an answer or a refusal also queues its row and
the payment's delivery state; a separate write stores how the post went. The outbox posts one row
at a time, under the contact engine's turn, over the carrier for an Epicbox route, HTTPS for an
`http` route and the host's Tor for a `tor` route. A post that was not sent or was refused moves the
payment to its next route; one sent and not answered is posted again on the same route with the
same bytes, after a back-off, until a day passes or the payment's cutoff; only a caller's
`next_route` moves it on. A row posted to up to 3 usable relays keeps one copy per mailbox that took it, taken,
owed or owing a cancel: the row is posted once one mailbox took it, the owed copies are posted
again on the same back-off until the payment is answered or ends, and the cancel of an answered
payment goes to the mailboxes that took a copy, again on the back-off while the payment is open.
The first post is made in the call that made the row. Every later one reads the tip the wallet
confirmed and waits while there is none, and nothing is posted at or past the cutoff. The
collect runs the due rows.

**Boosts and the service API.** `lepic serve` holds one wallet open and answers `/api/v1` for a
service that takes payments (see the [API guide](api/README.md)). A client can ask for a boost, a
short window in which serve's contact tick or the node refresh runs more often (at most every 5
seconds, for at most 10 minutes). Serve can also send its event log to a webhook set in
settings. Apps call the same boosts through the FFI. The host runs the polling loops; the engine
only holds the leases (`lepic-wallet`, `boost`). In serve the contact tick runs every 30
seconds beside the push sessions: it asks each session how much waits, which ends drained
pairings, counts the wait of contacts not heard from and reports relays that do not answer, ends
what expired and posts the outbox's due rows. Mail is read as the relays push it; on a relay
without `mux/1`, native mail is not read.

## The FFI host

`lepic-ffi` exposes the engine to Dart with flutter_rust_bridge (ADR 0007). The generated Dart
package lives in its own repository, lepic-flutter (ADR 0023), which records the fingerprint of
the API it was generated from in `crates/lepic-ffi/bridge.sha256`.

- `LepicRuntime` owns one multi-threaded Tokio runtime for the app.
- On a device, the seed stays in the platform keystore; the binding passes the sealed vault bytes in and out
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
