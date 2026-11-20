# The Flutter binding

`lepic-ffi` is the LEPIC wallet engine as a library for Flutter apps on Linux, Windows, Android and
iOS. Its `api` module is the surface the app calls; `flutter_rust_bridge` turns it into a
Dart package. This page covers the session model, the secret store, the streams, each API module,
the error codes, which secrets cross into Dart, and how to build the native libraries.

The Dart side lives in its own repository,
[lepic-flutter](https://github.com/BTLabsUK/lepic-flutter), which generates
`src/frb_generated.rs` and the Dart package (`package:lepic`) in one run
([ADR 0007](adr/0007-mobile-bindings.md), [ADR 0023](adr/0023-binding-in-its-own-repository.md)).

## How the binding is kept in step

The generated Rust module and the `api` module must match what lepic-flutter generated. A run
of `tool/lepic.sh generate` in lepic-flutter records the SHA-256 of every API file and of the
generated module in `crates/lepic-ffi/bridge.sha256`. `cargo xtask repo-lint` fails when any of
them changed since, or when the module comes from another `flutter_rust_bridge` version than
`Cargo.lock` resolves. Every change to `crates/lepic-ffi/src/api/`, comments included, therefore
needs a new run.

## Runtime and wallets

Nothing in the binding is global ([ADR 0011](adr/0011-no-global-state.md)). The app creates one
`LepicRuntime` and passes it to every call that opens a wallet.

| Call | What it does |
|---|---|
| `LepicRuntime::new(log_level)` | A runtime with the default PIN settings |
| `LepicRuntime::with_pin_settings(log_level, pin)` | A runtime with the app's `PinSettings` |
| `logs(sink)`, `stop_logs()` | Streams every log record to Dart |
| `open_log_ring(dir, max_bytes)` | Keeps recent logs in a file ring of 4 KiB to 16 MiB |
| `log_message(...)` | Writes an app record into the same log |

The runtime is a multi-thread Tokio runtime with two worker threads. Every call runs as a task on
it under the runtime's log subscriber:

- A panic inside LEPIC becomes a `Panic` error. The wallet stays usable.
- When Dart drops a future, the task runs to its end, so a write to the store is never cut
  in half.
- `lock` stops calls in flight at their next await, never inside a store write. A call stopped
  this way fails with `Cancelled`, and its write may still have been stored: read the
  transactions again on the next open before taking the failure as the outcome.
- `set_servers` lets running calls end first and cancels only a running scan.
- `drop_node_connections` closes the pooled node connections, so the next node call opens a new
  one. Call it when the network changes or the app returns from the background. It does no I/O,
  waits for no call or node switch, and leaves calls in flight to end on their own connection.
- `boost(poller, duration_secs, interval_secs)` runs the app's `Relays` or `Node` loop faster
  for a while and returns an id for `end_boost` ([ADR 0058](adr/0058-service-wallet-api.md)). It
  starts no loop: the app's loop asks `poll_interval(poller, base_secs)` before each wait. The
  id ends the boost, not a guard object, since Dart's collector drops objects late.

### Open, create and restore

An open wallet is an `EpicWallet`. Each call takes the runtime, a `WalletConfig` (see
[configuration.md](configuration.md#through-the-ffi)) and the app's secret store.

| Password wallets | PIN wallets | Purpose |
|---|---|---|
| `create(…, mnemonic, restore_from_height, password)` | `create_with_pin(…, pin)` | New seed, or restore one from its phrase |
| `import_wallet_seed(…, seed_file, seed_password, password)` | `import_wallet_seed_with_pin` | Import an `epic-wallet` seed file |
| `open(…, password)` | `open_with_pin(…, pin, sealed_password)` | Open an existing wallet |

- `create` without a phrase generates a seed. With a phrase it restores, and `scan` must run to
  the end before the wallet can send. `restore_from_height` starts that scan at a height; leave it
  `None` unless the phrase was first used above it.
- A PIN wallet's password is generated and sealed inside Rust. The `_with_pin` create calls return
  a `PinWallet { wallet, sealed_password }`. Store `sealed_password` before showing the phrase or
  receiving funds; `open_with_pin` needs it. Wrong PINs are counted in the store and delayed as
  `PinSettings` sets.
- `change_pin` returns a new sealed text. The change stays pending, and both PINs open the wallet,
  until `confirm_pin_change`. `change_password` changes a password wallet's password.
- `mnemonic(password)` and `mnemonic_with_pin(pin, sealed_password)` return the phrase for the
  backup screen.
- Dropping an `EpicWallet` stops its listener and scan and locks it once running calls finish.
  `lock()` locks it at once.

Free functions work without an open wallet: `validate_mnemonic`, `wallet_exists`,
`delete_wallet`, `reset_password` (with the phrase), `wallet_fingerprint` and
`node_tip(runtime, config, route)`.

## Secret store and vault

The app provides storage for the wallet's sealed secrets, such as `flutter_secure_storage` over
the Android Keystore and the iOS Keychain. In Dart, wrap it in `LepicSecretStore` from
`package:lepic`; it builds the `AppSecretStore` from three callbacks (read, write, delete) and turns
an exception in the store into a failed reply.

LEPIC writes these keys:

| Key | Holds |
|---|---|
| `lepic.vault` | The sealed seed |
| `lepic.vault-next` | The vault being replaced during a password change |
| `lepic.pin-failures` | Wrong password or PIN attempts since the last right one |
| `lepic.pin-key`, `lepic.pin-key-pending` | The key the sealed password is bound to, and the next one during a PIN change |

- The key names are fixed, so each wallet needs its own store.
- The vault is Argon2id with XChaCha20-Poly1305. The plain seed never reaches the store or Dart.
- A read or delete that gets no answer within 30 seconds fails with `SecretStore`. A write has
  no time limit, since a write given up on may still land; `lock` ends a write that hangs.

## Streams

Calls that report over time take a `StreamSink`, which Dart sees as a `Stream`.

| Call | Stream of | Ends |
|---|---|---|
| `EpicWallet::events` | `WalletEvent`: session, balance, transaction, sync, transport, delivery, invoice, pairing and contact changes, and payments refused at an open receipt cap (`PaymentRefused`) | When the wallet is dropped |
| `start_listener`, `start_listener_via` | `ListenerEvent` of the Epicbox listener | With `Stopped` after `stop_listener` |
| `watch_epicbox_sessions` | `EpicboxSessionEvent`: a session's state, a note when mail was queued, `NoneReachable` when no mailbox of the list can be reached and `MailboxBack` when one attaches again | When the wallet is dropped, or with `Unsupported` when no relay is configured |
| `refresh`, `scan` | `RefreshProgress`, `ScanProgress` | When the call completes |
| `start_tor` | `TorEvent`: `Starting`, `Bootstrapped`, `Publishing`, `Ready`, `Sending`, `Received`, `Refused`, `Failed`, `Stopped` | With `Stopped` |
| `start_http_listener` | `HttpListenerEvent` | With `Stopped` |
| `LepicRuntime::logs` | `LogEntry` | When replaced or stopped |
| `LepicRuntime::store_migration_progress` | Progress of a copy of a plain database into an encrypted one | When replaced |

A stream that cannot start ends with a `WalletError` as its error and no event.

## API modules

| Module | Contents |
|---|---|
| `runtime` | `LepicRuntime`, `init_app` and the log calls |
| `secret_store` | `AppSecretStore` and `SecretReply` |
| `types` | `WalletConfig`, `NetTuning`, events, views of transactions and outputs |
| `policy` | `HostPolicy` and `PinSettings` |
| `wallet` | Open and create, balance, transactions, refresh and scan, send and receive by slate, file and Epicbox, QR slate codes, fees, cancel and repost, address signatures |
| `invoice` | Issue and pay invoices by slate or file, `sweep_invoices` |
| `contact` | Pairing with invite links ([RFC 0002](rfcs/0002-contact-pairing.md)), contacts, sealed slates and invoices, outbox, export and import. `set_delivery` and `delivery_wake` drive the [delivery loop](#delivery-loop). The [mailbox list](#mailbox-list) calls are here too. `ContactView.awaiting` is true while a message waits to go out, a payment is unfinished or an invoice waits for an answer, so a timer can check only those contacts |
| `epicbox_sessions` | Push sessions with the relay: `start_listener_via`, `epicbox_sessions`, `watch_epicbox_sessions` |
| `http` | Sends to an `http(s)` listener and the wallet's own listener ([ADR 0017](adr/0017-foreign-api-over-http.md)) |
| `tor` | The wallet's own tor, its onion address, and Epicbox, node and HTTP traffic over it ([ADR 0018](adr/0018-tor-on-desktop.md)) |
| `in_person` | EPICTX between two devices by QR code ([RFC 0003](rfcs/0003-epictx-native-slates.md)) |
| `epic1` | EPICTX epic1 links: make, read, pay and answer them without pairing; one address per account, links stored nowhere; see [epic1 payments](#epic1-payments); `set_epic1_at_listener` per `ListenerSocket` (`Web`, `Onion`), off until turned on, read at the next listener start |
| `at_rest` | Whether the database is encrypted, migration progress, `retire_plain_store` |
| `app_data` | `seal_app_data` and `open_app_data`, with a key derived from the seed that stays in Rust |
| `diagnostics` | `LogLevel` and `LogEntry` |
| `error` | `WalletError` and `WalletErrorKind` |
| `testing` | Scripted node and relay for the binding's tests; every call fails `Unsupported` without the `mock` feature |

On iOS, `start_tor` starts nothing: its stream reports `Failed` and then `Stopped`. The wallet's
`tor_wanted` setting is ignored there.

### Epicbox push sessions

A relay that offers `mux/1` ([spec](protocols/epicbox-mux.md)) pushes mail over one socket for many
mailboxes. The `epicbox_sessions` calls let the app use it:

- `start_listener_via(ListenVia, sink)` starts the payments listener like `start_listener`, but
  reads the relay through a push session. When the relay does not offer `mux/1`, it listens on a
  socket as before.
- The [delivery loop](#delivery-loop) reads the contacts' mailboxes through push sessions. A
  relay without `mux/1` is reported unreachable to it.
- A `ListenVia` has a `group` and `waiting_every_s`. Two consumers that name the same group on the
  same relay share a session; it opens another socket when the relay's `mailboxes_per_socket` is
  reached, and is listed once. `waiting_every_s` is how often the session asks the relay whether
  mail waits (`None` never asks; 0 or over a day is `InvalidArgument`).
- `epicbox_sessions()` lists the sessions as `EpicboxSessionView`: relay, group, `state`
  (`Connecting`, `Attached`, `Reconnecting`, `NotOffered`, `Stopped`) and counters (sockets
  opened, attaches, resumes, mails, duplicates, stall reconnects).

### Delivery loop

The binding runs the contacts' delivery layer in the background, as `lepic serve` does. The host
calls `set_delivery` after every open.

- `set_delivery(ContactRelayMode)` sets the loop's mode. `Online` starts the loop, or keeps it
  running. `Offline` ends it and lets go of the contacts' push sessions. It fails
  with `Locked` on a locked wallet, and with `Unsupported` for `Online` when the configuration
  names no Epicbox relay. A lock ends the loop and clears the mode, so the wallet opened again
  has no loop until the next `set_delivery`.
- Each tick claims the contact mailboxes on push sessions, takes what arrived, raises an event for
  it, ends what expired and posts the outbox entries that are due. The first tick runs at once, the
  others every `EpicboxTuning.collect_every_s` (default 30), sooner while a boost of `Relays` lasts.
  Mail a relay pushes runs a tick at once, or a second after the last tick ended. So do a contacts
  session that attaches, when the loop starts and after each reconnect, a switch of the Epicbox
  relay, and a tick that completed a pairing. A tick that fails is logged; the next one runs as
  planned. Two ticks never run at once.
- The contacts' push sessions join the group `contacts` while the wallet's tor runs. Without
  tor they join the listener's group when it reads through a push session
  (`start_listener_via`), else the group `main`.
- `delivery_wake(open)` runs one tick now, after any tick under way, in the mode set, or
  `Online` when none was set. Use it for a pull to refresh with `open` false. The host passes
  `open` true when the app opens, unlocks or comes to the front: that tick takes back at once
  a mailbox another install of the wallet took over, such as the epic1 one; a tick with `open`
  false leaves it with the other install until its hold-off ends. It fails with `ContactsOffline` before
  connecting when the mode is `Offline`. Its results arrive as wallet events. In
  `Online` the tick opens the contacts' push sessions. They stay open after the call, with no
  loop running, until `set_delivery` with `Offline` or a lock ends them; a
  switch of the Epicbox relay ends those on the old relay.

### Mailbox list

Native mail uses one list: a post goes to at most 3 of its mailboxes, and mail is read on all of them. The app owns the list: it ships its mailboxes in
its own configuration and keeps the user's changes (`added`, `removed`) in its settings. The
session holds the list in memory only. The CLI keeps its list in `settings.toml` itself.

- `mailbox_set(shipped, added, removed)` sets the list: the shipped mailboxes less `removed`,
  then `added`. Call it after every open, and again whenever the list changes; running sessions
  use the new list at once. It fails with `MailboxInvalid` or `MailboxNotPublic` naming the host
  first in `message`, `MailboxListFull` for more than 16, and `InvalidArgument` when nothing
  would be left. A refused list changes nothing.
- `mailbox_list()` gives the list in use as `MailboxView`: host (`domain`, or `domain:port`
  off port 443), `origin` (`Shipped` or `Added`), `push` (offered at the last greeting),
  `no_mux` (known to lack mux/1: reachable, but never posted to for native mail),
  `last_success_at_ms`, `failures` and `last_error`. Before `mailbox_set` it is the wallet's own
  Epicbox relay alone. It fails with `Unsupported` when the configuration names no relay.
- `mailbox_add(host, anyway)` tests the host, then adds it when the test passed or `anyway` is
  true. It returns `MailboxAdded`: whether it was added, the `MailboxProbe`, and the new
  `MailboxChanges` for the app to store. A host on this device or a private network is refused
  with `MailboxNotPublic`, anyway or not. Health never takes a mailbox off the list.
- `mailbox_remove(host)` marks a shipped mailbox removed or drops an added one, and returns
  `MailboxRemoved` with the new `MailboxChanges`. The last mailbox cannot go (`LastMailbox`).
- `mailbox_probe(host)` tests one host and changes nothing. `MailboxProbe` has a step each for
  TLS, the greeting and push (`Passed`, `Failed`, `NotReached`), `failure` with the reason of
  the step that failed, and `passed`.
- `mailbox_add` and `mailbox_remove` fail with `InvalidArgument` before `mailbox_set`.

### epic1 payments

- `epic1_link_read(text)` returns `Epic1LinkRead`. `ignored_mailboxes` counts the `mailbox=`
  entries of the link; a payment never uses them.
- `epic1_pay(link, account, amount_nano, message, options, mailboxes, relay_mode)` posts the
  payment to at most 3 mailboxes of the list, the healthiest. A non-empty `mailboxes` posts it to those only. When
  the list holds none of the shipped mailboxes and `mailboxes` is empty, it fails with
  `NoSharedMailbox`, whose `message` names the shipped mailboxes, and stores nothing.
- `message`: `None` takes the link's message; an empty or blank string pays without one.
- `epic1_restore(relay_mode)` returns `Epic1Restored`: how many payments it took, and in
  `not_read` each mailbox it could not read with the reason (`NoPush`, `NotAnswering`,
  `SlotsLeftOut`). A mailbox not read is no failure of the call; it fails with
  `TransportFailed` only when no mailbox could be read.

### Polling and connections

- `boost(poller, duration_secs, interval_secs)` returns an id, and `end_boost(id)` ends it. A boost
  makes one poller (`Relays`, the delivery loop, or `Node`, the node refresh) run faster for a
  while: at least every 5 seconds, for at most 10 minutes; values outside are clamped. It starts no
  loop. The app asks `poll_interval(poller, base_secs)` before each wait.
- `drop_node_connections()` closes the connections kept open to the node. Call it when the
  network changes and when the app returns to the foreground. It fails with `Locked` on a locked
  wallet.
- `drain_epicbox_listings(listings)` drains up to 16 listing addresses, on one connection where it
  can. It returns one `ListingDrain` (a report or an error) per listing, in order.
- `encode_ur_slate(json, max_fragment_len, single_code_max_len)`: a slate of at most
  `single_code_max_len` bytes (0 to 1024) is one code. `decode_ur_slate` fails with
  `ForeignUrCode` for an in-person code or answer.
- `HostPolicy.listener_challenge_rounds` (2 to 10, default 3) moves the listener to a new socket
  when the relay sent no challenge for that many intervals; see
  [Epicbox](protocols/epicbox.md#messages-that-cannot-be-taken-yet).

## Secrets at the boundary

[ADR 0014](adr/0014-secrets-at-the-flutter-boundary.md) fixes which secrets cross between Dart
and Rust.

| Direction | Secrets |
|---|---|
| Dart to Rust | The wallet password, the PIN, the recovery phrase (create, restore, `validate_mnemonic`, `wallet_fingerprint`, `reset_password`), `WalletConfig.node_api_secret` |
| Rust to Dart | The recovery phrase, only from `mnemonic` and `mnemonic_with_pin`, for the backup screen |
| Rust to the app's store only | The sealed vault and the PIN key; Dart code never reads them |
| Both ways | Pairing invite links (`epiccash://pair/1/…`) |

Never out of Rust: seed bytes, private keys, blinding factors, nonces, vault keys, and the
generated password of a PIN wallet, which Dart holds only as sealed text. LEPIC never stores or
logs invite links, and the `Debug` output of a config or a store reply leaves
its secrets out.

## Errors

Every failing call returns a `WalletError`:

| Field | Meaning |
|---|---|
| `kind`, `code` | The `WalletErrorKind` and its number |
| `message` | Text for logs; it may change |
| `tx_id` | The stored transaction, when the failure left one |
| `set_aside` | The file a damaged database was moved to, for `DamagedDatabase` and `DamagedKept` |
| `retry_after_secs` | The seconds a mailbox or peer asked to wait before the post goes again (a rate limit or a full slot), when the refusal named a wait |
| `mailbox` | The mailbox, `host[:port]`, that refused a post, or that an epic1 link of an earlier release names, when the error says which |

Branch on `kind` or `code`, never on `message`. A code never changes meaning. Code 28, codes 32
to 36, 38 to 39, 65, 83, 86, 94, 97 to 101, 105, 107 and 114 are unused, and none is given to
another kind.

| Code | Kind | Meaning |
|---|---|---|
| 1 | `InvalidMnemonic` | The recovery phrase is not valid |
| 2 | `WrongPassword` | Wrong password or PIN |
| 3 | `WalletAlreadyExists` | The store holds a vault already |
| 4 | `WalletNotFound` | No wallet in the directory or store |
| 5 | `NodeUnreachable` | The node did not answer |
| 6 | `NotEnoughFunds` | The spendable balance is too low |
| 7 | `InvalidSlate` | The slate is damaged or not one |
| 8 | `InvalidArgument` | An argument is out of range or malformed |
| 9 | `TransportFailed` | The relay could not be reached or refused, or a slate file failed |
| 10 | `ChainBusy` | Never returned |
| 11 | `WalletBusy` | The wallet is open elsewhere or being deleted |
| 12 | `PaymentExpired` | The slate's time to live passed |
| 13 | `Io` | A file operation failed |
| 14 | `Other` | Any other failure |
| 15 | `Locked` | The wallet handle is locked; open it again |
| 16 | `ForeignWallet` | The directory holds another wallet's or network's database |
| 17 | `SecretStore` | The app's store failed or returned damaged data |
| 18 | `NotPosted` | Finalized and stored, but the node refused it; repost it |
| 19 | `Cancelled` | Stopped by `lock`, `cancel_scan` or `set_servers` |
| 20 | `Unsupported` | Not available in this build or configuration |
| 21 | `Panic` | A defect inside LEPIC; the wallet stays usable |
| 22 | `RestoreScanRequired` | Run `scan` to the end after a restore |
| 23 | `ChangedDuringCancel` | Another operation changed the transaction during the cancel |
| 24 | `OnChain` | The kernel is on chain; it cannot be cancelled |
| 25 | `ForeignAppData` | The app data belongs to another seed |
| 26 | `DamagedAppData` | The app data was changed or cut short |
| 27 | `InPool` | The node's pool holds the transaction |
| 29 | `InvoiceNotFound` | No invoice with that slate id waits |
| 30 | `AmountMismatch` | The invoice asks for another amount |
| 31 | `NotDelivered` | Stored, but the relay did not take it |
| 37 | `DamagedDatabase` | The database was damaged and has just been set aside under a new name, and nothing new was made. `set_aside` names the file. Ask the user, then call `start_over` (or `start_over_with_pin`) and scan to the end |
| 40 | `HttpUrlInvalid` | Not an `http(s)` URL, or an onion host |
| 41 | `PlainHttpNotAllowed` | Plain `http` to another computer without the user's consent |
| 42 | `OnionAddressInvalid` | Not an onion v3 address |
| 43 | `TorNotRunning` | The wallet's tor is not running or not bootstrapped |
| 44 | `OnionUnreachable` | The other wallet's onion did not answer; the send is stored |
| 45 | `ChangeTooSmall` | The change cannot be split into that many outputs |
| 46 | `TooHeavy` | Too many inputs or outputs for one transaction |
| 47 | `NothingToConsolidate` | Fewer than two spendable outputs |
| 48 | `InvoiceAlreadyPaid` | The invoice was paid or finalized already |
| 49 | `InvoiceLockedAboveTip` | The invoice's lock height is above the tip |
| 50 | `InvoiceChanged` | The payer's answer changed the invoice |
| 51 | `NotUrCode` | The QR code is not a slate code |
| 52 | `ForeignUrCode` | The QR code is another type of uniform resource |
| 53 | `MixedUrCodes` | Parts of two different slate codes |
| 54 | `InvalidUrCode` | The slate code is damaged or too new |
| 55 | `UrCodeTooLarge` | Too large for QR codes; use a file |
| 56 | `ContactsOffline` | The user chose Offline |
| 58 | `InvalidPairingText` | The link, card, reply or sealed text is damaged or for the other network |
| 59 | `InvalidContactName` | The name cannot go in a contact card |
| 60 | `InviteExpired` | The invite expired |
| 61 | `AlreadyPaired` | Already paired with that wallet, or it is this wallet |
| 62 | `ContactNotFound` | No paired contact with that id, or not in the needed state |
| 63 | `PairingNotFound` | No pairing in progress with that id |
| 64 | `ContactNotVerified` | The contact's words were not checked |
| 66 | `SealingOff` | Sealing is off for the contact |
| 67 | `NoSlateToSend` | No slate to send, or no outbox entry with that id |
| 68 | `SealedForAnotherWallet` | Sealed for another wallet, or signed by someone else |
| 69 | `SealedUnopenable` | The sealed text was changed on the way |
| 70 | `KeyCheckRefused` | A key check is not allowed for this pairing now |
| 71 | `PairingWordsNotFound` | No invite for these words |
| 72 | `InvalidPairingWords` | No longer produced; kept for its number |
| 73 | `ContactRefusesInvoices` | The contact does not pay invoices |
| 74 | `PhraseMismatch` | The phrase belongs to another wallet |
| 75 | `InvoiceNotForThisChain` | The invoice is for another network or has wrong heights |
| 76 | `InputsSpentElsewhere` | Another wallet on the same phrase spent the inputs |
| 77 | `WrongPairingClass` | Private and contact pairing mixed up |
| 78 | `Offline` | The wallet was opened offline |
| 79 | `InputsSpentByOwnTransaction` | Another transaction of this wallet spent the inputs |
| 80 | `PeerInputsSpent` | The other party spent its inputs elsewhere |
| 81 | `OtherAddress` | The pairing proves another payments address |
| 82 | `AddressProofMissing` | The pairing proves no payments address |
| 84 | `PairingInProgress` | A pairing with that wallet is in progress already |
| 85 | `PairingCrossed` | This wallet's own pairing with it wins; keep waiting |
| 87 | `PairingEnded` | The pairing ended |
| 88 | `PairingWaiting` | The contact's wallet has not answered in this pairing yet |
| 89 | `ForeignProofAddress` | A payment proof this wallet does not sign |
| 90 | `WrongKey` | The encrypted database does not open with this phrase's key |
| 91 | `PairingKindDiffers` | The card names another contact kind than the invite |
| 92 | `RelayMoveNotRequested` | The contact asked for no move, or for another relay |
| 93 | `InPersonNotFound` | No in-person code or answer for the slate |
| 95 | `InPersonNoMailbox` | The code names no reply mailbox; show the answer |
| 96 | `UrCodeIncomplete` | Keep scanning; the code is not whole |
| 102 | `SavedTransaction` | The text is an `epic-wallet` saved transaction, not a payment file |
| 103 | `Epic1CannotPay` | The link names no transport this wallet can use |
| 104 | `Epic1NoMoreRelays` | Every transport of the link was tried |
| 106 | `Epic1NotFound` | No such epic1 payment or answer, or an address this wallet never gave out |
| 108 | `Epic1RelayInvalid` | Making a link: an entry is not an `http` host or onion, is local, or there are more than three |
| 109 | `Epic1MessageInvalid` | The message is too long or has control characters |
| 110 | `Epic1Finalized` | The payment was finalized already |
| 111 | `Epic1WrongNetwork` | The link is for another network |
| 112 | `NotAnEpic1Link` | The text is not an epic1 link |
| 113 | `WalletTooNew` | A newer LEPIC wrote the database; update the app |
| 115 | `CancelledOnRelay` | The relay refused the slate because the other party cancelled it there; the transaction stays as it is here, its inputs locked until it is cancelled or expires |
| 116 | `RecoveryOpen` | The send has a recovery that is not done or failed |
| 117 | `NotRecoverable` | The transaction cannot be recovered |
| 118 | `SlateTooLarge` | The slate, or the answer to it, is longer than the mailbox takes; nothing was stored |
| 119 | `NoSharedMailbox` | The payer's list holds none of the shipped mailboxes; nothing was stored |
| 120 | `MailboxInvalid` | The mailbox is not a host name with an optional port other than 0 |
| 121 | `MailboxNotPublic` | The mailbox is on this device or a private network |
| 122 | `MailboxListFull` | The list holds 16 mailboxes |
| 123 | `LastMailbox` | The last mailbox of the list cannot go |
| 124 | `DamagedKept` | A damaged database was set aside earlier and is kept, and no database replaced it. Nothing was made; opening again gives this again. `set_aside` names the file. `start_over` (or `start_over_with_pin`) makes a new, empty database when the user asks |
| 125 | `EarlierEpic1Address` | The text is an epic1 address or link of LEPIC 0.5 or earlier, which this version cannot read. Nothing was stored. `mailbox` names the link's mailbox when it has one. Ask for the payee's Epicbox address or an epic1 address or link from an updated wallet |

## Building the native libraries

`cargo xtask mobile` builds the library that lepic-flutter loads. Run it from the LEPIC
repository root.

```sh
# Release libraries for every target this host can build, into dist/native/<triple>/
cargo xtask mobile --package

# One target only
cargo xtask mobile --package --target aarch64-linux-android

# Without the wallet's tor, into dist/native-no-tor/
cargo xtask mobile --package --no-tor

# Check that the library crates build for a target, without packaging
cargo xtask mobile --target aarch64-apple-ios --release
```

| Target | Host | Library |
|---|---|---|
| `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` | Any, with `cargo ndk`; API level 24 | `liblepic_ffi.so` |
| `aarch64-apple-ios`, `aarch64-apple-ios-sim` | macOS | `liblepic_ffi.dylib` |
| `x86_64-unknown-linux-gnu` | Linux | `liblepic_ffi.so` |
| `x86_64-pc-windows-msvc` | Windows | `lepic_ffi.dll` |

Without `--target`, `--package` builds the Android targets and the host's own targets. Each
target directory holds the library and three files:

- `SHA256SUMS`: the library's checksum.
- `FEATURES`: the features it was built with.
- `SOURCE`: the LEPIC commit and the `rustc` version.

Options of `--package`:

| Option | Effect | Default output |
|---|---|---|
| (none) | Release build with tor | `dist/native` |
| `--mock` | Adds the scripted node and relay for the binding's tests; never ship it | `dist/native-mock` |
| `--no-tor` | Leaves the `tor` feature out | `dist/native-no-tor` |
| `--mock --no-tor` | Both | `dist/native-mock-no-tor` |
| `--out <dir>` | Writes to another directory | |

`--package` always builds release and refuses `--release`. `--mock`, `--no-tor` and `--out`
work only with `--package`.

### Builds without tor

The `tor` feature is on by default. A build without it keeps every Tor function with the same
signature, so one generated binding serves both builds
([ADR 0026](adr/0026-tor-as-a-build-feature.md)):

- `start_tor`, `refresh_tor`, `onion_address`, `send_tor` and `resend_tor` fail with
  `Unsupported`.
- `tor_status` reports Off, and the `*_over_tor` getters return false.
- `stop_tor` and `tor_network_lost` do nothing; `set_onion_routes` keeps no routes.
- `validate_onion_address` returns false, and an onion node or relay address fails.

## Related

- [lepic-flutter](https://github.com/BTLabsUK/lepic-flutter): the Dart package and its generator
- [configuration.md](configuration.md#through-the-ffi): `WalletConfig`, `NetTuning`,
  `HostPolicy` and `PinSettings`
- [crates/lepic-ffi/README.md](../crates/lepic-ffi/README.md): the crate at a glance
- [ADR 0014: secrets at the Flutter boundary](adr/0014-secrets-at-the-flutter-boundary.md)
- [ADR 0026: Tor as a build feature](adr/0026-tor-as-a-build-feature.md)
- [ADR 0036: policy values are host parameters](adr/0036-policy-values-are-host-parameters.md)
- [ADR 0044: the onion has its own key](adr/0044-the-onion-has-its-own-key.md)
