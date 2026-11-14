# lepic-wallet

The wallet engine. A `Wallet` holds one wallet: its seed, accounts, outputs and transactions. It
builds, receives, finalizes, posts, cancels and releases transactions, refreshes and scans
against the Epic node, and tells the host what happened through an event stream. It runs on
ports the host supplies (node, database, secret storage, clock, randomness, Tokio runtime) and
keeps no global state, so several wallets, on different networks, can run in one process.

## Where it fits

The engine sits between the pure crates and the hosts.

| Direction | Crates |
|---|---|
| Depends on | `lepic-primitives`, `lepic-crypto`, `lepic-keychain`, `lepic-slate`, `lepic-legacy-slate`, `lepic-contact`, `lepic-store`, `lepic-node`, `lepic-transport` |
| Used by | `lepic-wallet-contacts`, `lepic-methods`, `lepic-cli`, `lepic-ffi` |

Features:

| Feature | Default | Effect |
|---|---|---|
| `sqlite` | on | The SQLite store openers (`lepic-store/sqlite`) |

What it does not do:

- It runs no transport loop. A method (`lepic_transport::method::Method`) carries slates;
  `lepic-methods` holds the methods and their relay and listener loops, which hand each message
  to the engine's inbox calls.
- It holds no contact code. `lepic-wallet-contacts` builds pairing, mailboxes and contact
  invoices on the public calls, the event stream and the hooks in `extension`.
- It applies no host policy of its own. Limits a host may choose come in through
  `WalletPolicy` (ADR 0036).

See [architecture](../../docs/architecture.md) for the layers and the crate map.

## Core concepts

### Configuration and ports

A wallet is built with `Wallet::new(config, ports)` and starts locked.

`WalletConfig` says what the wallet is:

| Field | Meaning |
|---|---|
| `name`, `network` | A `WalletName` of at most 64 bytes, and `Mainnet` or `Floonet` |
| `data_dir` | Where the database lives; the host creates it |
| `node` | The node's `NodeEndpoint`; only its host part appears in logs |
| `offline` | The session never asks the node (ADR 0031) |
| `host_features`, `profile` | Feature bits and profile the host claims to peers |
| `domain` | The domain the wallet claims to paired contacts (RFC 0002 6.3) |
| `policy` | `WalletPolicy`, the values the host chooses |
| `native_direct` | Send `lepic.v1` slates to contacts that claim them |

`Ports<N, S, V>` is what it runs on:

| Field | Type | Role |
|---|---|---|
| `node` | `N: NodeApi` | The Epic node client (`lepic-node`) |
| `stores` | `S: StoreOpener` | Opens the database once the seed is known |
| `secrets` | `V: SecretVault` | Keeps the seed under the password |
| `clock`, `rng` | `Arc<dyn Clock>`, `SharedRng` | Timestamps; every key, nonce and offset |
| `runtime` | `tokio::runtime::Handle` | Blocking work runs on its blocking pool |
| `methods` | `Option<Arc<dyn MethodLookup>>` | Finds the method that carries a notice |

Store openers:

| Opener | File | Use |
|---|---|---|
| `EncryptingSqliteStores` | `ENCRYPTED_DATABASE_FILE` | The product. Copies a plain `DATABASE_FILE` into the encrypted file at first open |
| `EncryptedSqliteStores` | `ENCRYPTED_DATABASE_FILE` | Encrypted at rest under the store key |
| `SqliteStores` | `DATABASE_FILE` | Plain SQLite, for tests and tools |

The `SecretVault` is the `lepic-keychain` vault on desktop and the platform keystore through
the host app on mobile. One vault holds one wallet.

### Session

`create`, `restore`, `restore_from_height`, `import_wallet_seed` and `open` unlock the wallet:
the root key is in memory and the database is open. `lock` drops both; `close` ends the
handle. Operations already running keep the session until they finish. Calls that need the
seed fail with `WalletError::Locked` while it is locked.

- `restore` finds outputs by a later scan from genesis.
- `restore_from_height` records a start height: a scan from that height, or from below it, to
  the tip completes the restore (ADR 0035). `restore_scan_required` and `restore_scan_start`
  tell the host what is left to scan.
- `import_wallet_seed` reads an `epic-wallet` `wallet.seed` file.
- An `offline` session (ADR 0031) uses the highest tip a refresh confirmed, unchecked, and
  stores a finalized transaction without pushing it. The host builds the node and relay ports
  to refuse every call as well.

### Transaction life

Each transaction entry has a state (`lepic_store::TxState`). The rules are in `state`:

```text
Sent ─────┬─> Finalized ─> Posted ─┬─> Confirmed
Received ─┘      │                 └─> Cancelled, Expired
  │              └─> Confirmed, Cancelled, Expired
  └─> Confirmed, Cancelled, Expired
```

- `Confirmed`, `Cancelled` and `Expired` are final.
- One step leaves a final state: `Cancelled` or `Expired` to `Confirmed`, when a watched
  kernel of a transaction that ended unconfirmed is found on chain.
- Moving to the state a transaction is already in succeeds without a change, so a slate
  delivered twice or a second post is harmless.
- The table ignores direction. The stage that takes a step checks which side may take it, for
  example that only an invoice issuer finalizes an incoming transaction.

What moves a transaction:

| To | Step | Code |
|---|---|---|
| `Sent` | `send` stores the S1; `pay_invoice` stores the I2 | `send.rs`, `invoice.rs` |
| `Received` | `receive` stores the S2; `issue_invoice` stores the I1 | `receive.rs`, `invoice.rs` |
| `Finalized` | `finalize` builds S3; `finalize_invoice` builds I3 | `finalize.rs`, `invoice.rs` |
| `Posted` | The node took the push (`finalize`, `post`) | `finalize.rs` |
| `Confirmed` | A refresh finds the kernel on chain | `refresh.rs` |
| `Cancelled` | `cancel`, `release`, a refresh that finds the receipt superseded or the inputs spent elsewhere, a scan | `cancel.rs`, `release.rs`, `refresh.rs`, `scan.rs` |
| `Expired` | A refresh finds the TTL passed and no kernel in pool or chain | `refresh.rs` |

A send in `Sent` that failed to deliver can be delivered again with `resend`. A finalized
transaction whose push failed stays `Finalized`, and `post` tries again; each failed push
raises `Event::NotPosted`.

`cancel` works as `epic-wallet`'s `cancel_tx`: unconfirmed outputs are dropped and locked inputs
unlocked. A posted transaction is not cancelled, nor is one whose kernel the node's chain or
pool holds while the peer could complete it. A transaction that ends while its peer can
complete it stays watched, so a later refresh confirms it and restores its outputs.

A finalized or posted send whose kernel a refresh has not found `RELEASE_AFTER_BLOCKS` (1,440)
blocks after finalizing becomes releasable. `release` is the owner's call, never automatic,
because another node may hold the transaction. It cancels the send and keeps its kernel and
change: for `RELEASED_WATCH_BLOCKS` (10,080) a refresh looks for the kernel, then it asks the
node for the change outputs with no end.

`docs/compat/states.md` maps these states to the transaction types `epic-wallet` stores.

### Refresh and scan

`refresh` brings outputs and transactions in line with the node, in steps that each run in
their own store transaction:

1. outputs, marked unspent or spent by what the node holds;
2. kernel confirmations;
3. received payments another transaction superseded;
4. finalized or posted transactions whose inputs were spent elsewhere;
5. TTL expiry;
6. the kernel checks that make a send releasable.

Dropping the future between steps leaves a consistent store that the next refresh completes.
`refresh_scan` is the short update scan to run after it: it finds what another wallet on the
same recovery phrase received or spent.

`scan` pages through the node's outputs for a height range (`scan::DEFAULT_PAGE_SIZE`, 1,000
outputs a request), rewinding range proofs to find the wallet's outputs. Each page is stored with a
checkpoint, so a cancelled or failed scan resumes after the last stored page.
`reset_chain_position` forgets the stored heights and scans from genesis.

### Inbox

A method's loop receives messages and hands each one to the engine (`inbox`). An S1 is received
and answered with S2 through the same method; an S2 is finalized and posted. Every message is
idempotent on its message id and on `(slate_id, stage)`: a redelivered S1 gets the S2 stored the
first time and raises `Event::AnsweredAgain`.

- A held message is bounded to 3 attempts and 3 minutes, because a relay delivers one message at a
  time.
- An S2 or I2 for an unknown slate may belong to another install on the same phrase. It is held
  for `TWIN_HOLD` (90 s) and then requeued for that install, at most `MAX_TWIN_ANSWERS` (4) at a
  time, within `TWIN_REQUEUE_WINDOW` (24 h).
- Open receipts nobody asked for are capped by `WalletPolicy` (10 per sender key, 100 in all).

### Boosts and the API log

`boost::Boosts` lets a host poll faster for a while (ADR 0058). The host runs one loop for each
`Poller`: `Relays` for the contact collect cycle and `Node` for the refresh. It asks
`Boosts::interval(poller, base)` before each sleep and wakes on `changed()`. `boost` returns a
`Lease` that ends the boost when dropped, unless `keep()` hands its random id on for
`Boosts::end`. A poller with several boosts runs at the shortest interval among them. An interval
below `MIN_INTERVAL` (5 s) and a window above `MAX_DURATION` (10 min) are clamped. `Boosts` starts
no loop of its own.

`api_log` keeps the serve API's event log and idempotency records in the wallet's store:
`append_api_event`, `api_events_after`, `prune_api_events`, `put_api_request`, `api_request`
and the matching prune and delete calls.

### Policy

`WalletPolicy` holds the values a host chooses (ADR 0036). `WalletPolicy::DEFAULT`:

| Field | Default |
|---|---|
| `max_open_receipts_per_sender` | 10 |
| `max_open_receipts` | 100 |
| `default_minimum_confirmations` | 6 |
| `contact_check_answers_per_hour` / `_per_day` | 1 / 3 |
| `contact_hold_attempts` / `contact_hold_patience` | 3 / 3 min |
| `refuse_unsolicited_payments` / `_invoices` | off (ADR 0045) |
| `listener_held_rounds` | `None` |
| `listener_challenge_rounds` | `Some(3)` |
| `quarantine_max_bytes` | `None` (ADR 0049) |
| `early_notice_max_count` / `_max_age` | `None` (ADR 0049) |

`Wallet::new` fails with `WalletError::Config` for a value out of range. The bounds are
associated constants, such as `WalletPolicy::MAX_QUARANTINE_BYTES` (64 MiB).

### Extension hooks

Crates that build on the engine plug in through `extension`. Each hook is set once; the first
install stays, and the setter returns whether this one was installed.

| Hook | Setter | Purpose |
|---|---|---|
| `ReplyKeys` | `set_reply_keys` | Reply key in the marker of file and paste S1s and I1s (RFC 0002 5) |
| `NativeSlates` | `set_native_slates` | Converts slates to and from `lepic.v1` (RFC 0003) |
| `ContactNotices` | `set_contact_notices` | Seals notices into a paired contact's mailbox |
| `PairRequests` | `set_pair_requests` | Takes pairing requests sent to the payments address |

### Events

`Wallet::subscribe` returns a `tokio::sync::broadcast::Receiver<Event>`. A subscriber more than
`EVENT_CAPACITY` (256) events behind misses the oldest ones and is told how many. `Event` is
`non_exhaustive`.

| Group | Variants |
|---|---|
| Session and chain | `Session`, `Balance`, `Sync`, `Transport`, `TransportDisconnected` |
| Transactions | `Transaction`, `Received`, `SelfSent`, `AnsweredAgain`, `ReplyUndelivered`, `ReceiveSuperseded`, `NotPosted`, `InPersonAnswer` |
| Notices | `PaymentPosted`, `PaymentCancelled`, `PaymentDeclined`, `UnknownSlate`, `NoticeUnmatched` |
| Invoices | `InvoiceParked`, `InvoiceFinalized`, `InvoiceExpired`, `InvoicePosted`, `InvoiceDeclined`, `InvoiceWithdrawn`, `InvoiceBounced` |
| Pairing | `PairingReplied`, `PairingConfirmed`, `PairingFailed`, `PairingRequested` |
| Contacts | `ContactUpdated`, `ContactRelayMoveRequested`, `HomeRelayUnreachable`, `ContactKeysRestored`, `ContactKeysChanged`, `ContactUnpaired`, `InvoiceFromContact`, `WithdrawalFromContact`, `ContactPaymentFinalized`, `ContactPayload`, `ContactPayloadsParked` |
| Sealed and outbox | `SealedReceived`, `SealedUnopenable`, `OutboxDelivered`, `OutboxStuck` |

`SessionState` is `Unlocked`, `Locked` or `Closed`. `UnknownSlate` and `NoticeUnmatched` carry
nothing verified: a host shows them as information and does not act on them.

### Keys

Keys the wallet derives from its seed, besides the BIP32 output keys:

| Call | Key |
|---|---|
| `onion_key` | The onion service key, a LEPIC namespace key (ADR 0044) |
| `previous_onion_key` | The payment-proof key of `m/0/0`, index 0, the previous onion's key |
| `api_tls_key` | The certificate key of the owner TLS listener |
| `epic1_seal_key`, `epic1_proof_key` | The epic1 seal and proof keys |
| `reply_mailbox_key`, `link_mailbox_key`, `post_key` | Mailbox and posting keys |

The namespace labels are in `namespace` (for example `"lepic-wallet onion key v1"`).

## Public API

All calls are methods of `Wallet<N, S, V>`.

| Area | Calls |
|---|---|
| Lifecycle | `new`, `create`, `restore`, `restore_from_height`, `import_wallet_seed`, `open`, `lock`, `close`, `is_unlocked`, `check_phrase`, `fingerprint` |
| Accounts | `accounts`, `account`, `create_account` (labels up to 64 bytes, `DEFAULT_ACCOUNT_LABEL` is `"default"`) |
| Send | `send`, `send_unsent`, `resend`, `estimate_fee`, `estimate_max` |
| Send to self | `send_to_self`, `estimate_send_to_self` (up to `MAX_SELF_SEND_OUTPUTS`, 10; ADR 0037) |
| Receive | `receive`, `receive_decoded`, `receive_unsolicited` |
| Finalize and post | `finalize`, `finalize_decoded`, `check_send_answer`, `post` |
| End | `cancel`, `release` |
| Invoices | `issue_invoice`, `issue_unsent`, `pay_invoice`, `pay_decoded`, `finalize_invoice`, `finalize_invoice_decoded`, `check_invoice_answer`, `pending_invoices`, `pay_parked_invoice`, `decline_invoice`, `sweep_invoices` |
| Chain | `refresh`, `refresh_scan`, `scan`, `reset_chain_position`, `kernel_on_chain`, `last_confirmed_height` |
| Balance | `balance`, `outputs`, `minimum_confirmations`, `set_minimum_confirmations` |
| Records | `transactions`, `transaction_details` |
| Peers | `peer_compat`, `forget_peers`, `peer_pin`, `pin_peer`, `peer_pins`, `forget_peer_pin` |
| Other | `build_coinbase` (ADR 0046), `import_legacy_history`, `seal_app_data`, `open_app_data` |
| Events and hooks | `subscribe`, `set_reply_keys`, `set_native_slates`, `set_contact_notices`, `set_pair_requests` |

Main types at the crate root: `WalletConfig`, `WalletPolicy`, `NodeEndpoint`, `WalletName`,
`Ports`, `StoreOpener`, `SecretVault`, `Clock`, `SharedRng`, `Event`, `SessionState`,
`WalletError`, `Password`, `RecoveryPhrase`, `WordCount`, `ReceiveRequest`, `Received`,
`Finalized`, `SlateFormat`. `send::SendRequest` and `send::Delivery` describe a send;
`refresh::RefreshOutcome` and `scan::ScanOptions` drive the chain calls.

`lepic_wallet::method` re-exports `lepic_transport::method` (ADR 0051), and
`lepic_wallet::slate` re-exports the slate model and codecs a host needs.

Constants a host often shows:

| Constant | Value | Meaning |
|---|---|---|
| `refresh::DEFAULT_MINIMUM_CONFIRMATIONS` | 6 | Confirmations before an output is spendable (ADR 0027) |
| `release::RELEASE_AFTER_BLOCKS` | 1,440 | Blocks before a send with no kernel is releasable |
| `invoice::INVOICE_TTL_BLOCKS` | 1,440 | TTL of an issued invoice |
| `epicbox_invoice::DEFAULT_INVOICE_EXPIRY` | 24 h | How long a parked invoice waits |

## Related

- [Architecture](../../docs/architecture.md), [configuration](../../docs/configuration.md),
  [CLI](../../docs/cli.md), [FFI](../../docs/ffi.md)
- [Transaction states against `epic-wallet`](../../docs/compat/states.md),
  [node API, refresh and scan](../../docs/compat/node-api.md),
  [legacy slates](../../docs/compat/legacy-slates.md)
- [Protocols](../../docs/protocols/README.md): [EPICTX](../../docs/protocols/epictx.md),
  [pairing](../../docs/protocols/pairing.md), [Epicbox](../../docs/protocols/epicbox.md)
- RFCs: [0001 LEPIC slate v1](../../docs/rfcs/0001-lepic-slate-v1.md),
  [0002 contact pairing](../../docs/rfcs/0002-contact-pairing.md),
  [0003 EPICTX native slates](../../docs/rfcs/0003-epictx-native-slates.md)
- ADRs: [0011 no global state](../../docs/adr/0011-no-global-state.md),
  [0027 minimum confirmations](../../docs/adr/0027-minimum-confirmations.md),
  [0031 offline session](../../docs/adr/0031-offline-session.md),
  [0035 restore from a start height](../../docs/adr/0035-restore-from-a-start-height.md),
  [0036 policy values](../../docs/adr/0036-policy-values-are-host-parameters.md),
  [0037 one send to self](../../docs/adr/0037-one-send-to-self.md),
  [0044 the onion's own key](../../docs/adr/0044-the-onion-has-its-own-key.md),
  [0045 refusing slates](../../docs/adr/0045-refusing-slates-nobody-asked-for.md),
  [0046 mining node wallet](../../docs/adr/0046-a-wallet-for-a-mining-node.md),
  [0049 keeping messages](../../docs/adr/0049-keeping-messages-that-cannot-be-taken-yet.md),
  [0051 methods in one crate](../../docs/adr/0051-transaction-methods-in-one-crate.md)
- [Logging fields](../../docs/logging.md)
