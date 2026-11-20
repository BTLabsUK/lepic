# lepic-epicbox

The Epicbox relay protocol as `epic-wallet` `v4.1.0` speaks it: addresses, the encryption and
signatures of one message, the websocket frames, and a client that sends to a relay, listens
for the wallet's messages and drains other mailboxes (ADR 0004). It holds no wallet state; the
wallet consumes what a subscription hands out and acknowledges each item once its effect is
stored. With feature `mock-relay` it also holds an in-process relay for tests.

## Where it fits

| Direction | Crates |
|---|---|
| Depends on | `lepic-crypto` (keys, ECDSA), `lepic-primitives`, `lepic-slate`, `lepic-transport` |
| Used by | `lepic-methods` (feature `epicbox`), `lepic-wallet`, `lepic-wallet-contacts`, `lepic-epic1`, `lepic-cli`, `lepic-ffi` |

Features:

| Feature | Default | Effect |
|---|---|---|
| `mock-relay` | off | `mock_relay::MockRelay`, a relay with the public relay's behaviour, `mock_mux::MuxMockRelay`, a mux/1 relay, and `testing`, the settings the app ships |

What it does not do:

- It holds no default relay. An address without `@domain` fails to parse with
  `AddressError::MissingDomain`, unless the caller names a default domain.
- It has no default timeouts. The host passes `ClientTimings`; `testing` holds the app's
  values for tests.
- It does not store messages or decide what a slate means. `lepic-methods` and `lepic-wallet`
  do that.
- It ships no tor. `tunnel::Tunnel` is the hook a host fills with tor's SOCKS port.

## Core concepts

### Addresses

`EpicboxAddress` is `[epicbox://]<key>@<domain>[:<port>]`: a base58 public key with the
network's version bytes, and the relay that holds its messages. For example
`epicbox://<base58 key>@relay.example:443`. The port is kept exactly as given, absent
included, because the encrypted message carries it and `epic-wallet` writes it as parsed;
`Display` leaves out `DEFAULT_PORT` (443). `Network` is `Mainnet` or `Floonet`, and an address
on the wrong network is refused.

### One message

A sender encrypts the slate text for one receiver and signs the result:

1. `MessageKey` comes from ECDH between the sender's secret key and the receiver's public key,
   stretched with PBKDF2-HMAC-SHA512 over a fresh `Salt`. Both sides derive the same key.
2. `EncryptedMessage` is the ChaCha20-Poly1305 ciphertext under a fresh `Nonce`, and its JSON
   form travels as the `str` field of the frame.
3. `SignedMessage` adds the sender's ECDSA signature over SHA-256 of exactly that `str` text
   (`sign_text`).

On receipt, `ReceivedMessage` verifies the signature over `str` as received before parsing
anything in it, then checks the key and decrypts. A message that does not open gets a
`RejectionReason`: `InvalidSender`, `InvalidSignature`, `NotAddressedToUs`, `Undecryptable`
or `Malformed`. Each is permanent.

`sign_listing_message` and `listing_message_verifies` sign app-chosen bytes with an address key
under a `ServiceDomain`, such as `epic-listing/1`. The signed digest holds a byte UTF-8 never
uses, so no listing signature passes as a relay text signature, or the other way round.

### Frames

The client speaks `PROTOCOL_VERSION` `"3.0.0"` of the relay protocol over a websocket. When the
relay answers `GetVersion` with `3.1.0` or a later 3.x, the client also uses the cancel protocol
(`CANCEL_PROTOCOL_VERSION`); against any other relay it behaves exactly as 3.0.0 and sends no
txid field.

| `ClientFrame` | Purpose |
|---|---|
| `ClientDetails` | Says the wallet mode (`WalletMode::Listener` or `Send`) and the version `4.1.0` |
| `Subscribe` | Signs the relay's latest challenge, to receive an address's messages |
| `PostSlate` | Posts a signed message to an address; on 3.1.0 with an optional signed `epicboxtxid` |
| `CancelTx` | 3.1.0: cancels a transaction by its txid, signed by the key of one party |
| `Made` | Acknowledges a message, so the relay deletes it |
| `Unsubscribe`, `GetVersion` | Leave an address; ask the relay's version |

| `RelayFrame` | Meaning |
|---|---|
| `Challenge` | A short random token to sign |
| `Ok`, `Error` | The answer to the last request; `RelayErrorKind` names the error; on 3.1.0 an `Ok` may carry `epicboxtxid` and `epicboxmsgid` |
| `TransactionCancelled` | 3.1.0: the transaction with that txid was cancelled |
| `Slate` | A pending message (`SlateFrame`), with a `RelayMessageId` when the relay stores it |
| `GetVersion`, `Keepalive`, `Unknown` | The relay's version, keepalives, and frames this version does not know |

Every frame is bounded before it is parsed: `MAX_FRAME_LEN` is `MAX_MESSAGE_LEN` (4 MiB) plus
64 KiB, and challenges, frame types and message ids are at most 64 characters.

### The client

`EpicboxClient::new(settings, identity, connector)` serves one `Identity`, an address and its
secret key. The relay serves a connection as the address it last subscribed with, so a wallet
with several addresses runs one client per address.

- `post(to, plaintext)` encrypts, signs and posts on a short connection of its own. Resending
  is safe: receivers deduplicate.
- `listen()` holds a connection, keeps it alive with pings and reconnects with `Backoff` after
  a failure. It registers as the address's live listener.
- `listen_with(ListenOptions)` adds a watchdog with two rules, both off by default. With
  `held_rounds` the listener moves to a fresh socket after that many rounds that began with a
  message held. With `challenge_rounds` it moves when the relay sent no challenge for that many
  of its challenge intervals (at least 30 seconds each, 60 until two are seen). The held message
  and the waiting mail are taken up again on the new socket.
- `drain()` connects once, takes every stored message and ends. It never takes live delivery
  from a listener elsewhere. `drain_on_with(connection, options)` reuses a `DrainConnection`
  that an earlier drain handed on with `Subscription::take_connection`, so several addresses on
  one relay drain over one socket. A drain that ended with mail outstanding closes its connection instead.
- `with_prefilter` asks a `Prefilter` about each message's claimed sender before opening it;
  `Admission::Drop` acknowledges the message and forgets it.

Both `listen` and `drain` return a `Subscription`. The relay sends one message at a time and
holds back the rest until that one is acknowledged, so a consumer takes each envelope or
`Rejection`, records it, then acknowledges its token. `Subscription` also gives the
`ConnectionState` (`Connecting`, `Subscribed`, `Waiting`, `Stopped`, `Drained`, `Failed`) as a
`watch` channel, the last `Disconnect`, the relay's version and `InboxCounters`. `requeue`
posts a handed-out message back to the same address, for another install to collect.

#### Cancelling (3.1.0)

- `post_tx(to, plaintext, &txid)` posts like `post` and, on a 3.1.0 relay, adds the txid and its
  signature by the sender's key. The `EpicboxTxId` is a version 4 UUID in simple form
  (`EpicboxTxId::generate`), not the slate id. A 3.0.0 relay gets no txid field. A relay that
  already cancelled the txid refuses the post: `ClientError::TransactionCancelled`. The
  `PostReceipt` returns the txid and message id the relay reports.
- `cancel(&txid)` opens a short connection, subscribes send-only and posts `CancelTx`. The
  `CancelReport` holds a `CancelOutcome`: `Cancelled` (the relay sent `TransactionCancelled`),
  `NotFoundOrNotParticipant` (a bare `Ok`: the relay does not say which, and nothing changed),
  or `Unsupported` (a 3.0.0 relay; nothing was sent). A relay `Error` is a `ClientError`. It
  lists the cancellations of other transactions it met on the way in `other_cancelled`. Slate
  frames on this connection are ignored and never acknowledged, so the relay keeps them.
- `ListenOptions::cancel` (off by default) subscribes with cancel on. The relay then sends
  `TransactionCancelled` on that socket and holds back everything else until the next successful
  `Subscribe` on it. `Subscription::next_cancelled` takes one; the consumer applies it (applying
  must be idempotent), then calls `Subscription::ack_cancelled(&txid)`, which lets the
  reconnect or the next subscribe acknowledge it. An unacknowledged cancellation is delivered
  again. `Subscription::epicbox_txid(&token)` gives the txid of a handed-out message.
- A message put back with `requeue` is posted as it was signed and carries no txid.
- The relay's `cancelrequestid` field (relay to relay) is accepted and ignored, and never sent.

Received messages wait in a bounded queue. Past its bounds the client stops acknowledging, so
the relay keeps the message for later. A relay keeps a message for `RELAY_RETENTION` (seven
days).

### Mailboxes

`MailboxClient` reaches mailboxes that are not the wallet's own address, such as pairing and
contact mailboxes. `start_mux_queued` starts a queued mux/1 session that reads them
(RFC 0002 8.2), and `post` sends from their keys. `drain_once` reads each mailbox once: it
greets the relay as a sender, so it never becomes a live listener, and subscribes as each
mailbox in turn. A
`MailboxHandler` answers each message `Handled::Stored` (acknowledge it) or `Handled::Later`
(leave it and move to the next mailbox). `DrainLimits` caps one drain at
`MAX_MAILBOXES_PER_DRAIN` (50) mailboxes and `MAX_MESSAGES_PER_MAILBOX` (32) messages each; the
`DrainReport` holds one `MailboxReport` per mailbox.

### mux/1 sessions

`MuxSession` is an optional client for the relay's mux/1 extension
(`docs/protocols/epicbox-mux.md`): one socket carries
up to 256 mailboxes, the relay pushes each message when it is stored, and acknowledgements need no
signature. The crate starts nothing by itself. A host calls `MuxSession::start`; every other path
keeps plain 3.0.0. `sessions::PushedSessions` shares one session per relay and group for its
hosts, and `lepic-ffi` exposes those sessions to the app.

- `start(settings, connector, identities, handler, options)` greets with `ext: ["mux/1"]`. A plain
  `Ok` means the relay does not offer it: the state becomes `MuxState::NotOffered` and the host
  keeps its classic listeners. The answer is not final: `PushedSessions` asks the relay again
  after 1 minute, doubling to 1 hour, as a relay at its connection limit answers the same way. A session that has never attached reads two more answers the same
  way: an `Error` to the greeting at once, and no answer to the greeting at all on the third try
  in a row. A session that attached once keeps retrying, as it does after any lost socket. A
  challenge that is not 22 characters of `[A-Za-z0-9_-]` is refused. The handler of `start` runs on
  the session's own task, so it must not block (a blocked handler stops pings); a consumer that
  cannot promise that uses queued mode.
- The mailboxes are attached in `Attach` frames of at most 64 entries, each signed over the
  socket's challenge. More than 256 mailboxes give `MuxError::TooManyMailboxes`.
- A `Mail` goes to the `MailboxHandler` as a `MailboxMessage`. `Handled::Stored` queues an `Ack`
  (batched over `MuxOptions::ack_window`, at most 256 ids per frame); `Handled::Later` sends
  `Hold` for `MuxOptions::hold`. A relay id seen before is acknowledged again without calling the
  handler.
- After a drop the session reconnects with `Backoff` and sends `Resume` with the single-use token,
  so no new signature is made. On `token_unknown` (a relay restart) it signs and attaches again.
  `rate_limited` waits for `retry_after`. `Detached` with `replaced` (another install took the
  mailbox) leaves it to the other socket: it keeps its index and is attached again after
  `MuxOptions::replaced_hold_off` (10 minutes), whatever sockets come and go meanwhile; sooner
  on `take_back_now` or when an owner claims it afresh. `retry_now` does not take it back. `shutdown` reconnects. The first reconnect after a socket
  that stayed up is spread over `MuxOptions::first_reconnect_from` to `first_reconnect_to` (1 to
  10 seconds).
- With `MuxOptions::waiting_every` set, the session sends `Waiting` probes. Two probes in a row
  that find waiting mail with nothing in flight or held, and no mail between them, reconnect the
  socket (a stalled push). `waiting()` asks once, for a read the user asked for, and returns a
  `MuxWaiting` (count per mailbox index, `inflight`, `held`); a claim made before it is attached
  first, and the mail the relay pushed before its answer is already queued or handled. It does
  not count toward the stall check, and with no attached socket it fails at once.
- With the relay's `txcancel/1` extension (the client lists it next to `mux/1`), `cancel(&identity,
  &txid)` returns a `MuxCancelOutcome` (`Cancelled`, `NotFoundOrNotParticipant`, `Unsupported`
  without the extension; nothing is sent then), a refusal is `MuxError::Refused { code }`, and a
  lost socket is `MuxError::NotConnected` (repeat it). The relay pushes `Cancelled` before the
  `Mail` of that mailbox, live and on each `Attach` and `Resume`, until `ack_cancelled(mailbox,
  &txid)` sends `CancelAck`. `MuxEvent::Cancelled` carries it to the host; the event is lossy, the
  relay's repeat covers a miss. A `Mail` may carry its txid: `MailboxMessage::epicbox_txid`.
- `attach` and `detach` change the mailbox set while it runs. `state()` is a `watch` channel
  (`Connecting`, `Attached`, `Waiting`, `NotOffered`, `Stopped`), `events()` a `broadcast` of
  `MuxEvent`, and `counters()` gives exact `MuxCounters` (sockets, signatures, attaches, resumes,
  mails, acks, holds, stall reconnects). Logs hold no tokens, keys or message text.
- Queued mode: `MuxSession::start_queued(settings, connector, identities, options)` opens each
  mail and queues it instead of calling a handler, so the session loop never waits on the
  consumer. The consumer calls `take(&[mailbox, ...])` (never waits; oldest first), waits on the
  `queued()` watch channel, and answers every message with `settle(id, Handled)`: `Stored`
  acknowledges, `Later` holds. Until it settles, a message counts against the relay's in-flight
  limit (32 per socket), so a consumer that stops settling stops new mail. A relay that pushes
  past the limit anyway gets a `Hold` for the extra message, which is offered again later. Unsettled mail is
  forgotten when the socket drops and the relay offers it again. `set_mailboxes(identities)` makes
  the set exactly that list: it attaches what is new, detaches what is gone, and signs only for
  the new ones. Consumers that share a session use `set_claim(owner, identities)` instead: the
  attached set is the union of every owner's claim, so one owner never detaches another's
  mailboxes, an empty claim releases the owner, and `add_to_claim` adds without replacing.
  `set_mailboxes` is the owner `""`, which also holds the mailboxes the session started with.
  Owners are internal callers: the session holds at most the lower of 256 and the relay's
  `mailboxes_per_socket` across all claims. `release_claim(owner)` empties a claim without
  waiting for the session to apply it. `mailbox_cap`, `claimed_keys(owner)` and
  `room_for(owner)` tell a host that spreads mailboxes over several sessions where they fit.

With feature `mock-relay`, `mock_mux::MuxMockRelay` is an in-process mux/1 relay with knobs to
refuse the extension, send a bad challenge, stall pushes, rate limit attaches, drop sockets,
restart (forget tokens) and send `Detached`. `MockRelay::offer_mux(true)` makes the plain mock
serve mux/1 as well, over the same store as its 3.0.0 frames; it never issues resume tokens.

`sessions::PushedSessions` holds the sessions of one Epicbox transport. A
session is named by the relay and a group the host picks. Two owners that name the same group
on the same relay share its sockets, each with its own claim on the mailboxes, and a socket
lives until its last owner lets go. A session that holds more mailboxes than the relay allows on
one socket opens more: `place` spreads an owner's mailboxes over them and keeps each mailbox on
the socket it is attached on, so adding or removing one moves no other. The extra sockets add
capacity, not privacy. The owners are the enum `Owner`: `Owner::Contacts` (the contacts
collect, set up with `set_contacts(PushedConfig)`) and `Owner::Payments` (`listen_via`). Their
claims on a `MuxSession` are named by `Owner::as_str`, `contacts` and `payments`.
`health()` keeps one `MailboxHealth` per relay its sockets greeted: whether it offered push,
when a socket last attached, the sockets lost since and the last error. The record is never a
final verdict: a relay that answered without mux/1, or that is at its connection limit, is asked
again after 1 minute, doubling to 1 hour (`ask_again_at`), and a relay that fails stays in use.
`supports_push(relay)` reads the push answer of that record, without a connection, and `None`
before any. `watch` raises `SessionEvent::NoneReachable` once when no relay with a socket can be
reached and `SessionEvent::MailboxBack` when one attaches again. `infos` lists
the sessions with their state and counters, `watch` reports `SessionEvent`s, `release(owner)` lets
an owner go and `clear` drops them all.
The payments listener in `lepic-methods` and the contacts collect in `lepic-wallet-contacts`
are its owners.

### Connections and tunnels

`RelayEndpoint` names the relay: host, port and `Security` (`Tls`, or `Plain` for a local
relay, on port `DEFAULT_PLAIN_PORT` 80 when none is named). A `Connector` opens the byte
stream: `TcpConnector` uses TCP with rustls, and refuses a plain endpoint that is not loopback.
`UntrustedHosts` wraps a connector for relays that untrusted input named.

`tunnel::TunnelConnector` reaches relays through a `Tunnel`, such as tor, while it is active
(ADR 0021). It dials the relay's onion when one is known from `OnionRoutes` or from the relay's
`/.well-known/epicbox.json` document, and the relay's domain through the tunnel otherwise. TLS
and the websocket URL keep the relay's domain, so the onion must show that domain's
certificate.

## Public API

| Item | Purpose |
|---|---|
| `EpicboxAddress`, `Domain`, `Network`, `AddressError` | Addresses |
| `EncryptedMessage`, `SignedMessage`, `ReceivedMessage`, `MessageKey`, `Salt`, `Nonce`, `Destination` | One message |
| `sign_text`, `verify_text`, `sign_listing_message`, `listing_message_verifies`, `ServiceDomain` | Signatures |
| `ClientFrame`, `RelayFrame`, `SlateFrame`, `RelayMessageId`, `RelayErrorKind`, `WalletMode` | Frames |
| `EpicboxTxId`, `InvalidEpicboxTxId`, `EPICBOX_TXID_LEN`, `CANCEL_PROTOCOL_VERSION`, `PostReceipt`, `CancelOutcome`, `CancelReport` | Cancel protocol (3.1.0) |
| `EpicboxClient`, `Identity`, `ClientSettings`, `ClientTimings`, `Backoff`, `ListenOptions`, `ClientError` | The client |
| `Subscription`, `DrainConnection`, `Mode`, `ConnectionState`, `Rejection`, `RejectionReason`, `InboxCounters`, `Disconnect` | Listening and draining |
| `Prefilter`, `Admission` | Dropping unknown senders before opening |
| `MailboxClient`, `MailboxHandler`, `MailboxMessage`, `MailboxContent`, `Handled`, `DrainLimits`, `DrainReport` | Other mailboxes |
| `MuxSession`, `MuxOptions`, `MuxState`, `MuxEvent`, `MuxCounters`, `MuxError`, `MuxCode`, `MuxLimits`, `Claimed`, `MuxCancelOutcome`, `TXCANCEL_EXTENSION` | The optional mux/1 session (`start`, `start_queued`, `take`, `settle`, `set_mailboxes`) |
| `sessions` module: `PushedSessions`, `PushedConfig`, `Placement`, `SessionInfo`, `SessionEvent`, `Owner` | The shared mux/1 sessions |
| `RelayEndpoint`, `Security`, `Connector`, `TcpConnector`, `UntrustedHosts`, `RelayStream` | Connections |
| `tunnel` module: `Tunnel`, `TunnelConnector`, `OnionRoutes`, `OnionRoute`, `parse_discovery` | Relays through tor |
| `TRANSPORT_ID` | `"epicbox"` |

## Related

- [Epicbox](../../docs/protocols/epicbox.md), [Tor](../../docs/protocols/tor.md),
  [pairing](../../docs/protocols/pairing.md)
- [Epicbox compatibility](../../docs/compat/epicbox.md)
- [RFC 0002 contact pairing](../../docs/rfcs/0002-contact-pairing.md)
- ADRs: [0004 Epicbox client](../../docs/adr/0004-epicbox-client.md),
  [0006 TLS and HTTP](../../docs/adr/0006-tls-and-http.md),
  [0021 Epicbox over Tor](../../docs/adr/0021-epicbox-over-tor.md),
  [0033 key and domain registry](../../docs/adr/0033-key-and-domain-registry.md)
- [`lepic-methods`](../lepic-methods/README.md), [`lepic-wallet`](../lepic-wallet/README.md),
  [`lepic-wallet-contacts`](../lepic-wallet-contacts/README.md)
