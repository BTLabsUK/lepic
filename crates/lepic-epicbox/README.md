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
| `mock-relay` | off | `mock_relay::MockRelay`, a relay with the public relay's behaviour, and `testing`, the settings the app ships |

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

The client speaks `PROTOCOL_VERSION` `"3.0.0"` of the relay protocol over a websocket.

| `ClientFrame` | Purpose |
|---|---|
| `ClientDetails` | Says the wallet mode (`WalletMode::Listener` or `Send`) and the version `4.1.0` |
| `Subscribe` | Signs the relay's latest challenge, to receive an address's messages |
| `PostSlate` | Posts a signed message to an address |
| `Made` | Acknowledges a message, so the relay deletes it |
| `Unsubscribe`, `GetVersion` | Leave an address; ask the relay's version |

| `RelayFrame` | Meaning |
|---|---|
| `Challenge` | A short random token to sign |
| `Ok`, `Error` | The answer to the last request; `RelayErrorKind` names the error |
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
- `drain()` connects once, takes every stored message and ends. It never takes live delivery
  from a listener elsewhere.
- `with_prefilter` asks a `Prefilter` about each message's claimed sender before opening it;
  `Admission::Drop` acknowledges the message and forgets it.

Both `listen` and `drain` return a `Subscription`. The relay sends one message at a time and
holds back the rest until that one is acknowledged, so a consumer takes each envelope or
`Rejection`, records it, then acknowledges its token. `Subscription` also gives the
`ConnectionState` (`Connecting`, `Subscribed`, `Waiting`, `Stopped`, `Drained`, `Failed`) as a
`watch` channel, the last `Disconnect`, the relay's version and `InboxCounters`. `requeue`
posts a handed-out message back to the same address, for another install to collect.

Received messages wait in a bounded queue. Past its bounds the client stops acknowledging, so
the relay keeps the message for later. A relay keeps a message for `RELAY_RETENTION` (seven
days).

### Mailboxes

`MailboxClient` drains mailboxes that are not the wallet's own address, such as pairing and
contact mailboxes (RFC 0002 8.2), and posts from their keys. `drain_once` greets the relay as a
sender, so it never becomes a live listener, and subscribes as each mailbox in turn. A
`MailboxHandler` answers each message `Handled::Stored` (acknowledge it) or `Handled::Later`
(leave it and move to the next mailbox). `DrainLimits` caps one drain at
`MAX_MAILBOXES_PER_DRAIN` (50) mailboxes and `MAX_MESSAGES_PER_MAILBOX` (32) messages each; the
`DrainReport` holds one `MailboxReport` per mailbox.

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
| `EpicboxClient`, `Identity`, `ClientSettings`, `ClientTimings`, `Backoff`, `ClientError` | The client |
| `Subscription`, `Mode`, `ConnectionState`, `Rejection`, `RejectionReason`, `InboxCounters`, `Disconnect` | Listening and draining |
| `Prefilter`, `Admission` | Dropping unknown senders before opening |
| `MailboxClient`, `MailboxHandler`, `MailboxMessage`, `MailboxContent`, `Handled`, `DrainLimits`, `DrainReport` | Other mailboxes |
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
