# Epicbox

Epicbox is a relay that holds encrypted messages for an address until its owner connects. A
LEPIC wallet uses it for payments to its payments address, for listing addresses, and for the
pairing and contact mailboxes of [pairing](pairing.md). This guide covers the address, the
message encryption, the websocket frames, listening and draining, notices, and the rules for a
message the wallet cannot take yet. LEPIC speaks the protocol of `epic-wallet` `v4.0.2` and
relay protocol `3.0.0`. The behaviour of other clients and relays is in the
[Epicbox compatibility notes](../compat/epicbox.md). Contact and pairing mailboxes are specified
in [RFC 0002 §8](../rfcs/0002-contact-pairing.md#8-mailboxes-and-the-home-relay), and native
slates at the payments address in
[RFC 0003 §11](../rfcs/0003-epictx-native-slates.md#11-native-slates-over-epicbox).

| Crate | Holds |
|---|---|
| [`lepic-epicbox`](../../crates/lepic-epicbox/README.md) | Addresses, message crypto, frames, the relay client, one-off mailbox drains, tunnels |
| `lepic-methods` (`epicbox`) | The Epicbox method: format policy, notice lengths, listing addresses |
| `lepic-wallet` | The inbox: what each message does, notices, holds |
| `lepic-wallet-contacts` | Pairing and contact mailboxes, quarantine |

## Addresses

```text
[epicbox://]<key>@<domain>[:<port>]
key = base58(version (2) || compressed secp256k1 key (33) || checksum (4))   52 characters
checksum = SHA-256(SHA-256(version || key))[0..4]
```

| Network | Version bytes |
|---|---|
| Mainnet | `01 00` |
| Floonet | `01 88` |

The wallet's payments address uses the address key at index 0 of account 0, as `epic-wallet`
does. A port that is not 443 must be written: `DEFAULT_PORT` is 443, and `Display` leaves it out
only then.

```rust
use lepic_epicbox::{EpicboxAddress, Network};

let address = EpicboxAddress::parse(text, Network::Mainnet)?;
println!("{address}"); // key@domain, with :port only when it is not 443
```

`EpicboxAddress::parse` needs the `@domain` part: LEPIC holds no default relay.
`parse_with_default` takes a domain for an address without one, and `parse_key` reads only the
key. Each fails with an `AddressError`:

| Variant | Message |
|---|---|
| `TooLong` | address has N bytes, the limit is 512 |
| `KeyLength` | address key has N characters, expected 52 |
| `NotBase58` | address key is not base58 |
| `Checksum` | address checksum does not match |
| `WrongNetwork` | address is not a Mainnet address |
| `InvalidPublicKey` | address key is not a valid public key |
| `InvalidDomain` | address domain is empty, too long or has characters outside `[a-zA-Z0-9.]` |
| `InvalidPort` | address port is not a number from 0 to 65535 |
| `MissingDomain` | address names no domain and no default domain was given |

A domain holds letters, digits and dots only, at most 253 bytes (`MAX_DOMAIN_LEN`). The checksum
is checked before the version bytes.

## Messages

A message travels as the `str` of a frame: JSON with the destination, and a ChaCha20-Poly1305
ciphertext under a key both sides derive.

```text
shared  = X coordinate of ECDH(peer key, own secret)
key     = PBKDF2-HMAC-SHA512(shared, salt, 100 rounds)[0..32]
str     = {"destination":{"public_key":…,"domain":…,"port":…},
           "encrypted_message":"<hex ciphertext || tag>","salt":"<hex 8>","nonce":"<hex 12>"}
signature = ECDSA(SHA-256(str)) by the sender's address key, DER, hex
```

A fresh salt and nonce are drawn for every message. Only the destination key is checked on
receipt. The domain and port are carried as the sender wrote them.

```rust
use lepic_epicbox::{ReceivedMessage, SignedMessage};

let message = SignedMessage::seal(plaintext, &to, &own_secret, salt, nonce)?;
let received = ReceivedMessage::open(from, str, signature_hex, &own, &own_secret)?;
```

`ReceivedMessage::open` verifies the signature over `str` as received before it parses
anything. A `str` over `MAX_MESSAGE_LEN`, 4 MiB, is refused.

| Constant | Value |
|---|---|
| `SALT_LEN` | 8 |
| `NONCE_LEN` | 12 |
| `TAG_LEN` | 16 |
| `KEY_LEN` | 32 |
| `MAX_MESSAGE_LEN` | 4 MiB |

A message that cannot be opened gets a `RejectionReason`. Each is permanent, since the same bytes
never open:

| Reason | When |
|---|---|
| `InvalidSender` | `from` is not an address on the wallet's network |
| `InvalidSignature` | The signature over `str` does not verify |
| `NotAddressedToUs` | Encrypted for another key |
| `Undecryptable` | Does not decrypt, or the plaintext is not text |
| `Malformed` | `str` is not the expected JSON |

## Frames

Frames are JSON objects over a websocket, `wss://domain:port`. Plain `ws://` is allowed only to
`localhost` or an IPv4 loopback address (`EndpointError::PlainToRemoteHost`).

| From | `type` | Fields |
|---|---|---|
| Wallet | `ClientDetails` | `wallet_version`, `wallet_mode` (`listener` or `send`), `protocol_version` |
| Wallet | `Subscribe` | `address` (key), `ver`, `signature` over the latest challenge |
| Wallet | `PostSlate` | `from`, `to`, `str`, `signature` |
| Wallet | `Made` | `address`, `signature` over `epicboxmsgid`, `ver`, `epicboxmsgid` |
| Wallet | `Unsubscribe` | `address` |
| Wallet | `GetVersion` | none |
| Relay | `Challenge` | `str` |
| Relay | `Slate` | `from`, `str`, `signature`, `challenge`, `epicboxmsgid`, `ver` |
| Relay | `Ok`, `Error` | `Error`: `kind`, `description` |
| Relay | `GetVersion` | `str` |

`wallet_version` is `4.1.0` (`RELAY_WALLET_VERSION`), what `epic-wallet` sends.
`protocol_version` and `ver` are `3.0.0` (`PROTOCOL_VERSION`). Text that is not a JSON object,
such as `pong`, is a keepalive. A relay frame of an unknown type is ignored.

The address key signs the SHA-256 of each challenge. A challenge must be 1 to 64 characters of
`[A-Za-z0-9_-]` and must not look like a transaction id (32 hex digits or a UUID). Otherwise the
client refuses it with `FrameError::Challenge` and signs nothing.

| Constant | Value |
|---|---|
| `PROTOCOL_VERSION` | `3.0.0` |
| `MAX_FRAME_LEN` | `MAX_MESSAGE_LEN` + 64 KiB |
| `MAX_CHALLENGE_LEN` | 64 |
| `MAX_RELAY_MESSAGE_ID_LEN` | 64 |
| `RELAY_RETENTION` | 7 days; a relay message id older than this cannot come back |

`RelayErrorKind` is one of `UnknownError`, `InvalidRequest`, `InvalidSignature`,
`InvalidChallenge`, `TooManySubscriptions`, or `Other` with the text cut to 64 characters.

## Sending

`EpicboxClient::post(to, plaintext)` seals the message, posts it on a short connection of its
own and waits for the relay's answer. Sending again is safe, since receivers deduplicate.

The method's `EpicboxPolicy` decides the slate format:

- it reads V3, then V2, by shape;
- a new slate goes out as V2 JSON with the LEPIC marker;
- a reply goes out in the shape it answers.

A first slate to a peer whose marker claimed native slates is sealed instead, as in
[EPICTX](epictx.md#native-slates-over-epicbox).

## Listening and draining

The relay serves a connection as the address it last subscribed with, so each address runs its
own client and connection.

| Call | `Mode` | Greets as | Does |
|---|---|---|---|
| `EpicboxClient::listen` | `Listen` | `listener` | Holds the connection, pings, reconnects with backoff until stopped |
| `EpicboxClient::drain` | `Drain` | `send` | Connects once, takes every waiting message, disconnects |
| `MailboxClient::drain_once` | — | `send` | Subscribes as each mailbox in turn on one connection |

A drain never becomes a live listener, so it never takes live delivery from a listener elsewhere.
Stored messages reach both. `Subscription::state` reports a `ConnectionState`: `Connecting`,
`Subscribed`, `Waiting`, `Stopped`, `Drained` or `Failed`.

Reconnects back off from `Backoff::initial` and double up to `Backoff::max`. Each wait falls at
a random point between half the ceiling and the ceiling.

### Acknowledge after store

The relay sends one message at a time. Each waits until the wallet sends `Made` for it, and
everything behind it waits too.

1. The subscription checks and decrypts the message. It hands it out with
   `Inbound::next_envelope`, or as a `Rejection` with `next_rejection`.
2. The wallet's inbox routes it by stage. An S1 is received and answered with an S2 through the
   same method. An S2 is finalized and posted.
3. The inbox acknowledges once the effect is stored, or once a rejection is recorded. A
   transient failure leaves it unacknowledged, and the relay delivers it again.

Every message is idempotent on its relay message id and on `(slate_id, stage)`. A redelivered S1
is answered with the S2 stored the first time. Up to 4,096 acknowledged ids are remembered per
subscription, so a redelivery after a lost `Made` is acknowledged again.

A subscription holds at most 64 messages or 16 MiB ready to hand out. Past that, the relay gets
no acknowledgement and keeps the message.

### Mailbox drains

`MailboxClient::drain_once` reads mailboxes that are not the wallet's own address
([RFC 0002 §8.2](../rfcs/0002-contact-pairing.md#82-one-off-drains)). A
`MailboxHandler` answers each message:

- `Handled::Stored` acknowledges it;
- `Handled::Later` leaves it on the relay, and the drain moves on.

| Constant | Value |
|---|---|
| `MAX_MESSAGES_PER_MAILBOX` | 32 |
| `MAX_MAILBOXES_PER_DRAIN` | 50 |

Each mailbox ends with a `MailboxEnd`: `Empty`, `Capped`, `Kept` or `Refused`.

### Prefilter

An address that takes only known senders sets a `Prefilter` with
`EpicboxClient::with_prefilter`. It sees the claimed sender key before any signature check or
decryption, and answers `Admission::Accept` or `Admission::Drop`. A dropped message is
acknowledged and counted, and is not reported as a rejection.

## Notices

A notice is a short advisory message between LEPIC wallets about an invoice or a payment, sent
over the method that carried it (ADR 0016):

```json
{"lepic":1,"type":"posted","slate_id":"0436430c-2b02-624c-2032-570501212b00","excess":"09…"}
```

| `type` | From → to | Effect |
|---|---|---|
| `declined` | Payer → invoice issuer; a receiver that refuses unasked payments → sender; an epic1 payee → payer, reason `amount` | Reports the invoice declined; cancels a send the receiver never answered, or an epic1 payment of the wrong amount |
| `withdrawn` | Invoice issuer → payer | The issuer cancelled the invoice or let it expire |
| `posted` | Issuer of a paid invoice → payer; sender → receiver | The transaction was posted; carries the kernel `excess` |
| `cancelled` | Sender → receiver | The sender cancelled a payment the receiver had answered |

Rules:

- A notice is at most `MAX_NOTICE_LEN`, 8 KiB, and `NOTICE_VERSION` is 1.
- It is accepted only from the recorded counterparty of its slate. It never moves funds.
- Over Epicbox, a `pad` key of zeros pads it to one of `NOTICE_LENGTHS`, the lengths of the
  wallet's first slate with one, two or three inputs. A wallet that takes native slates uses
  `NATIVE_NOTICE_LENGTHS`.
- A wallet that removes a pairing seals `{"lepic":1,"type":"unpaired"}` to the contact
  ([pairing](pairing.md)). It names no slate.
- A plain notice goes to a payments address only when the exchange came marked from that key,
  and that key sent a marked message within `NOTICE_WINDOW`, 30 days.

A host can keep `declined`, `withdrawn` and `cancelled` notices that arrive before their slate,
by setting both `early_notice_max_count` (at most 10,000) and `early_notice_max_age` (at most
30 days). They are applied when the slate arrives.

## Messages that cannot be taken yet

A held message holds back everything behind it, so every hold is bounded.

**Payments address.** Some messages are held:

- a reply the method could not deliver;
- a slate that only the node's tip says has expired.

Each is held for at most 3 tries in one listen (`MAX_HOLD_ATTEMPTS`), and for 3 minutes for
drains (`HOLD_PATIENCE`). At the bound:

- an undelivered reply leaves the payment received and raises `ReplyUndelivered`;
- a slate still expired is refused.

An S2 or I2 for a slate the store does not know may belong to another install on the same
recovery phrase. It is held for `TWIN_HOLD`, 90 seconds, then posted back to the address as
its sender signed it (`Subscription::requeue`), so the other install can collect it. An answer
first seen 24 hours ago or more (`TWIN_REQUEUE_WINDOW`) is refused, and so is a new one while 4
others cycle (`MAX_TWIN_ANSWERS`).

**Contact mailboxes** (ADR 0049). A message whose taking fails for a lasting reason is kept for
the next collect. A failure that passes (node, relay or store not answering, wallet locked) does
not count.

| `WalletPolicy` field | Default | Bound |
|---|---|---|
| `contact_hold_attempts` | 3 | 10 |
| `contact_hold_patience` | 3 minutes | 24 hours |
| `quarantine_max_bytes` | `None` | 64 MiB |
| `listener_held_rounds` | `None` | 64 |

With `quarantine_max_bytes` set, a message past the bound goes to a local quarantine instead of
being dropped, and its hold count is kept for 14 days. When the quarantine is full, the
contact's own oldest entry goes first, then the wallet's oldest.

`listener_held_rounds` moves a listener to a fresh socket after that many rounds that began with
a message held. The held message is taken up again there.

## Over Tor

A `Tunnel`, such as the wallet's tor, carries the byte stream to the relay. The TLS server name
and the websocket URL stay the relay's domain, so the relay must still show that domain's
certificate. While the tunnel is active, no relay connection is made directly.

The relay is reached:

- at an onion from the host's `OnionRoutes`;
- else at the onion named in the relay's `/.well-known/epicbox.json` (at most 4,096 bytes);
- else by its domain through the Tor network.

[Tor](tor.md) covers the tor process.

## From the CLI

```bash
lepic wallet address
lepic tx send 1.5 --to <address>
lepic epicbox drain
lepic epicbox listen
lepic epicbox status
```

[docs/cli.md](../cli.md#epicbox) has every option, and
[Epicbox over Tor](../cli.md#epicbox-over-tor) the Tor settings. Relay host names in examples
here are placeholders, such as `relay.example`.
