# Epicbox protocol

LEPIC speaks Epicbox protocol 3.0.0, the version the public relay speaks (`PROTOCOL_VERSION` in
`crates/lepic-epicbox/src/frame.rs`), and the 3.1.0 cancel protocol (`CANCEL_PROTOCOL_VERSION`)
against a relay that reports 3.1.0 or a later 3.x; see [Cancel (3.1.0)](#cancel-310). The format is read from `epic-wallet` v4.1.0
(`impls/src/adapters/epicbox.rs`, `impls/src/epicbox/protocol.rs`,
`libwallet/src/{message,crypto,epicbox_address,address,base58,tx_proof}.rs`) and from the relay
source `EpicCash/epic-epicbox-docker` (`app_mongo.js`, `epicboxlib_source/`) at the commit in
`interop/pins.env`. The client is `lepic-epicbox`.

## Connection

- URL: `wss://<domain>:<port>`, default port 443. With the plain flag, `ws://<domain>:<port>`,
  default port 80. The port is always written out. `RelayEndpoint::check_security` allows `ws://`
  only to a loopback host (`localhost` or a `127.x` address).
- A reverse proxy in front of a relay may close an idle connection. The client sends websocket
  ping frames to keep it open.
- Protocol messages are JSON text frames tagged by `"type"`. The relay answers the JSON
  `{"type":"ping"}` with the bare text `pong`, which is not JSON, so the client never sends the
  JSON ping.
- A frame is at most `MAX_FRAME_LEN`: 4 MiB (`MAX_MESSAGE_LEN`) plus 64 KiB. A longer frame is
  refused before it is parsed.

## Messages, client to relay

| Type | Fields |
|---|---|
| `ClientDetails` | `wallet_version` (`"4.1.0"`, what `epic-wallet` v4.1.0 sends), `wallet_mode` (`"listener"` or `"send"`), `protocol_version` (`"3.0.0"`) |
| `Subscribe` | `address` (base58 key only, no domain), `ver` (`"3.0.0"`), `signature` (over the current challenge) |
| `PostSlate` | `from` and `to` (`key@domain[:port]`), `str` (the encrypted message as a JSON string), `signature` (over `str`); 3.1.0: optional `epicboxtxid` and `epicboxtxidsig`, both or neither |
| `CancelTx` | 3.1.0: `address` (key), `epicboxtxid`, `signature` (over the txid) |
| `Made` | `address`, `signature` (over `epicboxmsgid`), `ver`, `epicboxmsgid` |
| `Unsubscribe` | `address` |
| `GetVersion` | none |

## Messages, relay to client

| Type | Fields |
|---|---|
| `Challenge` | `str` |
| `Ok` | none; it answers several requests, so it is not tied to one. 3.1.0: an answer to `PostSlate` may carry `epicboxtxid` and `epicboxmsgid` |
| `TransactionCancelled` | 3.1.0: `epicboxtxid` |
| `Error` | `kind` (`InvalidSignature`, `InvalidRequest`, `UnknownError`, `InvalidChallenge`, `TooManySubscriptions`, `Busy`; any other text is kept as an unknown kind), `description` |
| `Slate` | `from`, `str`, `signature`, `challenge` (always present, empty for a live push), and when the subscription carried `ver`: `epicboxmsgid`, `ver`; 3.1.0: `epicboxtxid` when the sender gave one |
| `GetVersion` | `str`, the relay's protocol version |

`Busy` is what an overloaded relay answers (epic-epicbox-docker PR 11 sends it, with no
description). A wait is never named. LEPIC takes it as passing on every request: a `PostSlate`
answered `Busy` is retried by the outbox on its back-off and never ends the payment; a
`Subscribe` answered `Busy` ends the session and listen mode reconnects with back-off; a `Made`
answered `Busy` leaves the message on the relay, which delivers it again.

The client ignores frame types it does not know. An unknown key inside a known frame is skipped.

A challenge is signed only if it is 1 to 64 characters of letters, digits, `-` and `_` and is not
a transaction id (32 lowercase hex digits or a UUID), because the address key signs other texts
too. A relay message id (`epicboxmsgid`) has the same character set and length limit.

## Session

1. The relay sends `Challenge` on connect.
2. The client sends `ClientDetails`, then `Subscribe` signed over the challenge just received. A
   client that wants live messages greets as `listener` before it subscribes, or the relay does not
   push live messages to the socket.
3. The relay verifies and sends the oldest pending `Slate` for the address, or `Ok`.
4. After handling a slate, the client re-subscribes with the latest challenge and sends `Made`
   for the message id. The relay answers `Ok` and later sends a new `Challenge`.

Always sign the most recent challenge received. Pending messages stay on the relay until `Made`,
and a socket that subscribes while one is in flight can receive it again. The relay keeps the
first listening socket per address and forgets it when any of that address's sockets closes. A
client closes its old socket before it reconnects. Live messages missed in between arrive on the
next subscribe.

## Cancel (3.1.0)

A relay of 3.1.0 or later 3.x lets the two parties of a transaction cancel it. The client reads the
relay's version from `GetVersion` and takes the cancel protocol only when it is 3.1.0 or later in
major 3. Every other answer, or none, leaves the exact 3.0.0 behaviour: `Subscribe` and `Made` carry
`ver` `3.0.0`, `PostSlate` carries no txid fields, and `EpicboxClient::cancel` returns
`CancelOutcome::Unsupported` after the greeting, with no `Subscribe` or `CancelTx` sent.

- **Transaction id.** A UUIDv4 in simple form (32 lowercase hex digits), made by the sender
  (`EpicboxTxId::generate`). It is not the slate id. The client accepts upper case and writes lower
  case. Persist it before posting; posting again with the same id is safe.
- **Signature.** ECDSA over SHA-256 of the 32 characters, DER hex, as for every other signed text:
  `epicboxtxidsig` with the `from` key, and the `CancelTx` signature with the key of `address`.
  `CancelTx` is signed after `Subscribe` on the same socket, which one relay needs to know the key.
- **Signature form.** A client may sign `epicbox-cancel/1:<txid>` instead of the bare id
  ([ADR 0061](../adr/0061-cancel-domain-separation.md)), so that a copy of `epicboxtxidsig` is not
  a cancel. The short cancel connection offers `"ext":["epicbox-cancel/1"]` in `ClientDetails`;
  a relay that accepts the form answers `{"type":"Ok","ext":["epicbox-cancel/1"]}`. The client
  signs the prefixed text only after that echo and the bare id otherwise. Relays list the feature
  in `/.well-known/epicbox.json` as well; the client does not read it.
- **Posting.** `EpicboxClient::post_tx` sends `epicboxtxid` and `epicboxtxidsig` on 3.1.0 and the
  plain `PostSlate` otherwise; `PostReceipt::txid_sent` says which. The `Ok` may carry the txid and
  the relay message id. A post for a transaction the relay holds as cancelled is answered with
  `TransactionCancelled` instead of `Ok`; it fails with `ClientError::TransactionCancelled`.
- **Receiving.** A `Slate` from a 3.1.0 subscription may carry `epicboxtxid`. The client keeps it
  when it is well formed and drops only the field when it is not, where the reference drops the
  slate. `Subscription::epicbox_txid(token)` returns it. `requeue` posts the copy exactly as
  signed, and a copy carries no txid: it cannot be signed again, because the signature of
  `epicboxtxidsig` is by the sender. The copy cannot be cancelled through the relay.
- **Cancelling.** `EpicboxClient::cancel(txid)` opens a short connection: greeting, `Subscribe`
  (3.1.0, send mode), `CancelTx`, then it waits for the answer. `TransactionCancelled` for the txid
  is `CancelOutcome::Cancelled`. A plain `Ok` is `CancelOutcome::NotFoundOrNotParticipant`: the relay
  does not say whether the transaction is unknown or this address is not a party. An `Error` is
  `ClientError::Relay`. A `TransactionCancelled` for another txid is returned in
  `CancelReport::other_cancelled`. `Slate` frames on this connection are ignored: no `Made`, no
  post, nothing surfaced. They stay on the relay for a listener, so a queued reply is not
  finalized and posted by a wallet that is cancelling.
- **Being told.** `TransactionCancelled` can arrive on any 3.1.0 connection that subscribed with
  `ver` 3.1.0. A listener or drain opts in with `ListenOptions::cancel`; each one is read with
  `Subscription::next_cancelled`.
- **Acknowledging.** The relay takes the next successful `Subscribe` on a 3.1.0 socket as the
  acknowledgement and delivers nothing else on that socket until then. The consumer applies the
  cancellation first (idempotently), then calls `Subscription::ack_cancelled`, which sends that
  `Subscribe`. A cancellation that is not acknowledged is delivered again on the next connection.
  The short cancel connection never acknowledges: its `Subscribe` is the first on the socket, and
  it sends none afterwards. The first `Subscribe` of a new socket acknowledges nothing.
- **`cancelrequestid`.** It passes between relays only. The client never sends it and ignores it
  when it reads one.
- **Mux.** `txcancel/1`, see [mux/1](../protocols/epicbox-mux.md). `MailboxClient` stays on 3.0.0.
  A wallet with an attached mux session that negotiated `txcancel/1` cancels over it; the short
  connection above is the fallback for relays and wallets without one.

## Addresses

- Text form: `[epicbox://]<52 base58 chars>[@<domain>[:<port>]]`. The domain is 1 to 253
  characters of `[a-zA-Z0-9.]`. An address is at most 512 bytes. The relay checks `from` and `to`
  of a `PostSlate` against this rule (`epicboxlib verifyaddress`) and refuses a post that fails
  it, so a relay on a domain with a hyphen cannot carry a message. The default domain applies when
  `@` is absent. The port is printed only when it is not 443.
- Payload: 2 version bytes followed by the 33-byte compressed secp256k1 public key, base58check
  with the Bitcoin alphabet and a 4-byte double-SHA256 checksum.
- Version bytes: mainnet `0x01 0x00`, floonet `0x01 0x88`.
- Key: take the account parent path (default `m/0/0`), set the second component to 1, append the
  address index (`m/0/1/<index>`), derive the raw BIP32 secret key without a switch commitment,
  then hash it with unkeyed BLAKE2b-256. The result is the address secret key
  (`Keychain::address_key`). `epic-wallet` always uses index 0.

## Message encryption

Byte-compatible with `EncryptedMessage` in `libwallet/src/message.rs` and the relay's copy
(`lepic-epicbox/src/crypto.rs`):

1. Shared point: the receiver's public key times the sender's secret key, compressed to 33 bytes.
   The shared secret is bytes 1 to 32, the X coordinate.
2. Key: PBKDF2-HMAC-SHA512 with the shared secret as password, 8 random bytes as salt, 100
   iterations and a 32-byte output.
3. Ciphertext: ChaCha20-Poly1305 (IETF, 12-byte random nonce, empty associated data), the
   ciphertext followed by the 16-byte tag.
4. `str` is the JSON
   `{"destination":{"public_key":"<base58>","domain":"<domain>","port":<u16 or null>},"encrypted_message":"<hex>","salt":"<16 hex>","nonce":"<24 hex>"}`.
   An explicit port 443 stays in `destination.port` although the text form omits it (vector
   `message_v3_slate_mainnet_explicit_port_443`). `str` is at most 4 MiB.
5. The plaintext is the slate JSON in a legacy version ([legacy-slates.md](legacy-slates.md)).

## Signatures

ECDSA over secp256k1 of the SHA-256 of the UTF-8 text, DER-encoded, hex. `Subscribe` signs the
challenge, `PostSlate` signs `str` exactly as sent, `Made` signs the message id. A receiver
verifies against the `str` bytes as received and never re-serializes before verifying.

LEPIC subscribes the wallet's address key at its own relay only. A contact, pairing or epic1
mailbox has a key of its own and is read on each usable relay of the relay list.

## Receiving a slate

1. Parse `from`, checking the network version bytes.
2. Verify the signature over `str` with the sender's key.
3. Require `destination.public_key` to equal the wallet's own key.
4. Derive the shared secret with the sender's key, decrypt and decode the slate.

The sender's key in `from` is the identity. LEPIC does not use the `@domain:port` of `from` or the destination's domain to decide anything: it posts every reply through its own relay and keys contacts, notices and invoices on the public key alone.

## Relay behaviour LEPIC relies on

These facts of the relay at the pinned commit shape LEPIC's outbox schedule, its notice rules and
its contact mailboxes. They are read from the relay source (`app_mongo.js`, `subscribe` and
`made`). `interop/acceptance/run.sh --probes` checks a part of them against a running stack
(`interop/acceptance/probes.sh`, with the client in `interop/probe`).

- The relay keeps a message for 7 days (MongoDB TTL index `expireAfterSeconds: 604800`), the value
  of `RELAY_RETENTION`. The 24-hour `expiration` field it also writes is not enforced.
- A live push carries the newly posted message. A fresh subscription gets the oldest pending one.
- Messages queue per address key, not per socket. Every socket that subscribes for the address,
  including another install on the same recovery phrase, is handed the oldest message not yet
  acknowledged, and `Made` from any of them marks it handled for all.
- A client acknowledges a message as soon as its effect is stored.
- `PostSlate` checks that `signature` verifies over `str` for the key in `from` and that both
  addresses parse. The queue is the key in `str.destination`.
- A socket serves the address it subscribed with last. A second `Subscribe` on the same socket
  switches the socket to the second address, and `Made` is then checked against the second key.
  An address that needs its own live connection runs on its own socket.
- A socket greeted as `send` may subscribe as one address, take and acknowledge every pending
  message, subscribe as the next address with the latest challenge and drain that one. Such a
  socket is never an address's live listener. The "message in flight" flag belongs to the socket,
  so a message left unacknowledged on it stops it serving the next address. A mailbox drain greets
  as `send`, acknowledges each message before it subscribes again, and moves to a new socket after
  leaving a message unacknowledged.
- A stock `epic-wallet` listener acknowledges payloads that parse as a V3 or V2 slate
  (`TxProof::from_response`). LEPIC sends a payload that is not a slate only to a key shown to
  run LEPIC. A stock listener writes its reply from its own `Slate` type, which carries only the
  keys it defines.

## What the client does regardless of the relay

- Deduplicates on the relay message id and on `(slate_id, stage)`; deliveries can repeat. The
  client remembers a bounded number of acknowledged ids per subscription.
- Does not rely on ordering across transactions.
- Ignores message types it does not know, and non-JSON keepalive text.
- Redoes the full session after any reconnect.

## Stock slates and LEPIC notices

A payments address carries stock slates only (ADR 0062): an S1 and the S2 that answers it, in the V2
or V3 shape, with no key a stock wallet does not write. Whatever else arrives there, such
as a notice, an invoice stage or a sealed slate, is acknowledged and dropped. A
wallet that refuses a payment sends nothing back. ADR 0016 and RFC 0002 have the contact flows.

### Notices

A notice is a JSON object `{"lepic":1,"type":<kind>,"slate_id":<uuid>}`, plus `excess` (the
kernel excess, 66 hex characters) for `posted`. It is at most 8 KiB (`MAX_NOTICE_LEN`) and moves
no funds. It travels sealed, to a contact's mailbox (below) or between the two sides of an epic1
payment (the payer's reply mailbox, the address's delivery mailbox), never to a payments
address.

| Kind | Meaning |
|---|---|
| `declined` | The payer declined an invoice, or a receiver refused an unsolicited slate. Sent to the other side. |
| `withdrawn` | The issuer cancelled an invoice or let it expire. Sent to the payer. |
| `posted` | The payer of an epic1 address, or the issuer of an invoice to a contact, pushed the transaction to a node. |
| `cancelled` | The sender cancelled an ordinary payment the receiver had answered. |
| `unpaired` | A contact ended the pairing. |
| `pair-finished`, `pair-match`, `pair-mismatch` | A contact finished pairing, or its SAS check matched or did not (with `sas`, no `slate_id`). |

- A notice is accepted only from the recorded counterparty of its slate. For `posted`, the excess
  must match the one the payment implies. Another version, an unknown type, and a notice over
  8 KiB are acknowledged and dropped.
- Every notice to a contact is padded with a last `pad` key of zeros to one of three lengths
  drawn at random: those of a first slate with one, two and three inputs (2,423, 2,522 and
  2,621 bytes), so its size does not tell it from a payment. Readers ignore the key. An epic1
  notice goes unpadded into its sealed envelope, which pads it.

### Contact mailboxes

- Each side of a pairing reads a mailbox of its own, `box_pk@<relay>`, with a key derived from
  the seed, the pairing's slot and a random salt, on each usable relay of its relay list and on
  the relay its card names. It is read by push on the contacts' sessions
  ([mux/1](../protocols/epicbox-mux.md)), and a message is acknowledged only after its effect is
  stored. A message to a mailbox is posted from the sender's own mailbox key.
- The plaintext is the armored sealed envelope (`BEGINEPICSEALED.`). A plain payload, an
  anonymous envelope, or one signed by any key but the contact's is acknowledged and dropped.
- An outbox entry is posted at once and retried after 30 s, 2 min, 10 min, then every 30 min. An
  entry undelivered after 24 hours is reported as stuck (`lepic-wallet-contacts/src/outbox.rs`).
- A contact update whose card names another relay is stored and the mailbox in use stays. The
  event `Event::ContactRelayMoveRequested` tells the host, which may apply the move with
  `ContactBook::apply_relay_move`. The old mailbox is then drained for 7 days and queued entries
  follow the new address.
