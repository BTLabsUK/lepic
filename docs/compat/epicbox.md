# Epicbox protocol

Derived from `epic-wallet` `v4.0.2` (`impls/src/adapters/epicbox.rs`, `impls/src/epicbox/protocol.rs`,
`libwallet/src/{message,crypto,epicbox_address,address,base58,tx_proof}.rs`) and the public relay at
`EpicCash/epic-epicbox-docker` (`app_mongo.js`, `epicboxlib_source/`). This page covers protocol
3.0.0, which the public relay speaks. Later protocol versions add optional fields and message types;
the client enables them only when the relay reports support.

## Connection

- URL: `wss://<domain>:<port>` (default port 443); `ws://<domain>:<port>` when the insecure flag is set
  (default port 80). The port is always explicit. Default domain `epicbox.epiccash.com`. LEPIC
  allows `ws://` only to a loopback host.
- Relays terminate TLS in a reverse proxy with an idle timeout. Keep traffic flowing with websocket
  ping frames.
- All protocol messages are JSON text frames tagged by `"type"`. The relay also answers the JSON
  `{"type":"ping"}` with the bare text `pong`, which is not JSON.

## Messages, client to relay

| Type | Fields |
|---|---|
| `ClientDetails` | `wallet_version`, `wallet_mode` (`"listener"` or `"send"`), `protocol_version` (`"3.0.0"`) |
| `Subscribe` | `address` (base58 key only, no domain), `ver` (`"3.0.0"`), `signature` (over the current challenge) |
| `PostSlate` | `from` and `to` (`key@domain[:port]`), `str` (the encrypted message as a JSON string), `signature` (over `str`) |
| `Made` | `address`, `signature` (over `epicboxmsgid`), `ver`, `epicboxmsgid` |
| `Unsubscribe` | `address` |
| `GetVersion` | none |

## Messages, relay to client

| Type | Fields |
|---|---|
| `Challenge` | `str` |
| `Ok` | none; answers several requests, so it is not correlated to one |
| `Error` | `kind` (`InvalidSignature`, `InvalidRequest`, `UnknownError`, `InvalidChallenge`, `TooManySubscriptions`), `description`; the public relay sends only `InvalidSignature` and `InvalidRequest` |
| `Slate` | `from`, `str`, `signature`, `challenge` (always present, empty for a live push), and when the subscription carried `ver`: `epicboxmsgid`, `ver` |
| `GetVersion` | `str`, the relay's protocol version |

## Session

1. The relay sends `Challenge` on connect.
2. The client sends `ClientDetails` (mode `listener` before subscribing, or the relay will not push
   live messages to this socket), then `Subscribe` signed over the challenge just received.
3. The relay verifies and sends the oldest pending `Slate` for the address, or `Ok`.
4. After handling a slate, the client re-subscribes with the latest challenge and sends `Made` for the
   message id. The relay answers `Ok` and later sends a new `Challenge`.

Always sign the most recent challenge received. Pending messages persist on the relay until `Made`; a
socket that subscribes while one is in flight can receive it again. The relay keeps the first
listening socket per address and forgets it when any of that address's sockets closes; a client
closes its old socket before it reconnects, and live messages missed in between arrive on the next
subscribe.

## Addresses

- Text form: `[epicbox://]<52 base58 chars>[@<domain>[:<port>]]`, with the domain limited to
  `[a-zA-Z0-9.]` upstream. The default domain applies when `@` is absent. `:port` is printed only
  when it is not 443.
- Payload: 2 version bytes followed by the 33-byte compressed secp256k1 public key, base58check with
  the Bitcoin alphabet and a 4-byte double-SHA256 checksum.
- Version bytes: mainnet `0x01 0x00`, floonet `0x01 0x88`.
- Key: take the account parent path (default `m/0/0`), set the second component to 1, append the
  address index (`m/0/1/<index>`), derive the raw BIP32 secret key without switch commitment, then
  hash it with unkeyed BLAKE2b-256. The result is the address secret key. `epic-wallet` always uses
  index 0.

## Message encryption

Byte-compatible with `EncryptedMessage` in `libwallet/src/message.rs` and the relay's copy:

1. Shared point = receiver public key times sender secret key, compressed (33 bytes). The shared
   secret is bytes 1..33, the X coordinate.
2. Key = PBKDF2-HMAC-SHA512(password = shared secret, salt = 8 random bytes, 100 iterations, 32 bytes).
3. Ciphertext = ChaCha20-Poly1305 (IETF, 12-byte random nonce, empty AAD), ciphertext followed by the
   16-byte tag.
4. `str` = JSON `{"destination":{"public_key":"<base58>","domain":"<domain>","port":<u16 or null>},"encrypted_message":"<hex>","salt":"<16 hex>","nonce":"<24 hex>"}`.
   An explicit port 443 stays in `destination.port` although the text form omits it (vector
   `message_v3_slate_mainnet_explicit_port_443`).
5. Plaintext: the slate JSON in a legacy version (`docs/compat/legacy-slates.md`).

## Signatures

ECDSA over secp256k1 of SHA-256 of the UTF-8 string, DER-encoded, hex. `Subscribe` signs the
challenge, `PostSlate` signs `str` exactly as transmitted, `Made` signs the message id. Verify against
the received `str` bytes; never re-serialize before verifying.

None of the signed texts names the relay, so a signature made for one relay is valid at any
other. LEPIC therefore subscribes each key at one relay only: the wallet's address key at its
own relay, and every contact or pairing mailbox under a key of its own for that relationship.
Binding the texts to the relay's domain would need a protocol change on both sides.

## Receiving a slate

Parse `from` (network version bytes checked), verify the signature over `str` with the sender key,
require `destination.public_key` to equal our own key, derive the shared secret with the sender's key
and decrypt, then decode the slate.

Only the sender's key in `from` is authenticated: a relay may change its `@domain:port`, and the
destination's domain is not checked either. The sender's domain is advisory. LEPIC posts every
reply through its own relay, never to the relay a `from` names, and keys contacts, notices and
invoices on the public key alone.

## Relay retention

- The relay stores each message for 7 days (MongoDB TTL index `expireAfterSeconds: 604800`). The
  24-hour `expiration` field it also writes is not enforced.
- A message that is delivered but not acknowledged is redelivered; after several redelivery rounds
  the relay may drop the address's unacknowledged messages. Acknowledge promptly once the effect is
  stored, and do not hold a delivered message across many challenge intervals.
- Live pass-through delivers the newly posted message; a fresh subscription delivers the oldest
  pending one.
- Messages queue per address key, not per socket. Every socket that subscribes for the address,
  including another install on the same recovery phrase, is handed the oldest message not yet
  acknowledged, even while another socket holds it, and `Made` from any of them marks it handled
  for all. The resend and discard counters are per socket: three subscribes answered `Ok` while
  a message is in flight make a resend round, the round counter is not reset by `Made`, and
  three rounds discard every unacknowledged message of the address (`app_mongo.js` `subscribe`,
  `made`).
- `PostSlate` checks only that `signature` verifies over `str` for the key in `from` and that
  both addresses parse; the queue is the key in `str.destination`. A client may therefore post a
  message it received back to its own address unchanged, with the original sender's `from`,
  `str` and `signature`; the copy is a new message at the back of the queue.

## Robustness the client must provide

- Deduplicate on the relay message id and on `(slate_id, stage)`; deliveries can repeat.
- Do not rely on ordering across transactions.
- Ignore message types it does not know, and non-JSON keepalive text.
- Redo the full session after any reconnect.

## Invoices, markers and payloads a stock listener accepts

What invoices and notices over Epicbox build on, checked against the stock `epic-wallet` `v4.0.2`
Epicbox listener and the relay at the commit in `interop/pins.env`. `interop/acceptance/run.sh
--probes` reproduces every point: `probes.sh` drives the stack, and the probe client in
`interop/probe` posts payloads from a key of its own and drains what comes back. Each run keeps
the raw probe output under `.work/logs/<time>/probes/`.

1. An I1 is sent back unchanged. For a slate with a participant missing and no inputs,
   `process_incoming_slate` (`impls/src/adapters/epicbox.rs`) does nothing at its
   `// TODO: invoicing` branch. `on_slate` then posts the slate back to the message's `from`, in the
   version it arrived in, and acknowledges it. In the run, LEPIC's V3 I1 (header `3/3/6`) came back
   from the listener's key with the same slate id. Its key-sorted JSON matched what was sent, apart
   from the marker. The stock wallet recorded no transaction, and it answered and acknowledged the
   next message, a V3 S1. A LEPIC issuer can therefore recognise a bounce: its own slate id, stage I1,
   from the key it invoiced.
2. A marker key does not survive a stock round trip. Before replying, stock converts every
   slate into its own `Slate` and back (`on_slate`). It drops any top-level key it does not know, and
   it accepts slates that carry one. In the run, `"lepic":{"version":1}` was missing from the bounced
   I1 and from the V3 S2 that answered a marked V3 S1.
3. Stock acknowledges only slates. Stock sends `Made` only after the decrypted payload parses
   as a V3 or V2 slate (`TxProof::from_response`). A payload that does not parse stays pending, and
   the relay delivers it again when the listener next subscribes. In the run, a notice-shaped JSON
   object was delivered twice and rejected as `Unable to parse slate` both times. It was never
   acknowledged. LEPIC sends a payload that is not a slate only to a peer that has proved it runs
   LEPIC.
4. One address per socket. The relay serves a socket as the address it most recently
   subscribed with. It accepts a `Subscribe` for a second address on the same socket and switches
   that socket to it. Pending messages for the second address are delivered there, and `Made` is
   then checked against the second key. A message for the first address can still be passed through
   to that socket, because the relay keeps the first listener mapping. It cannot be acknowledged
   there (`InvalidSignature`), so it stays pending. The relay never sends `TooManySubscriptions`,
   which does not appear in `app_mongo.js`. The only error kind the run saw was that
   `InvalidSignature`. Two sockets with one address each were served at the same time. An invoice
   address therefore runs on its own socket, and a socket never re-subscribes as another identity.
5. The Epicbox policy reads a marked V3 invoice as V3. `EpicboxPolicy::decode` selects the V3
   shape when the `ttl_cutoff_height` key is present, even when its value is null. The marker does
   not affect that choice. In the run, LEPIC's I1 with the marker decoded as `legacy-v3`, stage
   `I1`, header `3/3/6` and no TTL. With `ttl_cutoff_height` set to `"1440"`, it decoded the same way
   with a TTL of 1440.

6. One socket drains several addresses in turn. A socket greeted as a sender (`wallet_mode`
   `send`) may subscribe as one address, take and acknowledge every pending message (`Made`, then
   a fresh `Subscribe` signed over the challenge the relay sends after it), and, once a subscribe
   is answered `Ok`, subscribe as the next address with the latest challenge and drain that one.
   In the run two addresses with two messages each were drained this way in both modes, with every
   `Made` answered `Ok` and no error in send mode. Such a socket is never an address's live
   listener, so a message posted while it runs is not passed through to it: the late message for
   each address stayed pending and a later drain on a fresh socket collected it. On a listener
   socket the late message for the earlier address was passed through, and `Made` signed by that
   address was refused (`InvalidSignature`, fact 4), so it too stayed pending. The relay's
   "message in flight" flag belongs to the socket, not the address (`app_mongo.js` `subscribe`
   checks `ws.process_slate`): with a message for the first address unacknowledged, a subscribe as
   the second was answered `Ok` and its message was not handed out. Its resend and discard
   counters also follow the socket, and discarding deletes the queue of the address subscribed
   last. A mailbox drain therefore greets as a sender, acknowledges each message before it
   subscribes again, and moves to a new socket after leaving a message unacknowledged.

Recorded run on 2026-10-04 (`drover lock lepic-acceptance -- interop/acceptance/run.sh --probes --no-build --lepic
target/debug/lepic`, after `cargo build -p lepic-cli`):

```
lepic: lepic 0.1.0 at target/debug/lepic
tree: 504010f

Step                                     Result   Time  Detail
----                                     ------   ----  ------
setup and funding                        PASS      28s  probe esXy9GNMNoP4CE8g9o7CkqQdWgF6ku5nP4x2fkTap6LKjoHxuPLv@localhost:3423, stock listener esZeFpQo6YozzwNZCgRdA487DXdhYDFNZXYuA7CRgGNW2uk8vJKK@localhost:3423
fact 4 relay sessions and addresses      PASS       2s  one socket serves the last subscribed address only; two sockets serve two; relay source names TooManySubscriptions 0 times
fact 1, 2 stock listener bounces a V3 I1 PASS       5s  I1 980b3df4-6cd8-41ef-bb6f-2a6eecaa6951 acknowledged, not recorded, posted back identical except the marker, which is gone
fact 2 stock reply drops the marker      PASS       2s  V3 S1 with marker answered with a V3 S2 without it; acknowledged after the bounce
fact 5 policy decodes a marked V3 invoice PASS       0s  legacy-v3 I1 header 3/3/6, TTL read as 1440
fact 3 non-slate payload unacknowledged  PASS      24s  delivered 2 times, refused as no slate each time, never acknowledged

6 of 6 steps passed
```

Fact 6 was added in a run on 2026-10-24 (`drover lock lepic-acceptance --
interop/acceptance/run.sh --probes --no-build --lepic interop/.work/bin/lepic`, the stack's own
build of `lepic`). The tree was dirty only with the fact 6 text of this page:

```
lepic: lepic 0.1.0 at interop/.work/bin/lepic
tree: 2baafccf-dirty

Step                                     Result   Time  Detail
----                                     ------   ----  ------
setup and funding                        PASS      27s  probe esZjFjrvRnqem2q8z4i372hYZsyx2pFJgmc2hiwkGmwPcvpj6n9Q@localhost:3423, stock listener esZ1aCarpVBX36x4x4Jee5Pgi8ziJGQC975DwtjNZM4RhY2vqenM@localhost:3423
fact 4 relay sessions and addresses      PASS       2s  one socket serves the last subscribed address only; two sockets serve two; relay source names TooManySubscriptions 0 times
fact 6 one socket drains mailboxes in turn PASS      14s  2+2 messages drained on one socket in send and listener mode; late messages wait for the next drain; listener socket gets the earlier key's late message, unackable; a kept message stops the socket serving the next key
fact 1, 2 stock listener bounces a V3 I1 PASS       2s  I1 952d4163-8e86-4093-9203-aab0fd192b29 acknowledged, not recorded, posted back identical except the marker, which is gone
fact 2 stock reply drops the marker      PASS       1s  V3 S1 with marker answered with a V3 S2 without it; acknowledged after the bounce
fact 5 policy decodes a marked V3 invoice PASS       1s  legacy-v3 I1 header 3/3/6, TTL read as 1440
fact 3 non-slate payload unacknowledged  PASS      23s  delivered 2 times, refused as no slate each time, never acknowledged

7 of 7 steps passed
```

## Invoices between LEPIC wallets

LEPIC's behaviour on top of the protocol above; nothing on the wire or the relay changes.

- No invoice address. The invoice address (`m/0/1/<index>`, index 1 and up), its allowlist and
  its prefilter are retired (RFC 0002 section 11.5): a payer parks invoices only from paired
  contacts, through their mailboxes. An I1 that reaches the payments address is refused, unless
  it is a bounce (below).
- Shapes. I1 goes out in the V3 shape, header `3/3/<b>`, and I2 answers in the shape of I1. Both
  carry `"lepic":{"version":1}` as their last top-level key. S1 keeps the V2 shape and carries
  the same key last (see "Ordinary sends between LEPIC wallets").
- Replies. The payer sends I2 from its payments address to the address the parked invoice names
  as its sender (a resend does the same). The
  issuer's payments address finalizes an I2 that answers an invoice it issued and still waits for,
  and posts it with `stem`, as for an S2.
- Bounce. An I1 that arrives with a slate id this wallet issued, from the key it was sent to, and
  equal to the stored I1 apart from its wire form, is what a stock listener sends back. It is
  acknowledged and ignored, and the peer is recorded as not paying invoices.
- Nothing in the inbox pays. Paying a parked I1 is a host call that names the invoiced amount.

## Contact mailboxes (RFC 0002)

LEPIC-only use of ordinary relay messages; nothing on the wire or the relay changes.

- Mailboxes. Each side of a pairing reads a mailbox of its own on the pairing's home relay,
  `box_pk@<home relay>`, with a key derived from the seed, the pairing's slot and a random salt.
  It is drained with one-off connections that greet the relay as a sender (fact 6), never by the
  listener, and acknowledged only after a message's effect is stored. Messages to it are posted
  from the sender's own mailbox key, so the relay sees two per-contact keys.
- Payload. The Epicbox plaintext is the armored sealed envelope (`BEGINEPICSEALED. ...`). A plain
  payload, an anonymous envelope, or one signed by any key but the contact's is acknowledged and
  dropped.
- Invoices. An I1 parks only from a verified contact the user allows invoices from; its payment
  (I2) goes back sealed through the outbox to the contact's mailbox, never over the payments
  address. S1 from a contact (a withdrawal) is received and its S2 goes back the same way. Notices
  (`posted`, `declined`, `withdrawn`) for these slates travel sealed in the mailboxes, type `02`;
  a `withdrawn` for a paid invoice cancels the payment.
- Outbox. Entries are stored, posted at once and retried after 30 s, 2 min, 10 min, then every
  30 min and on every collecting cycle, to the home relay whatever relay the wallet uses; after a
  day undelivered they stop as stuck.
- Home relay moves. A newer card from a shop or exchange whose mailbox names another relay moves
  this side's mailbox there too; the old one is drained for 7 days and queued entries follow the
  new address. People re-pair instead.

## Notices between LEPIC wallets

ADR 0016 has the reasons; this is the format and who sends what.

- Plaintext: a JSON object of at most 512 bytes whose `lepic` key is the number 1, with `type`
  and `slate_id` (hyphenated UUID). `posted` adds `excess`, the kernel excess as 66 hex
  characters. A slate never has a number under `lepic`, which is how a receiver tells the two
  apart.
- `declined`: payer to issuer, from the payer's payments address to the parked invoice's sender.
  `withdrawn`: issuer to payer, on a cancel or an expiry. `posted`: issuer to payer, after the
  paid invoice was pushed. Both go to the address the invoice was issued to. `posted` also goes
  from the sender of an ordinary payment to its receiver, from the payments address, after the
  sender pushed it.
- Sent to a payments address only when the exchange's own incoming slate came marked (the S2 or
  I2 just finalized, the send's latest S2 for `cancelled`, the parked I1 for `declined`) and the
  key is LEPIC lately: its last marked message (a marked I1 parked, I2 finalized, which also
  counts for the key the invoice went to, S1 answered, S2 from the key its send went to, or an
  accepted notice) is newer than its last unmarked slate or bounced I1, and at most 30 days
  old (ADR 0016, schema version 12 amendment). A stock listener never acknowledges a notice and
  loses its queue to one (relay retention below), so every other case sends nothing.
- Accepted only from the recorded counterparty of the slate, and for `posted` only with the
  excess the payment implies: the I2 for an invoice this wallet paid, the stored S2 for a
  payment it received. Every other notice, one of another version or an unknown type, and
  one over 512 bytes, is acknowledged and dropped.
- Advisory: a notice moves no funds. `withdrawn` deletes an unpaid parked invoice and reports a
  paid one for the host to offer a cancel; `posted` and `declined` are reported only.

## Ordinary sends between LEPIC wallets

LEPIC's behaviour for sends; the slate is the one `epic-wallet` sends, plus one key.

- S1 over Epicbox goes out in the V2 shape, as before, with `"lepic":{"version":1}` as its last
  top-level key. Over files and the foreign API nothing changes.
- A receiver answers a marked S1 with an S2 in the same shape that carries the key, and an S1
  without it with an S2 without it. Stock `epic-wallet` `v4.0.2` and `v4.1.0` read the Epicbox
  payload as an untagged `VersionedSlate` (`libwallet/src/tx_proof.rs`), whose `SlateV2`
  (`libwallet/src/slate_versions/v2.rs`) refuses no unknown key, and write their S2 from their
  own struct, so a stock receiver answers a marked S1 with an unmarked S2 (fact 2 shows the
  same for V3).
- The key proves, under the Epicbox signature, that the key it came from runs LEPIC: the S1's
  sender, and the S2's sender when that is the key the send went to.
- After the push that completes a send whose S2 came marked from a receiver that is LEPIC
  lately, the sender posts `posted` with the
  kernel excess to the address the send went to. The receiver takes it as the notices section
  above says, and shows it as the sender's report while the payment waits; only the chain
  confirms the payment.

