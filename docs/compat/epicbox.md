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

## Receiving a slate

Parse `from` (network version bytes checked), verify the signature over `str` with the sender key,
require `destination.public_key` to equal our own key, derive the shared secret with the sender's key
and decrypt, then decode the slate.

## Relay retention

- The relay stores each message for 7 days (MongoDB TTL index `expireAfterSeconds: 604800`). The
  24-hour `expiration` field it also writes is not enforced.
- A message that is delivered but not acknowledged is redelivered; after several redelivery rounds
  the relay may drop the address's unacknowledged messages. Acknowledge promptly once the effect is
  stored, and do not hold a delivered message across many challenge intervals.
- Live pass-through delivers the newly posted message; a fresh subscription delivers the oldest
  pending one.

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
