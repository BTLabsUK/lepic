# Epicbox protocol

Derived from `epic-wallet` `v4.0.2` (`impls/src/adapters/epicbox.rs`, `impls/src/epicbox/protocol.rs`,
`libwallet/src/{message,crypto,epicbox_address,address,base58,tx_proof}.rs`) and the public relay at
`EpicCash/epic-epicbox-docker` (`app_mongo.js`, `epicboxlib_source/`). This page covers protocol
3.0.0, which the public relay speaks. Later protocol versions add optional fields and message types;
the client enables them only when the relay reports support.

## Connection

- URL: `wss://<domain>:<port>` (default port 443); `ws://<domain>:<port>` when the insecure flag is set
  (default port 80). The port is always explicit. Default domain `epicbox.epiccash.com`.
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
| `Error` | `kind` (`InvalidSignature`, `InvalidRequest`, `UnknownError`, `InvalidChallenge`, `TooManySubscriptions`), `description` |
| `Slate` | `from`, `str`, `signature`, `challenge`, and when the subscription carried `ver`: `epicboxmsgid`, `ver` |
| `GetVersion` | `str`, the relay's protocol version |

## Session

1. The relay sends `Challenge` on connect.
2. The client sends `ClientDetails` (mode `listener` before subscribing, or the relay will not push
   live messages to this socket), then `Subscribe` signed over the challenge just received.
3. The relay verifies and sends the oldest pending `Slate` for the address, or `Ok`.
4. After handling a slate, the client re-subscribes with the latest challenge and sends `Made` for the
   message id. The relay answers `Ok` and later sends a new `Challenge`.

Always sign the most recent challenge received. Pending messages persist on the relay until `Made`; a
socket that subscribes while one is in flight can receive it again. The relay keeps one listening
socket per address.

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

- The relay stores each message with a 24-hour expiration.
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
