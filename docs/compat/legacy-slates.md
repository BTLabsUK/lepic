# Legacy slate formats (V2 and V3 JSON)

`epic-wallet` v4.1.0 (ADR 0020) exchanges slates as JSON in two shapes, V2 and V3. This page says
how the shapes differ, which header each method writes and what LEPIC checks on decode. The
format is read from `libwallet/src/slate.rs`, `libwallet/src/slate_versions/{mod,ser,v2,v3}.rs`,
`impls/src/adapters/{file,epicbox,http}.rs`, `libwallet/src/api_impl/{owner,foreign}.rs`,
`libwallet/src/internal/tx.rs` and `libwallet/src/tx_proof.rs`. The codecs are `V2JsonCodec` and
`V3JsonCodec` in `lepic-legacy-slate`. The golden vectors in `testdata/vectors/slates/` decide
every fact here, and the vectors win where this page differs.

## Shape and header

A legacy slate has a JSON shape (V2 or V3, which differ by two keys) and a header
`version_info`, `{ "version", "orig_version", "block_header_version" }`, of JSON numbers. The two
can disagree, so LEPIC carries the header as received (`WireOrigin` in `lepic-slate`, ADR 0002)
and writes the combinations `epic-wallet` writes.

- A slate this wallet starts has `orig_version` 3 and the block header version `<b>` of the chain
  tip: 6 below height 9,000,000 on mainnet and 25,800 on floonet, 7 from there on
  (`lepic-wallet/src/send.rs`). Floonet slates carry `3/3/7` in V3 and `2/3/7` in V2
  (vectors `*_header_7_*`).
- `version` follows the shape: a V2-shaped slate says 2, a V3-shaped one says 3. `orig_version` and
  `block_header_version` are carried through from a received slate.
- `epic-wallet` has two read paths:
  1. `Slate::deserialize_upgrade` (file and HTTP) reads `version_info.version`, accepts 2 or 3 and
     parses the matching shape. A V2-shaped payload with header version 3 fails here.
  2. An untagged enum (Epicbox) that tries the V3 shape, then the V2 shape, and ignores the
     header. The V3 shape needs the `ttl_cutoff_height` key, so a payload without it is V2.
- LEPIC follows each method's path. The file policy (`lepic-transport/src/file.rs`) dispatches on
  the header: version 2 goes to the V2 codec with any `ttl_cutoff_height` and `payment_proof` keys
  ignored, version 3 goes to the V3 codec only, and any other version is refused. The Epicbox and
  HTTP policies detect the shape (V3 first) and ignore the header. The codecs detect by shape and
  decode whichever header they find, as long as `version` is 2 or 3.

## V3 fields

| Field | JSON | Notes |
|---|---|---|
| `version_info` | object of numbers | see above |
| `num_participants` | number | 2 |
| `id` | UUID string | |
| `tx.offset` | 64 hex characters | 32 bytes |
| `tx.body.inputs[]` | `{features, commit}` | features `"Plain"` or `"Coinbase"`, commit 66 hex characters |
| `tx.body.outputs[]` | `{features, commit, proof}` | proof is the hex of the bulletproof |
| `tx.body.kernels[]` | `{features, fee, lock_height, excess, excess_sig}` | features `"Plain"` or `"HeightLocked"`, fee and lock height as strings, excess 66 hex, signature 128 hex. Before stage 3 both are all-zero placeholders |
| `amount`, `fee`, `height`, `lock_height` | string or number | written as strings, read as either |
| `ttl_cutoff_height` | string, number or `null` | the key is always present in V3 |
| `participant_data[]` | `{id, public_blind_excess, public_nonce, part_sig, message, message_sig}` | `id` string or number; keys 66 hex; signatures 128 hex or `null`; message string or `null` |
| `payment_proof` | `{sender_address, receiver_address, receiver_signature}` or `null` | written as `null` without a proof; may be absent on read; addresses 64 hex (ed25519), signature 128 hex or `null` |

V2 is V3 without the `ttl_cutoff_height` and `payment_proof` keys.

## Rules both codecs follow

- LEPIC always writes `ttl_cutoff_height` and `payment_proof` in the V3 shape, as `null` when
  unset.
- The V2 shape has no field for a TTL or a payment proof. `V2JsonCodec` refuses to encode a slate
  that has either (ADR 0003) and refuses to decode a V2-shaped slate with a non-null
  `payment_proof`.
- The participant `id` is a string and `num_participants` a number.
- Roles are positional. In the standard flow the sender is id 0 and the receiver id 1. In the
  invoice flow the issuer (who receives the funds) is id 1 and the payer id 0.
- A participant message is at most 256 bytes. LEPIC cuts its own message to that length, on a
  character boundary, before it signs it.
- Signatures are the compact 64-byte form in hex.
- An unfinished kernel carries an all-zero `excess` and `excess_sig`. A decoder accepts that
  placeholder before the final stage and requires a valid point and signature at it.
- A wire slate is at most 8 MiB (`MAX_WIRE_SLATE_LEN`), checked before parsing.

## Which shape each method uses

What `epic-wallet` v4.1.0 writes:

| Method | New slate | Reply |
|---|---|---|
| File | V2 shape with header `2/2/<b>`; V3 with the slate's own header when the slate has a TTL or a payment proof. Compact JSON | same rule |
| Epicbox | V2 shape | the shape of the inbound slate |

What LEPIC writes (ADR 0015 for files, ADR 0003 for Epicbox):

| Method | New slate | Reply |
|---|---|---|
| File | V3 shape, header `3/3/<b>` with the chain's `<b>`; compact JSON | V3 shape, header `3/3/<b>` with the received `<b>` |
| Epicbox | V2 shape, header `2/3/<b>` | the shape and codec of the inbound slate, `version` following the shape, the rest carried through |
| HTTP | V2 shape, header `2/3/<b>` | the shape and codec of the inbound slate |

A slate with a payment proof cannot go out in the V2 shape, so such a send over Epicbox or HTTP
fails with `Unrepresentable` and stores nothing. A send with a TTL goes out in the V2 shape without
it: the wallet keeps the height as the send's wallet-local cutoff
([states.md](states.md#wallet-local-cutoff)) and expires the send at refresh if it is still
unanswered. The receiver does not see the TTL.

LEPIC's file output differs in bytes from `epic-wallet`'s for slates without a TTL or payment
proof. `epic-wallet` reads it through path 1, which accepts header version 3 with the V3 shape. A
reply always carries version 3, so a TTL or payment proof that LEPIC adds to a slate it received
under a version 2 header is read by the peer. The interop file scenarios exercise `epic-wallet`
receiving, paying and finalizing files LEPIC writes ([interop/README.md](../../interop/README.md)).

LEPIC does not require a file extension. The CLI writes a reply to `<input>.response`.

LEPIC's own markers on slates sent over Epicbox are in [epicbox.md](epicbox.md).

## Standard flow

1. Sender (S1): a new slate id, `height` set to the chain tip, `lock_height` 0 and an optional
   `ttl_cutoff_height` of tip plus the TTL. It adds inputs and change, the fee, one kernel and the
   first random offset, then its public blind excess, public nonce, optional message and message
   signature. It locks the inputs. With a recipient address it sets the payment-proof addresses.
2. Receiver (S2): checks the TTL, refuses a slate id it already received, adds its output (the
   outputs stay sorted by hash, as the node requires), its public data and its partial signature,
   and signs the payment proof when one is requested.
3. Sender (S3): verifies the receiver's data and the payment proof, adds its partial signature,
   aggregates, builds the final kernel, verifies the transaction and posts it to the node.

The kernel features are `Plain { fee }` when `lock_height` is 0 and `HeightLocked { fee,
lock_height }` otherwise. The kernel signature message is in
[keys-and-proofs.md](keys-and-proofs.md).

Invoice flow: the issuer creates I1, the payer adds inputs and signs (I2), the issuer finalizes
(I3). `epic-wallet` runs it over files only. LEPIC also runs it over Epicbox between LEPIC
wallets, with I1 and I2 in the V3 shape and the LEPIC marker ([epicbox.md](epicbox.md)).

## Checks on decode

Both codecs refuse a slate that fails any of these:

- Hex of the exact length, valid curve points and signatures, and a range proof within the
  bulletproof maximum.
- `num_participants` equal to 2. The participant count does not exceed it, ids are below it and
  unique, and there is exactly one kernel.
- `version_info.version` 2 or 3.
- The fee is the same in the slate, the kernel and the transaction, and not below the
  weight-based minimum of the transaction.
- Integer fields written as strings hold ASCII digits only. A leading `+`, spaces and other signs
  are refused, which keeps decode and encode exact inverses.
- No non-null `payment_proof` in a V2-shaped slate. On the file path the V3-only keys of a header
  version 2 file are removed before the V2 codec reads it.

The vectors named `malformed_*` hold one case for each of these. Every slate `epic-wallet` emits
decodes; the `send_*` and `invoice_*` vectors hold them.
