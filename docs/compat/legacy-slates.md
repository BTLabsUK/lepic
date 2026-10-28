# Legacy slate formats (V2 and V3 JSON)

Derived from `epic-wallet` `v4.1.0` (ADR 0020; earlier `v4.0.2` behaviour is noted where it differs): `libwallet/src/slate.rs`, `libwallet/src/slate_versions/{mod,ser,v2,v3}.rs`,
`impls/src/adapters/{file,epicbox,http}.rs`, `libwallet/src/api_impl/{owner,foreign}.rs`,
`libwallet/src/internal/tx.rs`, `libwallet/src/tx_proof.rs`. The golden vectors in
`testdata/vectors/slates/` (task G-03) settle every fact on this page; where they disagree with it, the
vectors win.

## Shape versus header

A legacy slate has a JSON shape (V2 or V3, differing by two keys) and a `version_info` header
`{ "version", "orig_version", "block_header_version" }` of JSON numbers. They can disagree, and
LEPIC must reproduce exactly the combinations upstream produces:

- New slates are created with header `3/3/<b>`, where `<b>` is the block header version at the chain
  tip: 6 below the first header-version change (mainnet height 9,000,000, floonet 25,800), 7 at or
  above it. Floonet slates today carry `3/3/7` (vectors `*_header_7_*`).
- The header's `version` follows the shape: every V2-shaped slate upstream writes says 2, every
  V3-shaped one says 3. `orig_version` and `block_header_version` are carried through. The Epicbox
  sender always converts to the V2 shape, so Epicbox payloads carry the V2 shape with header
  `2/3/6`. (`v4.0.2` copied the whole header on conversion and sent `3/3/6`; LEPIC still reads it.)
- The file method forces `version` and `orig_version` to 2 when it writes the V2 shape.
- The Epicbox receiver replies in the shape it received, with `orig_version` and
  `block_header_version` carried through.

Upstream has two parse paths:

1. `Slate::deserialize_upgrade` (file and HTTP methods) reads `version_info.version`, accepts 2 or 3,
   and parses the matching shape. A V2-shaped payload with header version 3 fails here.
2. An untagged enum (Epicbox) that tries the V3 shape, then the V2 shape, ignoring the header. The V3
   shape requires the `ttl_cutoff_height` key, so a payload without it parses as V2.

LEPIC keeps the header as received (`WireOrigin`, ADR 0002) and follows each method's path:

- The file path dispatches on the header, as path 1 does: version 2 goes to the V2 codec with any
  `ttl_cutoff_height` and `payment_proof` keys ignored, version 3 to the V3 codec only, and any
  other version is refused. A V3-shaped file with header version 2, which `v4.0.2` wrote in the
  invoice flow, is therefore read without its TTL and payment proof, as upstream reads it.
  `v4.1.0` writes that file with version 3 (`invoice_file_ttl_i2_file`), so its TTL is read.
- The Epicbox path detects the shape structurally, as path 2 does, and ignores the header.

The codecs themselves detect by shape; the file policy in `lepic-transport` does the header
dispatch.

## V3 fields

| Field | JSON | Notes |
|---|---|---|
| `version_info` | object of numbers | see above |
| `num_participants` | number | 2 in practice |
| `id` | UUID string | |
| `tx.offset` | 64 hex chars | 32 bytes |
| `tx.body.inputs[]` | `{features, commit}` | features `"Plain"` or `"Coinbase"`, commit 66 hex |
| `tx.body.outputs[]` | `{features, commit, proof}` | proof is hex of the Bulletproof |
| `tx.body.kernels[]` | `{features, fee, lock_height, excess, excess_sig}` | features `"Plain"` or `"HeightLocked"`, fee and lock height as strings, excess 66 hex, signature 128 hex; before S3 and I3 both are all-zero placeholders |
| `amount`, `fee`, `height`, `lock_height` | string or number | written as strings, read as either |
| `ttl_cutoff_height` | string, number or `null` | key always present in V3 |
| `participant_data[]` | `{id, public_blind_excess, public_nonce, part_sig, message, message_sig}` | id string-or-number; keys 66 hex; signatures 128 hex or `null`; message string or `null` |
| `payment_proof` | `{sender_address, receiver_address, receiver_signature}` or `null` | key always written, `null` without a proof; may be absent on read; addresses 64 hex (ed25519), signature 128 hex or `null` |

V2 is V3 without the `ttl_cutoff_height` and `payment_proof` keys.

## Quirks that must be preserved

- LEPIC always writes `ttl_cutoff_height` and `payment_proof` in the V3 shape, as `null` when unset.
- Converting to V2 drops TTL and payment proof. LEPIC refuses instead (ADR 0003), but must accept V2
  slates that were produced this way.
- Participant `id` is string-encoded while `num_participants` is a number.
- Roles are positional: in the standard flow the sender is id 0 and the receiver id 1; in the invoice
  flow the issuer (receiving funds) is id 1 and the payer id 0.
- Each party truncates its own message to 256 bytes before signing it.
- Signatures are the compact 64-byte form in hex.
- An unfinalized kernel carries all-zero `excess` and `excess_sig`. Decoders accept that placeholder
  before the final stage and require valid points and signatures at it.
- The V2 shape has no field for TTL or a payment proof, so a slate sent in that shape carries neither.
- The file path rejects a V3-shaped slate without `ttl_cutoff_height`, and a V2-shaped slate with
  header version 3; the Epicbox path reads both as V2. Both accept a V3 slate without the
  `payment_proof` key.

## Which shape each method uses

What `epic-wallet` `v4.1.0` writes:

| Method | New slate | Accepts | Reply |
|---|---|---|---|
| File | V2 shape with header `2/2/<b>`, unless the slate has a TTL or payment proof, then V3 with the slate's header; compact JSON | path 1 | same content rule as a new slate |
| Epicbox | V2 shape, header `2/3/<b>` (`v4.0.2`: `3/3/<b>`) | path 2 | shape of the inbound slate |
| HTTP (not in LEPIC) | V3 if the peer lists V3, else V2 | path 1 | |

What LEPIC writes (ADR 0015), next to upstream's choice:

| Method | LEPIC new slate | LEPIC reply | Upstream |
|---|---|---|---|
| File | V3 shape, header `3/3/<b>` with the chain's `<b>`; compact JSON | V3 shape, header `3/3/<b>` with the received `<b>` | V2 unless TTL or payment proof |
| Epicbox | V2 shape, header `2/3/<b>` | shape of the inbound slate, `version` following the shape, the rest echoed | same as LEPIC |

LEPIC's file output therefore differs in bytes from upstream's for slates without TTL or payment
proof. `epic-wallet` reads it through path 1, which accepts header version 3 with the V3 shape. A
reply always carries version 3, so a TTL or payment proof LEPIC adds to a slate received under a
version 2 header is read by the peer, as upstream `v4.1.0`'s own reply in that case
(`invoice_file_ttl_i2_file`) is; `v4.0.2`'s lost it. The differential suite and the interop file scenarios show
`epic-wallet` receives, pays and finalizes every file LEPIC writes.

File naming has no enforced extension. The CLI writes the receiver's reply to `<input>.response`.

## Lifecycle, standard flow

1. Sender (S1): new slate id, `height` set to the chain tip, `lock_height` 0, optional
   `ttl_cutoff_height` = tip + TTL. Adds inputs and change, the fee, one kernel, and the first random
   offset. Adds its public blind excess, public nonce, optional message and message signature. Locks
   the inputs. With a recipient address, sets the payment proof addresses.
2. Receiver (S2): checks TTL, rejects a slate id it already received, adds its output (the body's
   outputs stay sorted by hash, as the node requires), its public data and its partial signature,
   and with a payment proof request signs the proof.
3. Sender (S3): verifies the receiver's data and the payment proof, adds its partial signature,
   aggregates, builds the final kernel, verifies the transaction, and posts it to the node.

Kernel features: `Plain { fee }` when `lock_height` is 0, otherwise `HeightLocked { fee, lock_height }`.
The kernel signature message is in `docs/compat/keys-and-proofs.md`.

Invoice flow: issuer creates I1, payer adds inputs and signs (I2), issuer finalizes (I3). Upstream
runs it over the file method only; its Epicbox listener posts an I1 back unchanged. LEPIC also runs
it over Epicbox between LEPIC wallets, with I1 and I2 in the V3 shape and the LEPIC marker
(`docs/compat/epicbox.md`, "Invoices between LEPIC wallets").

## Checks LEPIC performs on decode

Exact hex lengths, valid curve points and signatures, range proof size within the Bulletproof maximum,
`num_participants` equal to 2 (upstream only creates 2, and `v4.1.0` refuses 0; see
`malformed_num_participants_zero`), participant count not above `num_participants`, ids below `num_participants`,
no duplicate ids, exactly one kernel, fees consistent between slate, kernel and transaction, fee not
below the weight-based minimum, `version_info.version` 2 or 3 (upstream's Epicbox path accepts any
version for the V2 shape; see `malformed_header_version_1` and `_4`), and no non-null
`payment_proof` in a V2-shaped slate (the V2 codec refuses it rather than reading the slate
without it; the file path removes the V3-only keys before a header-2 file reaches it). Upstream
`v4.1.0` refuses an offset of the wrong length on both paths (`malformed_offset_too_short`), and on
the file path also a duplicate participant id and a zero participant count
(`malformed_duplicate_participant_id`, `malformed_num_participants_zero`), which its Epicbox path
still reads; `v4.0.2` read all three; the other checks are LEPIC's own and stricter
than upstream's parse step.
Integer fields written as strings take ASCII digits only: a leading `+`, which upstream's
`str::parse::<u64>` accepts, is refused, as are spaces and other signs. No `epic-wallet` version
writes a sign, and the strict form keeps decode and encode exact inverses.
Any slate `epic-wallet` emits must still decode; the vectors prove it.
