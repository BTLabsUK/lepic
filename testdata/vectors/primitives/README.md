# primitives vectors

Written by `conformance/vectors/src/primitives/` (task G-02) from the Epic node code at the commit in
each file's `upstream`. Deterministic: every key, blinding factor, nonce and offset is a fixed test
value, so `cargo xtask vectors generate --area primitives` reproduces these files byte for byte. The
generator's own test (`cargo test -p vectors` in `conformance/`) fails if they drift.

## Conventions

- Files whose name is a group (`ser_*`, `hash_*`, `kernel_features*`, `inputs`, `outputs`,
  `kernels`, `fee_grid`, `weight_limits`) have empty `inputs`; each row of `expected.cases` carries
  its own inputs next to its results.
- `serialized_v1` and `serialized_v2` are the binary layouts at protocol versions 1 and 2. They
  differ only in kernel features: version 1 always writes fee and lock height, version 2 only the
  fields the variant has. The node's local protocol version is 2.
- Hashes are unkeyed BLAKE2b-256. A kernel always hashes its version 1 layout; an output hashes
  features and commitment, not its proof.
- In JSON forms, signatures are the 64-byte compact form. Binary layouts carry the wrapper's
  internal form, which is the compact form with each 32-byte half byte-reversed.
- Decode outcomes are `ok` or the upstream `ser::Error` variant: `CorruptedData`,
  `TooLargeReadErr`, `IOErr(UnexpectedEof)`.
- Output nonces: each output's Bulletproof is built with `bullet_proof(value, blind,
  rewind_nonce, private_nonce, None, None)` from the nonces listed with it.

## Files

| File | Contents |
|---|---|
| `ser_integers` | Big-endian u8, u16, u32, i32, u64, i64 at edge values. |
| `ser_length_prefixed_bytes` | `write_bytes`: u64 length prefix, then the bytes. |
| `ser_composites` | Tuples (written field after field, no prefix) and `ProtocolVersion` (u32). |
| `ser_truncated_reads` | Reading integers from too few bytes. |
| `hash_bytes` | BLAKE2b-256 of raw byte strings around the 128-byte block size. |
| `hash_values` | `Hashed::hash` of u8, u64, tuples and hashes, with the preimage. |
| `hash_operations` | `ZERO_HASH`, `Hash + Hash` (hash of the two concatenated), `Hash::to_u64`. |
| `crypto_types` | Commitment, blinding factor, public key, signature and range proof, JSON and binary forms. |
| `output_features` | Feature byte decoding, including unknown bytes. |
| `kernel_features` | Each kernel variant at both versions, and its signature message. |
| `kernel_features_decode` | Kernel feature decoding at both versions, including the zero-field checks of version 1. |
| `inputs`, `outputs`, `kernels` | Each part with features variants, layouts and hashes. Kernels are signed and verify. |
| `chain_params_mainnet`, `chain_params_floonet` | Coinbase maturity, block and transaction weight limits, weights per item, protocol version, unit constants, default base fee. |
| `fee_grid` | `weight`, `weight_as_block` and `tx_fee` over an input, output and kernel grid. |
| `weight_limits` | The `AsTransaction` weight rule and the body reader's count check near both limits, per network. |
| `tx_valid_*`, `tx_invalid_*` | Whole transactions, below. |

## Transactions

Each `tx_*` file lists the spec in `inputs.spec`: input coins, outputs with their nonces, kernel
features, offset and kernel nonce. The kernel excess is the output blinds less the input blinds less
the offset, signed by one signer with the kernel nonce. `inputs.mutation` names a change applied
after signing, or `none`. `expected.transaction` holds the result as parts in transaction order, so
a test can build a transaction a decoder would refuse, and `expected.serialized_v2` the bytes.

`expected.validation` is the outcome of `Transaction::validate(Weighting::AsTransaction)`. Each
invalid case breaks exactly one rule, so the result does not depend on check order. `rule` is one
of `sort_order`, `duplicate`, `cut_through`, `range_proof`, `kernel_signature`, `output_features`,
`kernel_features`, `kernel_sum`; `upstream_error` is the node's error, for reference. The weight
rule is covered by `weight_limits`, because a transaction at the limit would hold tens of thousands
of items.

`expected.decode_v2` is the result of the node reading the bytes. Reading runs the weight, sort,
cut-through and feature checks but not proofs, signatures or sums, so those three invalid cases
decode.

`tx_valid_aggregate_two_kernels` lists two specs in `inputs.specs`; the transaction is upstream's
`aggregate` of the two, with both kernels and the summed offset.

Fee rules (a fee below `tx_fee` for the actual counts) are checked on slates, not by
`Transaction::validate`; `fee_grid` gives the expected fee for any counts.
