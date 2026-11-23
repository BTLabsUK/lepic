# Payment proofs for epic1 payments

A LEPIC payee signs a payment proof into its answer (the S2) to every payment to its epic1
address. The proof says that the owner of the address took this amount in the transaction whose
kernel excess it names, for this slate id. Anyone checks it with only the address. The chain
shows whether the transaction was posted: one `get_kernel` lookup on any node.

Code and the wire call the proof a receipt. Users see "payment proof".

| Crate | Holds |
|---|---|
| [`lepic-epic1`](../../crates/lepic-epic1/README.md) `receipt` | The receipt key, the signed message, signing and verifying; pure |
| `lepic-seal` | Tags `84` and `85` of the tx envelope |
| `lepic-wallet-contacts` `epic1_receipt` | The ask, the answer's check, the proof file, the kernel lookup |
| `lepic-cli` | `lepic proof export`, `lepic proof verify`, `--require-proof`, `GET /api/v1/payments/{id}/proof` |

Only LEPIC wallets sign and check proofs: the CLI, `lepic serve`, and the BT wallet app through
LEPIC. Stock Epic wallets never pay an epic1 address. The address does not change.
[ADR 0069](../adr/0069-epic1-payment-proofs.md) records the decision.

## Keys

The address carries the delivery key `D`, 33 bytes compressed secp256k1
([epic1](epic1.md#the-address)). The receipt key is a public tweak of it:

```text
t = SHA-256("lepic-epic1-receipt-key/1" || D)        read as a 256-bit big-endian number
R = D + t·G                                          the receipt key: anyone computes it
r = d + t  (mod n)                                   the receipt secret: only the payee has d
```

- A `t` of zero or not below the curve order `n`, or an `R` at infinity, makes no key. No such
  `D` is known; a payee with one signs nothing and a verifier refuses.
- `r` signs only receipts. The delivery secret `d` signs the mailbox's socket challenge with
  ECDSA, over text the mailbox picks; it never signs a receipt, and `r` never signs a challenge.
- `t` is public, so a leak of `r` is a leak of `d`. Both live in the same wallet.
- Every install of the same phrase derives the same `r`.

The **payer key** `P` is a one-time secp256k1 key from the payer's seed, label
`lepic-wallet receipt payer key v1` with context `account (u32 BE) || net || slate id (16)`, by
the counter rule of RFC 0003 §5.2. It names no payer to the payee or to anyone the proof is shown
to. The payer derives it again from the slate id when the answer comes.

## On the wire

Two extension fields of the tx envelope ([RFC 0003 §5.6](../rfcs/0003-epictx-native-slates.md#56-inner-content)):

| Tag | In | Value |
|---|---|---|
| `84` | S1 | The receipt ask: `P`, 33 bytes |
| `85` | S2 | The receipt: the 64-byte signature |

- A LEPIC payer puts tag `84` in every S1 it seals to an epic1 address.
- A payee that reads tag `84` answers with tag `85` when it can sign. It signs nothing when the ask
  is not a key or the slate has no kernel excess yet; the payment goes on.
- Tags from `80` up are skipped by readers that do not know them, so a payee of 0.6.1 or older
  answers as before, with no tag `85`.
- A slate-level payment proof (flag `04` of `lepic.v1`) at an epic1 address is still refused
  (`ForeignProofAddress`). The proof travels only in the envelope.

## The signed message

```text
message = "lepic-epic1-receipt/1"  (21 bytes, ASCII)
       || net                      (1)    00 mainnet, 01 floonet
       || D                        (33)
       || amount                   (8)    base units, u64 big-endian
       || kernel excess            (33)   the sum of both participants' public excesses
       || slate id                 (16)   the UUID's bytes
       || P                        (33)
                                   145 bytes
digest  = SHA-256(message)
```

The payee knows every field once it has added its part to the slate: it computes the kernel
excess as the payer will. The payer computes the same message from its own slate and `P`.

## The signature

The signature is the single-signer Schnorr signature of the secp256k1-zkp the Epic node uses for
kernels (`aggsig`), in its 64-byte compact form:

```text
k = SHA-256("lepic-epic1-receipt-nonce/1" || r || digest)    the secret nonce, deterministic
K = k·G, negated to a square Y                                the public nonce
e = SHA-256(x(K) || R (33, compressed) || digest)             the challenge
s = k + e·r
```

The same facts give the same signature. Verification is `aggsig` `verify_completed_sig` with
`R` as both the key and the challenge key.

### The challenge commits to the key

The challenge hashes `R`. The C code, vendored at
`third_party/epic_secp256k1zkp/depend/secp256k1-zkp/src/modules/aggsig/main_impl.h`:

- `secp256k1_compute_sighash_single` (line 36) hashes the nonce's x (32 bytes), then the key in
  compressed form (33 bytes) when one is given, then the 32-byte message.
- Signing passes its `pubkey_for_e` to it (lines 258 and 261), verifying its `pubkey_total`
  (lines 684 and 688).
- The Rust wrapper passes them through: `sign_single` (`third_party/epic_secp256k1zkp/src/aggsig.rs`
  line 88) and `verify_single` (line 147).
- LEPIC gives `Some(R)` on both sides: `lepic_epic1::receipt::sign` and `verify`.

With no key given, the C code leaves it out of the challenge. The vector case
`key_not_in_challenge` is such a signature over the same facts, and `verify` refuses it.

Against BIP-340 it differs in three ways: the key is 33 bytes compressed, not 32 x-only; the
hashes are plain SHA-256, not tagged; and the nonce has a square Y, not an even one.

## The proof file

The payer keeps a proof that holds with the payment for good, and exports it as JSON, media type
`application/vnd.lepic.receipt+json`, at most 4096 bytes:

```json
{
  "type": "lepic-epic1-receipt",
  "version": 1,
  "network": "floonet",
  "address": "tepic1q…",
  "amount": 200000000,
  "kernel_excess": "08…",
  "slate_id": "434956b0-3e01-480b-a4c0-2f6e36d1e400",
  "payer_key": "02…",
  "signature": "…"
}
```

| Field | Value |
|---|---|
| `type` | `lepic-epic1-receipt` |
| `version` | `1` |
| `network` | `mainnet` or `floonet`; must be the address's network |
| `address` | The epic1 address paid; `D` comes from it |
| `amount` | Base units, an integer |
| `kernel_excess` | 66 hex digits, a Pedersen commitment |
| `slate_id` | The slate id as a UUID |
| `payer_key` | 66 hex digits, `P` |
| `signature` | 128 hex digits |

All fields are required. A reader refuses another type or version and any other field.

## Verifying

1. Parse the file. Decode the address, and refuse a `network` that is not the address's.
2. Refuse a proof for another network than the one asked for.
3. Build the message from the fields and `D`, and check the signature against `R`.
4. To know the payment happened, ask a node for the kernel with that excess
   (`get_kernel`). A kernel on chain gives its height.

`lepic proof verify FILE [--on-chain] [--node URL]` does all four ([CLI](../cli.md#payment-proofs)).

## What a proof shows

- It shows: the holder of the address's delivery secret signed for this amount, this kernel and
  this slate id, to the holder of `P`.
- It does not show that the transaction was posted. The kernel lookup does.
- It does not name the payer. The payer proves the proof is theirs by signing a challenge with
  the secret of `P`, which they derive again from the seed and the slate id. LEPIC has no command
  for that yet.
- It does not show what was bought or why.
- A payment taken again from its sealed text is answered with a proof for the payer key that
  copy carries. Only the payer can make a valid copy, so a payer can hold two true proofs for one
  payment under two payer keys. This is by design.

## The payer's side

- The payer checks tag `85` when it finalizes, whether the answer came to its reply mailbox or
  was pasted as sealed text. A proof that holds is stored; one that does not is dropped.
- Without a requirement the payment finalizes either way.
- With `--require-proof` on the payment, the setting `epic1_require_proof`, or `require_proof` in
  `POST /api/v1/payments`, an answer without a proof that holds is refused
  (`Epic1Refusal::NoReceipt` or `BadReceipt`): the payment is cancelled unfinalized, its inputs
  are unlocked and the payee gets a `declined` notice. A cancel that fails (the store cannot be
  written) leaves the payment unfinalized with its inputs locked until it is cancelled again or
  expires. The flag on a payment that is not to an epic1 address is a usage error.
- The answer is refused for its proof only when it is otherwise the payee's genuine S2: the
  payee's partial signature holds, the fields of the S1 are unchanged and the sender's check
  passes. Any other S2 is dropped as a failed finalize, and the payment keeps waiting for its
  answer, as without a requirement.
- An S2 finalized from a plain slate file carries no proof and is not checked.

## Vectors

[`testdata/vectors/keys/epic1_receipts.json`](../../testdata/vectors/keys/epic1_receipts.json),
made by `cargo xtask vectors generate --area keys`:

- `cases`: four mainnet and four floonet payments, each with the delivery secret and key, `t`,
  `r`, `R`, the message, the digest, the nonce and the signature.
- `refused`: `flipped_bit`, `amount_changed`, `untweaked_delivery_key` (signed with `d` and not
  `r`) and `key_not_in_challenge`.

`cargo xtask vectors verify` checks the code against them.
