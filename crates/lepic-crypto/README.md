# lepic-crypto

The checked boundary over the vendored secp256k1-zkp library: Pedersen commitments, bulletproof
range proofs, aggregated Schnorr signatures and ECDSA. A pure crate at the bottom of the
workspace. Every value is checked when it is built, so the C library only sees well-formed keys,
points and lengths, and every failure comes back as a `CryptoError`.

## Where it fits

- Depends on no other LEPIC crate. Its C backend is `grin_secp256k1zkp`, vendored in
  `third_party/` with its changes listed in `third_party/PATCHES.md`.
- Used by almost every other crate: `lepic-primitives` for transactions, `lepic-keychain` for
  keys and proofs, the slate crates for signatures, the engine for building transactions.
- No features.
- Does no I/O and creates no randomness of its own: functions that need randomness take a
  `CryptoRng`.

## Core concepts

- **One context.** The library holds a single secp256k1 context for the process, created on
  first use. A host may call `randomize_context` once at start, before anything else, to blind it
  against timing and power side channels; afterwards it fails with
  `CryptoError::ContextAlreadyCreated` and changes nothing.
- **Bounded work.** Sums and batch verification refuse more terms than one consensus-valid block
  can hold (`MAX_SUM_TERMS`, `MAX_PROOF_BATCH`), so untrusted input cannot ask for unbounded work.
- **Deterministic proofs.** `RangeProof::create` takes its nonces as arguments; equal inputs give
  the same proof. Whoever holds the rewind nonce can recover the value and message with
  `RangeProof::rewind`, which is how a wallet finds its own outputs.
- **Typed errors.** `CryptoError` names the failure and, through `Item`, the kind of value.

## Public API

| Area | Items |
|---|---|
| Keys | `SecretKey` (`from_bytes`, `from_array`, `from_hex`, `sum`, `blind_switch`), `PublicKey` (`from_secret_key`, `sum`, `shared_secret`), `SharedSecret` |
| Commitments | `Commitment` (`commit`, `commit_value`, `from_public_key`, `sum`, `from_hex`) |
| Range proofs | `RangeProof` (`create`, `verify`, `verify_batch`, `rewind`), `ProofMessage`, `CommittedProof`, `RewoundProof` |
| Schnorr signatures | `aggsig::{create_secnonce, calculate_partial_sig, verify_partial_sig, add_signatures, verify_completed_sig, sign_single, verify_single_from_commit}`, `Signature`, `Message` |
| ECDSA | `EcdsaSignature` (`sign`, `verify`, DER and compact forms) |
| Context | `randomize_context`, `context_is_randomized` |
| Limits and errors | `MAX_SUM_TERMS`, `MAX_PROOF_BATCH`, `CryptoError`, `Item` |
| Hex | `hex::{encode, decode_into, decode_array, decode_bounded, HexError}` |

## Example

```rust
use lepic_crypto::{Commitment, CryptoError, ProofMessage, RangeProof, SecretKey};

fn main() -> Result<(), CryptoError> {
    let blinding = SecretKey::from_array([7; 32])?;
    let nonce = SecretKey::from_array([9; 32])?;
    let message = ProofMessage::from_bytes(&[0; ProofMessage::LEN])?;

    let commitment = Commitment::commit(1_000, &blinding)?;
    let proof = RangeProof::create(1_000, &blinding, &nonce, &nonce, &message)?;
    proof.verify(&commitment)?;

    let rewound = proof.rewind(&commitment, &nonce)?;
    assert_eq!(rewound.value, 1_000);
    Ok(())
}
```

## Related

- [Architecture](../../docs/architecture.md)
- [ADR 0011: no process-global state](../../docs/adr/0011-no-global-state.md)
- [`lepic-primitives`](../lepic-primitives/README.md), [`lepic-keychain`](../lepic-keychain/README.md)
