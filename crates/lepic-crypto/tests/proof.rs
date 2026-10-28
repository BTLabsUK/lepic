// SPDX-License-Identifier: Apache-2.0
// Helpers outside `#[test]` functions are not covered by clippy's allow-unwrap-in-tests setting,
// and tests may unwrap (docs/rules.md).
#![allow(clippy::unwrap_used)]

use lepic_crypto::{
    Commitment, CommittedProof, CryptoError, Item, MAX_PROOF_BATCH, ProofMessage, RangeProof,
    RewoundProof, SecretKey,
};

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_bytes(&[byte; 32]).unwrap()
}

fn message() -> ProofMessage {
    let mut bytes = [0u8; 20];
    bytes[2] = 1;
    bytes[3] = 3;
    ProofMessage::from(bytes)
}

struct Output {
    commitment: Commitment,
    proof: RangeProof,
}

fn output(value: u64, blinding: u8) -> Output {
    let blinding = secret(blinding);
    Output {
        commitment: Commitment::commit(value, &blinding).unwrap(),
        proof: RangeProof::create(value, &blinding, &secret(0x11), &secret(0x22), &message())
            .unwrap(),
    }
}

fn committed(output: &Output) -> CommittedProof<'_> {
    CommittedProof {
        commitment: &output.commitment,
        proof: &output.proof,
    }
}

#[test]
fn created_proof_verifies_and_rewinds_to_its_inputs() {
    let blinding = secret(7);
    let commitment = Commitment::commit(1_000, &blinding).unwrap();
    let proof = RangeProof::create(1_000, &blinding, &secret(1), &secret(2), &message()).unwrap();
    assert_eq!(proof.as_bytes().len(), RangeProof::BULLETPROOF_LEN);
    assert_eq!(proof.verify(&commitment), Ok(()));

    assert_eq!(
        proof.rewind(&commitment, &secret(1)),
        Ok(RewoundProof {
            value: 1_000,
            message: message()
        })
    );
}

#[test]
fn proofs_cover_zero_and_the_largest_value() {
    for value in [0, 1, u64::MAX] {
        let out = output(value, 3);
        assert_eq!(out.proof.verify(&out.commitment), Ok(()), "value {value}");
    }
}

#[test]
fn proof_creation_is_deterministic() {
    assert_eq!(output(42, 5).proof, output(42, 5).proof);
}

#[test]
fn round_trips_proof_bytes_and_hex() {
    let proof = output(42, 5).proof;
    assert_eq!(RangeProof::from_bytes(proof.as_bytes()), Ok(proof.clone()));
    assert_eq!(RangeProof::from_hex(&proof.to_hex()), Ok(proof));
}

#[test]
fn rejects_proof_for_another_commitment() {
    let out = output(42, 5);
    let other = Commitment::commit(43, &secret(5)).unwrap();
    assert_eq!(
        out.proof.verify(&other),
        Err(CryptoError::InvalidRangeProof)
    );
}

#[test]
fn rejects_tampered_proof() {
    let out = output(42, 5);
    let mut bytes = out.proof.as_bytes().to_vec();
    bytes[100] ^= 0x01;
    let tampered = RangeProof::from_bytes(&bytes).unwrap();
    assert_eq!(
        tampered.verify(&out.commitment),
        Err(CryptoError::InvalidRangeProof)
    );
}

#[test]
fn rejects_truncated_proof_without_calling_the_verifier() {
    let out = output(42, 5);
    let short =
        RangeProof::from_bytes(&out.proof.as_bytes()[..RangeProof::BULLETPROOF_LEN - 1]).unwrap();
    assert_eq!(
        short.verify(&out.commitment),
        Err(CryptoError::InvalidRangeProof)
    );
    assert_eq!(
        short.rewind(&out.commitment, &secret(0x11)).err(),
        Some(CryptoError::RangeProofRewindFailed)
    );
}

#[test]
fn rejects_proof_bytes_outside_the_length_bounds() {
    for len in [0, RangeProof::MAX_LEN + 1] {
        assert_eq!(
            RangeProof::from_bytes(&vec![0u8; len]),
            Err(CryptoError::LengthOutOfRange {
                item: Item::RangeProof,
                min: 1,
                max: RangeProof::MAX_LEN,
                actual: len
            })
        );
    }
    assert_eq!(
        RangeProof::from_hex(&"00".repeat(RangeProof::MAX_LEN + 1)),
        Err(CryptoError::LengthOutOfRange {
            item: Item::RangeProof,
            min: 1,
            max: RangeProof::MAX_LEN,
            actual: RangeProof::MAX_LEN + 1
        })
    );
}

#[test]
fn rejects_proof_message_of_the_wrong_length() {
    assert_eq!(
        ProofMessage::from_bytes(&[0u8; 21]),
        Err(CryptoError::WrongLength {
            item: Item::ProofMessage,
            expected: 20,
            actual: 21
        })
    );
}

#[test]
fn rewind_with_another_nonce_fails() {
    let out = output(42, 5);
    assert_eq!(
        out.proof.rewind(&out.commitment, &secret(0x33)).err(),
        Some(CryptoError::RangeProofRewindFailed)
    );
}

#[test]
fn rewind_against_another_commitment_fails() {
    let out = output(42, 5);
    let other = Commitment::commit(42, &secret(6)).unwrap();
    assert_eq!(
        out.proof.rewind(&other, &secret(0x11)).err(),
        Some(CryptoError::RangeProofRewindFailed)
    );
}

#[test]
fn batch_verifies_valid_proofs() {
    let outputs: Vec<Output> = (1..=4).map(|i| output(u64::from(i) * 10, i)).collect();
    let items: Vec<_> = outputs.iter().map(committed).collect();
    assert_eq!(RangeProof::verify_batch(&items), Ok(()));
}

#[test]
fn batch_rejects_one_proof_against_the_wrong_commitment() {
    let a = output(10, 1);
    let b = output(20, 2);
    let items = [
        committed(&a),
        CommittedProof {
            commitment: &a.commitment,
            proof: &b.proof,
        },
    ];
    assert_eq!(
        RangeProof::verify_batch(&items),
        Err(CryptoError::InvalidRangeProof)
    );
}

#[test]
fn batch_rejects_a_short_proof_before_calling_the_verifier() {
    let a = output(10, 1);
    let short = RangeProof::from_bytes(&[0u8; 32]).unwrap();
    let items = [
        committed(&a),
        CommittedProof {
            commitment: &a.commitment,
            proof: &short,
        },
    ];
    assert_eq!(
        RangeProof::verify_batch(&items),
        Err(CryptoError::InvalidRangeProof)
    );
}

#[test]
fn rejects_empty_proof_batch() {
    assert_eq!(
        RangeProof::verify_batch(&[]),
        Err(CryptoError::EmptyBatch {
            item: Item::RangeProof
        })
    );
}

#[test]
fn rejects_oversized_proof_batch() {
    let a = output(10, 1);
    let items = vec![committed(&a); MAX_PROOF_BATCH + 1];
    assert_eq!(
        RangeProof::verify_batch(&items),
        Err(CryptoError::BatchTooLarge {
            item: Item::RangeProof,
            max: MAX_PROOF_BATCH,
            actual: MAX_PROOF_BATCH + 1
        })
    );
}

#[test]
fn proofs_are_created_and_verified_concurrently() {
    let threads: Vec<_> = (1..=8u8)
        .map(|i| {
            std::thread::spawn(move || {
                let out = output(u64::from(i), i);
                out.proof.verify(&out.commitment)
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), Ok(()));
    }
}

#[test]
fn proof_debug_shows_only_the_length() {
    let proof = output(10, 1).proof;
    assert_eq!(format!("{proof:?}"), "RangeProof(675 bytes)");
}
