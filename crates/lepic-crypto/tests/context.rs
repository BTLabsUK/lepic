// The context is created once per process, so this binary holds the single test that randomizes
// it first. Helpers outside `#[test]` functions are not covered by clippy's allow-unwrap-in-tests
// setting, and tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::convert::Infallible;

use lepic_crypto::{
    Commitment, CryptoError, EcdsaSignature, Message, ProofMessage, PublicKey, RangeProof,
    SecretKey, context_is_randomized, randomize_context,
};
use rand_core::{TryCryptoRng, TryRng};
use secp256k1zkp::key::SecretKey as BackendSecretKey;
use secp256k1zkp::pedersen::ProofMessage as BackendProofMessage;
use secp256k1zkp::{ContextFlag, Message as BackendMessage, Secp256k1};

/// Yields a fixed byte and counts how many bytes were drawn.
struct CountingRng {
    byte: u8,
    drawn: usize,
}

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.drawn += 4;
        Ok(u32::from_le_bytes([self.byte; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.drawn += 8;
        Ok(u64::from_le_bytes([self.byte; 8]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.drawn += dst.len();
        dst.fill(self.byte);
        Ok(())
    }
}

impl TryCryptoRng for CountingRng {}

const GENERATOR_HEX: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_bytes(&[byte; 32]).unwrap()
}

fn backend_secret(secp: &Secp256k1, byte: u8) -> BackendSecretKey {
    BackendSecretKey::from_slice(secp, &[byte; 32]).unwrap()
}

#[test]
fn randomized_context_draws_one_seed_and_changes_no_result() {
    let mut rng = CountingRng {
        byte: 0x5c,
        drawn: 0,
    };
    assert!(!context_is_randomized());
    assert_eq!(randomize_context(&mut rng), Ok(()));
    assert_eq!(rng.drawn, 32);
    assert!(context_is_randomized());

    let mut again = CountingRng {
        byte: 0x5d,
        drawn: 0,
    };
    assert_eq!(
        randomize_context(&mut again),
        Err(CryptoError::ContextAlreadyCreated)
    );
    assert_eq!(again.drawn, 0);

    let mut one = [0u8; 32];
    one[31] = 1;
    let one = SecretKey::from_bytes(&one).unwrap();
    assert_eq!(
        PublicKey::from_secret_key(&one).unwrap().to_hex(),
        GENERATOR_HEX
    );

    // An unblinded context built straight from the wrapper is the reference: blinding must not
    // change any key, commitment, signature or proof.
    let plain = Secp256k1::with_caps(ContextFlag::Commit);

    let commitment = Commitment::commit(1_000, &secret(7)).unwrap();
    let expected = plain.commit(1_000, backend_secret(&plain, 7)).unwrap();
    assert_eq!(commitment.as_bytes(), &expected.0);

    let digest = Message::from([0x42; 32]);
    let signature = EcdsaSignature::sign(&digest, &secret(9)).unwrap();
    let expected = plain
        .sign(
            &BackendMessage::from([0x42; 32]),
            &backend_secret(&plain, 9),
        )
        .unwrap();
    assert_eq!(signature.to_der(), expected.serialize_der(&plain));
    let public = PublicKey::from_secret_key(&secret(9)).unwrap();
    assert_eq!(signature.verify(&digest, &public), Ok(()));

    let message = ProofMessage::from([3; ProofMessage::LEN]);
    let proof =
        RangeProof::create(1_000, &secret(7), &secret(0x11), &secret(0x22), &message).unwrap();
    let expected = plain.bullet_proof(
        1_000,
        backend_secret(&plain, 7),
        backend_secret(&plain, 0x11),
        backend_secret(&plain, 0x22),
        None,
        Some(BackendProofMessage::from_bytes(message.as_bytes())),
    );
    assert_eq!(proof.as_bytes(), &expected.proof[..expected.plen]);
    assert_eq!(proof.verify(&commitment), Ok(()));
    assert_eq!(
        proof.rewind(&commitment, &secret(0x11)).map(|r| r.value),
        Ok(1_000)
    );
}
