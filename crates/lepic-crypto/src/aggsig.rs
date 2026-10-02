//! Schnorr aggregate signatures as Epic kernels and participant messages use them.
//!
//! Ported from `core/src/libtx/aggsig.rs` of the Epic node. Nonces are always passed in, so every
//! function here is deterministic.

use rand_core::CryptoRng;
use secp256k1zkp::Signature as BackendSignature;
use secp256k1zkp::aggsig;
use zeroize::Zeroizing;

use crate::commitment::Commitment;
use crate::context::secp;
use crate::error::{CryptoError, Item};
use crate::limits::{MAX_SUM_TERMS, check_batch_len};
use crate::public_key::PublicKey;
use crate::secret::SecretKey;
use crate::signature::{Message, Signature};

// A uniform 32-byte draw falls outside the scalar range with probability below 2^-127, so running
// out of attempts means the RNG is broken, not unlucky.
const NONCE_ATTEMPTS: usize = 4;

/// Draws a secret nonce for one signature from `rng`.
///
/// Upstream also negates the nonce so its public point has a square Y coordinate. Signing
/// normalises the nonce sign itself and partial verification compares X coordinates only, so the
/// signatures are the same either way and the negation is left out.
pub fn create_secnonce<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<SecretKey, CryptoError> {
    let mut bytes = Zeroizing::new([0u8; SecretKey::LEN]);
    for _ in 0..NONCE_ATTEMPTS {
        rng.fill_bytes(bytes.as_mut_slice());
        if let Ok(nonce) = SecretKey::from_bytes(bytes.as_slice()) {
            return Ok(nonce);
        }
    }
    Err(CryptoError::InvalidSecretKey)
}

/// This party's share of an aggregate signature over `msg`.
///
/// `nonce_sum` is the sum of every party's public nonce and `pubkey_sum`, when given, the sum of
/// every party's public key; both enter the challenge, so all parties must use the same values.
pub fn calculate_partial_sig(
    sec_key: &SecretKey,
    sec_nonce: &SecretKey,
    nonce_sum: &PublicKey,
    pubkey_sum: Option<&PublicKey>,
    msg: &Message,
) -> Result<Signature, CryptoError> {
    let signature = aggsig::sign_single(
        secp(),
        &msg.to_backend(),
        sec_key.as_backend(),
        Some(sec_nonce.as_backend()),
        None,
        Some(nonce_sum.as_backend()),
        pubkey_sum.map(PublicKey::as_backend),
        Some(nonce_sum.as_backend()),
    )?;
    from_backend(&signature)
}

/// Checks another party's partial signature against its public key and the shared sums.
///
/// Fails with [`CryptoError::SignatureMismatch`] when the signature, key, nonce sum, key sum or
/// message disagree with what was signed.
pub fn verify_partial_sig(
    sig: &Signature,
    pub_nonce_sum: &PublicKey,
    pubkey: &PublicKey,
    pubkey_sum: Option<&PublicKey>,
    msg: &Message,
) -> Result<(), CryptoError> {
    verify(
        sig,
        msg,
        Some(pub_nonce_sum),
        pubkey,
        pubkey_sum,
        Share::Partial,
    )
}

/// Adds partial signatures into the final signature, whose nonce is `nonce_sum`.
///
/// A wrong `nonce_sum` still produces a signature; it fails [`verify_completed_sig`].
pub fn add_signatures(
    partials: &[Signature],
    nonce_sum: &PublicKey,
) -> Result<Signature, CryptoError> {
    check_batch_len(partials.len(), MAX_SUM_TERMS, Item::Signature)?;
    let partials = partials
        .iter()
        .map(to_backend)
        .collect::<Result<Vec<_>, _>>()?;
    let signature =
        aggsig::add_signatures_single(secp(), partials.iter().collect(), nonce_sum.as_backend())?;
    from_backend(&signature)
}

/// Checks a final aggregate or single-signer signature against `pubkey`.
///
/// `pubkey_sum` must match the challenge key the signers used, or `None` when they used none.
///
/// Deliberately stricter than upstream's `verify_completed_sig`, which checks only the nonce's X
/// coordinate: this also requires a square Y, as the node's kernel verification
/// (`core/src/core/transaction.rs`) and `epic-wallet`'s participant-message verification
/// (`libwallet/src/slate.rs`) do. It rejects only signatures those checks reject too.
pub fn verify_completed_sig(
    sig: &Signature,
    pubkey: &PublicKey,
    pubkey_sum: Option<&PublicKey>,
    msg: &Message,
) -> Result<(), CryptoError> {
    verify(sig, msg, None, pubkey, pubkey_sum, Share::Completed)
}

/// A complete signature by one key, as participant messages are signed.
pub fn sign_single(
    msg: &Message,
    sec_key: &SecretKey,
    sec_nonce: &SecretKey,
    pubkey_sum: Option<&PublicKey>,
) -> Result<Signature, CryptoError> {
    let signature = aggsig::sign_single(
        secp(),
        &msg.to_backend(),
        sec_key.as_backend(),
        Some(sec_nonce.as_backend()),
        None,
        None,
        pubkey_sum.map(PublicKey::as_backend),
        None,
    )?;
    from_backend(&signature)
}

/// Checks a final signature against an excess commitment, read as a public key that is also the
/// challenge key, as kernel verification does.
pub fn verify_single_from_commit(
    sig: &Signature,
    msg: &Message,
    commit: &Commitment,
) -> Result<(), CryptoError> {
    let pubkey = commit
        .to_backend()
        .to_pubkey(secp())
        .map_err(|_| CryptoError::InvalidCommitment)
        .and_then(PublicKey::from_backend)?;
    verify(sig, msg, None, &pubkey, Some(&pubkey), Share::Completed)
}

/// How much of the aggregate a signature claims to be. Upstream passes this as `is_partial`.
#[derive(Clone, Copy)]
enum Share {
    /// One party's share: only the nonce's X coordinate is checked.
    Partial,
    /// The whole signature: the nonce must also have a square Y coordinate.
    Completed,
}

fn verify(
    sig: &Signature,
    msg: &Message,
    pub_nonce: Option<&PublicKey>,
    pubkey: &PublicKey,
    pubkey_sum: Option<&PublicKey>,
    share: Share,
) -> Result<(), CryptoError> {
    let is_partial = match share {
        Share::Partial => true,
        Share::Completed => false,
    };
    let valid = aggsig::verify_single(
        secp(),
        &to_backend(sig)?,
        &msg.to_backend(),
        pub_nonce.map(PublicKey::as_backend),
        pubkey.as_backend(),
        pubkey_sum.map(PublicKey::as_backend),
        None,
        is_partial,
    );
    if valid {
        Ok(())
    } else {
        Err(CryptoError::SignatureMismatch)
    }
}

// The wrapper's signature type is reached through its raw form, which carries the aggregate
// signature bytes unchanged in both directions.
fn to_backend(sig: &Signature) -> Result<BackendSignature, CryptoError> {
    BackendSignature::from_raw_data(&sig.to_raw()).map_err(|_| CryptoError::InvalidSignature)
}

fn from_backend(sig: &BackendSignature) -> Result<Signature, CryptoError> {
    Signature::from_raw(&sig.to_raw_data())
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};

    use super::*;

    /// Repeats a fixed byte pattern, so nonce creation is reproducible.
    struct RepeatingRng(u8);

    impl TryRng for RepeatingRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(u32::from_le_bytes([self.0; 4]))
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(u64::from_le_bytes([self.0; 8]))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            dst.fill(self.0);
            Ok(())
        }
    }

    impl TryCryptoRng for RepeatingRng {}

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn public(key: &SecretKey) -> PublicKey {
        PublicKey::from_secret_key(key).unwrap()
    }

    fn public_sum(keys: &[&SecretKey]) -> PublicKey {
        let keys: Vec<SecretKey> = keys.iter().map(|key| (*key).clone()).collect();
        public(&SecretKey::sum(&keys, &[]).unwrap())
    }

    struct Party {
        excess: SecretKey,
        nonce: SecretKey,
    }

    struct TwoParty {
        alice: Party,
        bob: Party,
        nonce_sum: PublicKey,
        excess_sum: PublicKey,
        msg: Message,
    }

    impl TwoParty {
        fn new() -> Self {
            let alice = Party {
                excess: secret(0x11),
                nonce: secret(0x12),
            };
            let bob = Party {
                excess: secret(0x21),
                nonce: secret(0x22),
            };
            Self {
                nonce_sum: public_sum(&[&alice.nonce, &bob.nonce]),
                excess_sum: public_sum(&[&alice.excess, &bob.excess]),
                alice,
                bob,
                msg: Message::from([0x33; 32]),
            }
        }

        fn partial(&self, party: &Party) -> Signature {
            calculate_partial_sig(
                &party.excess,
                &party.nonce,
                &self.nonce_sum,
                Some(&self.excess_sum),
                &self.msg,
            )
            .unwrap()
        }
    }

    fn with_last_byte_flipped(sig: &Signature) -> Signature {
        let mut raw = sig.to_raw();
        raw[63] ^= 1;
        Signature::from_raw(&raw).unwrap()
    }

    #[test]
    fn two_party_signature_verifies_against_the_excess_sum_and_commitment() {
        let flow = TwoParty::new();
        let (alice, bob) = (flow.partial(&flow.alice), flow.partial(&flow.bob));
        for (sig, party) in [(&alice, &flow.alice), (&bob, &flow.bob)] {
            assert_eq!(
                verify_partial_sig(
                    sig,
                    &flow.nonce_sum,
                    &public(&party.excess),
                    Some(&flow.excess_sum),
                    &flow.msg
                ),
                Ok(())
            );
        }

        let final_sig = add_signatures(&[alice, bob], &flow.nonce_sum).unwrap();
        assert_eq!(
            verify_completed_sig(
                &final_sig,
                &flow.excess_sum,
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Ok(())
        );
        let excess = Commitment::commit(
            0,
            &SecretKey::sum(&[flow.alice.excess.clone(), flow.bob.excess.clone()], &[]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_single_from_commit(&final_sig, &flow.msg, &excess),
            Ok(())
        );
    }

    #[test]
    fn rejects_tampered_partial_signature() {
        let flow = TwoParty::new();
        let tampered = with_last_byte_flipped(&flow.partial(&flow.bob));
        assert_eq!(
            verify_partial_sig(
                &tampered,
                &flow.nonce_sum,
                &public(&flow.bob.excess),
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_all_zero_partial_signature() {
        let flow = TwoParty::new();
        let zero = Signature::from_raw(&[0u8; 64]).unwrap();
        assert_eq!(
            verify_partial_sig(
                &zero,
                &flow.nonce_sum,
                &public(&flow.bob.excess),
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_partial_signature_checked_against_a_mismatched_nonce_sum() {
        let flow = TwoParty::new();
        let bob = flow.partial(&flow.bob);
        let bob_nonce_only = public(&flow.bob.nonce);
        assert_eq!(
            verify_partial_sig(
                &bob,
                &bob_nonce_only,
                &public(&flow.bob.excess),
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_partial_signature_made_over_a_mismatched_nonce_sum() {
        let flow = TwoParty::new();
        let wrong_sum = public_sum(&[&flow.alice.nonce, &secret(0x44)]);
        let bob = calculate_partial_sig(
            &flow.bob.excess,
            &flow.bob.nonce,
            &wrong_sum,
            Some(&flow.excess_sum),
            &flow.msg,
        )
        .unwrap();
        assert_eq!(
            verify_partial_sig(
                &bob,
                &flow.nonce_sum,
                &public(&flow.bob.excess),
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_final_signature_aggregated_over_a_mismatched_nonce_sum() {
        let flow = TwoParty::new();
        let partials = [flow.partial(&flow.alice), flow.partial(&flow.bob)];
        let final_sig = add_signatures(&partials, &public(&flow.bob.nonce)).unwrap();
        assert_eq!(
            verify_completed_sig(
                &final_sig,
                &flow.excess_sum,
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_final_signature_missing_a_partial() {
        let flow = TwoParty::new();
        let final_sig = add_signatures(&[flow.partial(&flow.alice)], &flow.nonce_sum).unwrap();
        assert_eq!(
            verify_completed_sig(
                &final_sig,
                &flow.excess_sum,
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_partial_signature_with_scalar_above_the_curve_order() {
        let flow = TwoParty::new();
        let mut raw = flow.partial(&flow.alice).to_raw();
        raw[32..].fill(0xff);
        let overflowing = Signature::from_raw(&raw).unwrap();
        assert_eq!(
            add_signatures(&[overflowing], &flow.nonce_sum),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            verify_partial_sig(
                &overflowing,
                &flow.nonce_sum,
                &public(&flow.alice.excess),
                Some(&flow.excess_sum),
                &flow.msg
            ),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_partial_signature_checked_as_complete() {
        // Over a one-party nonce sum the share and the complete signature differ only in the
        // nonce's Y coordinate. Exactly one of a nonce and its negation has a square Y, so one of
        // these two shares fails only the completed-signature Y rule.
        let (key, msg) = (secret(0x66), Message::from([0x67; 32]));
        let pubkey = public(&key);
        let nonce = secret(0x68);
        let negated = SecretKey::sum(&[], std::slice::from_ref(&nonce)).unwrap();
        for (nonce, nonce_sum) in [(&nonce, public(&negated)), (&negated, public(&nonce))] {
            let share =
                calculate_partial_sig(&key, nonce, &nonce_sum, Some(&pubkey), &msg).unwrap();
            assert_eq!(
                verify_partial_sig(&share, &nonce_sum, &pubkey, Some(&pubkey), &msg),
                Ok(())
            );
            assert_eq!(
                verify_completed_sig(&share, &pubkey, Some(&pubkey), &msg),
                Err(CryptoError::SignatureMismatch)
            );
        }
    }

    #[test]
    fn rejects_empty_and_oversized_signature_aggregation() {
        let flow = TwoParty::new();
        assert_eq!(
            add_signatures(&[], &flow.nonce_sum),
            Err(CryptoError::EmptyBatch {
                item: Item::Signature
            })
        );
        let partials = vec![flow.partial(&flow.alice); MAX_SUM_TERMS + 1];
        assert_eq!(
            add_signatures(&partials, &flow.nonce_sum),
            Err(CryptoError::BatchTooLarge {
                item: Item::Signature,
                max: MAX_SUM_TERMS,
                actual: MAX_SUM_TERMS + 1
            })
        );
    }

    #[test]
    fn single_signature_verifies_only_with_the_challenge_key_it_was_made_with() {
        let (key, nonce, msg) = (secret(0x55), secret(0x56), Message::from([0x57; 32]));
        let pubkey = public(&key);
        let with_key = sign_single(&msg, &key, &nonce, Some(&pubkey)).unwrap();
        let without_key = sign_single(&msg, &key, &nonce, None).unwrap();
        assert_eq!(
            verify_completed_sig(&with_key, &pubkey, Some(&pubkey), &msg),
            Ok(())
        );
        assert_eq!(
            verify_completed_sig(&without_key, &pubkey, None, &msg),
            Ok(())
        );
        assert_eq!(
            verify_completed_sig(&with_key, &pubkey, None, &msg),
            Err(CryptoError::SignatureMismatch)
        );
        assert_eq!(
            verify_completed_sig(&without_key, &pubkey, Some(&pubkey), &msg),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn signing_with_a_given_nonce_is_deterministic() {
        let (key, nonce, msg) = (secret(0x55), secret(0x56), Message::from([0x57; 32]));
        assert_eq!(
            sign_single(&msg, &key, &nonce, None),
            sign_single(&msg, &key, &nonce, None)
        );
        let flow = TwoParty::new();
        assert_eq!(flow.partial(&flow.alice), flow.partial(&flow.alice));
    }

    #[test]
    fn rejects_signature_against_another_commitment() {
        let (key, nonce, msg) = (secret(0x55), secret(0x56), Message::from([0x57; 32]));
        let pubkey = public(&key);
        let sig = sign_single(&msg, &key, &nonce, Some(&pubkey)).unwrap();
        let own = Commitment::commit(0, &key).unwrap();
        let other = Commitment::commit(0, &secret(0x58)).unwrap();
        assert_eq!(verify_single_from_commit(&sig, &msg, &own), Ok(()));
        assert_eq!(
            verify_single_from_commit(&sig, &msg, &other),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn creates_the_nonce_the_rng_supplies() {
        let nonce = create_secnonce(&mut RepeatingRng(0x5a)).unwrap();
        assert_eq!(nonce.expose_bytes(), &[0x5a; 32]);
    }

    #[test]
    fn rejects_rng_that_never_yields_a_valid_scalar() {
        assert_eq!(
            create_secnonce(&mut RepeatingRng(0)).err(),
            Some(CryptoError::InvalidSecretKey)
        );
        assert_eq!(
            create_secnonce(&mut RepeatingRng(0xff)).err(),
            Some(CryptoError::InvalidSecretKey)
        );
    }
}
