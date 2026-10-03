use std::sync::OnceLock;

use rand_core::CryptoRng;
use secp256k1zkp::pedersen::RangeProof as BackendRangeProof;
use secp256k1zkp::rand::RngCore as BackendRngCore;
use secp256k1zkp::{ContextFlag, Secp256k1};
use zeroize::Zeroizing;

use crate::error::CryptoError;

static CONTEXT: OnceLock<Secp256k1> = OnceLock::new();

const SEED_LEN: usize = 32;

/// The one secp256k1 context, able to sign, verify and commit.
///
/// Created without blinding on first use unless [`randomize_context`] created it first.
pub(crate) fn secp() -> &'static Secp256k1 {
    CONTEXT.get_or_init(|| with_generators(Secp256k1::with_caps(ContextFlag::Commit)))
}

/// Creates the secp256k1 context blinded with 32 bytes from `rng`, as upstream randomizes its
/// context, so signing and key generation resist timing and power side channels.
///
/// Call it once at start, before any other function of this crate. Fails with
/// [`CryptoError::ContextAlreadyCreated`] when the context already exists; it then stays
/// unblinded, which changes no result. `rng` is not drawn from when the context existed before
/// the call; when another thread creates it during the call, the drawn seed is discarded.
pub fn randomize_context<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<(), CryptoError> {
    if CONTEXT.get().is_some() {
        return Err(CryptoError::ContextAlreadyCreated);
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    rng.fill_bytes(seed.as_mut_slice());
    CONTEXT
        .set(blinded_context(&mut SeedSource(&seed)))
        .map_err(|_| CryptoError::ContextAlreadyCreated)
}

/// A context blinded with the seed the wrapper's `randomize` pulls from `source`.
fn blinded_context<S: BackendRngCore>(source: &mut S) -> Secp256k1 {
    let mut secp = Secp256k1::with_caps(ContextFlag::Commit);
    secp.randomize(source);
    with_generators(secp)
}

fn with_generators(secp: Secp256k1) -> Secp256k1 {
    initialise_bulletproof_generators(&secp);
    secp
}

// Bulletproof generators must exist before two threads can call a bulletproof function. One call
// while creating the context creates them.
fn initialise_bulletproof_generators(secp: &Secp256k1) {
    if let Ok(commitment) = secp.commit_value(1) {
        let _rejected = secp.verify_bullet_proof(commitment, BackendRangeProof::zero(), None);
    }
}

/// Hands the wrapper's `randomize` the caller's seed through the RNG trait of the `rand` version
/// the wrapper pins, so this crate never depends on that version itself.
struct SeedSource<'a>(&'a Zeroizing<[u8; SEED_LEN]>);

impl BackendRngCore for SeedSource<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = Zeroizing::new([0u8; 4]);
        self.fill_bytes(bytes.as_mut_slice());
        u32::from_le_bytes(*bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = Zeroizing::new([0u8; 8]);
        self.fill_bytes(bytes.as_mut_slice());
        u64::from_le_bytes(*bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for (out, byte) in dst.iter_mut().zip(self.0.iter()) {
            *out = *byte;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Passes everything through from `inner` and records what it handed out.
    struct Recording<S> {
        inner: S,
        handed: Vec<u8>,
    }

    impl<S: BackendRngCore> BackendRngCore for Recording<S> {
        fn next_u32(&mut self) -> u32 {
            let value = self.inner.next_u32();
            self.handed.extend_from_slice(&value.to_le_bytes());
            value
        }

        fn next_u64(&mut self) -> u64 {
            let value = self.inner.next_u64();
            self.handed.extend_from_slice(&value.to_le_bytes());
            value
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            self.inner.fill_bytes(dst);
            self.handed.extend_from_slice(dst);
        }
    }

    #[test]
    fn blinding_pulls_exactly_the_whole_seed_in_order() {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        for (byte, value) in seed.iter_mut().zip(1u8..) {
            *byte = value;
        }
        let mut source = Recording {
            inner: SeedSource(&seed),
            handed: Vec::new(),
        };
        let secp = blinded_context(&mut source);
        assert_eq!(source.handed.as_slice(), seed.as_slice());
        assert!(secp.commit_value(1).is_ok());
    }
}
