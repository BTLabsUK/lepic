use std::sync::OnceLock;

use secp256k1zkp::pedersen::RangeProof as BackendRangeProof;
use secp256k1zkp::{ContextFlag, Secp256k1};

static CONTEXT: OnceLock<Secp256k1> = OnceLock::new();

/// The one secp256k1 context, able to sign, verify and commit.
pub(crate) fn secp() -> &'static Secp256k1 {
    CONTEXT.get_or_init(|| {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        initialise_bulletproof_generators(&secp);
        secp
    })
}

// The wrapper creates its bulletproof generators on first use through an unsynchronised static.
// Running one bulletproof call here, inside the `OnceLock` initialiser, makes that first use happen
// exactly once and before any other thread can reach a bulletproof function.
fn initialise_bulletproof_generators(secp: &Secp256k1) {
    if let Ok(commitment) = secp.commit_value(1) {
        let _rejected = secp.verify_bullet_proof(commitment, BackendRangeProof::zero(), None);
    }
}
