//! Smoke area: proves the harness end to end with one deterministic case, the hash of a plain
//! kernel serialized by the reference node code.

use epic_core::core::hash::Hashed;
use epic_core::core::transaction::{KernelFeatures, TxKernel};
use epic_core::libtx::aggsig;
use epic_core::ser::{self, ProtocolVersion};
use epic_util::secp::key::{PublicKey, SecretKey};
use epic_util::secp::{ContextFlag, Secp256k1};
use serde::Serialize;

use crate::{Error, Pins, Rendered, hex, render};

const AREA: &str = "smoke";

// Fixed test-only keys. The signature nonce is passed in, so the reference signer draws no
// randomness and the case regenerates byte for byte.
const FEE: u64 = 7_000_000;
const EXCESS_BLIND: [u8; 32] = [0x11; 32];
const SIG_NONCE: [u8; 32] = [0x22; 32];

#[derive(Serialize)]
struct Inputs {
    features: &'static str,
    fee: String,
    excess_blind: String,
    sig_nonce: String,
}

/// `serialized_v1` is also the preimage of `hash`: the node hashes every kernel in the v1 layout
/// whatever protocol version it speaks. `excess_sig` is the compact form used in JSON; the binary
/// layouts carry the wrapper's internal form, each 32-byte half byte-reversed.
#[derive(Serialize)]
struct Expected {
    excess: String,
    sig_msg: String,
    excess_sig: String,
    serialized_v1: String,
    serialized_v2: String,
    hash: String,
}

pub(crate) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let blind =
        SecretKey::from_slice(&secp, &EXCESS_BLIND).map_err(Error::reference("excess blind"))?;
    let nonce = SecretKey::from_slice(&secp, &SIG_NONCE).map_err(Error::reference("nonce"))?;
    let public_blind =
        PublicKey::from_secret_key(&secp, &blind).map_err(Error::reference("public blind"))?;

    let features = KernelFeatures::Plain { fee: FEE };
    let excess = secp
        .commit(0, blind.clone())
        .map_err(Error::reference("excess"))?;
    let sig_msg = features
        .kernel_sig_msg()
        .map_err(Error::reference("signature message"))?;
    let excess_sig =
        aggsig::sign_single(&secp, &sig_msg, &blind, Some(&nonce), Some(&public_blind))
            .map_err(Error::reference("excess signature"))?;
    let kernel = TxKernel {
        features,
        excess,
        excess_sig,
    };
    kernel
        .verify()
        .map_err(Error::reference("kernel verification"))?;

    let serialized_v1 =
        ser::ser_vec(&kernel, ProtocolVersion(1)).map_err(Error::reference("v1 serialization"))?;
    let serialized_v2 =
        ser::ser_vec(&kernel, ProtocolVersion(2)).map_err(Error::reference("v2 serialization"))?;

    let inputs = Inputs {
        features: "Plain",
        fee: FEE.to_string(),
        excess_blind: hex(EXCESS_BLIND),
        sig_nonce: hex(SIG_NONCE),
    };
    let expected = Expected {
        excess: hex(kernel.excess),
        sig_msg: hex(sig_msg),
        excess_sig: hex(kernel.excess_sig.serialize_compact(&secp)),
        serialized_v1: hex(serialized_v1),
        serialized_v2: hex(serialized_v2),
        hash: hex(kernel.hash().as_bytes()),
    };
    Ok(vec![render(
        AREA,
        "plain_kernel_hash",
        &pins.node,
        inputs,
        expected,
    )?])
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{DEFAULT_OUT, LOCKFILE};

    #[test]
    fn regenerated_vectors_match_committed_files() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins::from_lockfile(LOCKFILE)?;
        for vector in generate(&pins)? {
            let path = Path::new(DEFAULT_OUT)
                .join(AREA)
                .join(format!("{}.json", vector.name));
            assert_eq!(std::fs::read(&path)?, vector.bytes, "{}", path.display());
        }
        Ok(())
    }
}
