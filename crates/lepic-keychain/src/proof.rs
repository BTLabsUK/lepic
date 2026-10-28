// Portions Copyright 2019 The Grin Developers
// Ported from EpicCash/epic core/src/libtx/proof.rs (Apache-2.0); see NOTICE and upstream.toml.

//! Range proof builders: the nonces and message a wallet puts into an output's bulletproof, and
//! the rewind that recognises the wallet's own outputs, as the node's `libtx::proof` does.

use std::fmt;

use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::{Blake2b256, Blake2bMac};
use lepic_crypto::{Commitment, CryptoError, ProofMessage, RangeProof, SecretKey};
use lepic_primitives::output::{Output, OutputFeatures};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::identifier::{Identifier, MAX_DEPTH};
use crate::keychain::{Keychain, KeychainError, SwitchCommitment};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProofError {
    #[error("output key derivation failed")]
    Keychain(#[from] KeychainError),
    #[error("range proof operation failed")]
    Crypto(#[from] CryptoError),
    #[error("range proof nonce is not a valid secret key")]
    InvalidNonce,
}

/// What rewinding one of the wallet's own range proofs recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewoundOutput {
    pub amount: u64,
    pub identifier: Identifier,
    pub switch: SwitchCommitment,
}

/// A scheme for the nonces and message of a wallet's range proofs.
pub trait ProofBuild {
    /// The nonce that lets the wallet rewind the proof of `commit`.
    fn rewind_nonce(&self, commit: &Commitment) -> Result<SecretKey, ProofError>;

    /// The nonce that blinds the output key inside the proof of `commit`.
    fn private_nonce(&self, commit: &Commitment) -> Result<SecretKey, ProofError>;

    /// The 20 bytes the proof carries for its owner.
    fn proof_message(&self, id: &Identifier, switch: SwitchCommitment) -> ProofMessage;

    /// The key path and switch type of a rewound output when it belongs to this wallet: the
    /// message must parse and the commitment it implies must equal `commit`.
    fn check_output(
        &self,
        commit: &Commitment,
        amount: u64,
        message: &ProofMessage,
    ) -> Result<Option<(Identifier, SwitchCommitment)>, ProofError>;
}

/// The proof scheme every new output uses.
pub struct ProofBuilder<'a> {
    keychain: &'a Keychain,
    rewind_hash: Zeroizing<[u8; 32]>,
    private_hash: Zeroizing<[u8; 32]>,
}

impl<'a> ProofBuilder<'a> {
    pub fn new(keychain: &'a Keychain) -> Result<Self, ProofError> {
        let mut builder = Self {
            keychain,
            rewind_hash: Zeroizing::new([0u8; 32]),
            private_hash: Zeroizing::new([0u8; 32]),
        };
        let root = keychain.derive_key(0, &Identifier::ROOT, SwitchCommitment::None)?;
        blake2b_256_into(root.expose_bytes(), &mut builder.private_hash);
        let public_root = keychain.master_public_key()?.to_bytes();
        blake2b_256_into(&public_root, &mut builder.rewind_hash);
        Ok(builder)
    }
}

/// Unkeyed BLAKE2b-256 of `data`, written straight into `out` so the digest of a secret never
/// sits in an unwiped temporary. The hasher state wipes itself on drop.
fn blake2b_256_into(data: &[u8], out: &mut [u8; 32]) {
    let mut state = Blake2b256::default();
    state.update(data);
    state.finalize_into(out.into());
}

impl ProofBuild for ProofBuilder<'_> {
    fn rewind_nonce(&self, commit: &Commitment) -> Result<SecretKey, ProofError> {
        nonce(commit, self.rewind_hash.as_slice())
    }

    fn private_nonce(&self, commit: &Commitment) -> Result<SecretKey, ProofError> {
        nonce(commit, self.private_hash.as_slice())
    }

    /// Byte 0 is reserved, byte 1 the wallet type (0, standard), byte 2 the switch type and
    /// bytes 3 to 19 the identifier, depth first.
    fn proof_message(&self, id: &Identifier, switch: SwitchCommitment) -> ProofMessage {
        let mut message = [0u8; ProofMessage::LEN];
        message[2] = switch.code();
        message[3..].copy_from_slice(&id.to_bytes());
        ProofMessage::from(message)
    }

    fn check_output(
        &self,
        commit: &Commitment,
        amount: u64,
        message: &ProofMessage,
    ) -> Result<Option<(Identifier, SwitchCommitment)>, ProofError> {
        let [0, 0, switch, depth, path @ ..] = *message.as_bytes() else {
            return Ok(None);
        };
        let Ok(switch) = SwitchCommitment::try_from(switch) else {
            return Ok(None);
        };
        // Upstream clamps the depth rather than rejecting the message.
        let Ok(id) = Identifier::from_serialized_path(depth.min(MAX_DEPTH), path) else {
            return Ok(None);
        };
        let expected = self.keychain.commit(amount, &id, switch)?;
        Ok((&expected == commit).then_some((id, switch)))
    }
}

impl fmt::Debug for ProofBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProofBuilder([redacted])")
    }
}

/// The proof scheme of outputs created before the first hard fork. LEPIC only rewinds with it;
/// creating legacy proofs exists to prove the port against upstream.
pub struct LegacyProofBuilder<'a> {
    keychain: &'a Keychain,
    root_key: SecretKey,
}

impl<'a> LegacyProofBuilder<'a> {
    pub fn new(keychain: &'a Keychain) -> Result<Self, ProofError> {
        let root_key = keychain.derive_key(0, &Identifier::ROOT, SwitchCommitment::Regular)?;
        Ok(Self { keychain, root_key })
    }
}

/// Every legacy output is a depth-3 path with a regular switch commitment; the message carries
/// neither.
const LEGACY_DEPTH: u8 = 3;

impl ProofBuild for LegacyProofBuilder<'_> {
    fn rewind_nonce(&self, commit: &Commitment) -> Result<SecretKey, ProofError> {
        nonce(commit, self.root_key.expose_bytes())
    }

    fn private_nonce(&self, commit: &Commitment) -> Result<SecretKey, ProofError> {
        nonce(commit, self.root_key.expose_bytes())
    }

    /// Bytes 0 to 3 are zero and bytes 4 to 19 the path without its depth.
    fn proof_message(&self, id: &Identifier, _switch: SwitchCommitment) -> ProofMessage {
        let mut message = [0u8; ProofMessage::LEN];
        message[4..].copy_from_slice(&id.serialize_path());
        ProofMessage::from(message)
    }

    fn check_output(
        &self,
        commit: &Commitment,
        amount: u64,
        message: &ProofMessage,
    ) -> Result<Option<(Identifier, SwitchCommitment)>, ProofError> {
        let [0, 0, 0, 0, path @ ..] = *message.as_bytes() else {
            return Ok(None);
        };
        let Ok(id) = Identifier::from_serialized_path(LEGACY_DEPTH, path) else {
            return Ok(None);
        };
        let expected = self
            .keychain
            .commit(amount, &id, SwitchCommitment::Regular)?;
        Ok((&expected == commit).then_some((id, SwitchCommitment::Regular)))
    }
}

impl fmt::Debug for LegacyProofBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyProofBuilder([redacted])")
    }
}

/// BLAKE2b-256 keyed by the commitment over `secret`.
fn nonce(commit: &Commitment, secret: &[u8]) -> Result<SecretKey, ProofError> {
    let mut state = <Blake2bMac<U32> as KeyInit>::new_from_slice(commit.as_bytes())
        .map_err(|_| ProofError::InvalidNonce)?;
    state.update(secret);
    let mut hash = Zeroizing::new([0u8; 32]);
    state.finalize_into((&mut *hash).into());
    SecretKey::from_bytes(hash.as_slice()).map_err(|_| ProofError::InvalidNonce)
}

/// The range proof for the output `keychain` derives for `amount` at `id`, built by `builder`.
pub fn create_proof<B: ProofBuild>(
    keychain: &Keychain,
    builder: &B,
    amount: u64,
    id: &Identifier,
    switch: SwitchCommitment,
) -> Result<RangeProof, ProofError> {
    let commit = keychain.commit(amount, id, switch)?;
    let blinding = keychain.derive_key(amount, id, switch)?;
    let rewind_nonce = builder.rewind_nonce(&commit)?;
    let private_nonce = builder.private_nonce(&commit)?;
    let message = builder.proof_message(id, switch);
    Ok(RangeProof::create(
        amount,
        &blinding,
        &rewind_nonce,
        &private_nonce,
        &message,
    )?)
}

/// A plain output for `amount` at `id` with its range proof.
pub fn create_output<B: ProofBuild>(
    keychain: &Keychain,
    builder: &B,
    amount: u64,
    id: &Identifier,
    switch: SwitchCommitment,
) -> Result<Output, ProofError> {
    let commitment = keychain.commit(amount, id, switch)?;
    let proof = create_proof(keychain, builder, amount, id, switch)?;
    Ok(Output::new(OutputFeatures::Plain, commitment, proof))
}

/// Recovers amount, path and switch type from a proof `builder`'s wallet made. A proof that is
/// not the wallet's own, including any proof another wallet made, gives `None`.
pub fn rewind<B: ProofBuild>(
    builder: &B,
    commit: &Commitment,
    proof: &RangeProof,
) -> Result<Option<RewoundOutput>, ProofError> {
    let nonce = builder.rewind_nonce(commit)?;
    let rewound = match proof.rewind(commit, &nonce) {
        Ok(rewound) => rewound,
        Err(CryptoError::RangeProofRewindFailed) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let owned = builder.check_output(commit, rewound.value, &rewound.message)?;
    Ok(owned.map(|(identifier, switch)| RewoundOutput {
        amount: rewound.value,
        identifier,
        switch,
    }))
}

/// Both proof schemes of one wallet, for recognising its outputs during restore.
#[derive(Debug)]
pub struct OutputRewinder<'a> {
    current: ProofBuilder<'a>,
    legacy: LegacyProofBuilder<'a>,
}

impl<'a> OutputRewinder<'a> {
    pub fn new(keychain: &'a Keychain) -> Result<Self, ProofError> {
        Ok(Self {
            current: ProofBuilder::new(keychain)?,
            legacy: LegacyProofBuilder::new(keychain)?,
        })
    }

    /// Rewinds with [`ProofBuilder`] and, when that does not recognise the output, with
    /// [`LegacyProofBuilder`], in the order `epic-wallet` restores.
    pub fn rewind(
        &self,
        commit: &Commitment,
        proof: &RangeProof,
    ) -> Result<Option<RewoundOutput>, ProofError> {
        match rewind(&self.current, commit, proof)? {
            Some(output) => Ok(Some(output)),
            None => rewind(&self.legacy, commit, proof),
        }
    }
}

#[cfg(test)]
mod tests {
    use lepic_primitives::hash::{blake2b_256, blake2b_256_keyed};

    use super::*;

    #[test]
    fn hash_written_in_place_equals_the_primitives_hash() {
        for data in [&b""[..], b"abc", &[0x5a; 200]] {
            let mut out = [0u8; 32];
            blake2b_256_into(data, &mut out);
            assert_eq!(&out, blake2b_256(data).as_bytes());
        }
    }

    #[test]
    fn nonce_is_the_hash_of_the_secret_keyed_by_the_commitment() {
        let mut blinding = [0u8; 32];
        blinding[31] = 9;
        let blinding = SecretKey::from_bytes(&blinding).unwrap();
        let commit = Commitment::commit(5, &blinding).unwrap();
        let secret = [0x33; 32];
        let expected = blake2b_256_keyed(commit.as_bytes(), &secret).unwrap();
        assert_eq!(
            nonce(&commit, &secret).unwrap().expose_bytes(),
            expected.as_bytes()
        );
    }
}
