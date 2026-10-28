use std::fmt;

use secp256k1zkp::constants::{BULLET_PROOF_MSG_SIZE, MAX_PROOF_SIZE, SINGLE_BULLET_PROOF_SIZE};
use secp256k1zkp::pedersen::{
    ProofMessage as BackendProofMessage, RangeProof as BackendRangeProof,
};

use crate::commitment::Commitment;
use crate::context::secp;
use crate::error::{CryptoError, Item};
use crate::hex;
use crate::item_hex;
use crate::limits::{MAX_PROOF_BATCH, check_batch_len};
use crate::secret::SecretKey;

/// The 20 bytes a bulletproof carries for its owner to recover by rewinding.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProofMessage([u8; BULLET_PROOF_MSG_SIZE]);

impl ProofMessage {
    pub const LEN: usize = BULLET_PROOF_MSG_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        <[u8; BULLET_PROOF_MSG_SIZE]>::try_from(bytes)
            .map(Self)
            .map_err(|_| CryptoError::WrongLength {
                item: Item::ProofMessage,
                expected: Self::LEN,
                actual: bytes.len(),
            })
    }

    pub fn as_bytes(&self) -> &[u8; BULLET_PROOF_MSG_SIZE] {
        &self.0
    }
}

impl From<[u8; BULLET_PROOF_MSG_SIZE]> for ProofMessage {
    fn from(bytes: [u8; BULLET_PROOF_MSG_SIZE]) -> Self {
        Self(bytes)
    }
}

/// A range proof of at most [`RangeProof::MAX_LEN`] bytes.
///
/// Any length from 1 to the maximum parses, as upstream accepts; only a proof of exactly
/// [`RangeProof::BULLETPROOF_LEN`] bytes can verify.
#[derive(Clone)]
pub struct RangeProof {
    bytes: [u8; MAX_PROOF_SIZE],
    len: usize,
}

/// A commitment and the range proof that claims its value is in range, for batch verification.
#[derive(Clone, Copy, Debug)]
pub struct CommittedProof<'a> {
    pub commitment: &'a Commitment,
    pub proof: &'a RangeProof,
}

/// What the owner of a range proof recovers by rewinding it.
///
/// The wrapper also reports a blinding factor, but it is only correct when the proof was made
/// with equal rewind and private nonces, so it is not exposed; owners re-derive the key from the
/// identifier in the message, as upstream does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RewoundProof {
    pub value: u64,
    pub message: ProofMessage,
}

impl RangeProof {
    pub const MAX_LEN: usize = MAX_PROOF_SIZE;
    pub const BULLETPROOF_LEN: usize = SINGLE_BULLET_PROOF_SIZE;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut buffer = [0u8; MAX_PROOF_SIZE];
        let target = buffer
            .get_mut(..bytes.len())
            .filter(|_| !bytes.is_empty())
            .ok_or(CryptoError::LengthOutOfRange {
                item: Item::RangeProof,
                min: 1,
                max: Self::MAX_LEN,
                actual: bytes.len(),
            })?;
        target.copy_from_slice(bytes);
        Ok(Self {
            bytes: buffer,
            len: bytes.len(),
        })
    }

    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        Self::from_bytes(&item_hex::decode_bounded(
            hex,
            1,
            Self::MAX_LEN,
            Item::RangeProof,
        )?)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Creates a 64-bit bulletproof for `commit(value, blinding)`. The nonces decide every random
    /// choice, so equal inputs give an identical proof; whoever knows `rewind_nonce` can rewind it.
    pub fn create(
        value: u64,
        blinding: &SecretKey,
        rewind_nonce: &SecretKey,
        private_nonce: &SecretKey,
        message: &ProofMessage,
    ) -> Result<Self, CryptoError> {
        let backend = secp().bullet_proof(
            value,
            blinding.to_backend(),
            rewind_nonce.to_backend(),
            private_nonce.to_backend(),
            None,
            Some(BackendProofMessage::from_bytes(message.as_bytes())),
        );
        let proof = backend
            .proof
            .get(..backend.plen)
            .ok_or(CryptoError::RangeProofCreationFailed)
            .and_then(Self::from_bytes)?;
        // The wrapper discards the prover's status code, so verifying is the only way to tell a
        // failed proof from a good one.
        let commitment = Commitment::commit(value, blinding)?;
        proof
            .verify(&commitment)
            .map_err(|_| CryptoError::RangeProofCreationFailed)?;
        Ok(proof)
    }

    pub fn verify(&self, commitment: &Commitment) -> Result<(), CryptoError> {
        self.check_bulletproof_len()?;
        secp()
            .verify_bullet_proof(commitment.to_backend(), self.to_backend(), None)
            .map(|_| ())
            .map_err(|_| CryptoError::InvalidRangeProof)
    }

    /// Verifies all proofs at once. Fails if any one is invalid, without saying which.
    pub fn verify_batch(items: &[CommittedProof<'_>]) -> Result<(), CryptoError> {
        check_batch_len(items.len(), MAX_PROOF_BATCH, Item::RangeProof)?;
        for item in items {
            item.proof.check_bulletproof_len()?;
        }
        let commitments = items
            .iter()
            .map(|item| item.commitment.to_backend())
            .collect();
        let proofs = items.iter().map(|item| item.proof.to_backend()).collect();
        secp()
            .verify_bullet_proof_multi(commitments, proofs, None)
            .map(|_| ())
            .map_err(|_| CryptoError::InvalidRangeProof)
    }

    /// Recovers value and message. Fails with
    /// [`CryptoError::RangeProofRewindFailed`] when the nonce is not the one the proof was made
    /// with, which is how a wallet tells its own outputs from others.
    pub fn rewind(
        &self,
        commitment: &Commitment,
        rewind_nonce: &SecretKey,
    ) -> Result<RewoundProof, CryptoError> {
        self.check_bulletproof_len()
            .map_err(|_| CryptoError::RangeProofRewindFailed)?;
        let info = secp()
            .rewind_bullet_proof(
                commitment.to_backend(),
                rewind_nonce.to_backend(),
                None,
                self.to_backend(),
            )
            .map_err(|_| CryptoError::RangeProofRewindFailed)?;
        Ok(RewoundProof {
            value: info.value,
            message: ProofMessage::from_bytes(info.message.as_bytes())?,
        })
    }

    fn check_bulletproof_len(&self) -> Result<(), CryptoError> {
        if self.len == Self::BULLETPROOF_LEN {
            Ok(())
        } else {
            Err(CryptoError::InvalidRangeProof)
        }
    }

    fn to_backend(&self) -> BackendRangeProof {
        BackendRangeProof {
            proof: self.bytes,
            plen: self.len,
        }
    }
}

impl PartialEq for RangeProof {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for RangeProof {}

impl fmt::Debug for RangeProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RangeProof({} bytes)", self.len)
    }
}
