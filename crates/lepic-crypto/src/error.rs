use std::fmt;

use secp256k1zkp::Error as BackendError;

/// The value a [`CryptoError`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Item {
    SecretKey,
    PublicKey,
    Commitment,
    Signature,
    EcdsaSignature,
    RangeProof,
    ProofMessage,
    Message,
}

impl Item {
    fn as_str(self) -> &'static str {
        match self {
            Self::SecretKey => "secret key",
            Self::PublicKey => "public key",
            Self::Commitment => "commitment",
            Self::Signature => "signature",
            Self::EcdsaSignature => "ecdsa signature",
            Self::RangeProof => "range proof",
            Self::ProofMessage => "proof message",
            Self::Message => "message",
        }
    }
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("{item} has {actual} bytes, expected {expected}")]
    WrongLength {
        item: Item,
        expected: usize,
        actual: usize,
    },
    #[error("{item} has {actual} bytes, expected {min} to {max}")]
    LengthOutOfRange {
        item: Item,
        min: usize,
        max: usize,
        actual: usize,
    },
    #[error("{item} is not valid hex")]
    InvalidHex { item: Item },
    #[error("secret key is zero or not below the curve order")]
    InvalidSecretKey,
    #[error("public key is not a valid curve point")]
    InvalidPublicKey,
    #[error("commitment is not a valid curve point")]
    InvalidCommitment,
    #[error("signature encoding is invalid")]
    InvalidSignature,
    #[error("signature does not verify")]
    SignatureMismatch,
    #[error("range proof does not verify")]
    InvalidRangeProof,
    #[error("range proof creation failed")]
    RangeProofCreationFailed,
    #[error("range proof could not be rewound with this nonce")]
    RangeProofRewindFailed,
    #[error("batch of {item} is empty")]
    EmptyBatch { item: Item },
    #[error("batch of {actual} {item} exceeds the limit of {max}")]
    BatchTooLarge {
        item: Item,
        max: usize,
        actual: usize,
    },
    #[error("sum is zero")]
    SumIsZero,
    #[error("secp256k1 operation failed")]
    Backend,
    #[error("secp256k1 context was created before it could be randomized")]
    ContextAlreadyCreated,
}

impl From<BackendError> for CryptoError {
    fn from(error: BackendError) -> Self {
        match error {
            BackendError::InvalidSecretKey => Self::InvalidSecretKey,
            BackendError::InvalidPublicKey => Self::InvalidPublicKey,
            BackendError::InvalidCommit => Self::InvalidCommitment,
            BackendError::InvalidSignature => Self::InvalidSignature,
            BackendError::IncorrectSignature => Self::SignatureMismatch,
            BackendError::InvalidRangeProof => Self::InvalidRangeProof,
            BackendError::IncorrectCommitSum => Self::SumIsZero,
            BackendError::IncapableContext
            | BackendError::InvalidMessage
            | BackendError::InvalidRecoveryId
            | BackendError::PartialSigFailure
            | BackendError::SigSubtractionFailure => Self::Backend,
        }
    }
}
