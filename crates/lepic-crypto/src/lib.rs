//! Safe boundary over the secp256k1-zkp wrapper for commitments, proofs and signatures.
//!
//! Every value is checked when it is constructed, so the wrapper only ever sees well-formed keys,
//! points and lengths, and every wrapper failure comes back as a [`CryptoError`].

pub mod aggsig;
mod blinding;
mod commitment;
mod context;
mod error;
mod hex;
mod limits;
mod proof;
mod public_key;
mod secret;
mod signature;

pub use commitment::Commitment;
pub use error::{CryptoError, Item};
pub use limits::{MAX_PROOF_BATCH, MAX_SUM_TERMS};
pub use proof::{CommittedProof, ProofMessage, RangeProof, RewoundProof};
pub use public_key::PublicKey;
pub use secret::{SecretKey, SharedSecret};
pub use signature::{EcdsaSignature, Message, Signature};
