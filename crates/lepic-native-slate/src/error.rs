// SPDX-License-Identifier: Apache-2.0
//! Why a `lepic.v1` slate is refused, one variant per rule, so tests and callers can tell the
//! rules apart.

use lepic_crypto::CryptoError;
use lepic_primitives::params::Network;
use lepic_slate::error::{ProofAddressError, SlateError};
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use thiserror::Error;

/// A `lepic.v1` slate that cannot be decoded, or a JSON view that does not describe one.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NativeError {
    #[error("native slate of {len} bytes exceeds the limit of {max}")]
    TooLarge { len: usize, max: usize },
    #[error("input does not start with the lepic.v1 magic")]
    Magic,
    #[error("lepic.v1 version {version} is not supported")]
    Version { version: u8 },
    #[error("network byte {byte:#04x} names no network")]
    UnknownNetwork { byte: u8 },
    #[error("slate is for {found}, expected {expected}")]
    WrongNetwork { expected: Network, found: Network },
    #[error("stage byte {byte:#04x} names no stage")]
    UnknownStage { byte: u8 },
    #[error("flags {flags:#04x} set a reserved bit")]
    ReservedFlag { flags: u8 },
    #[error("kernel features byte {byte:#04x} is neither plain nor height locked")]
    KernelFeatures { byte: u8 },
    #[error("block header version {found} differs from {expected}, the version at the height")]
    HeaderVersion { found: u16, expected: u16 },
    #[error("height-locked slate has a zero lock height")]
    ZeroLockHeight,
    #[error("payment proof flag is set in the invoice flow")]
    ProofInInvoice,
    #[error("{role} message flag is set but the {role} is absent at stage {stage}")]
    MessageWithoutParticipant { stage: Stage, role: Role },
    #[error("{role} message flag is set at stage {stage}, where the initiator sends none")]
    InitiatorMessage { stage: Stage, role: Role },
    #[error("input ends inside {field}")]
    Truncated { field: &'static str },
    #[error("stage {stage} carries inputs or outputs")]
    BodyAtProposal { stage: Stage },
    #[error("body weight {weight} exceeds the transaction limit {max}")]
    TooHeavy { weight: u64, max: u64 },
    #[error("{field} features byte {byte:#04x} is neither plain nor coinbase")]
    OutputFeatures { field: &'static str, byte: u8 },
    #[error("{field} is not a valid curve value")]
    Crypto {
        field: &'static str,
        #[source]
        source: CryptoError,
    },
    #[error("{field} is not a valid payment proof address")]
    ProofAddress {
        field: &'static str,
        #[source]
        source: ProofAddressError,
    },
    #[error("{role} message of {len} bytes exceeds {max} bytes")]
    MessageTooLong { role: Role, len: usize, max: usize },
    #[error("{role} message is not UTF-8")]
    MessageNotUtf8 { role: Role },
    #[error("a {len}-byte range proof cannot be written; lepic.v1 carries {expected}-byte proofs")]
    RangeProofLength { len: usize, expected: usize },
    #[error("extension tail is invalid")]
    Tail(#[from] TailError),
    #[error("slate is not valid")]
    Model(#[from] SlateError),
    #[error("JSON view field {field} is invalid")]
    View { field: &'static str },
    #[error("JSON view disagrees with the slate it describes")]
    ViewMismatch,
}

/// An extension tail, or one of its records, that breaks the tail rule.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TailError {
    #[error("tail record runs past the end of the input")]
    Truncated,
    #[error("tail record type {found:#04x} follows {previous:#04x}; types must increase")]
    Order { previous: u8, found: u8 },
    #[error("tail record type {record_type:#04x} is unknown and below 0x80")]
    UnknownRequired { record_type: u8 },
    #[error("tail record type {record_type:#04x} has a {len}-byte value")]
    Length { record_type: u8, len: usize },
    #[error("reply mailbox key is not a valid public key")]
    MailboxKey(#[source] CryptoError),
    #[error("reply mailbox address is not a relay domain with an optional port")]
    MailboxAddress,
    #[error("reply mailbox is given without a reply key")]
    MailboxWithoutKey,
    #[error("tail record type {record_type:#04x} is not allowed at stage {stage}")]
    NotAllowed { record_type: u8, stage: Stage },
}
