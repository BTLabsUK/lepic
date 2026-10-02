//! Errors of the slate model, its validation helpers, codecs and the codec registry.

use lepic_crypto::CryptoError;
use lepic_primitives::amount::Fee;
use lepic_primitives::amount::Height;
use thiserror::Error;

use crate::codec::CodecId;
use crate::role::Role;
use crate::stage::Stage;

/// A slate that breaks an invariant of the domain model, or a transition that is not allowed
/// from the slate's stage.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SlateError {
    #[error("{role} data is missing at stage {stage}")]
    MissingParticipant { stage: Stage, role: Role },
    #[error("{role} data is not expected at stage {stage}")]
    UnexpectedParticipant { stage: Stage, role: Role },
    #[error("{role} partial signature is missing at stage {stage}")]
    MissingPartialSignature { stage: Stage, role: Role },
    #[error("{role} partial signature is not expected at stage {stage}")]
    UnexpectedPartialSignature { stage: Stage, role: Role },
    #[error("kernel excess is missing at stage {stage}")]
    MissingKernelExcess { stage: Stage },
    #[error("kernel excess is not expected at stage {stage}")]
    UnexpectedKernelExcess { stage: Stage },
    #[error("payment proof is not supported in the invoice flow")]
    PaymentProofInInvoice,
    #[error("payment proof signature is missing at stage {stage}")]
    MissingProofSignature { stage: Stage },
    #[error("payment proof signature is not expected at stage {stage}")]
    UnexpectedProofSignature { stage: Stage },
    #[error("fee {fee} is set before the sender has joined at stage {stage}")]
    FeeBeforeSender { stage: Stage, fee: Fee },
    #[error("body weight {weight} exceeds the transaction limit {max}")]
    BodyTooHeavy { weight: u64, max: u64 },
    #[error("participant message of {len} bytes exceeds {max} bytes")]
    MessageTooLong { len: usize, max: usize },
    #[error("{transition} is not allowed at stage {stage}")]
    InvalidTransition {
        stage: Stage,
        transition: Transition,
    },
}

/// A stage transition of [`crate::model::Slate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transition {
    Receive,
    Pay,
    Finalize,
}

impl std::fmt::Display for Transition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Receive => "receive",
            Self::Pay => "pay",
            Self::Finalize => "finalize",
        })
    }
}

/// Text that is not a hyphenated UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("slate id is not a hyphenated uuid")]
pub struct SlateIdError;

/// Bytes that are not a valid ed25519 point, so cannot be a payment proof address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("payment proof address is not a valid ed25519 point")]
pub struct ProofAddressError;

/// Hex text that does not decode to the expected bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HexError {
    #[error("expected {expected} hex digits, found {actual}")]
    WrongLength { expected: usize, actual: usize },
    #[error("expected between {min} and {max} hex digits, found {actual}")]
    LengthOutOfRange {
        min: usize,
        max: usize,
        actual: usize,
    },
    #[error("hex text has an odd number of digits")]
    OddLength,
    #[error("hex text contains a character that is not a hex digit")]
    InvalidDigit,
}

/// Legacy wire data that is well formed but inconsistent. These are LEPIC's own rules,
/// shared by the legacy codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("slate declares {declared} participants, only two-party slates are supported")]
    UnsupportedParticipantCount { declared: u64 },
    #[error("slate carries {count} participants but declares {declared}")]
    TooManyParticipants { count: usize, declared: u64 },
    #[error("participant id {id} is not below the declared count {declared}")]
    ParticipantIdOutOfRange { id: u64, declared: u64 },
    #[error("participant id {id} appears more than once")]
    DuplicateParticipantId { id: u64 },
    #[error("participant data does not match any slate stage")]
    UnrecognisedStage,
    #[error("slate has {count} kernels, expected exactly one")]
    KernelCount { count: usize },
    #[error("kernel is a coinbase kernel")]
    CoinbaseKernel,
    #[error("kernel fee {kernel} differs from the slate fee {slate}")]
    KernelFeeMismatch { slate: Fee, kernel: Fee },
    #[error("kernel lock height {kernel} differs from the slate lock height {slate}")]
    KernelLockMismatch { slate: Height, kernel: Height },
    #[error("kernel excess and signature must be both placeholders or both set")]
    PartialKernelPlaceholder,
    #[error("kernel excess is invalid")]
    InvalidKernelExcess(#[source] CryptoError),
    #[error("kernel signature is invalid")]
    InvalidKernelSignature(#[source] CryptoError),
    #[error("fee {fee} is below the minimum {minimum} for the transaction weight")]
    FeeBelowMinimum { fee: Fee, minimum: Fee },
    #[error("minimum fee overflows")]
    MinimumFeeOverflow,
}

/// What is wrong with one field of a wire slate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FieldProblem {
    #[error("is missing")]
    Missing,
    #[error("is not expected in this format")]
    Unexpected,
    #[error("has the wrong type")]
    WrongType,
    #[error("is not an integer in range")]
    IntegerOutOfRange,
    #[error("has an unsupported value")]
    UnsupportedValue,
    #[error("is {len} bytes, more than {max}")]
    TooLong { len: usize, max: usize },
    #[error("is not valid hex")]
    Hex(#[source] HexError),
    #[error("is not a valid curve value")]
    Crypto(#[source] CryptoError),
    #[error("is not a valid slate id")]
    SlateId(#[source] SlateIdError),
    #[error("is not a valid payment proof address")]
    ProofAddress(#[source] ProofAddressError),
}

/// Line and column of a syntax error in a text format, both starting at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextPosition {
    pub line: usize,
    pub column: usize,
}

/// A wire slate that could not be turned into a [`crate::model::Slate`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("wire slate of {len} bytes exceeds the limit of {max}")]
    TooLarge { len: usize, max: usize },
    #[error("no accepted codec recognises the wire slate")]
    UnknownFormat,
    #[error("codec {codec} does not recognise the wire slate")]
    NotRecognised { codec: CodecId },
    #[error("wire slate is not well formed for codec {codec}")]
    Syntax {
        codec: CodecId,
        position: Option<TextPosition>,
    },
    #[error("codec {codec} does not support version {version}")]
    UnsupportedVersion { codec: CodecId, version: u64 },
    #[error("field {field} {problem}")]
    Field {
        field: &'static str,
        #[source]
        problem: FieldProblem,
    },
    #[error("wire slate is inconsistent")]
    Validation(#[from] ValidationError),
    #[error("wire slate does not form a valid slate")]
    Model(#[from] SlateError),
}

/// Something a slate carries that a format has no way to express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unrepresentable {
    TimeToLive,
    PaymentProof,
    Flow(crate::stage::Flow),
}

impl std::fmt::Display for Unrepresentable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeToLive => f.write_str("a ttl cutoff height"),
            Self::PaymentProof => f.write_str("a payment proof"),
            Self::Flow(flow) => write!(f, "the {flow} flow"),
        }
    }
}

/// A slate that a codec cannot encode without losing information.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("codec {codec} cannot represent {what}")]
    Unrepresentable {
        codec: CodecId,
        what: Unrepresentable,
    },
}

/// A codec registry that cannot accept a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RegistryError {
    #[error("codec {codec} is already registered")]
    DuplicateCodec { codec: CodecId },
}
