// SPDX-License-Identifier: Apache-2.0
//! `lepic.v1` behind the [`Codec`] trait.

use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, WireSlate};
use lepic_slate::error::{DecodeError, EncodeError, FieldProblem, Unrepresentable};
use lepic_slate::model::Slate;
use lepic_slate::role::Role;
use lepic_slate::validate::check_size;

use crate::error::NativeError;
use crate::slate::{NativeSlate, check_proof_lengths, encode_slate, header_version};
use crate::{MAGIC, MEDIA_TYPE, NATIVE_V1};

/// `lepic.v1` for one network.
///
/// The trait has no place for the extension tail. [`Codec::decode`] checks the tail and drops it,
/// unknown records included, and [`Codec::encode`] writes an empty tail, as every slate inside an
/// envelope has. [`NativeSlate`] keeps the tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeV1Codec {
    network: Network,
}

impl NativeV1Codec {
    /// Reads and writes slates of `network` only.
    pub const fn new(network: Network) -> Self {
        Self { network }
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    const fn unrepresentable(what: Unrepresentable) -> EncodeError {
        EncodeError::Unrepresentable {
            codec: NATIVE_V1,
            what,
        }
    }
}

impl Codec for NativeV1Codec {
    fn id(&self) -> CodecId {
        NATIVE_V1
    }

    fn detect(&self, wire: &WireSlate) -> bool {
        wire.as_bytes().starts_with(&MAGIC)
    }

    fn decode(&self, wire: &WireSlate) -> Result<Slate, DecodeError> {
        check_size(wire)?;
        NativeSlate::decode(self.network, wire.as_bytes())
            .map(|native| native.into_parts().0)
            .map_err(DecodeError::from_native)
    }

    /// Refuses a header version other than the one the slate's height takes on this network.
    fn encode(&self, slate: &Slate, context: &EncodeContext) -> Result<WireSlate, EncodeError> {
        let expected = header_version(self.network, slate.height());
        if context.block_header_version != expected {
            return Err(Self::unrepresentable(Unrepresentable::BlockHeaderVersion {
                given: context.block_header_version,
                expected,
            }));
        }
        if let Err(NativeError::RangeProofLength { len, expected }) = check_proof_lengths(slate) {
            return Err(Self::unrepresentable(Unrepresentable::RangeProofLength {
                len,
                expected,
            }));
        }
        Ok(WireSlate::binary(
            MEDIA_TYPE,
            encode_slate(slate, self.network),
        ))
    }
}

/// How a [`NativeError`] reads as the codec-neutral [`DecodeError`].
trait FromNative {
    fn from_native(error: NativeError) -> Self;
}

impl FromNative for DecodeError {
    fn from_native(error: NativeError) -> Self {
        let field = |field, problem| Self::Field { field, problem };
        let syntax = Self::Syntax {
            codec: NATIVE_V1,
            position: None,
        };
        match error {
            NativeError::TooLarge { len, max } => Self::TooLarge { len, max },
            NativeError::Magic => Self::NotRecognised { codec: NATIVE_V1 },
            NativeError::Version { version } => Self::UnsupportedVersion {
                codec: NATIVE_V1,
                version: u64::from(version),
            },
            NativeError::UnknownNetwork { .. } | NativeError::WrongNetwork { .. } => {
                field("network", FieldProblem::UnsupportedValue)
            }
            NativeError::UnknownStage { .. } => field("stage", FieldProblem::UnsupportedValue),
            NativeError::ReservedFlag { .. } => field("flags", FieldProblem::UnsupportedValue),
            NativeError::KernelFeatures { .. } => {
                field("kernel_features", FieldProblem::UnsupportedValue)
            }
            NativeError::HeaderVersion { .. } => {
                field("header_version", FieldProblem::UnsupportedValue)
            }
            NativeError::ZeroLockHeight => field("lock_height", FieldProblem::UnsupportedValue),
            NativeError::MessageWithoutParticipant { .. }
            | NativeError::InitiatorMessage { .. } => field("flags", FieldProblem::Unexpected),
            NativeError::OutputFeatures { field: name, .. } => {
                field(name, FieldProblem::UnsupportedValue)
            }
            NativeError::Crypto {
                field: name,
                source,
            } => field(name, FieldProblem::Crypto(source)),
            NativeError::ProofAddress {
                field: name,
                source,
            } => field(name, FieldProblem::ProofAddress(source)),
            NativeError::MessageTooLong { role, len, max } => {
                field(message_field(role), FieldProblem::TooLong { len, max })
            }
            NativeError::MessageNotUtf8 { role } => {
                field(message_field(role), FieldProblem::WrongType)
            }
            NativeError::ProofInInvoice => {
                Self::Model(lepic_slate::error::SlateError::PaymentProofInInvoice)
            }
            NativeError::TooHeavy { weight, max } => {
                Self::Model(lepic_slate::error::SlateError::BodyTooHeavy { weight, max })
            }
            NativeError::Model(error) => Self::Model(error),
            NativeError::Truncated { .. }
            | NativeError::BodyAtProposal { .. }
            | NativeError::RangeProofLength { .. }
            | NativeError::Tail(_)
            | NativeError::View { .. }
            | NativeError::ViewMismatch => syntax,
        }
    }
}

const fn message_field(role: Role) -> &'static str {
    match role {
        Role::Sender => "sender.message",
        Role::Receiver => "receiver.message",
    }
}
