// SPDX-License-Identifier: Apache-2.0
//! Errors of transports and format policies.

use lepic_slate::codec::CodecId;
use lepic_slate::error::EncodeError;
use thiserror::Error;

use crate::transport::TransportId;

/// A transport that could not deliver, receive, export or import a wire slate.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport {transport} does not handle this kind of location")]
    UnsupportedLocation { transport: TransportId },
    #[error("transport {transport} does not know the destination")]
    UnknownDestination { transport: TransportId },
    /// An address the transport cannot read, with why.
    #[error("transport {transport} cannot read the destination")]
    InvalidDestination {
        transport: TransportId,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("transport {transport} has no unacknowledged envelope with this token")]
    UnknownAcknowledgement { transport: TransportId },
    #[error("slate file failed")]
    File(#[from] FileError),
    /// A failure specific to a transport implemented in another crate, kept as its own typed
    /// error so callers can downcast it.
    #[error("transport {transport} failed")]
    Backend {
        transport: TransportId,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// The step of a file export or import that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileOperation {
    Inspect,
    Open,
    Read,
    Create,
    Write,
    Sync,
}

impl std::fmt::Display for FileOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Inspect => "inspect",
            Self::Open => "open",
            Self::Read => "read",
            Self::Create => "create",
            Self::Write => "write",
            Self::Sync => "sync",
        })
    }
}

/// A slate file that could not be read or written. The path is left out so that error text
/// never carries the user's directory layout into logs.
#[derive(Debug, Error)]
pub enum FileError {
    #[error("could not {operation} the slate file")]
    Io {
        operation: FileOperation,
        #[source]
        source: std::io::Error,
    },
    #[error("slate path is not a regular file")]
    NotAFile,
    #[error("slate file of {len} bytes exceeds the limit of {max}")]
    TooLarge { len: u64, max: usize },
}

/// A slate that a format policy could not turn into a wire slate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FormatError {
    #[error("codec {codec} chosen by the format policy is not registered")]
    CodecNotRegistered { codec: CodecId },
    #[error("slate cannot be encoded in the chosen format")]
    Encode(#[from] EncodeError),
}
