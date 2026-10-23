use std::error::Error as StdError;
use std::fmt;

use lepic_crypto::CryptoError;
use lepic_primitives::amount::Height;
use lepic_primitives::hash::HashError;
use serde_json::error::Category;

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

/// A node call that failed, from the network up to validation of the answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NodeError {
    #[error("node url is invalid")]
    InvalidUrl,
    #[error("node url uses plain http to a host that is not loopback")]
    PlainHttpToRemoteHost,
    #[error("node api secret cannot be sent in an http header")]
    InvalidApiSecret,
    #[error("tls configuration could not be built")]
    TlsConfig(#[source] rustls::Error),
    #[error("could not connect to the node")]
    Connect(#[source] BoxError),
    #[error("node request failed")]
    Request(#[source] BoxError),
    #[error("node did not answer within the request timeout")]
    Timeout,
    #[error("node rejected the api secret")]
    Unauthorized,
    #[error("node answered with http status {status}")]
    HttpStatus { status: u16 },
    #[error("node response exceeds the limit of {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("request for {method} could not be encoded")]
    EncodeRequest {
        method: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("node response to {method} is not the expected json")]
    MalformedResponse {
        method: &'static str,
        #[source]
        source: JsonProblem,
    },
    #[error("node response to {method} carries another request id")]
    IdMismatch { method: &'static str },
    #[error("node response to {method} has neither a result nor an error")]
    EmptyResponse { method: &'static str },
    #[error("node response to {method} has an invalid {field}")]
    InvalidField {
        method: &'static str,
        field: &'static str,
        #[source]
        problem: FieldProblem,
    },
    #[error("node returned json-rpc error {code} for {method}")]
    Rpc { method: &'static str, code: i64 },
    #[error("node rejected {method}: {rejection}")]
    Rejected {
        method: &'static str,
        rejection: NodeRejection,
    },
    #[error("node reported tip {reported}, implausibly far above tip {previous} seen before")]
    ImplausibleTip { previous: Height, reported: Height },
}

impl NodeError {
    /// Failures where the same read may succeed when repeated: the node was unreachable, slow or
    /// briefly overloaded. A node that answered with something wrong is not retried.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Connect(_) | Self::Request(_) | Self::Timeout => true,
            Self::HttpStatus { status } => *status == 429 || (500..=599).contains(status),
            _ => false,
        }
    }

    pub(crate) fn invalid(
        method: &'static str,
        field: &'static str,
        problem: FieldProblem,
    ) -> Self {
        Self::InvalidField {
            method,
            field,
            problem,
        }
    }
}

/// Why a JSON document did not parse, without any of its text: a parser's message can quote the
/// document, and node responses are untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{} at line {line} column {column}", category_name(*.category))]
pub struct JsonProblem {
    pub category: Category,
    pub line: usize,
    pub column: usize,
}

impl From<serde_json::Error> for JsonProblem {
    fn from(error: serde_json::Error) -> Self {
        Self {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        }
    }
}

fn category_name(category: Category) -> &'static str {
    match category {
        Category::Io => "read error",
        Category::Syntax => "syntax error",
        Category::Data => "unexpected value",
        Category::Eof => "unexpected end",
    }
}

/// Why a field of a node response was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FieldProblem {
    #[error("value is not a valid curve value")]
    Crypto(#[from] CryptoError),
    #[error("value is not a valid hash")]
    Hash(#[from] HashError),
    #[error("value is missing")]
    Missing,
    #[error("value is longer than {max} bytes")]
    TooLong { max: usize },
    #[error("value was not requested")]
    NotRequested,
    #[error("value appears twice")]
    Duplicate,
    #[error("value lies outside the requested range")]
    OutOfRange,
    #[error("more entries than requested")]
    TooMany,
    #[error("value contradicts the call's contract")]
    Contradiction,
    #[error("value is not an rfc 3339 timestamp")]
    Timestamp,
    #[error("timestamp lies before the first block of any chain")]
    BeforeGenesis,
    #[error("height lies above the node's tip")]
    AboveTip,
}

/// The handler error a node returned inside a JSON-RPC result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRejection {
    pub kind: RejectionKind,
    /// The node's own text, cut to a bounded length. Untrusted; for diagnostics only.
    pub message: Option<String>,
}

impl fmt::Display for NodeRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

/// The variants of the node API's `Error` enum, plus one for shapes it does not define.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionKind {
    NotFound,
    Internal,
    Argument,
    Request,
    Response,
    Router,
    Unknown,
}

impl fmt::Display for RejectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "not found",
            Self::Internal => "internal error",
            Self::Argument => "bad arguments",
            Self::Request => "request error",
            Self::Response => "response error",
            Self::Router => "router error",
            Self::Unknown => "unknown error",
        })
    }
}

// Bounds the walk so a cyclic or very deep source chain cannot make a log line unbounded.
const MAX_ERROR_SOURCES: usize = 16;

/// Formats an error with its source chain, for the `error` log field.
pub(crate) struct ErrorChain<'a>(pub(crate) &'a (dyn StdError + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let sources = std::iter::successors(self.0.source(), |&error| error.source());
        for source in sources.take(MAX_ERROR_SOURCES) {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_chain_includes_sources() {
        let error = NodeError::Connect(Box::new(std::io::Error::other("refused by peer")));
        assert_eq!(
            ErrorChain(&error).to_string(),
            "could not connect to the node: refused by peer"
        );
    }
}
