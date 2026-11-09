// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

/// A field of an advert or of a `GET /v1/peer` answer that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeerFormatError {
    #[error("the answer is not the expected JSON")]
    Malformed,
    #[error("the seal key is not 64 hex digits")]
    Key,
    #[error("the endpoint path is not an absolute path")]
    Path,
    #[error("the format list is longer than any listener sends")]
    Formats,
}

/// Why [`crate::PeerClient`] got no reply envelope. Each problem code of the endpoint has its
/// own variant; anything else the endpoint answers is [`PeerClientError::Status`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PeerClientError {
    #[error("the TLS configuration could not be built")]
    TlsConfig(#[source] rustls::Error),
    #[error("the address could not be used: {0}")]
    Target(#[from] crate::origin::OriginError),
    #[error("the envelope is longer than the endpoint takes ({len} bytes, at most {max})")]
    EnvelopeTooLarge { len: usize, max: usize },
    #[error("the address is one of this computer's own ({})", class.as_str())]
    ThisComputer { class: crate::client::AddressClass },
    #[error("the wallet could not be reached")]
    Unreachable(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("the wallet took too long to answer")]
    Timeout,
    #[error("the wallet is not ready to take a payment")]
    NotReady { retry_after: Option<Duration> },
    #[error("the wallet refused the slate")]
    Refused,
    #[error("the wallet says the envelope is too large")]
    TooLarge,
    #[error("the wallet is taking no more payments for now")]
    RateLimited { retry_after: Option<Duration> },
    #[error("the wallet does not read the slate's format")]
    UnsupportedFormat,
    #[error("the wallet serves no native endpoint")]
    NotFound,
    #[error("the wallet answered with HTTP status {status}")]
    Status { status: u16 },
    #[error("the answer is larger than {max} bytes")]
    ResponseTooLarge { max: usize },
    #[error("the answer could not be read: {0}")]
    Format(#[from] PeerFormatError),
    #[error("the answer is not an envelope")]
    NotEnvelope,
}
