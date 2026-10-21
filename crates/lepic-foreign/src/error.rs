//! Errors of the foreign API client, the listener and the messages they exchange.

use thiserror::Error;

/// A foreign API message that could not be built or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RpcError {
    #[error("the body is larger than a foreign api message can be")]
    TooLarge,
    #[error("the body is not a foreign api answer")]
    Malformed,
    #[error("the slate is not json")]
    NotJson,
    #[error("the other wallet refused the request")]
    Refused,
    #[error("the other wallet speaks a foreign api older than version 2")]
    Incompatible,
}

/// A destination that is not a wallet's foreign API address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UrlError {
    #[error("the address is not an http or https url")]
    NotHttp,
    #[error("the address has no host")]
    NoHost,
    #[error("the address carries credentials, a query or a fragment")]
    ExtraParts,
    #[error("the address has an invalid port")]
    InvalidPort,
    #[error("plain http to another computer needs the sender's consent")]
    PlainHttpNotAllowed,
    #[error("onion addresses go through tor")]
    OnionNeedsTor,
}

/// Why a slate could not be sent to a listening wallet.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("invalid destination")]
    Url(#[from] UrlError),
    #[error("tls configuration failed")]
    TlsConfig(#[source] rustls::Error),
    #[error("could not reach the other wallet")]
    Unreachable(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("the other wallet did not answer in time")]
    Timeout,
    #[error("the other wallet answered with http status {status}")]
    Status { status: u16 },
    #[error("the other wallet has no foreign api at this address")]
    NotFound,
    #[error("the answer is larger than {max} bytes")]
    ResponseTooLarge { max: usize },
    #[error("the answer could not be read")]
    Rpc(#[from] RpcError),
    #[error("the other wallet offers no slate version this wallet sends")]
    NoCommonVersion,
}

/// Why the listener could not start.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ListenError {
    #[error("port {port} is in use")]
    PortInUse { port: u16 },
    #[error("could not listen on port {port}")]
    Bind {
        port: u16,
        #[source]
        source: std::io::Error,
    },
}
