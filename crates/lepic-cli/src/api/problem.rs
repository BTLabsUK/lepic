// SPDX-License-Identifier: Apache-2.0
//! Errors as RFC 9457 problem details.

use hyper::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa::openapi::schema::{Object, Type};

use crate::exit::{CliError, ErrorKind};

/// An error, as RFC 9457 problem details (`application/problem+json`).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct Problem {
    /// Always `about:blank`: `code` says what went wrong.
    #[serde(rename = "type")]
    #[schema(value_type = String)]
    kind: &'static str,
    /// The reason phrase of `status`.
    #[schema(value_type = String)]
    title: &'static str,
    status: u16,
    /// The error and its causes, outermost first.
    detail: String,
    /// The error kind, as the CLI reports it; it decides `status`.
    #[schema(schema_with = codes)]
    code: &'static str,
    /// The causes `detail` ends with, outermost first, as the CLI's JSON error lists them.
    /// `detail` is the error itself followed by these, joined by `: `.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    #[schema(value_type = Vec<String>)]
    causes: Box<[String]>,
    /// The transaction the error is about, when one was stored: a send stopped before its
    /// delivery was known, or a `slate_id` used before.
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_id: Option<u32>,
    /// The commands that finish or give up the transaction, in the order to try them; present
    /// with `code` `incomplete`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Vec<String>>)]
    // One pointer keeps the `Err` of every route under clippy's size limit.
    #[allow(clippy::box_collection)]
    recovery: Option<Box<Vec<String>>>,
    /// The methods the route takes, for the `Allow` header of a 405.
    #[serde(skip)]
    // One pointer, as for `recovery`.
    #[allow(clippy::box_collection)]
    pub(crate) allow: Option<Box<String>>,
}

impl Problem {
    pub(crate) fn new(status: StatusCode, code: ErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind: "about:blank",
            title: status.canonical_reason().unwrap_or(""),
            status: status.as_u16(),
            detail: detail.into(),
            code: code.name(),
            causes: Box::default(),
            tx_id: None,
            recovery: None,
            allow: None,
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub(crate) fn usage(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorKind::Usage, detail)
    }

    pub(crate) fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorKind::NotFound, "no such route")
    }

    pub(crate) fn method_not_allowed(allow: String) -> Self {
        Self {
            allow: Some(Box::new(allow)),
            ..Self::new(
                StatusCode::METHOD_NOT_ALLOWED,
                ErrorKind::Usage,
                "the route does not take this method",
            )
        }
    }

    pub(crate) fn too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorKind::Usage,
            "the request body is over the limit",
        )
    }

    pub(crate) fn too_slow() -> Self {
        Self::new(
            StatusCode::REQUEST_TIMEOUT,
            ErrorKind::Usage,
            "the request body did not arrive in time",
        )
    }

    pub(crate) fn socket_only() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorKind::Usage,
            "the route is answered on the socket only",
        )
    }

    /// A TLS client removed from `api-clients` since its connection opened.
    pub(crate) fn no_longer_listed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorKind::Usage,
            "this client is no longer listed",
        )
    }
}

impl From<CliError> for Problem {
    fn from(error: CliError) -> Self {
        let kind = error.kind();
        let chain = error.chain();
        Self {
            tx_id: error.tx_id(),
            causes: chain.get(1..).unwrap_or_default().into(),
            recovery: Some(crate::hint::recovery(&error))
                .filter(|commands| !commands.is_empty())
                .map(Box::new),
            ..Self::new(status(kind), kind, chain.join(": "))
        }
    }
}

/// The HTTP status of each error kind.
pub(crate) const fn status(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::Internal | ErrorKind::Config => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorKind::Usage => StatusCode::BAD_REQUEST,
        ErrorKind::WrongPassword => StatusCode::FORBIDDEN,
        ErrorKind::WalletState => StatusCode::CONFLICT,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Rejected | ErrorKind::InsufficientFunds => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorKind::Node | ErrorKind::Transport | ErrorKind::Incomplete => StatusCode::BAD_GATEWAY,
        ErrorKind::Interrupted => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// `code`: the closed list of error kinds.
fn codes() -> Object {
    Object::builder()
        .schema_type(Type::String)
        .enum_values(Some(ErrorKind::ALL.map(ErrorKind::name)))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_an_error_status() {
        for kind in ErrorKind::ALL {
            assert!(status(kind).is_client_error() || status(kind).is_server_error());
        }
    }
}
