// SPDX-License-Identifier: Apache-2.0
//! Errors as RFC 9457 problem documents (`application/problem+json`). `code` is one stable,
//! fine-grained name per error that programs branch on; `category` is the kind of error, the same
//! kinds the CLI's exit codes stand for, plus `conflict`; the HTTP status follows them.

use hyper::StatusCode;
use serde::Serialize;

use super::codes;
use crate::exit::{CliError, ErrorKind};

/// The kind of an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Category {
    Usage,
    Config,
    WrongPassword,
    WalletState,
    NotFound,
    Rejected,
    Funds,
    Node,
    Transport,
    Internal,
    Interrupted,
    /// The request conflicts with the object's state or with an earlier request of the same id.
    Conflict,
}

impl Category {
    /// The status of an error of this kind, unless its code names another.
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::Usage => StatusCode::BAD_REQUEST,
            Self::WrongPassword => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::WalletState | Self::Conflict => StatusCode::CONFLICT,
            Self::Rejected | Self::Funds => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Node | Self::Transport => StatusCode::BAD_GATEWAY,
            Self::Interrupted => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal | Self::Config => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The category of the CLI's error kind.
    pub(crate) const fn of(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::Usage => Self::Usage,
            ErrorKind::Config => Self::Config,
            ErrorKind::WrongPassword => Self::WrongPassword,
            ErrorKind::WalletState => Self::WalletState,
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::Rejected => Self::Rejected,
            ErrorKind::InsufficientFunds => Self::Funds,
            ErrorKind::Node => Self::Node,
            ErrorKind::Transport | ErrorKind::Incomplete => Self::Transport,
            ErrorKind::Internal => Self::Internal,
            ErrorKind::Interrupted => Self::Interrupted,
        }
    }

    /// The code of an error of this kind that has no finer one.
    const fn code(self) -> &'static str {
        match self {
            Self::Usage => "invalid_request",
            Self::Config => "config",
            Self::WrongPassword => "wrong_password",
            Self::WalletState => "wallet_state",
            Self::NotFound => "not_found",
            Self::Rejected => "rejected",
            Self::Funds => "insufficient_funds",
            Self::Node => "node_unreachable",
            Self::Transport => "transport_failed",
            Self::Internal => "internal",
            Self::Interrupted => "interrupted",
            Self::Conflict => "conflict",
        }
    }
}

/// One bad field, when a request has several.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct FieldError {
    pub(crate) code: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) detail: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) param: String,
}

#[derive(Debug, Serialize)]
struct Document {
    /// Always `about:blank`: `code` says what went wrong.
    #[serde(rename = "type")]
    kind: &'static str,
    /// The reason phrase of `status`.
    title: &'static str,
    status: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    code: &'static str,
    category: Category,
    /// A JSON pointer to the bad field.
    #[serde(skip_serializing_if = "Option::is_none")]
    param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<FieldError>,
    /// The methods the route takes, for the `Allow` header of a 405.
    #[serde(skip)]
    allow: Option<String>,
    /// Seconds to wait before trying again, for `Retry-After`.
    #[serde(skip)]
    retry_after: Option<u32>,
}

/// An error answer. One pointer, so every handler's `Err` stays small.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct Problem(Box<Document>);

/// How long a client waits before it tries again after a node, relay or stopping serve.
const RETRY_AFTER_SECS: u32 = 5;

impl Problem {
    pub(crate) fn new(
        status: StatusCode,
        category: Category,
        code: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        let retry_after = matches!(
            status,
            StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
        )
        .then_some(RETRY_AFTER_SECS);
        Self(Box::new(Document {
            kind: "about:blank",
            title: status.canonical_reason().unwrap_or(""),
            status: status.as_u16(),
            detail: detail.into(),
            code,
            category,
            param: None,
            payment_id: None,
            contact_id: None,
            errors: Vec::new(),
            allow: None,
            retry_after,
        }))
    }

    /// An error of `category` with its usual status.
    pub(crate) fn of(category: Category, code: &'static str, detail: impl Into<String>) -> Self {
        Self::new(category.status(), category, code, detail)
    }

    /// 400: the request is malformed or a field is invalid.
    pub(crate) fn bad_request(code: &'static str, detail: impl Into<String>) -> Self {
        Self::of(Category::Usage, code, detail)
    }

    /// 400 `invalid_request`.
    pub(crate) fn usage(detail: impl Into<String>) -> Self {
        Self::bad_request("invalid_request", detail)
    }

    /// 400 `invalid_field` at `param`, a JSON pointer such as `/amount`.
    pub(crate) fn invalid(param: &str, detail: impl Into<String>) -> Self {
        Self::bad_request("invalid_field", detail).with_param(param)
    }

    /// 404 `not_found`: no object with this id.
    pub(crate) fn not_found(detail: impl Into<String>) -> Self {
        Self::of(Category::NotFound, "not_found", detail)
    }

    /// 409 with `code`: the object's state does not allow the request.
    pub(crate) fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::of(Category::Conflict, code, detail)
    }

    /// 409 `action_not_available`: the payment's `actions` do not list this one.
    pub(crate) fn action_not_available(action: &str) -> Self {
        Self::conflict(
            "action_not_available",
            format!("the payment's actions do not include {action}"),
        )
    }

    /// 409 `idempotency_mismatch`: the id was used before with another body.
    pub(crate) fn idempotency_mismatch() -> Self {
        Self::conflict(
            "idempotency_mismatch",
            "this id was used before with another request body",
        )
        .with_param("/id")
    }

    /// 409 `in_progress`: a request with the same id is being answered.
    pub(crate) fn in_progress() -> Self {
        Self::conflict(
            "in_progress",
            "a request with this id is being answered; try again when it ends",
        )
        .with_param("/id")
    }

    /// 422 `unexpected_input`: `POST /open` found another kind of text than `expect` names.
    pub(crate) fn unexpected_input(detail: impl Into<String>) -> Self {
        Self::of(Category::Rejected, "unexpected_input", detail).with_param("/expect")
    }

    /// 403 `role_required`: the client's role is below what the call needs.
    pub(crate) fn role_required(needed: crate::api_clients::Role) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            Category::Usage,
            "role_required",
            format!("this call needs the {needed} role"),
        )
    }

    /// 403 `socket_only`: the operation is answered on the Unix socket only.
    pub(crate) fn socket_only() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            Category::Usage,
            "socket_only",
            "this call is answered on the Unix socket only",
        )
    }

    /// 403 `client_not_listed`: a TLS client removed from `api-clients` since its connection
    /// opened.
    pub(crate) fn no_longer_listed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            Category::Usage,
            "client_not_listed",
            "this client is no longer listed in api-clients",
        )
    }

    /// 404 `no_route`.
    pub(crate) fn no_route() -> Self {
        Self::of(Category::NotFound, "no_route", "no such path")
    }

    /// 405 `method_not_allowed`, with the methods the path takes for `Allow`.
    pub(crate) fn method_not_allowed(allow: String) -> Self {
        let mut problem = Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            Category::Usage,
            "method_not_allowed",
            "the path does not take this method",
        );
        problem.0.allow = Some(allow);
        problem
    }

    /// 413 `body_too_large`.
    pub(crate) fn too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            Category::Usage,
            "body_too_large",
            "the request body is over the limit",
        )
    }

    /// 408 `body_too_slow`.
    pub(crate) fn too_slow() -> Self {
        Self::new(
            StatusCode::REQUEST_TIMEOUT,
            Category::Usage,
            "body_too_slow",
            "the request body did not arrive in time",
        )
    }

    /// 501 `not_implemented`, for an operation serve does not answer yet.
    pub(crate) fn not_implemented() -> Self {
        Self::new(
            StatusCode::NOT_IMPLEMENTED,
            Category::Internal,
            "not_implemented",
            "this operation is not answered yet",
        )
    }

    /// This problem, about the field at JSON pointer `param`.
    pub(crate) fn with_param(mut self, param: &str) -> Self {
        self.0.param = Some(param.to_owned());
        self
    }

    /// This problem, about the payment `id`.
    pub(crate) fn with_payment(mut self, id: impl Into<String>) -> Self {
        self.0.payment_id = Some(id.into());
        self
    }

    /// This problem, about the contact `id`.
    pub(crate) fn with_contact(mut self, id: impl Into<String>) -> Self {
        self.0.contact_id = Some(id.into());
        self
    }

    /// This problem, with one entry per bad field.
    pub(crate) fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.0.errors = errors;
        self
    }

    pub(crate) fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub(crate) fn code(&self) -> &'static str {
        self.0.code
    }

    pub(crate) fn category(&self) -> Category {
        self.0.category
    }

    pub(crate) fn allow(&self) -> Option<&str> {
        self.0.allow.as_deref()
    }

    pub(crate) fn retry_after(&self) -> Option<u32> {
        self.0.retry_after
    }
}

impl From<CliError> for Problem {
    /// `detail` is the error and its causes, outermost first, joined by `: `.
    fn from(error: CliError) -> Self {
        let category = Category::of(error.kind());
        let classified = codes::classify(&error);
        let code = classified.code.unwrap_or_else(|| category.code());
        let status = classified.status.unwrap_or_else(|| category.status());
        Self::new(status, category, code, error.chain().join(": "))
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_kind_has_an_error_status() {
        for kind in ErrorKind::ALL {
            let status = Category::of(kind).status();
            assert!(status.is_client_error() || status.is_server_error());
        }
    }

    #[test]
    fn a_document_has_the_members_the_contract_names() {
        let problem = Problem::of(Category::Funds, "insufficient_funds", "short")
            .with_param("/amount")
            .with_payment("p");
        let json = serde_json::to_value(&problem).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "about:blank",
                "title": "Unprocessable Entity",
                "status": 422,
                "detail": "short",
                "code": "insufficient_funds",
                "category": "funds",
                "param": "/amount",
                "payment_id": "p",
            })
        );
        assert_eq!(problem.retry_after(), None);
        assert_eq!(
            Problem::of(Category::Node, "node_unreachable", "").retry_after(),
            Some(RETRY_AFTER_SECS)
        );
    }

    #[test]
    fn a_problem_is_one_pointer() {
        assert_eq!(size_of::<Problem>(), size_of::<usize>());
    }
}
