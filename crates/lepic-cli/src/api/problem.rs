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

    /// The name the problem document gives the category.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Config => "config",
            Self::WrongPassword => "wrong_password",
            Self::WalletState => "wallet_state",
            Self::NotFound => "not_found",
            Self::Rejected => "rejected",
            Self::Funds => "funds",
            Self::Node => "node",
            Self::Transport => "transport",
            Self::Internal => "internal",
            Self::Interrupted => "interrupted",
            Self::Conflict => "conflict",
        }
    }

    /// The category of the CLI's error kind.
    pub(crate) const fn of(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::Usage | ErrorKind::SlateTooLarge | ErrorKind::EarlierAddress => Self::Usage,
            ErrorKind::Config => Self::Config,
            ErrorKind::WrongPassword => Self::WrongPassword,
            ErrorKind::WalletState => Self::WalletState,
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::Rejected | ErrorKind::NoSharedMailbox => Self::Rejected,
            ErrorKind::InsufficientFunds => Self::Funds,
            ErrorKind::Node => Self::Node,
            ErrorKind::Transport | ErrorKind::Incomplete | ErrorKind::NotDelivered => {
                Self::Transport
            }
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
    /// For `payment_declined`: when the receiver declined the send.
    #[serde(skip_serializing_if = "Option::is_none")]
    declined_at: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<FieldError>,
    /// For `slate_too_large`: the size, the limit and the inputs.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    slate: Option<SlateSize>,
    /// The methods the route takes, for the `Allow` header of a 405.
    #[serde(skip)]
    allow: Option<String>,
    /// Seconds to wait before trying again: the `Retry-After` header says the same. A mailbox's
    /// wait when it asked for one, else a fixed wait for a node, relay or stopping serve.
    #[serde(rename = "retry_after_secs", skip_serializing_if = "Option::is_none")]
    retry_after: Option<u32>,
    /// The mailbox, `host[:port]`, that refused the post, or that an epic1 link of an earlier
    /// release names. Left out when the error does not say which.
    #[serde(skip_serializing_if = "Option::is_none")]
    mailbox: Option<String>,
}

/// The members of a `slate_too_large` problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct SlateSize {
    /// The longer of the slate and the answer, in bytes on the relay.
    pub(crate) bytes: usize,
    /// The most the relay takes.
    pub(crate) limit: usize,
    /// The outputs the payment spends.
    pub(crate) inputs: usize,
}

/// The `detail` of a `slate_too_large` problem.
const SLATE_TOO_LARGE: &str = "The slate of the payment is larger than the mailbox takes: it \
                               holds its inputs, the payee's output and the change. Consolidate \
                               the wallet's outputs or pay a smaller amount.";

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
            declined_at: None,
            errors: Vec::new(),
            slate: None,
            allow: None,
            retry_after,
            mailbox: None,
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
        let mut problem = Self::conflict(
            "in_progress",
            "a request with this id is being answered; try again when it ends",
        )
        .with_param("/id");
        problem.0.retry_after = Some(RETRY_AFTER_SECS);
        problem
    }

    /// 503 `busy`: as many creates are being made as the API takes connections.
    pub(crate) fn busy() -> Self {
        Self::of(
            Category::Interrupted,
            "busy",
            "as many creates are being made as serve takes connections; try again later",
        )
    }

    /// 503 `busy`: the listener holds as many connections as it takes.
    pub(crate) fn connections_full() -> Self {
        Self::of(
            Category::Interrupted,
            "busy",
            "serve holds as many connections as it takes; try again later",
        )
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

    /// 415 `unsupported_media_type`: a request body without `Content-Type: application/json`.
    pub(crate) fn unsupported_media_type() -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Category::Usage,
            "unsupported_media_type",
            "a request body needs Content-Type: application/json",
        )
    }

    /// This problem, with the wait a mailbox or peer asked for before the post goes again: the
    /// `retry_after_secs` member and `Retry-After` carry it instead of the fixed wait.
    pub(crate) fn with_retry_after(mut self, secs: u64) -> Self {
        self.0.retry_after = Some(u32::try_from(secs).unwrap_or(u32::MAX));
        self
    }

    /// This problem, naming the mailbox, `host[:port]`, it is about: the `mailbox` member.
    pub(crate) fn with_mailbox(mut self, mailbox: String) -> Self {
        self.0.mailbox = Some(mailbox);
        self
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

    /// 404 `payment_declined`: the receiver of the send `id` declined it at `declined_at`. The
    /// wallet erased the send and unlocked its inputs, so it holds nothing else of it.
    pub(crate) fn payment_declined(id: &str, declined_at: String) -> Self {
        let mut problem = Self::of(
            Category::NotFound,
            "payment_declined",
            format!(
                "the receiver declined payment {id}: nothing was sent and its inputs are free again"
            ),
        )
        .with_payment(id);
        problem.0.declined_at = Some(declined_at);
        problem
    }

    /// This problem, about the contact `id`.
    pub(crate) fn with_contact(mut self, id: impl Into<String>) -> Self {
        self.0.contact_id = Some(id.into());
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
        if let Some(size) = codes::slate_size(&error) {
            let mut problem = Self::new(status, category, code, SLATE_TOO_LARGE);
            problem.0.slate = Some(size);
            return problem;
        }
        let problem = Self::new(status, category, code, error.chain().join(": "));
        let problem = match error.retry_after_secs() {
            Some(secs) => problem.with_retry_after(secs),
            None => problem,
        };
        match error.mailbox() {
            Some(mailbox) => problem.with_mailbox(mailbox),
            None => problem,
        }
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
    fn a_fixed_wait_and_a_mailboxs_wait_are_the_retry_after_secs_member() {
        let node = Problem::of(Category::Node, "node_unreachable", "down");
        let json = serde_json::to_value(&node).unwrap();
        assert_eq!(json["retry_after_secs"], RETRY_AFTER_SECS);

        let refused = lepic_wallet_contacts::ContactError::Relay(
            lepic_epicbox::MailboxError::Protocol(lepic_epicbox::ClientError::PostRefused {
                kind: lepic_epicbox::RelayErrorKind::InvalidRequest,
                description: Some("Rate limit exceeded; retry in 12 s.".to_owned()),
                retry_after: Some(std::time::Duration::from_secs(12)),
                mailbox: Some("relay.test:443".to_owned()),
            }),
        );
        let problem = Problem::from(CliError::Contact(refused));
        assert_eq!(problem.retry_after(), Some(12));
        let json = serde_json::to_value(&problem).unwrap();
        assert_eq!(json["retry_after_secs"], 12);
        assert_eq!(json["mailbox"], "relay.test:443");
        assert_eq!(json["code"], "transport_failed");
        assert_eq!(json["status"], 502);

        // A wait read through `lepic serve` is passed on as it came.
        let served = CliError::Served {
            kind: crate::exit::ErrorKind::Transport,
            message: "refused".to_owned(),
            causes: None,
            tx_id: None,
            recovery: Box::default(),
            hint: None,
            retry_after_secs: Some(30),
            mailbox: Some("relay.test:443".to_owned()),
        };
        let problem = Problem::from(served);
        assert_eq!(problem.retry_after(), Some(30));
        assert_eq!(
            serde_json::to_value(&problem).unwrap()["mailbox"],
            "relay.test:443"
        );
    }

    #[test]
    fn a_slate_too_large_names_its_size_limit_and_inputs() {
        let error = CliError::Send(lepic_wallet::send::SendError::SlateTooLarge {
            bytes: 131_072,
            limit: 131_071,
            inputs: 600,
        });
        let json = serde_json::to_value(Problem::from(error)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "about:blank",
                "title": "Bad Request",
                "status": 400,
                "detail": SLATE_TOO_LARGE,
                "code": "slate_too_large",
                "category": "usage",
                "bytes": 131_072,
                "limit": 131_071,
                "inputs": 600,
            })
        );
    }

    #[test]
    fn a_problem_is_one_pointer() {
        assert_eq!(size_of::<Problem>(), size_of::<usize>());
    }
}
