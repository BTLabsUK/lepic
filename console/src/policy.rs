// SPDX-License-Identifier: Apache-2.0
//! What the console answers: requests addressed to its own listen address, writes from its own
//! page only, and a fixed list of API routes.

use hyper::Method;
use hyper::header::{self, HeaderMap};
use serde_json::Value;

/// Why a request is refused before it is routed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The `Host` header is not the console's own listen address.
    WrongHost,
    /// A request that is not a read came without the console's own `Origin`.
    ForeignOrigin,
}

/// Refuses a request sent to another host name, or a write another page sent. `listen` is the
/// address the console answers on, as a browser writes it in `Host`.
pub(crate) fn admit(listen: &str, method: &Method, headers: &HeaderMap) -> Result<(), Refusal> {
    let text = |name| headers.get(name).and_then(|value| value.to_str().ok());
    if text(header::HOST) != Some(listen) {
        return Err(Refusal::WrongHost);
    }
    if method == Method::GET {
        return Ok(());
    }
    let own = format!("http://{listen}");
    if text(header::ORIGIN) == Some(own.as_str()) {
        Ok(())
    } else {
        Err(Refusal::ForeignOrigin)
    }
}

/// An API route the page may call.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Allowed {
    /// Forwarded as it is.
    Read,
    /// The cancel of one transaction: forwarded when serve's document lists the route.
    Cancel,
}

const READS: &[&str] = &[
    "/v1/status",
    "/v1/wallet",
    "/v1/wallet/address",
    "/v1/outputs",
    "/v1/transactions",
    "/v1/node",
    "/v1/events",
    "/v1/openapi.json",
];

/// The route `method` and `path` (without its query) name, when the page may call it.
pub(crate) fn allowed(method: &Method, path: &str) -> Option<Allowed> {
    let under_transaction = path
        .strip_prefix("/v1/transactions/")
        .map(|rest| rest.split('/').collect::<Vec<_>>());
    match (method.as_str(), under_transaction.as_deref()) {
        ("GET", None) if READS.contains(&path) => Some(Allowed::Read),
        ("GET", Some([id])) if is_tx_id(id) => Some(Allowed::Read),
        ("POST", Some([id, "cancel"])) if is_tx_id(id) => Some(Allowed::Cancel),
        _ => None,
    }
}

fn is_tx_id(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether serve's OpenAPI document lists a POST under `/v1/transactions/{...}/cancel`.
pub(crate) fn lists_cancel(document: &Value) -> bool {
    let paths = document.get("paths").and_then(Value::as_object);
    paths.is_some_and(|paths| {
        paths
            .iter()
            .any(|(path, item)| is_cancel_template(path) && item.get("post").is_some())
    })
}

fn is_cancel_template(path: &str) -> bool {
    let segments = path
        .strip_prefix("/v1/transactions/")
        .map(|rest| rest.split('/').collect::<Vec<_>>());
    matches!(
        segments.as_deref(),
        Some([param, "cancel"]) if param.starts_with('{') && param.ends_with('}')
    )
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;
    use serde_json::json;

    use super::*;

    const LISTEN: &str = "127.0.0.1:7421";

    fn headers(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    #[test]
    fn a_read_needs_the_exact_host() {
        let own = headers(&[(header::HOST, LISTEN)]);
        assert_eq!(admit(LISTEN, &Method::GET, &own), Ok(()));
        for host in [
            "localhost:7421",
            "127.0.0.1",
            "127.0.0.1:7422",
            "evil.example",
        ] {
            let other = headers(&[(header::HOST, host)]);
            assert_eq!(admit(LISTEN, &Method::GET, &other), Err(Refusal::WrongHost));
        }
        assert_eq!(
            admit(LISTEN, &Method::GET, &HeaderMap::new()),
            Err(Refusal::WrongHost)
        );
    }

    #[test]
    fn a_write_needs_the_console_as_origin() {
        let own = headers(&[
            (header::HOST, LISTEN),
            (header::ORIGIN, "http://127.0.0.1:7421"),
        ]);
        assert_eq!(admit(LISTEN, &Method::POST, &own), Ok(()));
        let absent = headers(&[(header::HOST, LISTEN)]);
        assert_eq!(
            admit(LISTEN, &Method::POST, &absent),
            Err(Refusal::ForeignOrigin)
        );
        for origin in [
            "http://localhost:7421",
            "https://127.0.0.1:7421",
            "null",
            "http://evil.example",
        ] {
            let foreign = headers(&[(header::HOST, LISTEN), (header::ORIGIN, origin)]);
            assert_eq!(
                admit(LISTEN, &Method::POST, &foreign),
                Err(Refusal::ForeignOrigin)
            );
            assert_eq!(
                admit(LISTEN, &Method::OPTIONS, &foreign),
                Err(Refusal::ForeignOrigin)
            );
        }
    }

    #[test]
    fn the_host_check_comes_before_the_origin_check() {
        let other = headers(&[
            (header::HOST, "localhost:7421"),
            (header::ORIGIN, "http://127.0.0.1:7421"),
        ]);
        assert_eq!(
            admit(LISTEN, &Method::POST, &other),
            Err(Refusal::WrongHost)
        );
    }

    #[test]
    fn only_the_listed_reads_pass() {
        for path in READS {
            assert_eq!(allowed(&Method::GET, path), Some(Allowed::Read), "{path}");
        }
        assert_eq!(
            allowed(&Method::GET, "/v1/transactions/12"),
            Some(Allowed::Read)
        );
        for path in [
            "/v1/methods",
            "/v1/wallet/password",
            "/v1/slates/receive",
            "/v2/foreign",
            "/v1/transactions/",
            "/v1/transactions/abc",
            "/v1/transactions/12/",
            "/v1/transactions/12/messages",
            "/v1/status/",
            "/V1/status",
            "/",
        ] {
            assert_eq!(allowed(&Method::GET, path), None, "{path}");
        }
    }

    #[test]
    fn the_only_write_is_cancel() {
        assert_eq!(
            allowed(&Method::POST, "/v1/transactions/7/cancel"),
            Some(Allowed::Cancel)
        );
        for (method, path) in [
            (Method::POST, "/v1/transactions"),
            (Method::POST, "/v1/transactions/7"),
            (Method::POST, "/v1/transactions//cancel"),
            (Method::POST, "/v1/transactions/7/cancel/"),
            (Method::PUT, "/v1/transactions/7/cancel"),
            (Method::DELETE, "/v1/transactions/7"),
            (Method::PUT, "/v1/wallet/password"),
            (Method::POST, "/v1/status"),
        ] {
            assert_eq!(allowed(&method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn cancel_is_found_in_the_document_by_its_shape() {
        let with = json!({"paths": {"/v1/transactions/{tx_id}/cancel": {"post": {}}}});
        assert!(lists_cancel(&with));
        let other_name = json!({"paths": {"/v1/transactions/{id}/cancel": {"post": {}}}});
        assert!(lists_cancel(&other_name));
        let get_only = json!({"paths": {"/v1/transactions/{tx_id}/cancel": {"get": {}}}});
        assert!(!lists_cancel(&get_only));
        let without = json!({"paths": {"/v1/transactions/{tx_id}": {"get": {}}}});
        assert!(!lists_cancel(&without));
        assert!(!lists_cancel(&json!({})));
        assert!(!lists_cancel(&json!(null)));
    }
}
