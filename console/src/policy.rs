// SPDX-License-Identifier: Apache-2.0
//! What the console answers: requests addressed to its own listen address; the page and its
//! assets to anyone who reaches that address; a session exchange for the link token printed at
//! launch; API requests that carry a session in `Authorization: Bearer`; writes from its own
//! origin only; and a fixed list of API routes.

use hyper::Method;
use hyper::header::{self, HeaderMap};

/// The header that carries the link token to `POST /session`.
pub(crate) const LINK_HEADER: &str = "x-lepic-console-link";

/// Why a request is refused before it is routed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The `Host` header is not the console's own listen address.
    WrongHost,
    /// The request does not carry a session in `Authorization: Bearer`.
    NoSession,
    /// A request that is not a read came without the console's own `Origin`.
    ForeignOrigin,
}

/// Whether the request names the console's own listen address in `Host`, as a browser writes it.
pub(crate) fn host_is_own(listen: &str, headers: &HeaderMap) -> bool {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        == Some(listen)
}

/// Whether the request's `Origin` is exactly the console's own origin.
fn origin_is_own(listen: &str, headers: &HeaderMap) -> bool {
    let own = format!("http://{listen}");
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        == Some(own.as_str())
}

/// Compares two strings in time that depends on their length only.
pub(crate) fn same_token(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// The session in the request's `Authorization: Bearer` header, if there is one.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// The link token the request offers in the console's link header, if there is one.
pub(crate) fn offered_link(headers: &HeaderMap) -> Option<&str> {
    headers.get(LINK_HEADER)?.to_str().ok()
}

/// Refuses a request for the page or an asset that was sent to another host name. `listen` is
/// the address the console answers on, as a browser writes it in `Host`.
pub(crate) fn admit_page(listen: &str, headers: &HeaderMap) -> Result<(), Refusal> {
    if host_is_own(listen, headers) {
        Ok(())
    } else {
        Err(Refusal::WrongHost)
    }
}

/// Refuses a session exchange sent to another host name or from another origin. The link token
/// itself is checked by the caller, which owns it.
pub(crate) fn admit_exchange(listen: &str, headers: &HeaderMap) -> Result<(), Refusal> {
    admit_page(listen, headers)?;
    if origin_is_own(listen, headers) {
        Ok(())
    } else {
        Err(Refusal::ForeignOrigin)
    }
}

/// Refuses an API request sent to another host name, one without a session `is_session`
/// accepts, or a write another page sent.
pub(crate) fn admit_api(
    listen: &str,
    method: &Method,
    headers: &HeaderMap,
    is_session: impl FnOnce(&str) -> bool,
) -> Result<(), Refusal> {
    admit_page(listen, headers)?;
    if !bearer(headers).is_some_and(is_session) {
        return Err(Refusal::NoSession);
    }
    if method == Method::GET || origin_is_own(listen, headers) {
        Ok(())
    } else {
        Err(Refusal::ForeignOrigin)
    }
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

/// Whether the page may call the route `method` and `path` (without its query) name.
pub(crate) fn allowed(method: &Method, path: &str) -> bool {
    let under_transaction = path
        .strip_prefix("/v1/transactions/")
        .map(|rest| rest.split('/').collect::<Vec<_>>());
    match (method.as_str(), under_transaction.as_deref()) {
        ("GET", None) => READS.contains(&path),
        ("GET", Some([id])) | ("POST", Some([id, "cancel"])) => is_tx_id(id),
        _ => false,
    }
}

fn is_tx_id(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;

    const LISTEN: &str = "127.0.0.1:7421";
    const SESSION: &str = "0123456789abcdef";
    const BEARER: &str = "Bearer 0123456789abcdef";

    fn headers(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    fn is_session(offered: &str) -> bool {
        same_token(offered, SESSION)
    }

    #[test]
    fn a_page_needs_the_exact_host_and_nothing_else() {
        assert_eq!(
            admit_page(LISTEN, &headers(&[(header::HOST, LISTEN)])),
            Ok(())
        );
        for host in [
            "localhost:7421",
            "127.0.0.1",
            "127.0.0.1:7422",
            "evil.example",
        ] {
            assert_eq!(
                admit_page(LISTEN, &headers(&[(header::HOST, host)])),
                Err(Refusal::WrongHost)
            );
        }
        assert_eq!(
            admit_page(LISTEN, &HeaderMap::new()),
            Err(Refusal::WrongHost)
        );
    }

    #[test]
    fn an_api_read_needs_the_exact_host() {
        let own = headers(&[(header::HOST, LISTEN), (header::AUTHORIZATION, BEARER)]);
        assert_eq!(admit_api(LISTEN, &Method::GET, &own, is_session), Ok(()));
        for host in ["localhost:7421", "127.0.0.1", "127.0.0.1:7422"] {
            let other = headers(&[(header::HOST, host), (header::AUTHORIZATION, BEARER)]);
            assert_eq!(
                admit_api(LISTEN, &Method::GET, &other, is_session),
                Err(Refusal::WrongHost)
            );
        }
        assert_eq!(
            admit_api(LISTEN, &Method::GET, &HeaderMap::new(), is_session),
            Err(Refusal::WrongHost)
        );
    }

    #[test]
    fn an_api_write_needs_the_console_as_origin() {
        let own = headers(&[
            (header::HOST, LISTEN),
            (header::AUTHORIZATION, BEARER),
            (header::ORIGIN, "http://127.0.0.1:7421"),
        ]);
        assert_eq!(admit_api(LISTEN, &Method::POST, &own, is_session), Ok(()));
        let absent = headers(&[(header::HOST, LISTEN), (header::AUTHORIZATION, BEARER)]);
        assert_eq!(
            admit_api(LISTEN, &Method::POST, &absent, is_session),
            Err(Refusal::ForeignOrigin)
        );
        for origin in [
            "http://localhost:7421",
            "https://127.0.0.1:7421",
            "null",
            "http://evil.example",
        ] {
            let foreign = headers(&[
                (header::HOST, LISTEN),
                (header::AUTHORIZATION, BEARER),
                (header::ORIGIN, origin),
            ]);
            assert_eq!(
                admit_api(LISTEN, &Method::POST, &foreign, is_session),
                Err(Refusal::ForeignOrigin)
            );
            assert_eq!(
                admit_api(LISTEN, &Method::OPTIONS, &foreign, is_session),
                Err(Refusal::ForeignOrigin)
            );
        }
    }

    #[test]
    fn the_host_check_comes_before_the_session_and_origin_checks() {
        let other = headers(&[
            (header::HOST, "localhost:7421"),
            (header::ORIGIN, "http://evil.example"),
        ]);
        assert_eq!(
            admit_api(LISTEN, &Method::POST, &other, is_session),
            Err(Refusal::WrongHost)
        );
        assert_eq!(admit_exchange(LISTEN, &other), Err(Refusal::WrongHost));
    }

    #[test]
    fn an_api_request_needs_a_session_in_its_bearer_header() {
        let own = |authorization: Option<&str>| {
            let mut pairs = vec![(header::HOST, LISTEN)];
            if let Some(authorization) = authorization {
                pairs.push((header::AUTHORIZATION, authorization));
            }
            headers(&pairs)
        };
        assert_eq!(
            admit_api(LISTEN, &Method::GET, &own(None), is_session),
            Err(Refusal::NoSession)
        );
        for authorization in [
            "Bearer 0123456789abcdee",
            "Bearer 0123456789abcde",
            "Bearer ",
            "Bearer",
            "bearer 0123456789abcdef",
            "Basic 0123456789abcdef",
            "0123456789abcdef",
        ] {
            assert_eq!(
                admit_api(LISTEN, &Method::GET, &own(Some(authorization)), is_session),
                Err(Refusal::NoSession),
                "{authorization}"
            );
        }
        assert_eq!(
            admit_api(LISTEN, &Method::GET, &own(Some(BEARER)), is_session),
            Ok(())
        );
    }

    #[test]
    fn an_exchange_needs_the_console_as_origin() {
        let own = headers(&[
            (header::HOST, LISTEN),
            (header::ORIGIN, "http://127.0.0.1:7421"),
        ]);
        assert_eq!(admit_exchange(LISTEN, &own), Ok(()));
        for origin in [None, Some("null"), Some("http://localhost:7421")] {
            let mut pairs = vec![(header::HOST, LISTEN)];
            if let Some(origin) = origin {
                pairs.push((header::ORIGIN, origin));
            }
            assert_eq!(
                admit_exchange(LISTEN, &headers(&pairs)),
                Err(Refusal::ForeignOrigin)
            );
        }
    }

    #[test]
    fn the_link_is_read_from_its_header() {
        assert_eq!(
            offered_link(&headers(&[(
                header::HeaderName::from_static(LINK_HEADER),
                "ab"
            )])),
            Some("ab")
        );
        assert_eq!(offered_link(&HeaderMap::new()), None);
        assert!(same_token("ab", "ab"));
        assert!(!same_token("ab", "ac"));
        assert!(!same_token("ab", "abc"));
    }

    #[test]
    fn only_the_listed_reads_pass() {
        for path in READS {
            assert!(allowed(&Method::GET, path), "{path}");
        }
        assert!(allowed(&Method::GET, "/v1/transactions/12"));
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
            assert!(!allowed(&Method::GET, path), "{path}");
        }
    }

    #[test]
    fn the_only_write_is_cancel() {
        assert!(allowed(&Method::POST, "/v1/transactions/7/cancel"));
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
            assert!(!allowed(&method, path), "{method} {path}");
        }
    }
}
