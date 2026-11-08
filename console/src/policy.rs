// SPDX-License-Identifier: Apache-2.0
//! What the console answers: requests addressed to its own listen address, from the browser that
//! opened the printed link, writes from its own page only, and a fixed list of API routes.

use hyper::Method;
use hyper::header::{self, HeaderMap};

/// The name of the cookie that carries the launch token.
pub(crate) const COOKIE_NAME: &str = "lepic-console";

/// Why a request is refused before it is routed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The `Host` header is not the console's own listen address.
    WrongHost,
    /// The request does not carry the launch token in its cookie.
    NoToken,
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

/// Compares two strings in time that depends on their length only.
pub(crate) fn same_token(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// The value of the `token` parameter in a query string, if there is one.
pub(crate) fn query_token(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
}

fn has_cookie(token: &str, headers: &HeaderMap) -> bool {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| {
            pair.trim()
                .strip_prefix(COOKIE_NAME)
                .and_then(|rest| rest.strip_prefix('='))
        })
        .any(|value| same_token(value, token))
}

/// Refuses a request sent to another host name, one without the launch token's cookie, or a
/// write another page sent. `listen` is the address the console answers on, as a browser writes
/// it in `Host`; `token` is the token drawn at launch.
pub(crate) fn admit(
    listen: &str,
    token: &str,
    method: &Method,
    headers: &HeaderMap,
) -> Result<(), Refusal> {
    if !host_is_own(listen, headers) {
        return Err(Refusal::WrongHost);
    }
    if !has_cookie(token, headers) {
        return Err(Refusal::NoToken);
    }
    if method == Method::GET {
        return Ok(());
    }
    let own = format!("http://{listen}");
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if origin == Some(own.as_str()) {
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
    const TOKEN: &str = "0123456789abcdef";
    const COOKIE: &str = "lepic-console=0123456789abcdef";

    fn headers(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    #[test]
    fn a_read_needs_the_exact_host() {
        let own = headers(&[(header::HOST, LISTEN), (header::COOKIE, COOKIE)]);
        assert_eq!(admit(LISTEN, TOKEN, &Method::GET, &own), Ok(()));
        for host in [
            "localhost:7421",
            "127.0.0.1",
            "127.0.0.1:7422",
            "evil.example",
        ] {
            let other = headers(&[(header::HOST, host), (header::COOKIE, COOKIE)]);
            assert_eq!(
                admit(LISTEN, TOKEN, &Method::GET, &other),
                Err(Refusal::WrongHost)
            );
        }
        assert_eq!(
            admit(LISTEN, TOKEN, &Method::GET, &HeaderMap::new()),
            Err(Refusal::WrongHost)
        );
    }

    #[test]
    fn a_write_needs_the_console_as_origin() {
        let own = headers(&[
            (header::HOST, LISTEN),
            (header::COOKIE, COOKIE),
            (header::ORIGIN, "http://127.0.0.1:7421"),
        ]);
        assert_eq!(admit(LISTEN, TOKEN, &Method::POST, &own), Ok(()));
        let absent = headers(&[(header::HOST, LISTEN), (header::COOKIE, COOKIE)]);
        assert_eq!(
            admit(LISTEN, TOKEN, &Method::POST, &absent),
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
                (header::COOKIE, COOKIE),
                (header::ORIGIN, origin),
            ]);
            assert_eq!(
                admit(LISTEN, TOKEN, &Method::POST, &foreign),
                Err(Refusal::ForeignOrigin)
            );
            assert_eq!(
                admit(LISTEN, TOKEN, &Method::OPTIONS, &foreign),
                Err(Refusal::ForeignOrigin)
            );
        }
    }

    #[test]
    fn the_host_check_comes_before_the_origin_check() {
        let other = headers(&[
            (header::HOST, "localhost:7421"),
            (header::COOKIE, COOKIE),
            (header::ORIGIN, "http://127.0.0.1:7421"),
        ]);
        assert_eq!(
            admit(LISTEN, TOKEN, &Method::POST, &other),
            Err(Refusal::WrongHost)
        );
    }

    #[test]
    fn a_request_needs_the_launch_token_in_its_cookie() {
        let own = |cookie: Option<&str>| {
            let mut pairs = vec![(header::HOST, LISTEN)];
            if let Some(cookie) = cookie {
                pairs.push((header::COOKIE, cookie));
            }
            headers(&pairs)
        };
        assert_eq!(
            admit(LISTEN, TOKEN, &Method::GET, &own(None)),
            Err(Refusal::NoToken)
        );
        for cookie in [
            "lepic-console=0123456789abcdee",
            "lepic-console=0123456789abcde",
            "lepic-console=",
            "other=0123456789abcdef",
            "xlepic-console=0123456789abcdef",
        ] {
            assert_eq!(
                admit(LISTEN, TOKEN, &Method::GET, &own(Some(cookie))),
                Err(Refusal::NoToken),
                "{cookie}"
            );
        }
        for cookie in [
            COOKIE,
            "a=b; lepic-console=0123456789abcdef",
            "lepic-console=0123456789abcdef; a=b",
        ] {
            assert_eq!(
                admit(LISTEN, TOKEN, &Method::GET, &own(Some(cookie))),
                Ok(()),
                "{cookie}"
            );
        }
    }

    #[test]
    fn the_token_is_read_from_the_query() {
        assert_eq!(query_token(Some("token=ab")), Some("ab"));
        assert_eq!(query_token(Some("x=1&token=ab")), Some("ab"));
        assert_eq!(query_token(Some("x=1")), None);
        assert_eq!(query_token(None), None);
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
