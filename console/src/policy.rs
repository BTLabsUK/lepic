// SPDX-License-Identifier: Apache-2.0
//! What the console answers: requests addressed to its own listen address, writes from its own
//! page only, and a fixed list of API routes.

use hyper::Method;
use hyper::header::{self, HeaderMap};

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
