// SPDX-License-Identifier: Apache-2.0
//! The address of a listening wallet: `http(s)://host[:port][/path]`, normalised to its
//! `/v2/foreign` endpoint the way `epic-wallet` appends it.

use std::net::IpAddr;

use crate::error::UrlError;

/// The port `epic-wallet listen` serves the foreign API on.
pub const DEFAULT_LISTEN_PORT: u16 = 3415;

const ENDPOINT: &str = "v2/foreign";

/// Whether plain `http` may go to a host that is not this computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlainHttp {
    /// Only to loopback; anywhere else needs `https`.
    #[default]
    LoopbackOnly,
    /// The user agreed to send unencrypted to this host.
    Allowed,
}

/// The scheme of a [`ForeignUrl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

/// A checked foreign API endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForeignUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    endpoint: String,
}

impl ForeignUrl {
    /// Parses what a user typed. The scheme is matched without case (`HTTP://` works, as in the
    /// GUI); a missing scheme is refused, so a typo never sends unencrypted by surprise. A
    /// missing port is 3415 for `http` and 443 for `https`. A path is kept, and `/v2/foreign` is
    /// appended unless it already ends with it. `.onion` hosts are refused here: they go through
    /// Tor.
    pub fn parse(input: &str, plain: PlainHttp) -> Result<Self, UrlError> {
        let input = input.trim();
        let (scheme, rest) = split_scheme(input)?;
        if rest.contains(['?', '#', '@']) || rest.chars().any(char::is_whitespace) {
            return Err(UrlError::ExtraParts);
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = split_port(authority, scheme)?;
        if host.is_empty() {
            return Err(UrlError::NoHost);
        }
        let host = host.to_ascii_lowercase();
        if host.trim_end_matches('.').ends_with(".onion") {
            return Err(UrlError::OnionNeedsTor);
        }
        if scheme == Scheme::Http && plain == PlainHttp::LoopbackOnly && !is_loopback(&host) {
            return Err(UrlError::PlainHttpNotAllowed);
        }
        let path = path.trim_end_matches('/');
        let endpoint = if path.is_empty() {
            format!("/{ENDPOINT}")
        } else if path.ends_with(ENDPOINT) {
            format!("/{path}")
        } else {
            format!("/{path}/{ENDPOINT}")
        };
        Ok(Self {
            scheme,
            host,
            port,
            endpoint,
        })
    }

    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host as given, lowercase; an IPv6 address keeps its brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The full URL of the endpoint.
    pub fn as_uri(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        format!("{scheme}://{}:{}{}", self.host, self.port, self.endpoint)
    }
}

impl std::fmt::Display for ForeignUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_uri())
    }
}

fn split_scheme(input: &str) -> Result<(Scheme, &str), UrlError> {
    let (scheme, rest) = input.split_once("://").ok_or(UrlError::NotHttp)?;
    let scheme = if scheme.eq_ignore_ascii_case("http") {
        Scheme::Http
    } else if scheme.eq_ignore_ascii_case("https") {
        Scheme::Https
    } else {
        return Err(UrlError::NotHttp);
    };
    Ok((scheme, rest))
}

fn split_port(authority: &str, scheme: Scheme) -> Result<(&str, u16), UrlError> {
    let default = match scheme {
        Scheme::Http => DEFAULT_LISTEN_PORT,
        Scheme::Https => 443,
    };
    // `[::1]:3415`: the port follows the closing bracket.
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (inside, tail) = after.split_once(']').ok_or(UrlError::NoHost)?;
        let host_len = inside.len().checked_add(2).ok_or(UrlError::NoHost)?;
        let host = authority.get(..host_len).ok_or(UrlError::NoHost)?;
        match tail.strip_prefix(':') {
            Some(port) => (host, Some(port)),
            None if tail.is_empty() => (host, None),
            None => return Err(UrlError::InvalidPort),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => default,
        Some(port) => match port.parse::<u16>() {
            Ok(0) | Err(_) => return Err(UrlError::InvalidPort),
            Ok(port) => port,
        },
    };
    Ok((host, port))
}

fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(input: &str, plain: PlainHttp) -> String {
        ForeignUrl::parse(input, plain).unwrap().as_uri()
    }

    #[test]
    fn appends_the_endpoint_and_default_ports() {
        let all = PlainHttp::Allowed;
        assert_eq!(
            uri("http://203.0.113.7", all),
            "http://203.0.113.7:3415/v2/foreign"
        );
        assert_eq!(
            uri("HTTP://Host.Example:3420/", all),
            "http://host.example:3420/v2/foreign"
        );
        assert_eq!(
            uri("https://w.example", all),
            "https://w.example:443/v2/foreign"
        );
        assert_eq!(
            uri("https://w.example/wallet", all),
            "https://w.example:443/wallet/v2/foreign"
        );
        assert_eq!(
            uri("https://w.example/v2/foreign", all),
            "https://w.example:443/v2/foreign"
        );
        assert_eq!(
            uri("http://[::1]:13415", PlainHttp::LoopbackOnly),
            "http://[::1]:13415/v2/foreign"
        );
    }

    #[test]
    fn plain_http_needs_consent_except_on_loopback() {
        let loopback = PlainHttp::LoopbackOnly;
        assert_eq!(
            ForeignUrl::parse("http://203.0.113.7:3415", loopback),
            Err(UrlError::PlainHttpNotAllowed)
        );
        assert!(ForeignUrl::parse("http://127.0.0.1:3415", loopback).is_ok());
        assert!(ForeignUrl::parse("http://localhost", loopback).is_ok());
        assert!(ForeignUrl::parse("https://203.0.113.7", loopback).is_ok());
    }

    #[test]
    fn refuses_what_is_not_a_listener_address() {
        let all = PlainHttp::Allowed;
        let err = |input: &str| ForeignUrl::parse(input, all).unwrap_err();
        assert_eq!(err("host.example:3415"), UrlError::NotHttp);
        assert_eq!(err("ftp://host"), UrlError::NotHttp);
        assert_eq!(err("http://"), UrlError::NoHost);
        assert_eq!(err("http://:3415"), UrlError::NoHost);
        assert_eq!(err("http://user:pw@host"), UrlError::ExtraParts);
        assert_eq!(err("http://host/?a=1"), UrlError::ExtraParts);
        assert_eq!(err("http://host/#x"), UrlError::ExtraParts);
        assert_eq!(err("http://host:0"), UrlError::InvalidPort);
        assert_eq!(err("http://host:99999"), UrlError::InvalidPort);
        assert_eq!(err("http://[::1]x"), UrlError::InvalidPort);
        assert_eq!(
            err(&format!("http://{}.onion", "abcdefghijklmnop")),
            UrlError::OnionNeedsTor
        );
        assert_eq!(
            err(&format!("https://{}.onion.", "abcdefghijklmnop")),
            UrlError::OnionNeedsTor
        );
        assert_eq!(
            err(&format!("https://{}.Onion../", "ABCDEFGHIJKLMNOP")),
            UrlError::OnionNeedsTor
        );
    }

    proptest::proptest! {
        #[test]
        fn never_panics(input in "\\PC{0,80}") {
            let _ = ForeignUrl::parse(&input, PlainHttp::Allowed);
        }
    }
}
