// SPDX-License-Identifier: Apache-2.0
//! Where a native endpoint is: the origin a pin is kept under, and the target a client posts to.

use std::fmt;

use crate::valid_path;

/// The longest host read.
const MAX_HOST_LEN: usize = 253;

/// The scheme of a web origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WebScheme {
    Http,
    Https,
}

impl WebScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// An address that cannot be an origin or a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OriginError {
    #[error("the address has no host")]
    NoHost,
    #[error("the host is not a name or an address")]
    Host,
    #[error("the scheme is not http or https")]
    Scheme,
    #[error("the port is missing or not a number from 1 to 65535")]
    Port,
    #[error("the path is not an absolute path")]
    Path,
}

/// The origin a pin is kept under (5.15): scheme, lowercased host and explicit port; or, behind
/// an onion, the onion name alone, whatever scheme and port reached it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    Web {
        scheme: WebScheme,
        host: String,
        port: u16,
    },
    Onion {
        name: String,
    },
}

impl Origin {
    /// The origin of `host` reached with `scheme` on `port`; an onion host makes an onion
    /// origin. The host is lowercased and loses a trailing dot; an IPv6 address keeps its
    /// brackets.
    pub fn new(scheme: WebScheme, host: &str, port: u16) -> Result<Self, OriginError> {
        let host = normal_host(host)?;
        if host.ends_with(".onion") {
            return Ok(Self::Onion { name: host });
        }
        if port == 0 {
            return Err(OriginError::Port);
        }
        Ok(Self::Web { scheme, host, port })
    }

    /// Reads an origin as its `Display` writes it: `http://host:port`, `https://host:port`
    /// (the port written out), or `name.onion`. The scheme and host are matched without case.
    pub fn parse(text: &str) -> Result<Self, OriginError> {
        let text = text.trim();
        let Some((scheme, rest)) = text.split_once("://") else {
            if text.is_empty() {
                return Err(OriginError::NoHost);
            }
            let host = normal_host(text).map_err(|_| OriginError::Scheme)?;
            return if host.ends_with(".onion") {
                Ok(Self::Onion { name: host })
            } else {
                Err(OriginError::Scheme)
            };
        };
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "http" => WebScheme::Http,
            "https" => WebScheme::Https,
            _ => return Err(OriginError::Scheme),
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = split_port(authority)?;
        Self::new(scheme, host, port)
    }

    pub const fn is_onion(&self) -> bool {
        matches!(self, Self::Onion { .. })
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Web { scheme, host, port } => write!(f, "{}://{host}:{port}", scheme.as_str()),
            Self::Onion { name } => f.write_str(name),
        }
    }
}

/// The endpoint a client posts to: the scheme, host and port it connects to, and the path the
/// listener's advert named.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerTarget {
    scheme: WebScheme,
    host: String,
    port: u16,
    path: String,
    origin: Origin,
}

impl PeerTarget {
    /// The endpoint at `path` on `host:port`. Fails with [`OriginError`] for an empty or odd
    /// host, port 0 and a path that is not absolute.
    pub fn new(scheme: WebScheme, host: &str, port: u16, path: &str) -> Result<Self, OriginError> {
        let origin = Origin::new(scheme, host, port)?;
        if port == 0 {
            return Err(OriginError::Port);
        }
        if !valid_path(path) {
            return Err(OriginError::Path);
        }
        Ok(Self {
            scheme,
            host: normal_host(host)?,
            port,
            path: path.trim_end_matches('/').to_owned(),
            origin,
        })
    }

    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The URL of the endpoint's description.
    pub fn info_uri(&self) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme.as_str(),
            self.host,
            self.port,
            self.path
        )
    }

    /// The URL envelopes are posted to.
    pub fn slates_uri(&self) -> String {
        format!("{}/slates", self.info_uri())
    }
}

fn normal_host(host: &str) -> Result<String, OriginError> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(OriginError::NoHost);
    }
    let bracketed = host.starts_with('[') && host.ends_with(']');
    let allowed =
        |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_';
    let ipv6 = |byte: u8| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.';
    let inner = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(&host);
    let ok = if bracketed {
        !inner.is_empty() && inner.bytes().all(ipv6)
    } else {
        host.bytes().all(allowed)
    };
    if !ok || host.len() > MAX_HOST_LEN {
        return Err(OriginError::Host);
    }
    Ok(host)
}

/// `host:port`, an IPv6 host in brackets. The port is required.
fn split_port(authority: &str) -> Result<(&str, u16), OriginError> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(OriginError::Host)?;
        let (host, rest) = authority.split_at(end.saturating_add(1));
        (host, rest.strip_prefix(':').ok_or(OriginError::Port)?)
    } else {
        authority.rsplit_once(':').ok_or(OriginError::Port)?
    };
    let port = port.parse::<u16>().map_err(|_| OriginError::Port)?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

    #[test]
    fn origins_are_scheme_lowercased_host_and_explicit_port() {
        let origin = Origin::new(WebScheme::Https, "Wallet.Example.", 443).unwrap();
        assert_eq!(origin.to_string(), "https://wallet.example:443");
        assert_eq!(
            Origin::parse("HTTPS://WALLET.example:443/").unwrap(),
            origin
        );
        let ipv6 = Origin::new(WebScheme::Http, "[::1]", 3415).unwrap();
        assert_eq!(ipv6.to_string(), "http://[::1]:3415");
        assert_eq!(Origin::parse("http://[::1]:3415").unwrap(), ipv6);
        assert_ne!(
            Origin::new(WebScheme::Http, "wallet.example", 443).unwrap(),
            origin
        );
    }

    #[test]
    fn an_onion_origin_is_its_name_whatever_reached_it() {
        let upper = ONION.to_uppercase();
        let by_http = Origin::new(WebScheme::Http, &upper, 80).unwrap();
        let by_https = Origin::new(WebScheme::Https, ONION, 3415).unwrap();
        assert_eq!(by_http, by_https);
        assert_eq!(by_http.to_string(), ONION);
        assert!(by_http.is_onion());
        assert_eq!(Origin::parse(ONION).unwrap(), by_http);
        assert_eq!(
            Origin::parse(&format!("http://{ONION}:80")).unwrap(),
            by_http
        );
    }

    #[test]
    fn refuses_origins_without_scheme_port_or_host() {
        for (text, error) in [
            ("wallet.example:443", OriginError::Scheme),
            ("ftp://wallet.example:21", OriginError::Scheme),
            ("https://wallet.example", OriginError::Port),
            ("https://wallet.example:0", OriginError::Port),
            ("https://wallet.example:x", OriginError::Port),
            ("https://:443", OriginError::NoHost),
            ("https://wal let:443", OriginError::Host),
            ("https://wallet.example/path:443", OriginError::Host),
            ("", OriginError::NoHost),
        ] {
            assert_eq!(Origin::parse(text), Err(error), "{text}");
        }
    }

    #[test]
    fn targets_join_the_advert_path() {
        let target = PeerTarget::new(WebScheme::Http, "Wallet.Example", 3415, "/v1/peer").unwrap();
        assert_eq!(target.info_uri(), "http://wallet.example:3415/v1/peer");
        assert_eq!(
            target.slates_uri(),
            "http://wallet.example:3415/v1/peer/slates"
        );
        assert_eq!(target.origin().to_string(), "http://wallet.example:3415");
        assert_eq!(
            PeerTarget::new(WebScheme::Http, "wallet.example", 3415, "v1/peer"),
            Err(OriginError::Path)
        );
    }
}
