// SPDX-License-Identifier: Apache-2.0
//! Where a post goes: a delivery method and the text that addresses it on that method. These are
//! the forms a native post's route is stored in.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::relay::parse_host_port;

/// The port of an `http` entry that names none: HTTPS.
pub const HTTP_DEFAULT_PORT: u16 = 443;
/// The port of a `tor` entry that names none.
pub const TOR_DEFAULT_PORT: u16 = 80;
/// Characters in the name of an onion service, before `.onion`.
const ONION_NAME_LEN: usize = 56;

/// A delivery method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MethodId {
    Epicbox,
    Http,
    Tor,
}

impl MethodId {
    /// The text form: `epicbox`, `http` or `tor`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Epicbox => "epicbox",
            Self::Http => "http",
            Self::Tor => "tor",
        }
    }
}

impl fmt::Display for MethodId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A method name that is not one of [`MethodId`]'s text forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown delivery method")]
pub struct UnknownMethod;

impl FromStr for MethodId {
    type Err = UnknownMethod;

    /// Reads the exact text form; nothing else is taken, case included.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "epicbox" => Ok(Self::Epicbox),
            "http" => Ok(Self::Http),
            "tor" => Ok(Self::Tor),
            _ => Err(UnknownMethod),
        }
    }
}

/// One way to reach a recipient: the text of a link entry of the same key. `value` is
/// `<host>[:<port>]` for [`MethodId::Http`] (HTTPS) and `<56 base32>.onion[:<port>]` for
/// [`MethodId::Tor`]. For [`MethodId::Epicbox`] it is the mailbox key alone for a mailbox
/// route, posted to that mailbox on every usable relay of the list (an epic1 payment to the
/// delivery mailbox, built by `payer_routes` in lepic-wallet-contacts), and
/// `<mailbox key>@<domain>[:<port>]` for a post to one relay (an answer to a reply mailbox,
/// built by `reply_route`, and a post to a contact, built by `contact_owed`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteEntry {
    pub method: MethodId,
    pub value: String,
}

impl RouteEntry {
    /// The host and port an `http` or `tor` entry is posted to, with the method's default port.
    /// `None` for an `epicbox` entry and for a value not in its form. The onion checksum is not
    /// checked here: the poster checks it before it connects.
    pub fn host_port(&self) -> Option<(String, u16)> {
        match self.method {
            MethodId::Epicbox => None,
            MethodId::Http => {
                let (host, port) = parse_host_port(&self.value).ok()?;
                Some((host.to_string(), port.unwrap_or(HTTP_DEFAULT_PORT)))
            }
            MethodId::Tor => {
                let (host, port) = onion_host_port(&self.value)?;
                Some((host.to_owned(), port.unwrap_or(TOR_DEFAULT_PORT)))
            }
        }
    }
}

/// The host and port of a `tor` value: exactly `<56 of a-z2-7>.onion[:<port>]`, lower case.
/// Only the form is checked.
pub(crate) fn onion_host_port(text: &str) -> Option<(&str, Option<u16>)> {
    let host = text.split_once(':').map_or(text, |(host, _)| host);
    let name = host.strip_suffix(".onion")?;
    let base32 = name
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'));
    if name.len() != ONION_NAME_LEN || !base32 {
        return None;
    }
    let (_, port) = parse_host_port(text).ok()?;
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_text_forms_round_trip() {
        for (method, text) in [
            (MethodId::Epicbox, "epicbox"),
            (MethodId::Http, "http"),
            (MethodId::Tor, "tor"),
        ] {
            assert_eq!(method.as_str(), text);
            assert_eq!(method.to_string(), text);
            assert_eq!(text.parse::<MethodId>(), Ok(method));
        }
    }

    #[test]
    fn an_unknown_method_is_a_typed_error() {
        for text in ["", "smtp", "Epicbox", "TOR", " http", "epicbox "] {
            assert_eq!(text.parse::<MethodId>(), Err(UnknownMethod), "{text:?}");
        }
    }
}
