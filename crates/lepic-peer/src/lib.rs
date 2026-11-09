// SPDX-License-Identifier: Apache-2.0
//! The native direct endpoint (ADR 0052): the `/v1/peer` routes a LEPIC listener serves on the
//! same socket as the foreign API, the advert its `check_version` answer carries, and the client
//! that reads a listener's endpoint and posts an envelope to it.
//!
//! The crate moves envelope bytes only. Opening and sealing them is the [`SlateHandler`]'s, on
//! the listener side, and the caller's on the sending side.

pub mod client;
pub mod error;
pub mod origin;
pub mod problem;
pub mod server;

use serde::{Deserialize, Serialize};

pub use client::{
    AddressClass, PeerClient, PeerClientSettings, PeerDialFuture, PeerDialer, PeerStream,
};
pub use error::{PeerClientError, PeerFormatError};
pub use lepic_primitives::params::Network;
pub use origin::{Origin, OriginError, PeerTarget, WebScheme};
pub use problem::{Problem, ProblemCode};
pub use server::{
    HandlerFuture, MAX_CACHED_REPLIES, PeerAnswer, PeerEndpoint, PeerRefusal, PeerRoute,
    SlateHandler, problem_response,
};

/// The shape of the endpoint this crate speaks. An additive change keeps it; a break is a new
/// path.
pub const PROTOCOL: u32 = 1;
/// The slate format the endpoint carries in protocol 1.
pub const FORMAT_LEPIC_V1: &str = "lepic.v1";
/// The path of the endpoint's description, and the prefix of its other routes.
pub const PEER_PATH: &str = "/v1/peer";
/// The path an envelope is posted to.
pub const SLATES_PATH: &str = "/v1/peer/slates";
/// The media type of an envelope posted to [`SLATES_PATH`] and of its reply (D4).
pub const ENVELOPE_MEDIA_TYPE: &str = "application/vnd.lepic.epictx";
/// The largest body [`SLATES_PATH`] takes: the largest slate envelope, rounded up to 68 KiB.
pub const MAX_ENVELOPE_LEN: usize = 69_632;
/// The length of a listener's seal key.
pub const SEAL_KEY_LEN: usize = 32;
/// The most formats an advert or description is read with.
const MAX_FORMATS: usize = 16;
/// The longest format name read.
const MAX_FORMAT_LEN: usize = 64;
/// The longest endpoint path an advert is read with.
const MAX_PATH_LEN: usize = 256;

/// The `lepic` key of a LEPIC listener's `check_version` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    pub protocol: u32,
    pub formats: Vec<String>,
    /// The endpoint's path on the listener's origin.
    pub path: String,
    /// The seal key of the listener that accepted the connection.
    pub seal: [u8; SEAL_KEY_LEN],
}

impl Advert {
    /// The advert of this crate's endpoint under `seal`.
    pub fn new(seal: [u8; SEAL_KEY_LEN]) -> Self {
        Self {
            protocol: PROTOCOL,
            formats: vec![FORMAT_LEPIC_V1.to_owned()],
            path: PEER_PATH.to_owned(),
            seal,
        }
    }

    /// The advert as the JSON object the `lepic` key holds.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "protocol": self.protocol,
            "formats": self.formats,
            "path": self.path,
            "seal": to_hex(&self.seal),
        })
    }

    /// Reads the `lepic` key of a `check_version` answer. Unknown keys are ignored. Fails with
    /// [`PeerFormatError`] for a missing or malformed field, a seal key that is not 64 hex
    /// digits, a path that is not absolute, and more formats or longer names than any listener
    /// sends.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, PeerFormatError> {
        let raw: RawAdvert =
            serde_json::from_value(value.clone()).map_err(|_| PeerFormatError::Malformed)?;
        check_formats(&raw.formats)?;
        if !valid_path(&raw.path) {
            return Err(PeerFormatError::Path);
        }
        Ok(Self {
            protocol: raw.protocol,
            formats: raw.formats,
            path: raw.path,
            seal: key_from_hex(&raw.seal)?,
        })
    }

    /// Whether the advert offers `format`.
    pub fn offers(&self, format: &str) -> bool {
        self.formats.iter().any(|offered| offered == format)
    }
}

#[derive(Deserialize)]
struct RawAdvert {
    protocol: u32,
    formats: Vec<String>,
    path: String,
    seal: String,
}

/// The answer of `GET /v1/peer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub protocol: u32,
    pub formats: Vec<String>,
    /// `mainnet` or `floonet`.
    pub network: String,
    /// The listener's seal key, 64 hex digits.
    pub key: String,
}

impl PeerInfo {
    /// The seal key, read from its hex. Fails with [`PeerFormatError::Key`] when it is not 64
    /// hex digits.
    pub fn seal_key(&self) -> Result<[u8; SEAL_KEY_LEN], PeerFormatError> {
        key_from_hex(&self.key)
    }

    pub(crate) fn check(&self) -> Result<(), PeerFormatError> {
        check_formats(&self.formats)?;
        self.seal_key().map(|_| ())
    }
}

fn check_formats(formats: &[String]) -> Result<(), PeerFormatError> {
    if formats.len() > MAX_FORMATS || formats.iter().any(|format| format.len() > MAX_FORMAT_LEN) {
        return Err(PeerFormatError::Formats);
    }
    Ok(())
}

/// Whether `path` is an absolute path of printable ASCII with no query or fragment.
pub(crate) fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_PATH_LEN
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'?' && byte != b'#')
}

/// Lowercase hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte / 16, byte % 16] {
            text.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    text
}

/// A seal key from its 64 hex digits, either case. Fails with [`PeerFormatError::Key`].
pub fn key_from_hex(text: &str) -> Result<[u8; SEAL_KEY_LEN], PeerFormatError> {
    let digits = text.as_bytes();
    if digits.len() != SEAL_KEY_LEN.saturating_mul(2) {
        return Err(PeerFormatError::Key);
    }
    let mut key = [0; SEAL_KEY_LEN];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, [high, low]) in key.iter_mut().zip(pairs) {
        *byte = hex_digit(*high)?.wrapping_shl(4) | hex_digit(*low)?;
    }
    Ok(key)
}

fn hex_digit(digit: u8) -> Result<u8, PeerFormatError> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(PeerFormatError::Key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_other_lengths_and_digits() {
        let key = [0xab; 32];
        let text = to_hex(&key);
        assert_eq!(text, "ab".repeat(32));
        assert_eq!(key_from_hex(&text).unwrap(), key);
        assert_eq!(key_from_hex(&text.to_uppercase()).unwrap(), key);
        for bad in ["", &text[..62], &format!("{text}00"), &"zz".repeat(32)] {
            assert_eq!(key_from_hex(bad), Err(PeerFormatError::Key), "{bad}");
        }
    }

    #[test]
    fn adverts_round_trip_and_ignore_unknown_keys() {
        let advert = Advert::new([7; 32]);
        let mut json = advert.to_json();
        assert_eq!(
            json.to_string(),
            format!(
                r#"{{"formats":["lepic.v1"],"path":"/v1/peer","protocol":1,"seal":"{}"}}"#,
                "07".repeat(32)
            )
        );
        json["later"] = serde_json::json!({"x": 1});
        assert_eq!(Advert::from_json(&json).unwrap(), advert);
        assert!(advert.offers(FORMAT_LEPIC_V1));
        assert!(!advert.offers("lepic.v2"));
    }

    #[test]
    fn refuses_adverts_with_a_bad_key_path_or_formats() {
        let good = Advert::new([7; 32]).to_json();
        let with = |key: &str, value: serde_json::Value| {
            let mut json = good.clone();
            json[key] = value;
            Advert::from_json(&json)
        };
        assert_eq!(with("seal", "00".into()), Err(PeerFormatError::Key));
        assert_eq!(with("path", "v1/peer".into()), Err(PeerFormatError::Path));
        assert_eq!(
            with("path", "/v1/peer?x".into()),
            Err(PeerFormatError::Path)
        );
        assert_eq!(
            with("formats", serde_json::json!(vec!["a"; 17])),
            Err(PeerFormatError::Formats)
        );
        assert_eq!(
            with("protocol", "1".into()),
            Err(PeerFormatError::Malformed)
        );
        assert_eq!(
            Advert::from_json(&serde_json::json!("x")),
            Err(PeerFormatError::Malformed)
        );
    }
}
