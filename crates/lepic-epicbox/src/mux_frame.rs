// SPDX-License-Identifier: Apache-2.0
//! The frames of the mux/1 extension: one websocket carrying many proven mailboxes. The wire
//! format is `docs/protocols/epicbox-mux.md` (draft 2). Decoding follows [`crate::frame`]: the frame
//! length is bounded first, the `type` is read without buffering the frame, unknown fields are
//! ignored and unknown types are not errors.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::frame::{
    FrameError, RelayErrorKind, RelayMessageId, bounded_type_name, check_len, fields, probe_type,
};

/// The extension name, in `ClientDetails.ext` and in the relay's `Ok`.
pub const MUX_EXTENSION: &str = "mux/1";

/// The length of the socket challenge the relay issues: 16 random bytes in unpadded base64url.
pub const MUX_CHALLENGE_LEN: usize = 22;

/// Mailboxes in one `Attach` frame, whatever the relay says.
pub const MAX_ATTACH_PER_FRAME: usize = 64;

/// Mailboxes on one socket, whatever the relay says.
pub const MAX_MAILBOXES_PER_SOCKET: usize = 256;

/// Messages in flight on one socket, whatever the relay says.
pub const MAX_INFLIGHT_PER_SOCKET: usize = 1024;

/// Ids in one `Ack` frame.
pub const MAX_ACK_IDS: usize = 256;

/// The longest hold the relay accepts, in seconds.
pub const MAX_HOLD_SECS: u32 = 3600;

/// The longest resume token this client accepts. The relay issues 43 characters.
const MAX_TOKEN_LEN: usize = 128;

fn url_safe(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The challenge of a mux/1 socket: exactly [`MUX_CHALLENGE_LEN`] characters of `[A-Za-z0-9_-]`.
/// Attach signatures cover it, so nothing of another shape is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MuxChallenge(String);

impl MuxChallenge {
    pub(crate) fn parse(text: &str) -> Result<Self, FrameError> {
        if text.len() == MUX_CHALLENGE_LEN && url_safe(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(FrameError::MuxChallenge)
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the relay allows on one socket, from the negotiation `Ok`. Missing values take the
/// spec's defaults. Values are clamped to what this client supports, and none is below one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxLimits {
    pub attach_per_frame: usize,
    pub mailboxes_per_socket: usize,
    pub inflight_per_socket: usize,
    pub hold_max_s: u32,
}

impl Default for MuxLimits {
    fn default() -> Self {
        Self {
            attach_per_frame: MAX_ATTACH_PER_FRAME,
            mailboxes_per_socket: MAX_MAILBOXES_PER_SOCKET,
            inflight_per_socket: 32,
            hold_max_s: MAX_HOLD_SECS,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawLimits {
    #[serde(default)]
    attach_per_frame: Option<u64>,
    #[serde(default)]
    mailboxes_per_socket: Option<u64>,
    #[serde(default)]
    inflight_per_socket: Option<u64>,
    #[serde(default)]
    hold_max_s: Option<u64>,
}

fn clamp_to(value: Option<u64>, default: usize, max: usize) -> usize {
    let value = value.map_or(default, |value| usize::try_from(value).unwrap_or(max));
    value.clamp(1, max)
}

impl MuxLimits {
    fn from_raw(raw: Option<RawLimits>) -> Self {
        let defaults = Self::default();
        let Some(raw) = raw else { return defaults };
        let hold = raw
            .hold_max_s
            .map_or(defaults.hold_max_s, |secs| {
                u32::try_from(secs).unwrap_or(MAX_HOLD_SECS)
            })
            .clamp(1, MAX_HOLD_SECS);
        Self {
            attach_per_frame: clamp_to(
                raw.attach_per_frame,
                defaults.attach_per_frame,
                MAX_ATTACH_PER_FRAME,
            ),
            mailboxes_per_socket: clamp_to(
                raw.mailboxes_per_socket,
                defaults.mailboxes_per_socket,
                MAX_MAILBOXES_PER_SOCKET,
            ),
            inflight_per_socket: clamp_to(
                raw.inflight_per_socket,
                defaults.inflight_per_socket,
                MAX_INFLIGHT_PER_SOCKET,
            ),
            hold_max_s: hold,
        }
    }
}

/// A resume token: a secret that lets its holder receive and acknowledge the session's mail for
/// up to 24 hours. Held in memory only, wiped on drop, and never shown in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ResumeToken(Zeroizing<String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("resume token is empty, too long or not [A-Za-z0-9_-]")]
pub(crate) struct InvalidResumeToken;

impl ResumeToken {
    pub(crate) fn parse(text: &str) -> Result<Self, InvalidResumeToken> {
        if text.is_empty() || text.len() > MAX_TOKEN_LEN || !url_safe(text) {
            return Err(InvalidResumeToken);
        }
        Ok(Self(Zeroizing::new(text.to_owned())))
    }

    #[cfg(any(test, feature = "mock-relay"))]
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResumeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResumeToken([redacted])")
    }
}

impl TryFrom<String> for ResumeToken {
    type Error = InvalidResumeToken;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let token = Self::parse(&text);
        drop(Zeroizing::new(text));
        token
    }
}

impl From<ResumeToken> for String {
    fn from(token: ResumeToken) -> Self {
        token.0.as_str().to_owned()
    }
}

impl<'de> Deserialize<'de> for ResumeToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ResumeToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// The `code` of a mux/1 `Error`, or of a failed `Attached` entry. Codes this version does not
/// know are kept as bounded text.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum MuxCode {
    BadFrame,
    UnknownType,
    NotMux,
    ClassicOnly,
    BadAddress,
    BadSignature,
    TooManyMailboxes,
    TokenUnknown,
    NotAttached,
    UnknownId,
    RateLimited,
    PostRefused,
    Internal,
    Other(String),
}

impl From<String> for MuxCode {
    fn from(code: String) -> Self {
        match code.as_str() {
            "bad_frame" => Self::BadFrame,
            "unknown_type" => Self::UnknownType,
            "not_mux" => Self::NotMux,
            "classic_only" => Self::ClassicOnly,
            "bad_address" => Self::BadAddress,
            "bad_signature" => Self::BadSignature,
            "too_many_mailboxes" => Self::TooManyMailboxes,
            "token_unknown" => Self::TokenUnknown,
            "not_attached" => Self::NotAttached,
            "unknown_id" => Self::UnknownId,
            "rate_limited" => Self::RateLimited,
            "post_refused" => Self::PostRefused,
            "internal" => Self::Internal,
            _ => Self::Other(bounded_type_name(&code)),
        }
    }
}

impl From<MuxCode> for String {
    fn from(code: MuxCode) -> Self {
        match code {
            MuxCode::BadFrame => "bad_frame".to_owned(),
            MuxCode::UnknownType => "unknown_type".to_owned(),
            MuxCode::NotMux => "not_mux".to_owned(),
            MuxCode::ClassicOnly => "classic_only".to_owned(),
            MuxCode::BadAddress => "bad_address".to_owned(),
            MuxCode::BadSignature => "bad_signature".to_owned(),
            MuxCode::TooManyMailboxes => "too_many_mailboxes".to_owned(),
            MuxCode::TokenUnknown => "token_unknown".to_owned(),
            MuxCode::NotAttached => "not_attached".to_owned(),
            MuxCode::UnknownId => "unknown_id".to_owned(),
            MuxCode::RateLimited => "rate_limited".to_owned(),
            MuxCode::PostRefused => "post_refused".to_owned(),
            MuxCode::Internal => "internal".to_owned(),
            MuxCode::Other(code) => code,
        }
    }
}

impl fmt::Display for MuxCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from(self.clone()))
    }
}

/// Why the relay stopped delivering a mailbox on this socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub(crate) enum DetachReason {
    /// Attached or subscribed on another socket. The client must not attach it again by itself.
    Replaced,
    /// An operator limit was lowered.
    Limit,
    /// The relay is draining.
    Shutdown,
    Other(String),
}

impl From<String> for DetachReason {
    fn from(reason: String) -> Self {
        match reason.as_str() {
            "replaced" => Self::Replaced,
            "limit" => Self::Limit,
            "shutdown" => Self::Shutdown,
            _ => Self::Other(bounded_type_name(&reason)),
        }
    }
}

impl From<DetachReason> for String {
    fn from(reason: DetachReason) -> Self {
        match reason {
            DetachReason::Replaced => "replaced".to_owned(),
            DetachReason::Limit => "limit".to_owned(),
            DetachReason::Shutdown => "shutdown".to_owned(),
            DetachReason::Other(reason) => reason,
        }
    }
}

/// One mailbox of an `Attach`: its key or address, and its signature over the socket challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttachEntry {
    pub(crate) address: String,
    pub(crate) signature: String,
}

/// A frame the wallet sends on a mux/1 socket. `ref` is the wallet's own request number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum MuxClientFrame {
    Attach {
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
        mailboxes: Vec<AttachEntry>,
    },
    Detach {
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
        mailboxes: Vec<String>,
    },
    Resume {
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
        token: ResumeToken,
    },
    Ack {
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
        ids: Vec<RelayMessageId>,
    },
    Hold {
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
        id: RelayMessageId,
        seconds: u32,
    },
    Waiting {
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
    },
}

#[cfg(any(test, feature = "mock-relay"))]
const MUX_CLIENT_TYPES: [&str; 6] = ["Attach", "Detach", "Resume", "Ack", "Hold", "Waiting"];

impl MuxClientFrame {
    pub(crate) fn to_json(&self) -> Result<String, FrameError> {
        serde_json::to_string(self).map_err(|error| FrameError::Json(error.into()))
    }

    /// Whether `type_name` names a frame only a mux/1 socket takes.
    #[cfg(any(test, feature = "mock-relay"))]
    pub(crate) fn is_mux_type(type_name: &str) -> bool {
        MUX_CLIENT_TYPES.contains(&type_name)
    }

    /// Decodes a frame as a relay receives it, for a relay or a mock. `None` when the type is not
    /// a mux/1 frame.
    #[cfg(any(test, feature = "mock-relay"))]
    pub(crate) fn from_json(text: &str) -> Result<Option<Self>, FrameError> {
        check_len(text)?;
        let type_name = probe_type(text)?;
        if !Self::is_mux_type(&type_name) {
            return Ok(None);
        }
        fields(text, type_name).map(Some)
    }
}

/// The relay's `Ok`. The fields of the answers it carries are all optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OkFrame {
    pub(crate) reference: Option<String>,
    pub(crate) ext: Vec<String>,
    pub(crate) challenge: Option<MuxChallenge>,
    pub(crate) limits: MuxLimits,
    /// Per mailbox key, from a `Waiting` answer. `None` for any other `Ok`.
    pub(crate) waiting: Option<HashMap<String, u64>>,
    pub(crate) inflight: u64,
    pub(crate) held: u64,
}

impl OkFrame {
    pub(crate) fn offers_mux(&self) -> bool {
        self.ext.iter().any(|ext| ext == MUX_EXTENSION)
    }
}

#[derive(Debug, Deserialize)]
struct OkFields {
    #[serde(rename = "ref", default)]
    reference: Option<String>,
    #[serde(default)]
    ext: Option<Vec<String>>,
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    limits: Option<RawLimits>,
    #[serde(default)]
    waiting: Option<HashMap<String, u64>>,
    #[serde(default)]
    inflight: Option<u64>,
    #[serde(default)]
    held: Option<u64>,
}

/// One mailbox's result in an `Attached`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct AttachedEntry {
    pub(crate) mailbox: String,
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) waiting: Option<u64>,
    #[serde(default)]
    pub(crate) code: Option<MuxCode>,
}

/// The answer to an `Attach` or a `Resume`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct AttachedFrame {
    #[serde(rename = "ref", default)]
    pub(crate) reference: Option<String>,
    pub(crate) mailboxes: Vec<AttachedEntry>,
    /// The token the next `Resume` uses. Absent when no entry succeeded and none exists yet.
    #[serde(default)]
    pub(crate) token: Option<ResumeToken>,
    #[serde(default)]
    pub(crate) token_expires: Option<u64>,
}

/// A message pushed for an attached mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct MailFrame {
    pub(crate) mailbox: String,
    pub(crate) id: RelayMessageId,
    pub(crate) from: String,
    pub(crate) str: String,
    pub(crate) signature: String,
    #[serde(default)]
    pub(crate) created: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct DetachedFrame {
    pub(crate) mailbox: String,
    pub(crate) reason: DetachReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct ErrorFrame {
    pub(crate) kind: RelayErrorKind,
    #[serde(default)]
    pub(crate) code: Option<MuxCode>,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(rename = "ref", default)]
    pub(crate) reference: Option<String>,
    #[serde(default)]
    pub(crate) retry_after: Option<u64>,
}

/// A frame the relay sends on a mux/1 socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MuxRelayFrame {
    Ok(OkFrame),
    Attached(AttachedFrame),
    Mail(MailFrame),
    Detached(DetachedFrame),
    Error(ErrorFrame),
    /// The first `Challenge` a relay may send before negotiation. A mux/1 client ignores it.
    Challenge,
    /// A JSON frame of a type this version does not know.
    Unknown {
        type_name: String,
    },
    /// Text that is not a JSON object.
    Keepalive,
}

impl MuxRelayFrame {
    pub(crate) fn from_json(text: &str) -> Result<Self, FrameError> {
        check_len(text)?;
        if !text.trim_start().starts_with('{') {
            return Ok(Self::Keepalive);
        }
        let type_name = probe_type(text)?;
        Ok(match type_name.as_str() {
            "Ok" => {
                let raw: OkFields = fields(text, type_name)?;
                Self::Ok(OkFrame {
                    reference: raw.reference,
                    ext: raw.ext.unwrap_or_default(),
                    challenge: raw
                        .challenge
                        .as_deref()
                        .map(MuxChallenge::parse)
                        .transpose()?,
                    limits: MuxLimits::from_raw(raw.limits),
                    waiting: raw.waiting,
                    inflight: raw.inflight.unwrap_or_default(),
                    held: raw.held.unwrap_or_default(),
                })
            }
            "Attached" => Self::Attached(fields(text, type_name)?),
            "Mail" => Self::Mail(fields(text, type_name)?),
            "Detached" => Self::Detached(fields(text, type_name)?),
            "Error" => Self::Error(fields(text, type_name)?),
            "Challenge" => Self::Challenge,
            _ => Self::Unknown {
                type_name: bounded_type_name(&type_name),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::frame::{ClientFrame, MAX_FRAME_LEN, WalletMode};
    use proptest::prelude::*;

    const CHALLENGE: &str = "b3JkKQ1y0f5C3cS0nVb1zw";

    #[test]
    fn plain_client_details_keep_their_bytes_and_mux_adds_ext() {
        let plain = ClientFrame::client_details("4.1.0", WalletMode::Listener)
            .to_json()
            .unwrap();
        assert_eq!(
            plain,
            r#"{"type":"ClientDetails","wallet_version":"4.1.0","wallet_mode":"listener","protocol_version":"3.0.0"}"#
        );
        let mux = ClientFrame::client_details_with_mux("4.1.0", WalletMode::Listener)
            .to_json()
            .unwrap();
        assert_eq!(
            mux,
            r#"{"type":"ClientDetails","wallet_version":"4.1.0","wallet_mode":"listener","protocol_version":"3.0.0","ext":["mux/1"]}"#
        );
        // Old frames, without `ext`, still decode.
        assert_eq!(
            ClientFrame::from_json(&plain).unwrap(),
            ClientFrame::client_details("4.1.0", WalletMode::Listener)
        );
    }

    #[test]
    fn challenge_must_be_exactly_22_url_safe_characters() {
        assert!(MuxChallenge::parse(CHALLENGE).is_ok());
        for bad in [
            "",
            "short",
            "b3JkKQ1y0f5C3cS0nVb1zwX",
            "b3JkKQ1y0f5C3cS0nVb1z=",
            "b3JkKQ1y0f5C3cS0nVb1z+",
            "b3JkKQ1y0f5C3cS0nVb1 w",
            "b3JkKQ1y0f5C3cS0nVb1zé",
        ] {
            assert!(MuxChallenge::parse(bad).is_err(), "{bad:?}");
        }
        let ok = format!(r#"{{"type":"Ok","ext":["mux/1"],"challenge":"{CHALLENGE}"}}"#);
        assert!(matches!(
            MuxRelayFrame::from_json(&ok).unwrap(),
            MuxRelayFrame::Ok(frame) if frame.offers_mux()
        ));
        let bad = r#"{"type":"Ok","ext":["mux/1"],"challenge":"too short"}"#;
        assert!(matches!(
            MuxRelayFrame::from_json(bad),
            Err(FrameError::MuxChallenge)
        ));
    }

    #[test]
    fn ok_without_ext_is_plain_and_limits_are_clamped() {
        let MuxRelayFrame::Ok(plain) = MuxRelayFrame::from_json(r#"{"type":"Ok"}"#).unwrap() else {
            panic!("not an Ok");
        };
        assert!(!plain.offers_mux());
        let text = format!(
            r#"{{"type":"Ok","ext":["mux/1"],"challenge":"{CHALLENGE}","limits":{{"attach_per_frame":9999,"mailboxes_per_socket":0,"inflight_per_socket":5,"hold_max_s":99999,"shared_sources":["10.0.0.0/8"]}},"future":1}}"#
        );
        let MuxRelayFrame::Ok(frame) = MuxRelayFrame::from_json(&text).unwrap() else {
            panic!("not an Ok");
        };
        assert_eq!(
            frame.limits,
            MuxLimits {
                attach_per_frame: 64,
                mailboxes_per_socket: 1,
                inflight_per_socket: 5,
                hold_max_s: 3600,
            }
        );
    }

    #[test]
    fn decoding_ignores_unknown_fields_and_types() {
        let mail = r#"{"type":"Mail","mailbox":"k","id":"m-17","from":"f","str":"s","signature":"g","created":5,"later":{"x":[1]}}"#;
        let MuxRelayFrame::Mail(frame) = MuxRelayFrame::from_json(mail).unwrap() else {
            panic!("not a Mail");
        };
        assert_eq!(frame.id.as_str(), "m-17");
        assert!(matches!(
            MuxRelayFrame::from_json(r#"{"type":"Novel","a":1}"#).unwrap(),
            MuxRelayFrame::Unknown { .. }
        ));
        assert_eq!(
            MuxRelayFrame::from_json("pong").unwrap(),
            MuxRelayFrame::Keepalive
        );
        let error = r#"{"type":"Error","kind":"InvalidRequest","code":"rate_limited","description":"slow","ref":"3","retry_after":7,"more":true}"#;
        let MuxRelayFrame::Error(frame) = MuxRelayFrame::from_json(error).unwrap() else {
            panic!("not an Error");
        };
        assert_eq!(frame.code, Some(MuxCode::RateLimited));
        assert_eq!(frame.retry_after, Some(7));
        assert_eq!(frame.reference.as_deref(), Some("3"));
        let detached = r#"{"type":"Detached","mailbox":"k","reason":"replaced"}"#;
        assert!(matches!(
            MuxRelayFrame::from_json(detached).unwrap(),
            MuxRelayFrame::Detached(frame) if frame.reason == DetachReason::Replaced
        ));
    }

    #[test]
    fn frames_over_the_size_limit_and_bad_ids_are_refused() {
        let long = format!(r#"{{"type":"Ok","pad":"{}"}}"#, "x".repeat(MAX_FRAME_LEN));
        assert!(matches!(
            MuxRelayFrame::from_json(&long),
            Err(FrameError::TooLong { .. })
        ));
        let bad_id = r#"{"type":"Mail","mailbox":"k","id":"has space","from":"f","str":"s","signature":"g"}"#;
        assert!(MuxRelayFrame::from_json(bad_id).is_err());
        let empty_id =
            r#"{"type":"Mail","mailbox":"k","id":"","from":"f","str":"s","signature":"g"}"#;
        assert!(MuxRelayFrame::from_json(empty_id).is_err());
    }

    #[test]
    fn client_frames_round_trip_and_leave_out_a_missing_ref() {
        let ack = MuxClientFrame::Ack {
            reference: None,
            ids: vec![RelayMessageId::parse("a").unwrap()],
        };
        let text = ack.to_json().unwrap();
        assert_eq!(text, r#"{"type":"Ack","ids":["a"]}"#);
        assert_eq!(MuxClientFrame::from_json(&text).unwrap(), Some(ack));
        let waiting = MuxClientFrame::Waiting {
            reference: Some("w1".to_owned()),
        };
        assert_eq!(
            waiting.to_json().unwrap(),
            r#"{"type":"Waiting","ref":"w1"}"#
        );
        assert_eq!(
            MuxClientFrame::from_json(r#"{"type":"GetVersion"}"#).unwrap(),
            None
        );
    }

    #[test]
    fn tokens_are_shape_checked_and_never_printed() {
        let token = ResumeToken::parse("q9-_Z").unwrap();
        assert_eq!(format!("{token:?}"), "ResumeToken([redacted])");
        assert!(ResumeToken::parse("").is_err());
        assert!(ResumeToken::parse("a b").is_err());
        assert!(ResumeToken::parse(&"a".repeat(MAX_TOKEN_LEN + 1)).is_err());
        let resume = MuxClientFrame::Resume {
            reference: Some("r".to_owned()),
            token,
        };
        assert_eq!(
            resume.to_json().unwrap(),
            r#"{"type":"Resume","ref":"r","token":"q9-_Z"}"#
        );
        assert!(format!("{resume:?}").contains("[redacted]"));
        assert!(!format!("{resume:?}").contains("q9-_Z"));
    }

    /// Valid relay frames the mutations start from.
    const RELAY_SAMPLES: [&str; 6] = [
        r#"{"type":"Ok","ref":"1","ext":["mux/1"],"challenge":"b3JkKQ1y0f5C3cS0nVb1zw","limits":{"attach_per_frame":64,"mailboxes_per_socket":256,"inflight_per_socket":32,"hold_max_s":3600}}"#,
        r#"{"type":"Attached","ref":"2","mailboxes":[{"mailbox":"k","ok":true,"waiting":3},{"mailbox":"j","ok":false,"code":"bad_signature"}],"token":"q9-_Z","token_expires":86400}"#,
        r#"{"type":"Mail","mailbox":"k","id":"abc_DEF-123","from":"f","str":"s","signature":"g","created":7}"#,
        r#"{"type":"Detached","mailbox":"k","reason":"replaced"}"#,
        r#"{"type":"Error","kind":"InvalidRequest","code":"rate_limited","description":"d","ref":"3","retry_after":9}"#,
        r#"{"type":"Ok","waiting":{"k":2},"inflight":1,"held":0}"#,
    ];

    fn mux_client_frame() -> impl Strategy<Value = MuxClientFrame> {
        let reference = proptest::option::of("[ -~]{0,64}");
        let id = "[A-Za-z0-9_-]{1,64}".prop_map(|id| RelayMessageId::parse(&id).unwrap());
        let token = "[A-Za-z0-9_-]{1,64}".prop_map(|token| ResumeToken::parse(&token).unwrap());
        let entry = ("[ -~]{0,80}", "[0-9a-f]{0,140}")
            .prop_map(|(address, signature)| AttachEntry { address, signature });
        prop_oneof![
            (reference.clone(), proptest::collection::vec(entry, 0..8)).prop_map(
                |(reference, mailboxes)| MuxClientFrame::Attach {
                    reference,
                    mailboxes
                }
            ),
            (
                reference.clone(),
                proptest::collection::vec("[ -~]{0,80}", 0..8)
            )
                .prop_map(|(reference, mailboxes)| MuxClientFrame::Detach {
                    reference,
                    mailboxes
                }),
            (reference.clone(), token)
                .prop_map(|(reference, token)| MuxClientFrame::Resume { reference, token }),
            (
                reference.clone(),
                proptest::collection::vec(id.clone(), 0..8)
            )
                .prop_map(|(reference, ids)| MuxClientFrame::Ack { reference, ids }),
            (reference.clone(), id, any::<u32>()).prop_map(|(reference, id, seconds)| {
                MuxClientFrame::Hold {
                    reference,
                    id,
                    seconds,
                }
            }),
            reference.prop_map(|reference| MuxClientFrame::Waiting { reference }),
        ]
    }

    /// `sample` cut at a char boundary, or with one char replaced.
    fn mutated(sample: &str, at: usize, cut: bool, with: char) -> String {
        let at = sample
            .char_indices()
            .map(|(index, _)| index)
            .nth(at.checked_rem(sample.chars().count()).unwrap_or(0))
            .unwrap_or(0);
        if cut {
            return sample[..at].to_owned();
        }
        let mut out = String::with_capacity(sample.len().saturating_add(4));
        for (index, ch) in sample.char_indices() {
            out.push(if index == at { with } else { ch });
        }
        out
    }

    proptest! {
        #[test]
        fn mux_client_frames_round_trip(frame in mux_client_frame()) {
            let text = frame.to_json().unwrap();
            prop_assert_eq!(MuxClientFrame::from_json(&text).unwrap(), Some(frame));
        }

        #[test]
        fn mux_decoders_never_panic(text in any::<String>()) {
            let _ = MuxRelayFrame::from_json(&text);
            let _ = MuxClientFrame::from_json(&text);
        }

        #[test]
        fn mux_decoders_never_panic_on_json_shaped_text(
            type_name in prop_oneof![
                Just("Ok".to_owned()), Just("Attached".to_owned()), Just("Mail".to_owned()),
                Just("Detached".to_owned()), Just("Error".to_owned()), Just("Attach".to_owned()),
                Just("Ack".to_owned()), Just("Hold".to_owned()), Just("Resume".to_owned()),
                "[ -~]{0,70}",
            ],
            tail in "[ -~]{0,200}",
        ) {
            let text = format!("{{\"type\":{},{tail}", serde_json::Value::String(type_name));
            let _ = MuxRelayFrame::from_json(&text);
            let _ = MuxClientFrame::from_json(&text);
        }

        #[test]
        fn mutated_relay_frames_decode_or_error(
            sample in 0..RELAY_SAMPLES.len(),
            at in any::<usize>(),
            cut in any::<bool>(),
            with in any::<char>(),
        ) {
            let text = mutated(RELAY_SAMPLES[sample], at, cut, with);
            let _ = MuxRelayFrame::from_json(&text);
        }
    }

    #[test]
    fn every_relay_sample_decodes_and_text_over_the_limit_is_refused() {
        for sample in RELAY_SAMPLES {
            assert!(MuxRelayFrame::from_json(sample).is_ok(), "{sample}");
        }
        let long = "x".repeat(MAX_FRAME_LEN + 1);
        assert!(MuxRelayFrame::from_json(&long).is_err());
        assert!(MuxClientFrame::from_json(&long).is_err());
        let at_limit = " ".repeat(MAX_FRAME_LEN);
        assert!(!matches!(
            MuxRelayFrame::from_json(&at_limit),
            Err(FrameError::TooLong { .. })
        ));
    }
}
