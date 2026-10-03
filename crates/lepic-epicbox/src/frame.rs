use lepic_crypto::{CryptoError, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::address::EpicboxAddress;
use crate::crypto::{MAX_MESSAGE_LEN, SignedMessage, sign_text};

/// The protocol version LEPIC speaks, which the public relay supports.
pub const PROTOCOL_VERSION: &str = "3.0.0";
/// Longer frames are rejected before they are parsed. A frame carries at most one message.
pub const MAX_FRAME_LEN: usize = MAX_MESSAGE_LEN.saturating_add(64 * 1024);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    #[error("frame has {actual} bytes, the limit is {max}")]
    TooLong { actual: usize, max: usize },
    #[error("frame is not valid json")]
    Json(#[source] serde_json::Error),
    #[error("frame has no string \"type\"")]
    MissingType,
    #[error("frame of type {type_name} has missing or invalid fields")]
    Fields {
        type_name: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("client frame type {type_name} is unknown")]
    UnknownClientType { type_name: String },
    #[error("frame could not be signed")]
    Signature(#[source] CryptoError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletMode {
    /// Must be sent before subscribing, or the relay does not push live messages to the socket.
    Listener,
    Send,
}

/// A frame the wallet sends to the relay. Fields are in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientFrame {
    ClientDetails {
        wallet_version: String,
        wallet_mode: WalletMode,
        protocol_version: String,
    },
    Subscribe {
        address: String,
        ver: String,
        signature: String,
    },
    PostSlate {
        from: String,
        to: String,
        str: String,
        signature: String,
    },
    Made {
        address: String,
        signature: String,
        ver: String,
        epicboxmsgid: String,
    },
    Unsubscribe {
        address: String,
    },
    GetVersion,
}

impl ClientFrame {
    pub fn client_details(wallet_version: &str, wallet_mode: WalletMode) -> Self {
        Self::ClientDetails {
            wallet_version: wallet_version.to_owned(),
            wallet_mode,
            protocol_version: PROTOCOL_VERSION.to_owned(),
        }
    }

    /// Signs `challenge`, which must be the most recent one the relay sent.
    pub fn subscribe(
        own: &EpicboxAddress,
        challenge: &str,
        key: &SecretKey,
    ) -> Result<Self, FrameError> {
        Ok(Self::Subscribe {
            address: own.key_text(),
            ver: PROTOCOL_VERSION.to_owned(),
            signature: signed(challenge, key)?,
        })
    }

    pub fn post_slate(from: &EpicboxAddress, to: &EpicboxAddress, message: &SignedMessage) -> Self {
        Self::PostSlate {
            from: from.to_string(),
            to: to.to_string(),
            str: message.str.clone(),
            signature: message.signature.to_der_hex(),
        }
    }

    pub fn made(
        own: &EpicboxAddress,
        epicboxmsgid: &RelayMessageId,
        key: &SecretKey,
    ) -> Result<Self, FrameError> {
        Ok(Self::Made {
            address: own.key_text(),
            signature: signed(epicboxmsgid.as_str(), key)?,
            ver: PROTOCOL_VERSION.to_owned(),
            epicboxmsgid: epicboxmsgid.to_string(),
        })
    }

    pub fn unsubscribe(own: &EpicboxAddress) -> Self {
        Self::Unsubscribe {
            address: own.key_text(),
        }
    }

    pub fn to_json(&self) -> Result<String, FrameError> {
        serde_json::to_string(self).map_err(FrameError::Json)
    }

    /// Decodes a frame as a relay receives it. Unknown types are errors here; only the client
    /// side must tolerate them.
    pub fn from_json(text: &str) -> Result<Self, FrameError> {
        check_len(text)?;
        let value = parse_object(text)?;
        let type_name = type_name(&value)?.to_owned();
        if !KNOWN_CLIENT_TYPES.contains(&type_name.as_str()) {
            return Err(FrameError::UnknownClientType { type_name });
        }
        serde_json::from_value(value).map_err(|source| FrameError::Fields { type_name, source })
    }
}

fn signed(text: &str, key: &SecretKey) -> Result<String, FrameError> {
    sign_text(text, key)
        .map(|signature| signature.to_der_hex())
        .map_err(FrameError::Signature)
}

/// The `kind` of a relay `Error` frame. Kinds this version does not know are kept as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum RelayErrorKind {
    UnknownError,
    InvalidRequest,
    InvalidSignature,
    InvalidChallenge,
    TooManySubscriptions,
    Other(String),
}

impl From<String> for RelayErrorKind {
    fn from(kind: String) -> Self {
        match kind.as_str() {
            "UnknownError" => Self::UnknownError,
            "InvalidRequest" => Self::InvalidRequest,
            "InvalidSignature" => Self::InvalidSignature,
            "InvalidChallenge" => Self::InvalidChallenge,
            "TooManySubscriptions" => Self::TooManySubscriptions,
            _ => Self::Other(kind),
        }
    }
}

impl From<RelayErrorKind> for String {
    fn from(kind: RelayErrorKind) -> Self {
        match kind {
            RelayErrorKind::UnknownError => "UnknownError".to_owned(),
            RelayErrorKind::InvalidRequest => "InvalidRequest".to_owned(),
            RelayErrorKind::InvalidSignature => "InvalidSignature".to_owned(),
            RelayErrorKind::InvalidChallenge => "InvalidChallenge".to_owned(),
            RelayErrorKind::TooManySubscriptions => "TooManySubscriptions".to_owned(),
            RelayErrorKind::Other(kind) => kind,
        }
    }
}

/// Relay message ids longer than this are refused. The public relay issues 32 characters.
pub const MAX_RELAY_MESSAGE_ID_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "relay message id is empty, longer than {MAX_RELAY_MESSAGE_ID_LEN} bytes or not [A-Za-z0-9_-]"
)]
pub struct InvalidRelayMessageId;

/// The id a relay gives a stored message, which `Made` names to acknowledge it. Never empty, at
/// most [`MAX_RELAY_MESSAGE_ID_LEN`] bytes of ASCII letters, digits, `-` and `_`, so it is safe to
/// log and store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelayMessageId(String);

impl RelayMessageId {
    pub fn parse(text: &str) -> Result<Self, InvalidRelayMessageId> {
        if Self::is_valid(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(InvalidRelayMessageId)
        }
    }

    pub fn is_valid(text: &str) -> bool {
        let allowed = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
        !text.is_empty() && text.len() <= MAX_RELAY_MESSAGE_ID_LEN && text.bytes().all(allowed)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RelayMessageId {
    type Error = InvalidRelayMessageId;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if Self::is_valid(&text) {
            Ok(Self(text))
        } else {
            Err(InvalidRelayMessageId)
        }
    }
}

impl From<RelayMessageId> for String {
    fn from(id: RelayMessageId) -> Self {
        id.0
    }
}

impl std::fmt::Display for RelayMessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pending message pushed by the relay. `epicboxmsgid` and `ver` are present only when the
/// subscription carried `ver`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlateFrame {
    pub from: String,
    pub str: String,
    pub signature: String,
    pub challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epicboxmsgid: Option<RelayMessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ver: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
enum KnownRelayFrame {
    Challenge {
        str: String,
    },
    Ok,
    Error {
        kind: RelayErrorKind,
        description: String,
    },
    Slate(SlateFrame),
    GetVersion {
        str: String,
    },
}

/// A frame the relay sends to the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    Challenge {
        str: String,
    },
    /// Answers several requests, so it cannot be matched to one.
    Ok,
    Error {
        kind: RelayErrorKind,
        description: String,
    },
    Slate(SlateFrame),
    GetVersion {
        str: String,
    },
    /// A JSON frame of a type this version does not know; the client ignores it.
    Unknown {
        type_name: String,
    },
    /// Text that is not a JSON object, such as the bare `pong` the relay answers a ping with.
    Keepalive,
}

impl RelayFrame {
    pub fn from_json(text: &str) -> Result<Self, FrameError> {
        check_len(text)?;
        if !text.trim_start().starts_with('{') {
            return Ok(Self::Keepalive);
        }
        let value = parse_object(text)?;
        let type_name = type_name(&value)?.to_owned();
        if !KNOWN_RELAY_TYPES.contains(&type_name.as_str()) {
            return Ok(Self::Unknown { type_name });
        }
        let known = serde_json::from_value(value)
            .map_err(|source| FrameError::Fields { type_name, source })?;
        Ok(match known {
            KnownRelayFrame::Challenge { str } => Self::Challenge { str },
            KnownRelayFrame::Ok => Self::Ok,
            KnownRelayFrame::Error { kind, description } => Self::Error { kind, description },
            KnownRelayFrame::Slate(slate) => Self::Slate(slate),
            KnownRelayFrame::GetVersion { str } => Self::GetVersion { str },
        })
    }

    /// The JSON text of a known frame, or `None` for [`Self::Unknown`] and [`Self::Keepalive`].
    pub fn to_json(&self) -> Result<Option<String>, FrameError> {
        let known = match self {
            Self::Challenge { str } => KnownRelayFrame::Challenge { str: str.clone() },
            Self::Ok => KnownRelayFrame::Ok,
            Self::Error { kind, description } => KnownRelayFrame::Error {
                kind: kind.clone(),
                description: description.clone(),
            },
            Self::Slate(slate) => KnownRelayFrame::Slate(slate.clone()),
            Self::GetVersion { str } => KnownRelayFrame::GetVersion { str: str.clone() },
            Self::Unknown { .. } | Self::Keepalive => return Ok(None),
        };
        serde_json::to_string(&known)
            .map(Some)
            .map_err(FrameError::Json)
    }
}

const KNOWN_CLIENT_TYPES: [&str; 6] = [
    "ClientDetails",
    "Subscribe",
    "PostSlate",
    "Made",
    "Unsubscribe",
    "GetVersion",
];

const KNOWN_RELAY_TYPES: [&str; 5] = ["Challenge", "Ok", "Error", "Slate", "GetVersion"];

fn check_len(text: &str) -> Result<(), FrameError> {
    if text.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLong {
            actual: text.len(),
            max: MAX_FRAME_LEN,
        });
    }
    Ok(())
}

fn parse_object(text: &str) -> Result<Value, FrameError> {
    let value: Value = serde_json::from_str(text).map_err(FrameError::Json)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(FrameError::MissingType)
    }
}

fn type_name(value: &Value) -> Result<&str, FrameError> {
    value
        .get("type")
        .and_then(Value::as_str)
        .ok_or(FrameError::MissingType)
}
