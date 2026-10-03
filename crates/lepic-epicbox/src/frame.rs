use std::fmt;

use lepic_crypto::{CryptoError, SecretKey};
use serde::de::{DeserializeOwned, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::address::EpicboxAddress;
use crate::crypto::{MAX_MESSAGE_LEN, SignedMessage, sign_text};

/// The protocol version LEPIC speaks, which the public relay supports.
pub const PROTOCOL_VERSION: &str = "3.0.0";
/// Longer frames are rejected before they are parsed. A frame carries at most one message.
pub const MAX_FRAME_LEN: usize = MAX_MESSAGE_LEN.saturating_add(64 * 1024);
/// Frame type names and relay error kinds longer than this are cut before they reach an error
/// or a log.
pub const MAX_FRAME_TYPE_LEN: usize = 64;

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
        let type_name = probe_type(text)?;
        if !KNOWN_CLIENT_TYPES.contains(&type_name.as_str()) {
            return Err(FrameError::UnknownClientType { type_name });
        }
        fields(text, type_name)
    }
}

fn signed(text: &str, key: &SecretKey) -> Result<String, FrameError> {
    sign_text(text, key)
        .map(|signature| signature.to_der_hex())
        .map_err(FrameError::Signature)
}

/// The `kind` of a relay `Error` frame. Kinds this version does not know are kept as text,
/// bounded as frame type names are, because they reach errors and logs.
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
            _ => Self::Other(bounded_type_name(&kind)),
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

/// The wire shape of a known relay frame, for encoding. Decoding reads each type's fields
/// without the tag, so that no buffer of the whole frame is built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
        let type_name = probe_type(text)?;
        Ok(match type_name.as_str() {
            "Challenge" => Self::Challenge {
                str: fields::<TextFields>(text, type_name)?.str,
            },
            // The probe has read the whole frame, and `Ok` has no fields.
            "Ok" => Self::Ok,
            "Error" => {
                let ErrorFields { kind, description } = fields(text, type_name)?;
                Self::Error { kind, description }
            }
            "Slate" => Self::Slate(fields(text, type_name)?),
            "GetVersion" => Self::GetVersion {
                str: fields::<TextFields>(text, type_name)?.str,
            },
            _ => Self::Unknown { type_name },
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

fn check_len(text: &str) -> Result<(), FrameError> {
    if text.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLong {
            actual: text.len(),
            max: MAX_FRAME_LEN,
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct TextFields {
    str: String,
}

#[derive(Deserialize)]
struct ErrorFields {
    kind: RelayErrorKind,
    description: String,
}

/// Reads the fields of a frame whose type is known. The `type` key is ignored like any other
/// unknown key, which serde skips without keeping it.
fn fields<T: DeserializeOwned>(text: &str, type_name: String) -> Result<T, FrameError> {
    serde_json::from_str(text).map_err(|source| FrameError::Fields { type_name, source })
}

/// The frame's `type`, bounded, after checking that the whole text is one JSON object. Every
/// other value is skipped without being kept, so the work is bounded by the text alone.
fn probe_type(text: &str) -> Result<String, FrameError> {
    match serde_json::from_str::<TypeProbe>(text).map_err(FrameError::Json)? {
        TypeProbe::Object(Some(TypeTag::Text(name))) => Ok(name),
        TypeProbe::Object(Some(TypeTag::NotText) | None) | TypeProbe::NotObject => {
            Err(FrameError::MissingType)
        }
    }
}

/// A JSON value seen only for its `type` key, if it is an object.
enum TypeProbe {
    Object(Option<TypeTag>),
    NotObject,
}

impl<'de> Deserialize<'de> for TypeProbe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ProbeVisitor)
    }
}

struct ProbeVisitor;

impl<'de> Visitor<'de> for ProbeVisitor {
    type Value = TypeProbe;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a json value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut tag = None;
        while let Some(key) = map.next_key::<KeyName>()? {
            match key {
                KeyName::Type if tag.is_some() => {
                    return Err(serde::de::Error::duplicate_field("type"));
                }
                KeyName::Type => tag = map.next_value::<Option<TypeTag>>()?,
                KeyName::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(TypeProbe::Object(tag))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(TypeProbe::NotObject)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(TypeProbe::NotObject)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(TypeProbe::NotObject)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(TypeProbe::NotObject)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(TypeProbe::NotObject)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(TypeProbe::NotObject)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(TypeProbe::NotObject)
    }
}

/// An object key, compared without keeping it.
enum KeyName {
    Type,
    Other,
}

impl<'de> Deserialize<'de> for KeyName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(KeyVisitor)
    }
}

struct KeyVisitor;

impl Visitor<'_> for KeyVisitor {
    type Value = KeyName;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E>(self, key: &str) -> Result<Self::Value, E> {
        Ok(if key == "type" {
            KeyName::Type
        } else {
            KeyName::Other
        })
    }
}

/// The value of `type`: its bounded text, or a note that it is not a string.
enum TypeTag {
    Text(String),
    NotText,
}

impl<'de> Deserialize<'de> for TypeTag {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TagVisitor)
    }
}

struct TagVisitor;

impl<'de> Visitor<'de> for TagVisitor {
    type Value = TypeTag;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a frame type")
    }

    fn visit_str<E>(self, name: &str) -> Result<Self::Value, E> {
        Ok(TypeTag::Text(bounded_type_name(name)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(TypeTag::NotText)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(TypeTag::NotText)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(TypeTag::NotText)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(TypeTag::NotText)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(TypeTag::NotText)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(TypeTag::NotText)
    }
}

/// `name` as safe to show in an error or a log: printable ASCII, other characters replaced by
/// `?`, cut to [`MAX_FRAME_TYPE_LEN`] characters with `...` marking the cut. Known type names
/// pass unchanged, and a changed name never equals one.
fn bounded_type_name(name: &str) -> String {
    let printable = |c: char| if c.is_ascii_graphic() { c } else { '?' };
    let mut chars = name.chars();
    let mut bounded: String = chars
        .by_ref()
        .take(MAX_FRAME_TYPE_LEN)
        .map(printable)
        .collect();
    if chars.next().is_some() {
        bounded.push_str("...");
    }
    bounded
}
