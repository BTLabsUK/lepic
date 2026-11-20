// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The vault713 Developers
// Ported from EpicCash/epic-wallet impls/src/epicbox/protocol.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! The JSON frames of the Epicbox protocol, 3.0.0 and the 3.1.0 cancel additions, as the wallet
//! sends and reads them.

use std::fmt;

use lepic_crypto::{CryptoError, SecretKey};
use serde::de::{DeserializeOwned, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::address::EpicboxAddress;
use crate::crypto::{MAX_MESSAGE_LEN, SignedMessage, sign_text};
use crate::json::JsonProblem;
use crate::session::ProtocolVersion;

/// The protocol version LEPIC speaks, which the public relay supports.
pub const PROTOCOL_VERSION: &str = "3.0.0";
/// The version LEPIC names in `Subscribe` and `Made` towards a relay that reported 3.1.0 or
/// later: the version that has transaction cancel. A relay of 3.0.0 treats a `Subscribe` that
/// names it as one of 3.0.0, so it is only sent after the relay's `GetVersion` allowed it.
pub const CANCEL_PROTOCOL_VERSION: &str = "3.1.0";
/// The extension a wallet offers in `ClientDetails` and a relay echoes in its `Ok` when it
/// checks cancels signed over [`CANCEL_SIGNATURE_PREFIX`] and the transaction id.
pub const CANCEL_FORM_EXTENSION: &str = "epicbox-cancel/1";
/// The text before the transaction id in the domain-separated cancel signature. The bare id
/// is also the text of the `epicboxtxidsig` every `PostSlate` carries, so a signature over the
/// bare id is no proof that its signer asked to cancel; a signature over this text is.
pub const CANCEL_SIGNATURE_PREFIX: &str = "epicbox-cancel/1:";
/// Longer frames are rejected before they are parsed. A frame carries at most one message.
pub const MAX_FRAME_LEN: usize = MAX_MESSAGE_LEN.saturating_add(64 * 1024);
/// Frame type names and relay error kinds longer than this are cut before they reach an error
/// or a log.
pub const MAX_FRAME_TYPE_LEN: usize = 64;

/// The relay's challenges are short random tokens over letters, digits, `-` and `_`. The
/// address key signs a challenge, so nothing else, such as message text, is signed as one.
pub const MAX_CHALLENGE_LEN: usize = 64;

/// The length of a transaction id written as 32 hex digits.
const HEX_ID_LEN: usize = 32;

/// The length of a transaction id written as a hyphenated UUID.
const UUID_LEN: usize = 36;

fn is_challenge(text: &str) -> bool {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
    !text.is_empty()
        && text.len() <= MAX_CHALLENGE_LEN
        && text.bytes().all(allowed)
        && !looks_like_transaction_id(text)
}

/// A transaction id, as 32 lowercase hex digits or a UUID, is text the address key may sign for
/// another purpose, so it is never signed as a challenge. A random relay token has this shape
/// so rarely that refusing one costs at most a reconnect.
fn looks_like_transaction_id(text: &str) -> bool {
    let lower_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    let is_uuid = text.len() == UUID_LEN
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    is_uuid || (text.len() == HEX_ID_LEN && text.bytes().all(lower_hex))
}

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The text is longer than [`MAX_FRAME_LEN`].
    #[error("frame has {actual} bytes, the limit is {max}")]
    TooLong { actual: usize, max: usize },
    /// The text is not JSON, or a frame did not encode.
    #[error("frame is not valid json")]
    Json(#[source] JsonProblem),
    /// The JSON object has no string `type`.
    #[error("frame has no string \"type\"")]
    MissingType,
    /// A known frame type is missing a field or has one of the wrong shape.
    #[error("frame of type {type_name} has missing or invalid fields")]
    Fields {
        type_name: String,
        #[source]
        source: JsonProblem,
    },
    /// A relay received a client frame type it does not know.
    #[error("client frame type {type_name} is unknown")]
    UnknownClientType { type_name: String },
    /// Signing failed.
    #[error("frame could not be signed")]
    Signature(#[source] CryptoError),
    #[error(
        "challenge is empty, longer than {MAX_CHALLENGE_LEN} bytes, not [A-Za-z0-9_-] or a transaction id"
    )]
    /// A challenge is not one the address key may sign.
    Challenge,
    /// A mux/1 challenge does not have its fixed shape.
    #[error("mux/1 challenge is not exactly 22 characters of [A-Za-z0-9_-]")]
    MuxChallenge,
}

/// How the wallet uses the socket, sent in `ClientDetails`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletMode {
    /// Must be sent before subscribing, or the relay does not push live messages to the socket.
    Listener,
    /// Posts only.
    Send,
}

/// The text a `CancelTx` signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelSignature {
    /// The bare transaction id: what stock 3.1.0 wallets sign and every relay accepts.
    Bare,
    /// `epicbox-cancel/1:` and the transaction id, for a relay that offered
    /// [`CANCEL_FORM_EXTENSION`].
    Separated,
}

impl CancelSignature {
    /// The form to sign towards a relay: separated when it echoed [`CANCEL_FORM_EXTENSION`].
    pub fn negotiated(relay_offers_separated: bool) -> Self {
        if relay_offers_separated {
            Self::Separated
        } else {
            Self::Bare
        }
    }

    /// The DER hex signature of `key` over this form's text for `txid`.
    pub(crate) fn sign(self, txid: &EpicboxTxId, key: &SecretKey) -> Result<String, FrameError> {
        match self {
            Self::Bare => signed(txid.as_str(), key),
            Self::Separated => signed(&format!("{CANCEL_SIGNATURE_PREFIX}{}", txid.as_str()), key),
        }
    }
}

/// A frame the wallet sends to the relay. Fields are in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientFrame {
    /// The greeting: wallet version, mode, protocol version and extensions.
    ClientDetails {
        wallet_version: String,
        wallet_mode: WalletMode,
        protocol_version: String,
        /// Extensions the wallet asks for. Left out of the frame when `None`, so a plain
        /// 3.0.0 greeting keeps its exact bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ext: Option<Vec<String>>,
    },
    /// Asks for an address's messages, signed over the latest challenge.
    Subscribe {
        address: String,
        ver: String,
        signature: String,
    },
    /// Sends a signed message to another address. On a relay of 3.1.0 or later it may carry the
    /// transaction id and `from`'s signature over it, both or neither.
    PostSlate {
        from: String,
        to: String,
        str: String,
        signature: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epicboxtxid: Option<EpicboxTxId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epicboxtxidsig: Option<String>,
    },
    /// Acknowledges a stored message so the relay deletes it.
    Made {
        address: String,
        signature: String,
        ver: String,
        epicboxmsgid: String,
    },
    /// Stops delivery for an address.
    Unsubscribe { address: String },
    /// Asks for the relay's protocol version.
    GetVersion,
    /// Cancels a transaction the address took part in (3.1.0). The signature is the address
    /// key's over the bare transaction id.
    CancelTx {
        address: String,
        epicboxtxid: EpicboxTxId,
        signature: String,
    },
}

impl ClientFrame {
    /// The 3.0.0 greeting with no extensions.
    pub fn client_details(wallet_version: &str, wallet_mode: WalletMode) -> Self {
        Self::ClientDetails {
            wallet_version: wallet_version.to_owned(),
            wallet_mode,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            ext: None,
        }
    }

    /// As [`Self::client_details`], offering [`CANCEL_FORM_EXTENSION`]: a relay that checks the
    /// domain-separated cancel signature echoes it in its `Ok`.
    pub fn client_details_with_cancel_form(wallet_version: &str, wallet_mode: WalletMode) -> Self {
        Self::ClientDetails {
            wallet_version: wallet_version.to_owned(),
            wallet_mode,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            ext: Some(vec![CANCEL_FORM_EXTENSION.to_owned()]),
        }
    }

    /// As [`Self::client_details`], asking the relay for the mux/1 extension, the cancel
    /// extension of mux/1 and the domain-separated cancel signature.
    pub fn client_details_with_mux(wallet_version: &str, wallet_mode: WalletMode) -> Self {
        Self::ClientDetails {
            wallet_version: wallet_version.to_owned(),
            wallet_mode,
            protocol_version: PROTOCOL_VERSION.to_owned(),
            ext: Some(vec![
                crate::mux_frame::MUX_EXTENSION.to_owned(),
                crate::mux_frame::TXCANCEL_EXTENSION.to_owned(),
                CANCEL_FORM_EXTENSION.to_owned(),
                crate::mux_frame::ATTACH_HOST_EXTENSION.to_owned(),
            ]),
        }
    }

    /// Signs `challenge`, which must be the most recent one the relay sent.
    pub fn subscribe(
        own: &EpicboxAddress,
        challenge: &str,
        key: &SecretKey,
    ) -> Result<Self, FrameError> {
        if !is_challenge(challenge) {
            return Err(FrameError::Challenge);
        }
        Ok(Self::Subscribe {
            address: own.key_text(),
            ver: PROTOCOL_VERSION.to_owned(),
            signature: signed(challenge, key)?,
        })
    }

    /// As [`Self::subscribe`], naming the version the relay's `GetVersion` allows: 3.1.0 from a
    /// relay that supports cancel, 3.0.0 otherwise.
    pub fn subscribe_negotiated(
        own: &EpicboxAddress,
        challenge: &str,
        key: &SecretKey,
        relay: Option<ProtocolVersion>,
    ) -> Result<Self, FrameError> {
        let mut frame = Self::subscribe(own, challenge, key)?;
        if let Self::Subscribe { ver, .. } = &mut frame {
            *ver = ProtocolVersion::wire_version(relay).to_owned();
        }
        Ok(frame)
    }

    /// Posts `message` from `from` to `to`, with no transaction id: the 3.0.0 frame.
    pub fn post_slate(from: &EpicboxAddress, to: &EpicboxAddress, message: &SignedMessage) -> Self {
        Self::PostSlate {
            from: from.to_string(),
            to: to.to_string(),
            str: message.str.clone(),
            signature: message.signature.to_der_hex(),
            epicboxtxid: None,
            epicboxtxidsig: None,
        }
    }

    /// As [`Self::post_slate`], carrying `txid` and `from`'s signature over it, for a relay of
    /// 3.1.0 or later. `key` is the secret key of `from`.
    pub fn post_slate_with_txid(
        from: &EpicboxAddress,
        to: &EpicboxAddress,
        message: &SignedMessage,
        txid: &EpicboxTxId,
        key: &SecretKey,
    ) -> Result<Self, FrameError> {
        let mut frame = Self::post_slate(from, to, message);
        if let Self::PostSlate {
            epicboxtxid,
            epicboxtxidsig,
            ..
        } = &mut frame
        {
            *epicboxtxid = Some(txid.clone());
            *epicboxtxidsig = Some(signed(txid.as_str(), key)?);
        }
        Ok(frame)
    }

    /// Cancels the transaction `txid` for `own`, signed over the bare id.
    pub fn cancel_tx(
        own: &EpicboxAddress,
        txid: &EpicboxTxId,
        key: &SecretKey,
    ) -> Result<Self, FrameError> {
        Self::cancel_tx_with(own, txid, key, CancelSignature::Bare)
    }

    /// Cancels the transaction `txid` for `own`, signed over the text `form` names.
    pub fn cancel_tx_with(
        own: &EpicboxAddress,
        txid: &EpicboxTxId,
        key: &SecretKey,
        form: CancelSignature,
    ) -> Result<Self, FrameError> {
        Ok(Self::CancelTx {
            address: own.key_text(),
            epicboxtxid: txid.clone(),
            signature: form.sign(txid, key)?,
        })
    }

    /// Acknowledges `epicboxmsgid`, signed by the address key.
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

    /// As [`Self::made`], naming the version the relay's `GetVersion` allows.
    pub fn made_negotiated(
        own: &EpicboxAddress,
        epicboxmsgid: &RelayMessageId,
        key: &SecretKey,
        relay: Option<ProtocolVersion>,
    ) -> Result<Self, FrameError> {
        let mut frame = Self::made(own, epicboxmsgid, key)?;
        if let Self::Made { ver, .. } = &mut frame {
            *ver = ProtocolVersion::wire_version(relay).to_owned();
        }
        Ok(frame)
    }

    /// Stops delivery for `own`.
    pub fn unsubscribe(own: &EpicboxAddress) -> Self {
        Self::Unsubscribe {
            address: own.key_text(),
        }
    }

    /// The frame as wire JSON.
    pub fn to_json(&self) -> Result<String, FrameError> {
        serde_json::to_string(self).map_err(|error| FrameError::Json(error.into()))
    }

    /// Decodes a frame as a relay receives it. Unknown types are errors here; only the client
    /// side must tolerate them. For relay-side use: a known type's fields are read through
    /// serde's internally tagged decoding, which buffers that frame's other values, unlike
    /// [`RelayFrame::from_json`], which the wallet uses.
    pub fn from_json(text: &str) -> Result<Self, FrameError> {
        check_len(text)?;
        let type_name = probe_type(text)?;
        if !KNOWN_CLIENT_TYPES.contains(&type_name.as_str()) {
            return Err(FrameError::UnknownClientType { type_name });
        }
        fields(text, type_name)
    }
}

pub(crate) fn signed(text: &str, key: &SecretKey) -> Result<String, FrameError> {
    sign_text(text, key)
        .map(|signature| signature.to_der_hex())
        .map_err(FrameError::Signature)
}

/// The `kind` of a relay `Error` frame. Kinds this version does not know are kept as text,
/// bounded as frame type names are, because they reach errors and logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum RelayErrorKind {
    /// The relay's catch-all error.
    UnknownError,
    /// The relay could not read the request.
    InvalidRequest,
    /// A signature did not verify.
    InvalidSignature,
    /// The signed challenge is not the relay's current one.
    InvalidChallenge,
    /// The socket holds as many subscriptions as the relay allows.
    TooManySubscriptions,
    /// The relay is overloaded and answered nothing else; the request may go again later.
    Busy,
    /// A kind this version does not know, cut to [`MAX_FRAME_TYPE_LEN`].
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
            "Busy" => Self::Busy,
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
            RelayErrorKind::Busy => "Busy".to_owned(),
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
/// A relay message id that breaks the rules of [`RelayMessageId`].
pub struct InvalidRelayMessageId;

/// The id a relay gives a stored message, which `Made` names to acknowledge it. Never empty, at
/// most [`MAX_RELAY_MESSAGE_ID_LEN`] bytes of ASCII letters, digits, `-` and `_`, so it is safe to
/// log and store.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelayMessageId(String);

impl RelayMessageId {
    /// Checks `text` and keeps it as an id.
    pub fn parse(text: &str) -> Result<Self, InvalidRelayMessageId> {
        if Self::is_valid(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(InvalidRelayMessageId)
        }
    }

    /// Whether `text` is a valid id.
    pub fn is_valid(text: &str) -> bool {
        let allowed = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
        !text.is_empty() && text.len() <= MAX_RELAY_MESSAGE_ID_LEN && text.bytes().all(allowed)
    }

    /// The id as text.
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

/// The length of a transaction id: a UUID without hyphens.
pub const EPICBOX_TXID_LEN: usize = HEX_ID_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("epicbox transaction id is not a version 4 UUID of 32 hex digits")]
/// A transaction id that breaks the rules of [`EpicboxTxId`].
pub struct InvalidEpicboxTxId;

/// The id of one Epicbox transaction (3.1.0): a version 4 UUID in simple form, 32 lowercase hex
/// digits. The sender makes it and signs it with the `from` key. It is not the slate id. Both
/// sides use it to cancel, and a relay of 3.1.0 or later keeps it with the stored message.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EpicboxTxId(String);

impl EpicboxTxId {
    /// A new random id.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)?;
        Ok(Self::from_random(bytes))
    }

    /// The version 4 id made of 16 random bytes: the version and variant bits are set.
    pub(crate) fn from_random(mut bytes: [u8; 16]) -> Self {
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let mut text = String::with_capacity(EPICBOX_TXID_LEN);
        for byte in bytes {
            for nibble in [byte >> 4, byte & 0x0f] {
                text.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
            }
        }
        Self(text)
    }

    /// Checks `text` and keeps it as an id, in lowercase. Upper case is accepted, as the
    /// reference wallet does.
    pub fn parse(text: &str) -> Result<Self, InvalidEpicboxTxId> {
        let bytes = text.as_bytes();
        if bytes.len() != EPICBOX_TXID_LEN || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(InvalidEpicboxTxId);
        }
        let lower = text.to_ascii_lowercase();
        let version = lower.as_bytes().get(12).copied();
        let variant = lower.as_bytes().get(16).copied();
        if version != Some(b'4') || !matches!(variant, Some(b'8' | b'9' | b'a' | b'b')) {
            return Err(InvalidEpicboxTxId);
        }
        Ok(Self(lower))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EpicboxTxId {
    type Error = InvalidEpicboxTxId;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<EpicboxTxId> for String {
    fn from(id: EpicboxTxId) -> Self {
        id.0
    }
}

impl fmt::Display for EpicboxTxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reads an optional text field that is kept only if `parse` accepts it. Anything else, a
/// different type or a text that is not valid, reads as absent: the frame it is on stays usable.
fn lenient<'de, D, T>(deserializer: D, parse: fn(&str) -> Option<T>) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Lenient<T>(fn(&str) -> Option<T>);

    impl<'de, T> Visitor<'de> for Lenient<T> {
        type Value = Option<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an optional text")
        }

        fn visit_str<E>(self, text: &str) -> Result<Self::Value, E> {
            Ok((self.0)(text))
        }

        fn visit_some<D2: Deserializer<'de>>(self, inner: D2) -> Result<Self::Value, D2::Error> {
            inner.deserialize_any(self)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(None)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(None)
        }
    }

    deserializer.deserialize_any(Lenient(parse))
}

pub(crate) fn lenient_txid<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<EpicboxTxId>, D::Error> {
    lenient(deserializer, |text| EpicboxTxId::parse(text).ok())
}

fn lenient_msgid<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RelayMessageId>, D::Error> {
    lenient(deserializer, |text| RelayMessageId::parse(text).ok())
}

/// The extensions an `Ok` lists. Anything that is not a list of texts reads as none; texts that
/// are too long and entries past the bound are dropped, since the list is read only to find
/// the few tokens this client knows.
fn lenient_ext<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    const MAX_ENTRIES: usize = 16;

    /// Keeps the first short texts of a list and skips every other entry without building it.
    struct Lenient;

    impl<'de> Visitor<'de> for Lenient {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a list of extension names, or anything else read as none")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum Entry {
                Text(String),
                Other(IgnoredAny),
            }
            let mut kept = Vec::new();
            while let Some(entry) = seq.next_element::<Entry>()? {
                if let Entry::Text(text) = entry
                    && kept.len() < MAX_ENTRIES
                    && text.len() <= MAX_FRAME_TYPE_LEN
                {
                    kept.push(text);
                }
            }
            Ok(kept)
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(Vec::new())
        }

        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(Lenient)
}

/// A pending message pushed by the relay. `epicboxmsgid` and `ver` are present only when the
/// subscription carried `ver`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlateFrame {
    /// The sender's address.
    pub from: String,
    /// The message JSON.
    pub str: String,
    /// The sender's DER signature over `str`, as hex.
    pub signature: String,
    /// A challenge the relay sends with the message. The client does not read it.
    pub challenge: String,
    /// The id to acknowledge with `Made`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epicboxmsgid: Option<RelayMessageId>,
    /// The protocol version, sent when the subscription carried `ver`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ver: Option<String>,
    /// The transaction id the sender gave the message, on a relay of 3.1.0 or later. A value
    /// that is not a valid id reads as absent. `cancelrequestid` is between relays and is
    /// never read.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lenient_txid"
    )]
    pub epicboxtxid: Option<EpicboxTxId>,
}

/// The wire shape of a known relay frame, for encoding. Decoding reads each type's fields
/// without the tag, so that no buffer of the whole frame is built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
enum KnownRelayFrame {
    Challenge {
        str: String,
    },
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        epicboxtxid: Option<EpicboxTxId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        epicboxmsgid: Option<RelayMessageId>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        ext: Vec<String>,
    },
    Error {
        kind: RelayErrorKind,
        #[serde(default)]
        description: String,
    },
    Slate(SlateFrame),
    GetVersion {
        str: String,
    },
    TransactionCancelled {
        epicboxtxid: EpicboxTxId,
    },
}

/// A frame the relay sends to the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    /// A new challenge to sign.
    Challenge { str: String },
    /// Answers several requests, so it cannot be matched to one. A relay of 3.1.0 or later
    /// adds the ids of a stored message to the answer of a `PostSlate`.
    Ok {
        /// The transaction id the relay stored the message under.
        epicboxtxid: Option<EpicboxTxId>,
        /// The id the relay gave the stored message.
        epicboxmsgid: Option<RelayMessageId>,
        /// The extensions the relay accepted from the greeting. Empty from any other answer.
        ext: Vec<String>,
    },
    /// An error the relay reports.
    Error {
        kind: RelayErrorKind,
        description: String,
    },
    /// A message for a subscribed address.
    Slate(SlateFrame),
    /// The relay's protocol version.
    GetVersion { str: String },
    /// The transaction was cancelled (3.1.0): the answer to a `CancelTx`, or a push to the other
    /// participant. The next successful `Subscribe` on the socket acknowledges it.
    TransactionCancelled { epicboxtxid: EpicboxTxId },
    /// A JSON frame of a type this version does not know; the client ignores it.
    Unknown { type_name: String },
    /// Text that is not a JSON object, such as the bare `pong` the relay answers a ping with.
    Keepalive,
}

#[derive(Deserialize)]
struct OkFields {
    #[serde(default, deserialize_with = "lenient_txid")]
    epicboxtxid: Option<EpicboxTxId>,
    #[serde(default, deserialize_with = "lenient_msgid")]
    epicboxmsgid: Option<RelayMessageId>,
    #[serde(default, deserialize_with = "lenient_ext")]
    ext: Vec<String>,
}

#[derive(Deserialize)]
struct CancelledFields {
    #[serde(default, deserialize_with = "lenient_txid")]
    epicboxtxid: Option<EpicboxTxId>,
}

impl RelayFrame {
    /// An `Ok` with no ids: the answer of the 3.0.0 relay.
    pub fn ok() -> Self {
        Self::Ok {
            epicboxtxid: None,
            epicboxmsgid: None,
            ext: Vec::new(),
        }
    }

    /// Whether this is a `TransactionCancelled` whose transaction id was missing or not a
    /// valid id, which [`Self::from_json`] reads as unknown.
    pub(crate) fn is_cancel_without_txid(&self) -> bool {
        matches!(self, Self::Unknown { type_name } if type_name == "TransactionCancelled")
    }

    /// Decodes a frame from the relay. Unknown types and non-JSON text are not errors.
    pub fn from_json(text: &str) -> Result<Self, FrameError> {
        check_len(text)?;
        if !text.trim_start().starts_with('{') {
            return Ok(Self::Keepalive);
        }
        let type_name = probe_type(text)?;
        Ok(match type_name.as_str() {
            "Challenge" => {
                let challenge = fields::<TextFields>(text, type_name)?.str;
                if !is_challenge(&challenge) {
                    return Err(FrameError::Challenge);
                }
                Self::Challenge { str: challenge }
            }
            "Ok" => {
                let OkFields {
                    epicboxtxid,
                    epicboxmsgid,
                    ext,
                } = fields(text, type_name)?;
                Self::Ok {
                    epicboxtxid,
                    epicboxmsgid,
                    ext,
                }
            }
            // A cancel that names no valid id cannot be matched to anything: ignored as unknown.
            "TransactionCancelled" => {
                match fields::<CancelledFields>(text, type_name.clone())?.epicboxtxid {
                    Some(epicboxtxid) => Self::TransactionCancelled { epicboxtxid },
                    None => Self::Unknown { type_name },
                }
            }
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
            Self::Ok {
                epicboxtxid,
                epicboxmsgid,
                ext,
            } => KnownRelayFrame::Ok {
                epicboxtxid: epicboxtxid.clone(),
                epicboxmsgid: epicboxmsgid.clone(),
                ext: ext.clone(),
            },
            Self::TransactionCancelled { epicboxtxid } => KnownRelayFrame::TransactionCancelled {
                epicboxtxid: epicboxtxid.clone(),
            },
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
            .map_err(|error| FrameError::Json(error.into()))
    }
}

const KNOWN_CLIENT_TYPES: [&str; 7] = [
    "ClientDetails",
    "Subscribe",
    "PostSlate",
    "Made",
    "Unsubscribe",
    "GetVersion",
    "CancelTx",
];

pub(crate) fn check_len(text: &str) -> Result<(), FrameError> {
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
    /// Absent from a `Busy` answer.
    #[serde(default)]
    description: String,
}

/// Reads the fields of a frame whose type is known. The `type` key is ignored like any other
/// unknown key, which serde skips without keeping it.
pub(crate) fn fields<T: DeserializeOwned>(text: &str, type_name: String) -> Result<T, FrameError> {
    serde_json::from_str(text).map_err(|error| FrameError::Fields {
        type_name,
        source: error.into(),
    })
}

/// The frame's `type`, bounded, after checking that the whole text is one JSON object. Every
/// other value is skipped without being kept, so the work is bounded by the text alone.
pub(crate) fn probe_type(text: &str) -> Result<String, FrameError> {
    match serde_json::from_str::<TypeProbe>(text).map_err(|error| FrameError::Json(error.into()))? {
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

/// The longest refusal description a mailbox's `Error` frame passes on, in characters.
pub const MAX_REFUSAL_DESCRIPTION_LEN: usize = 256;

/// A mailbox's refusal `description` as safe to show in an error or a log: control characters
/// replaced by `?`, cut to [`MAX_REFUSAL_DESCRIPTION_LEN`] characters with `...` marking the
/// cut. `None` for an empty one.
pub(crate) fn bounded_description(description: &str) -> Option<String> {
    let shown = |c: char| if c.is_control() { '?' } else { c };
    let mut chars = description.trim().chars();
    let mut bounded: String = chars
        .by_ref()
        .take(MAX_REFUSAL_DESCRIPTION_LEN)
        .map(shown)
        .collect();
    if chars.next().is_some() {
        bounded.push_str("...");
    }
    (!bounded.is_empty()).then_some(bounded)
}

/// `name` as safe to show in an error or a log: printable ASCII, other characters replaced by
/// `?`, cut to [`MAX_FRAME_TYPE_LEN`] characters with `...` marking the cut. Known type names
/// pass unchanged, and a changed name never equals one.
pub(crate) fn bounded_type_name(name: &str) -> String {
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
