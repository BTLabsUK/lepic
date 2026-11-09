// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic-wallet api/src/foreign_rpc.rs, impls/src/adapters/http.rs
// (Apache-2.0); see NOTICE and upstream.toml.

//! The JSON-RPC 2.0 messages of the wallet foreign API at `/v2/foreign`, as `epic-wallet`
//! `v4.1.0` writes and reads them: `check_version`, `receive_tx` and the node's `build_coinbase`,
//! with every answer wrapped in `result.Ok` or `result.Err`. Pure functions over bytes, so both
//! sides and the fuzz targets share them.

use lepic_peer::Advert;
use lepic_slate::codec::{MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::error::RpcError;

/// The foreign API version this crate speaks, the lowest `epic-wallet` sends slates to.
pub const FOREIGN_API_VERSION: u16 = 2;

/// A request or response body: one slate plus the JSON-RPC envelope around it.
pub const MAX_BODY_LEN: usize = MAX_WIRE_SLATE_LEN + 64 * 1024;

// An id is echoed back, so a large one would make the answer large.
const MAX_ID_LEN: usize = 64;

/// The slate versions a listening wallet offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub foreign_api_version: u16,
    pub v3: bool,
    pub v2: bool,
    /// The native endpoint a LEPIC listener advertises, when the answer carries a readable
    /// `lepic` key.
    pub lepic: Option<Advert>,
}

/// What a caller asked the listener for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    CheckVersion,
    /// The sender's S1, as the text that came in.
    ReceiveTx(WireSlate),
    /// A mining node asking for the reward output and kernel of the block it is building.
    BuildCoinbase(BlockFees),
}

/// The length of a keychain identifier: a depth byte and four path indexes.
pub const KEY_ID_LEN: usize = 17;

/// What `build_coinbase` asks for, as the node's `BlockFees`: the fees of the block's
/// transactions, the height of the block, and the key of the wallet's last answer at this
/// height, if the node kept one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockFees {
    pub fees: u64,
    pub height: u64,
    pub key_id: Option<[u8; KEY_ID_LEN]>,
}

/// The answer to `build_coinbase`: the reward output and its kernel, and the key the output
/// is on, which the node passes back on its next request at the same height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseAnswer {
    pub commit: [u8; 33],
    pub proof: Vec<u8>,
    pub excess: [u8; 33],
    /// The compact signature, as `epic-wallet` writes it.
    pub excess_sig: [u8; 64],
    pub key_id: [u8; KEY_ID_LEN],
}

/// A request read by the listener: its id, echoed in the answer, and the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub call: Call,
}

/// A request the listener could read but will not run, answered with a JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unanswerable {
    pub id: String,
    pub code: i32,
}

pub(crate) const PARSE_ERROR: i32 = -32700;
pub(crate) const INVALID_REQUEST: i32 = -32600;
pub(crate) const METHOD_NOT_FOUND: i32 = -32601;
pub(crate) const INVALID_PARAMS: i32 = -32602;

#[derive(Deserialize)]
struct RawRequest<'a> {
    #[serde(borrow)]
    jsonrpc: Option<&'a str>,
    #[serde(borrow)]
    method: &'a str,
    #[serde(borrow)]
    id: Option<&'a RawValue>,
    #[serde(borrow, default, deserialize_with = "bounded_params")]
    params: Params<'a>,
}

/// The parameters of a request: by position, as wallets send them, or by name, as the node
/// sends `build_coinbase`.
#[derive(Debug)]
enum Params<'a> {
    List(Vec<&'a RawValue>),
    /// The one named parameter this wallet reads; any other name is skipped.
    Named {
        block_fees: Option<&'a RawValue>,
    },
}

impl Default for Params<'_> {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

// `receive_tx` takes at most this many parameters.
const MAX_PARAMS: usize = 4;

/// `params` with at most one entry past [`MAX_PARAMS`] kept, which is enough for the call to
/// refuse the request, and the rest skipped unparsed, so the memory a request spends does not
/// grow with the length of the array. `null` reads as no parameters. Of an object only
/// `block_fees` is kept.
fn bounded_params<'de, D>(deserializer: D) -> Result<Params<'de>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(ParamsVisitor)
}

struct ParamsVisitor;

impl<'de> Visitor<'de> for ParamsVisitor {
    type Value = Params<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array, an object or null")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Params::default())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Params::default())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut kept = Vec::new();
        while kept.len() <= MAX_PARAMS {
            match seq.next_element::<&'de RawValue>()? {
                Some(param) => kept.push(param),
                None => return Ok(Params::List(kept)),
            }
        }
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Params::List(kept))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut block_fees = None;
        while let Some(name) = map.next_key::<ParamName>()? {
            match name {
                ParamName::BlockFees if block_fees.is_some() => {
                    return Err(de::Error::duplicate_field("block_fees"));
                }
                ParamName::BlockFees => block_fees = Some(map.next_value::<&'de RawValue>()?),
                ParamName::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Params::Named { block_fees })
    }
}

/// A parameter name, read without keeping it.
enum ParamName {
    BlockFees,
    Other,
}

impl<'de> Deserialize<'de> for ParamName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NameVisitor;
        impl Visitor<'_> for NameVisitor {
            type Value = ParamName;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a parameter name")
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<Self::Value, E> {
                Ok(if name == "block_fees" {
                    ParamName::BlockFees
                } else {
                    ParamName::Other
                })
            }
        }
        deserializer.deserialize_identifier(NameVisitor)
    }
}

/// Reads a listener request body. A body that is not a JSON-RPC 2.0 request is an
/// [`Unanswerable`] with id `null`; a method other than the three this wallet knows is
/// [`METHOD_NOT_FOUND`]. Whether a listener serves `build_coinbase` is the listener's setting.
pub fn decode_request(body: &[u8]) -> Result<Request, Unanswerable> {
    let null = || "null".to_owned();
    if body.len() > MAX_BODY_LEN {
        return Err(Unanswerable {
            id: null(),
            code: INVALID_REQUEST,
        });
    }
    let raw: RawRequest<'_> = serde_json::from_slice(body).map_err(|_| Unanswerable {
        id: null(),
        code: PARSE_ERROR,
    })?;
    // Serde reads `"id": null` as no id; both are answered with `null`.
    let id = match raw.id {
        None => null(),
        Some(id) if id.get().len() <= MAX_ID_LEN && is_id(id.get()) => id.get().to_owned(),
        Some(_) => {
            return Err(Unanswerable {
                id: null(),
                code: INVALID_REQUEST,
            });
        }
    };
    if raw.jsonrpc != Some("2.0") {
        return Err(Unanswerable {
            id,
            code: INVALID_REQUEST,
        });
    }
    let invalid = |id| Unanswerable {
        id,
        code: INVALID_PARAMS,
    };
    let call = match raw.method {
        "check_version" => Call::CheckVersion,
        "receive_tx" => match receive_tx_slate(&raw.params) {
            Some(slate) => Call::ReceiveTx(slate),
            None => return Err(invalid(id)),
        },
        "build_coinbase" => match build_coinbase_fees(&raw.params) {
            Some(fees) => Call::BuildCoinbase(fees),
            None => return Err(invalid(id)),
        },
        _ => {
            return Err(Unanswerable {
                id,
                code: METHOD_NOT_FOUND,
            });
        }
    };
    Ok(Request { id, call })
}

/// A JSON-RPC id is a number, a string or null.
fn is_id(text: &str) -> bool {
    matches!(
        serde_json::from_str::<serde_json::Value>(text),
        Ok(serde_json::Value::Number(_) | serde_json::Value::String(_) | serde_json::Value::Null)
    )
}

/// `receive_tx` takes the slate, then the destination account, a message and the sender's
/// address, each optional; `epic-wallet` 4.0 sends three of them and 4.1 four. Only the slate
/// is used: this wallet receives into its default account and the sender's extras are
/// unauthenticated.
fn receive_tx_slate(params: &Params<'_>) -> Option<WireSlate> {
    let Params::List(params) = params else {
        return None;
    };
    let (slate, rest) = params.split_first()?;
    if params.len() > MAX_PARAMS || !slate.get().starts_with('{') {
        return None;
    }
    let extras_ok = rest.iter().all(|extra| {
        matches!(
            serde_json::from_str::<serde_json::Value>(extra.get()),
            Ok(serde_json::Value::Null | serde_json::Value::String(_))
        )
    });
    extras_ok.then(|| WireSlate::text(MediaType::JSON, slate.get().to_owned()))
}

/// `build_coinbase` takes one parameter, `block_fees`, by name as the node sends it or by
/// position. Fees and height are numbers or decimal text, as `epic-wallet` reads them; the key
/// is `null` or 17 bytes in hex. Other fields of `block_fees` are skipped.
fn build_coinbase_fees(params: &Params<'_>) -> Option<BlockFees> {
    let block_fees = match params {
        Params::Named { block_fees } => (*block_fees)?,
        Params::List(params) => match params.as_slice() {
            [block_fees] => *block_fees,
            _ => return None,
        },
    };
    let raw: RawBlockFees = serde_json::from_str(block_fees.get()).ok()?;
    let key_id = match raw.key_id {
        None => None,
        Some(hex) => Some(from_hex::<KEY_ID_LEN>(&hex)?),
    };
    Some(BlockFees {
        fees: raw.fees.value()?,
        height: raw.height.value()?,
        key_id,
    })
}

#[derive(Deserialize)]
struct RawBlockFees {
    fees: Decimal,
    height: Decimal,
    #[serde(default)]
    key_id: Option<String>,
}

/// A `u64` as a JSON number or as decimal text.
#[derive(Deserialize)]
#[serde(untagged)]
enum Decimal {
    Number(u64),
    Text(String),
}

impl Decimal {
    fn value(&self) -> Option<u64> {
        match self {
            Self::Number(value) => Some(*value),
            Self::Text(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => {
                text.parse().ok()
            }
            Self::Text(_) => None,
        }
    }
}

fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N.checked_mul(2)? || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut bytes = [0u8; N];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, pair) in bytes.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        },
    )
}

/// The answer to `build_coinbase` in `epic-wallet`'s `CoinbaseV3` shape: a coinbase output, a
/// coinbase kernel with no fee and no lock height, and the key.
pub fn encode_coinbase_response(id: &str, answer: &CoinbaseAnswer) -> Vec<u8> {
    format!(
        r#"{{"id":{id},"jsonrpc":"2.0","result":{{"Ok":{{"output":{{"features":"Coinbase","commit":"{}","proof":"{}"}},"kernel":{{"features":"Coinbase","fee":"0","lock_height":"0","excess":"{}","excess_sig":"{}"}},"key_id":"{}"}}}}}}"#,
        to_hex(&answer.commit),
        to_hex(&answer.proof),
        to_hex(&answer.excess),
        to_hex(&answer.excess_sig),
        to_hex(&answer.key_id),
    )
    .into_bytes()
}

/// The answer to `check_version`: version 2 with the V3 and V2 slates.
pub fn encode_version_response(id: &str) -> Vec<u8> {
    encode_version_response_with(id, None)
}

/// The answer to `check_version`, with the `lepic` key holding `advert` when there is one.
pub fn encode_version_response_with(id: &str, advert: Option<&Advert>) -> Vec<u8> {
    let lepic = advert
        .map(|advert| format!(r#","lepic":{}"#, advert.to_json()))
        .unwrap_or_default();
    format!(
        r#"{{"id":{id},"jsonrpc":"2.0","result":{{"Ok":{{"foreign_api_version":{FOREIGN_API_VERSION},"supported_slate_versions":["V3","V2"]{lepic}}}}}}}"#
    )
    .into_bytes()
}

/// The answer to `receive_tx`: the S2 reply. Fails when the reply is not a JSON object, which
/// only a broken codec would produce.
pub fn encode_slate_response(id: &str, reply: &WireSlate) -> Result<Vec<u8>, RpcError> {
    let text = reply.as_text().ok_or(RpcError::NotJson)?;
    let slate: &RawValue = serde_json::from_str(text).map_err(|_| RpcError::NotJson)?;
    if !slate.get().starts_with('{') {
        return Err(RpcError::NotJson);
    }
    Ok(format!(
        r#"{{"id":{id},"jsonrpc":"2.0","result":{{"Ok":{}}}}}"#,
        slate.get()
    )
    .into_bytes())
}

/// A refusal of `receive_tx` in the shape `epic-wallet` reports wallet errors: `result.Err`.
/// `reason` is one of this crate's fixed words, never peer text.
pub fn encode_refusal_response(id: &str, reason: &'static str) -> Vec<u8> {
    format!(r#"{{"id":{id},"jsonrpc":"2.0","result":{{"Err":{{"GenericError":"{reason}"}}}}}}"#)
        .into_bytes()
}

/// A JSON-RPC error answer.
pub fn encode_error_response(unanswerable: &Unanswerable) -> Vec<u8> {
    let message = match unanswerable.code {
        PARSE_ERROR => "Parse error",
        METHOD_NOT_FOUND => "Method not found",
        INVALID_PARAMS => "Invalid params",
        _ => "Invalid Request",
    };
    format!(
        r#"{{"id":{},"jsonrpc":"2.0","error":{{"code":{},"message":"{message}"}}}}"#,
        unanswerable.id, unanswerable.code
    )
    .into_bytes()
}

/// The `check_version` request a sender posts first.
pub fn encode_version_request() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","method":"check_version","id":1,"params":[]}"#.to_vec()
}

/// The `receive_tx` request carrying `slate`, with the three optional parameters `null` as
/// `epic-wallet` sends them.
pub fn encode_receive_request(slate: &WireSlate) -> Result<Vec<u8>, RpcError> {
    let text = slate.as_text().ok_or(RpcError::NotJson)?;
    let slate: &RawValue = serde_json::from_str(text).map_err(|_| RpcError::NotJson)?;
    Ok(format!(
        r#"{{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[{},null,null,null]}}"#,
        slate.get()
    )
    .into_bytes())
}

#[derive(Deserialize)]
struct RawResponse<'a> {
    #[serde(borrow, default)]
    error: Option<&'a RawValue>,
    #[serde(borrow, default)]
    result: Option<RawResult<'a>>,
}

#[derive(Deserialize)]
struct RawResult<'a> {
    #[serde(rename = "Ok", borrow, default)]
    ok: Option<&'a RawValue>,
    #[serde(rename = "Err", borrow, default)]
    err: Option<&'a RawValue>,
}

/// The `result.Ok` of a response, or why there is none.
fn response_ok(body: &[u8]) -> Result<&RawValue, RpcError> {
    if body.len() > MAX_BODY_LEN {
        return Err(RpcError::TooLarge);
    }
    let response: RawResponse<'_> =
        serde_json::from_slice(body).map_err(|_| RpcError::Malformed)?;
    if response.error.is_some_and(|error| error.get() != "null") {
        return Err(RpcError::Refused);
    }
    let result = response.result.ok_or(RpcError::Malformed)?;
    if result.err.is_some_and(|error| error.get() != "null") {
        return Err(RpcError::Refused);
    }
    result.ok.ok_or(RpcError::Malformed)
}

#[derive(Deserialize)]
struct RawVersion {
    foreign_api_version: u16,
    supported_slate_versions: Vec<String>,
    #[serde(default)]
    lepic: Option<serde_json::Value>,
}

// More names than any wallet sends means the answer is not a version list.
const MAX_SLATE_VERSIONS: usize = 16;

/// Reads the answer to `check_version`. Fails with [`RpcError::Incompatible`] for a foreign
/// API older than version 2. Unknown keys are ignored; a `lepic` key that is not a readable
/// advert is read as no advert.
pub fn decode_version_response(body: &[u8]) -> Result<VersionInfo, RpcError> {
    let ok = response_ok(body)?;
    let raw: RawVersion = serde_json::from_str(ok.get()).map_err(|_| RpcError::Malformed)?;
    if raw.supported_slate_versions.len() > MAX_SLATE_VERSIONS {
        return Err(RpcError::Malformed);
    }
    if raw.foreign_api_version < FOREIGN_API_VERSION {
        return Err(RpcError::Incompatible);
    }
    let offers = |name: &str| raw.supported_slate_versions.iter().any(|v| v == name);
    Ok(VersionInfo {
        foreign_api_version: raw.foreign_api_version,
        v3: offers("V3"),
        v2: offers("V2"),
        lepic: raw
            .lepic
            .as_ref()
            .and_then(|value| Advert::from_json(value).ok()),
    })
}

/// Reads the answer to `receive_tx`: the receiver's S2 as it came, for the codecs to decode.
pub fn decode_slate_response(body: &[u8]) -> Result<WireSlate, RpcError> {
    let ok = response_ok(body)?;
    if !ok.get().starts_with('{') {
        return Err(RpcError::Malformed);
    }
    Ok(WireSlate::text(MediaType::JSON, ok.get().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(wire: &WireSlate) -> &str {
        wire.as_text().unwrap()
    }

    #[test]
    fn reads_receive_tx_with_three_or_four_extras() {
        for body in [
            r#"{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[{"id":"a"},null,null,null]}"#,
            r#"{"jsonrpc":"2.0","method":"receive_tx","id":"x","params":[{"id":"a"},null,"hi"]}"#,
            r#"{"jsonrpc":"2.0","method":"receive_tx","id":null,"params":[{"id":"a"}]}"#,
        ] {
            let request = decode_request(body.as_bytes()).unwrap();
            let Call::ReceiveTx(slate) = request.call else {
                panic!("not a receive_tx");
            };
            assert_eq!(text(&slate), r#"{"id":"a"}"#);
        }
    }

    #[test]
    fn carries_the_advert_and_reads_it_back() {
        let advert = Advert::new([5; 32]);
        let answer = encode_version_response_with("3", Some(&advert));
        assert_eq!(
            std::str::from_utf8(&answer).unwrap(),
            format!(
                r#"{{"id":3,"jsonrpc":"2.0","result":{{"Ok":{{"foreign_api_version":2,"supported_slate_versions":["V3","V2"],"lepic":{{"formats":["lepic.v1"],"path":"/v1/peer","protocol":1,"seal":"{}"}}}}}}}}"#,
                "05".repeat(32)
            )
        );
        let info = decode_version_response(&answer).unwrap();
        assert_eq!(info.lepic, Some(advert));
        assert!(info.v3 && info.v2);
        assert_eq!(
            encode_version_response_with("3", None),
            encode_version_response("3")
        );
    }

    #[test]
    fn reads_the_advert_among_unknown_keys_and_drops_a_malformed_one() {
        let seal = "0a".repeat(32);
        let body = |lepic: &str| {
            format!(
                r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{{"foreign_api_version":2,"supported_slate_versions":["V2"],"other":[1],{lepic}}}}}}}"#
            )
        };
        let read = |lepic: &str| decode_version_response(body(lepic).as_bytes()).unwrap();
        let info = read(&format!(
            r#""lepic":{{"protocol":1,"formats":["lepic.v1","later"],"path":"/v1/peer","seal":"{seal}","x":true}}"#
        ));
        let advert = info.lepic.unwrap();
        assert_eq!(advert.seal, [10; 32]);
        assert!(advert.offers("lepic.v1"));
        for malformed in [
            r#""lepic":null"#.to_owned(),
            r#""lepic":"yes""#.to_owned(),
            r#""lepic":{"protocol":1,"formats":["lepic.v1"],"path":"/v1/peer","seal":"00"}"#
                .to_owned(),
            format!(r#""lepic":{{"protocol":1,"formats":[],"path":"v1","seal":"{seal}"}}"#),
            r#""unrelated":1"#.to_owned(),
        ] {
            assert_eq!(read(&malformed).lepic, None, "{malformed}");
        }
    }

    #[test]
    fn reads_check_version_and_echoes_its_id() {
        let request =
            decode_request(br#"{"jsonrpc":"2.0","method":"check_version","id":7,"params":[]}"#)
                .unwrap();
        assert_eq!(request.call, Call::CheckVersion);
        let answer = encode_version_response(&request.id);
        let info = decode_version_response(&answer).unwrap();
        assert_eq!(
            info,
            VersionInfo {
                foreign_api_version: 2,
                v3: true,
                v2: true,
                lepic: None,
            }
        );
        assert!(
            std::str::from_utf8(&answer)
                .unwrap()
                .starts_with(r#"{"id":7,"#)
        );
    }

    #[test]
    fn refuses_requests_it_does_not_serve() {
        let code = |body: &str| decode_request(body.as_bytes()).unwrap_err().code;
        assert_eq!(code("not json"), PARSE_ERROR);
        assert_eq!(
            code(r#"{"method":"check_version","id":1}"#),
            INVALID_REQUEST
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","method":"finalize_invoice_tx","id":1,"params":[{}]}"#),
            METHOD_NOT_FOUND
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","method":"build_foundation","id":1,"params":[{}]}"#),
            METHOD_NOT_FOUND
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":{"slate":{}}}"#),
            INVALID_PARAMS
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[]}"#),
            INVALID_PARAMS
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":["s"]}"#),
            INVALID_PARAMS
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[{},1]}"#),
            INVALID_PARAMS
        );
        assert_eq!(
            code(
                r#"{"jsonrpc":"2.0","method":"receive_tx","id":1,"params":[{},null,null,null,null]}"#
            ),
            INVALID_PARAMS
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","method":"check_version","id":{"a":1}}"#),
            INVALID_REQUEST
        );
        let long_id = format!(
            r#"{{"jsonrpc":"2.0","method":"check_version","id":"{}"}}"#,
            "a".repeat(80)
        );
        assert_eq!(code(&long_id), INVALID_REQUEST);
    }

    #[test]
    fn keeps_no_more_params_than_it_needs_to_refuse() {
        let many = format!(
            r#"{{"jsonrpc":"2.0","method":"receive_tx","id":5,"params":[{{}}{}]}}"#,
            ",0".repeat(1_000_000)
        );
        let raw: RawRequest<'_> = serde_json::from_str(&many).unwrap();
        let Params::List(kept) = raw.params else {
            panic!("not a list");
        };
        assert_eq!(kept.len(), MAX_PARAMS + 1);
        let refused = decode_request(many.as_bytes()).unwrap_err();
        assert_eq!(refused.code, INVALID_PARAMS);
        assert_eq!(refused.id, "5");

        for params in ["null", "[]"] {
            let body =
                format!(r#"{{"jsonrpc":"2.0","method":"check_version","id":1,"params":{params}}}"#);
            let raw: RawRequest<'_> = serde_json::from_str(&body).unwrap();
            assert!(matches!(raw.params, Params::List(kept) if kept.is_empty()));
        }
        let not_array = r#"{"jsonrpc":"2.0","method":"check_version","id":1,"params":5}"#;
        assert_eq!(
            decode_request(not_array.as_bytes()).unwrap_err().code,
            PARSE_ERROR
        );
        let broken =
            r#"{"jsonrpc":"2.0","method":"check_version","id":1,"params":[{},1,2,3,4,5,}]}"#;
        assert_eq!(
            decode_request(broken.as_bytes()).unwrap_err().code,
            PARSE_ERROR
        );
    }

    #[test]
    fn error_answers_are_json_rpc_errors() {
        let unanswerable = decode_request(b"[").unwrap_err();
        let answer = encode_error_response(&unanswerable);
        let value: serde_json::Value = serde_json::from_slice(&answer).unwrap();
        assert_eq!(value["error"]["code"], PARSE_ERROR);
        assert_eq!(value["id"], serde_json::Value::Null);
        assert_eq!(decode_slate_response(&answer), Err(RpcError::Refused));
    }

    #[test]
    fn slate_response_round_trips_the_reply_text() {
        let reply = WireSlate::text(MediaType::JSON, r#"{"id":"b","amount":"1"}"#.to_owned());
        let body = encode_slate_response("1", &reply).unwrap();
        assert_eq!(
            text(&decode_slate_response(&body).unwrap()),
            r#"{"id":"b","amount":"1"}"#
        );
    }

    #[test]
    fn refusal_is_read_as_refused() {
        let body = encode_refusal_response("1", "refused");
        assert_eq!(decode_slate_response(&body), Err(RpcError::Refused));
    }

    #[test]
    fn rejects_malformed_responses() {
        for body in [
            "not json",
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":"text"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"Ok":{"foreign_api_version":"bad","supported_slate_versions":[]}}}"#,
        ] {
            assert!(
                decode_slate_response(body.as_bytes()).is_err()
                    || decode_version_response(body.as_bytes()).is_err()
            );
            assert!(decode_version_response(body.as_bytes()).is_err());
        }
        assert_eq!(
            decode_version_response(
                br#"{"id":1,"result":{"Ok":{"foreign_api_version":1,"supported_slate_versions":["V2"]}}}"#
            ),
            Err(RpcError::Incompatible)
        );
    }

    #[test]
    fn receive_request_carries_the_slate_and_three_nulls() {
        let slate = WireSlate::text(MediaType::JSON, r#"{"id":"c"}"#.to_owned());
        let body = encode_receive_request(&slate).unwrap();
        let request = decode_request(&body).unwrap();
        assert_eq!(request.call, Call::ReceiveTx(slate));
    }

    const KEY: &str = "0200000000000000000000000500000000";

    fn coinbase_call(body: &str) -> Result<BlockFees, i32> {
        match decode_request(body.as_bytes()) {
            Ok(Request {
                call: Call::BuildCoinbase(fees),
                ..
            }) => Ok(fees),
            Ok(other) => panic!("not a build_coinbase: {other:?}"),
            Err(unanswerable) => Err(unanswerable.code),
        }
    }

    #[test]
    fn reads_build_coinbase_as_the_node_sends_it() {
        let node = format!(
            r#"{{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{{"block_fees":{{"fees":"7000000","height":"812","key_id":"{KEY}"}}}}}}"#
        );
        let mut key = [0u8; KEY_ID_LEN];
        key[0] = 2;
        key[12] = 5;
        assert_eq!(
            coinbase_call(&node),
            Ok(BlockFees {
                fees: 7_000_000,
                height: 812,
                key_id: Some(key),
            })
        );
        for body in [
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":0,"height":3,"key_id":null}}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":[{"fees":"0","height":3}]}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"other":[1],"block_fees":{"fees":0,"height":"3","extra":true}}}"#,
        ] {
            assert_eq!(
                coinbase_call(body),
                Ok(BlockFees {
                    fees: 0,
                    height: 3,
                    key_id: None,
                }),
                "{body}"
            );
        }
    }

    #[test]
    fn refuses_build_coinbase_with_bad_block_fees() {
        for body in [
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":[]}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":[{"fees":0,"height":1},null]}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":0}}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":-1,"height":1}}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":"+1","height":1}}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":"18446744073709551616","height":1}}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":0,"height":1,"key_id":"02"}}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":0,"height":1,"key_id":"+200000000000000000000000500000000"}}}"#,
            r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":"x"}}"#,
        ] {
            assert_eq!(coinbase_call(body), Err(INVALID_PARAMS), "{body}");
        }
        let twice = r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":{"block_fees":{"fees":0,"height":1},"block_fees":{"fees":0,"height":2}}}"#;
        assert_eq!(coinbase_call(twice), Err(PARSE_ERROR));
    }

    #[test]
    fn coinbase_answer_has_the_shape_the_node_reads() {
        let answer = CoinbaseAnswer {
            commit: [8; 33],
            proof: vec![0xab; 3],
            excess: [9; 33],
            excess_sig: [1; 64],
            key_id: from_hex::<KEY_ID_LEN>(KEY).unwrap(),
        };
        let body = encode_coinbase_response("\"n\"", &answer);
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["id"], "n");
        assert!(value["error"].is_null());
        let ok = &value["result"]["Ok"];
        assert_eq!(ok["output"]["features"], "Coinbase");
        assert_eq!(ok["output"]["commit"], "08".repeat(33));
        assert_eq!(ok["output"]["proof"], "ababab");
        assert_eq!(ok["kernel"]["features"], "Coinbase");
        assert_eq!(ok["kernel"]["fee"], "0");
        assert_eq!(ok["kernel"]["lock_height"], "0");
        assert_eq!(ok["kernel"]["excess"], "09".repeat(33));
        assert_eq!(ok["kernel"]["excess_sig"], "01".repeat(64));
        assert_eq!(ok["key_id"], KEY);
    }

    proptest::proptest! {
        #[test]
        fn never_panics_on_any_request_bytes(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            let _ = decode_request(&bytes);
            let _ = decode_version_response(&bytes);
            let _ = decode_slate_response(&bytes);
        }
    }
}
