// Portions Copyright 2019 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic-wallet api/src/foreign_rpc.rs, impls/src/adapters/http.rs
// (Apache-2.0); see NOTICE and upstream.toml.

//! The JSON-RPC 2.0 messages of the wallet foreign API at `/v2/foreign`, as `epic-wallet`
//! `v4.1.0` writes and reads them: `check_version` and `receive_tx`, with every answer wrapped
//! in `result.Ok` or `result.Err`. Pure functions over bytes, so both sides and the fuzz
//! targets share them.

use lepic_slate::codec::{MAX_WIRE_SLATE_LEN, MediaType, WireSlate};
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::error::RpcError;

/// The foreign API version this crate speaks, the lowest `epic-wallet` sends slates to.
pub const FOREIGN_API_VERSION: u16 = 2;

/// A request or response body: one slate plus the JSON-RPC envelope around it.
pub const MAX_BODY_LEN: usize = MAX_WIRE_SLATE_LEN + 64 * 1024;

// An id is echoed back, so a large one would make the answer large.
const MAX_ID_LEN: usize = 64;

/// The slate versions a listening wallet offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    pub foreign_api_version: u16,
    pub v3: bool,
    pub v2: bool,
}

/// What a caller asked the listener for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    CheckVersion,
    /// The sender's S1, as the text that came in.
    ReceiveTx(WireSlate),
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
    params: Vec<&'a RawValue>,
}

// `receive_tx` takes at most this many parameters.
const MAX_PARAMS: usize = 4;

/// `params` with at most one entry past [`MAX_PARAMS`] kept, which is enough for the call to
/// refuse the request, and the rest skipped unparsed, so the memory a request spends does not
/// grow with the length of the array. `null` reads as no parameters.
fn bounded_params<'de, D>(deserializer: D) -> Result<Vec<&'de RawValue>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(ParamsVisitor)
}

struct ParamsVisitor;

impl<'de> Visitor<'de> for ParamsVisitor {
    type Value = Vec<&'de RawValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array or null")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Vec::new())
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut kept = Vec::new();
        while kept.len() <= MAX_PARAMS {
            match seq.next_element::<&'de RawValue>()? {
                Some(param) => kept.push(param),
                None => return Ok(kept),
            }
        }
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(kept)
    }
}

/// Reads a listener request body. A body that is not a JSON-RPC 2.0 request is an
/// [`Unanswerable`] with id `null`; a method other than the two this wallet serves is
/// [`METHOD_NOT_FOUND`].
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
    let call = match raw.method {
        "check_version" => Call::CheckVersion,
        "receive_tx" => match receive_tx_slate(&raw.params) {
            Some(slate) => Call::ReceiveTx(slate),
            None => {
                return Err(Unanswerable {
                    id,
                    code: INVALID_PARAMS,
                });
            }
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
fn receive_tx_slate(params: &[&RawValue]) -> Option<WireSlate> {
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

/// The answer to `check_version`: version 2 with the V3 and V2 slates.
pub fn encode_version_response(id: &str) -> Vec<u8> {
    format!(
        r#"{{"id":{id},"jsonrpc":"2.0","result":{{"Ok":{{"foreign_api_version":{FOREIGN_API_VERSION},"supported_slate_versions":["V3","V2"]}}}}}}"#
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
}

// More names than any wallet sends means the answer is not a version list.
const MAX_SLATE_VERSIONS: usize = 16;

/// Reads the answer to `check_version`. Fails with [`RpcError::Incompatible`] for a foreign
/// API older than version 2.
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
                v2: true
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
            code(r#"{"jsonrpc":"2.0","method":"build_coinbase","id":1,"params":[{}]}"#),
            METHOD_NOT_FOUND
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
        assert_eq!(raw.params.len(), MAX_PARAMS + 1);
        let refused = decode_request(many.as_bytes()).unwrap_err();
        assert_eq!(refused.code, INVALID_PARAMS);
        assert_eq!(refused.id, "5");

        for params in ["null", "[]"] {
            let body =
                format!(r#"{{"jsonrpc":"2.0","method":"check_version","id":1,"params":{params}}}"#);
            let raw: RawRequest<'_> = serde_json::from_str(&body).unwrap();
            assert!(raw.params.is_empty());
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

    proptest::proptest! {
        #[test]
        fn never_panics_on_any_request_bytes(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            let _ = decode_request(&bytes);
            let _ = decode_version_response(&bytes);
            let _ = decode_slate_response(&bytes);
        }
    }
}
