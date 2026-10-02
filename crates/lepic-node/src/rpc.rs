//! JSON-RPC 2.0 framing as the node's foreign API speaks it.
//!
//! The node wraps each handler's outcome in `result` as `{"Ok": value}` or `{"Err": error}`;
//! only failures of the RPC layer itself use the standard `error` object.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{NodeError, NodeRejection, RejectionKind};

pub(crate) const FOREIGN_ENDPOINT: &str = "/v2/foreign";

// Upstream sends every request with id 1 and the node echoes it.
pub(crate) const REQUEST_ID: u64 = 1;

const MAX_REJECTION_MESSAGE_CHARS: usize = 256;

pub(crate) fn encode_request(method: &'static str, params: &Value) -> Result<Vec<u8>, NodeError> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": REQUEST_ID,
    });
    serde_json::to_vec(&request).map_err(|source| NodeError::EncodeRequest { method, source })
}

#[derive(Deserialize)]
#[serde(bound = "T: DeserializeOwned")]
struct Envelope<T> {
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    result: Option<HandlerResult<T>>,
    #[serde(default)]
    error: Option<RpcErrorObject>,
}

#[derive(Deserialize)]
enum HandlerResult<T> {
    Ok(T),
    Err(Value),
}

#[derive(Deserialize)]
struct RpcErrorObject {
    code: i64,
}

/// Decodes a response body into the handler's value, or the error the node reported.
pub(crate) fn decode_response<T: DeserializeOwned>(
    method: &'static str,
    body: &[u8],
) -> Result<T, NodeError> {
    let envelope: Envelope<T> = serde_json::from_slice(body)
        .map_err(|source| NodeError::MalformedResponse { method, source })?;
    if envelope
        .id
        .as_ref()
        .is_some_and(|id| id.as_u64() != Some(REQUEST_ID))
    {
        return Err(NodeError::IdMismatch { method });
    }
    match (envelope.result, envelope.error) {
        (Some(HandlerResult::Ok(value)), _) => Ok(value),
        (Some(HandlerResult::Err(error)), _) => Err(NodeError::Rejected {
            method,
            rejection: rejection_from(&error),
        }),
        (None, Some(error)) => Err(NodeError::Rpc {
            method,
            code: error.code,
        }),
        (None, None) => Err(NodeError::EmptyResponse { method }),
    }
}

/// The node's `api::Error`: `"NotFound"`, or a one-key object such as `{"Internal": "text"}`.
fn rejection_from(error: &Value) -> NodeRejection {
    let (name, message) = match error {
        Value::String(name) => (name.as_str(), None),
        Value::Object(map) if map.len() == 1 => match map.iter().next() {
            Some((name, Value::String(text))) => (name.as_str(), Some(bounded(text))),
            Some((name, _)) => (name.as_str(), None),
            None => ("", None),
        },
        _ => ("", None),
    };
    let kind = match name {
        "NotFound" => RejectionKind::NotFound,
        "Internal" => RejectionKind::Internal,
        "Argument" => RejectionKind::Argument,
        "RequestError" => RejectionKind::Request,
        "ResponseError" => RejectionKind::Response,
        "Router" => RejectionKind::Router,
        _ => RejectionKind::Unknown,
    };
    NodeRejection { kind, message }
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_REJECTION_MESSAGE_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ok_result() {
        let body = br#"{"id":1,"jsonrpc":"2.0","result":{"Ok":7}}"#;
        assert_eq!(decode_response::<u64>("m", body).unwrap(), 7);
    }

    #[test]
    fn decodes_not_found_rejection() {
        let body = br#"{"id":1,"jsonrpc":"2.0","result":{"Err":"NotFound"}}"#;
        let error = decode_response::<u64>("m", body).unwrap_err();
        assert!(matches!(
            error,
            NodeError::Rejected {
                rejection: NodeRejection {
                    kind: RejectionKind::NotFound,
                    message: None
                },
                ..
            }
        ));
    }

    #[test]
    fn bounds_rejection_message() {
        let text = "x".repeat(10_000);
        let body = format!(r#"{{"id":1,"result":{{"Err":{{"Internal":"{text}"}}}}}}"#);
        let error = decode_response::<u64>("m", body.as_bytes()).unwrap_err();
        let NodeError::Rejected { rejection, .. } = error else {
            panic!("expected a rejection, got {error:?}");
        };
        assert_eq!(rejection.kind, RejectionKind::Internal);
        assert_eq!(
            rejection.message.map(|m| m.len()),
            Some(MAX_REJECTION_MESSAGE_CHARS)
        );
    }

    #[test]
    fn reports_rpc_error_object() {
        let body = br#"{"id":1,"jsonrpc":"2.0","error":{"code":-32601,"message":"no"}}"#;
        assert!(matches!(
            decode_response::<u64>("m", body),
            Err(NodeError::Rpc { code: -32601, .. })
        ));
    }

    #[test]
    fn rejects_other_request_id() {
        let body = br#"{"id":2,"jsonrpc":"2.0","result":{"Ok":7}}"#;
        assert!(matches!(
            decode_response::<u64>("m", body),
            Err(NodeError::IdMismatch { .. })
        ));
    }

    #[test]
    fn rejects_empty_envelope() {
        assert!(matches!(
            decode_response::<u64>("m", br#"{"id":1}"#),
            Err(NodeError::EmptyResponse { .. })
        ));
    }
}
