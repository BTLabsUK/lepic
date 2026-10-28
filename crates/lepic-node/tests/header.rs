// SPDX-License-Identifier: Apache-2.0
//! `get_header`: decoding the node's answer, every rejection, and the client's request shape.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{
    CallPolicy, FieldProblem, NodeApi, NodeClient, NodeError, NodeVersion, RejectionKind,
    RetryPolicy, RpcTransport, Tip, decode,
};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use serde_json::{Value, json};

const HASH: &str = "a163b1254f0b3afd1be875f351e1c2ff1213facd21e6956d9e7fdf56608eea92";

#[cfg(test)]
fn answer(height: u64, hash: &str, timestamp: &str) -> Vec<u8> {
    // A real node's header carries many more fields; the decoder ignores them.
    let body = json!({"id": 1, "jsonrpc": "2.0", "result": {"Ok": {
        "edge_bits": 16, "hash": hash, "height": height, "nonce": 8544941439127494349u64,
        "previous": HASH, "proof": "RandomX", "timestamp": timestamp, "version": 6,
    }}});
    serde_json::to_vec(&body).unwrap()
}

#[cfg(test)]
#[allow(clippy::needless_pass_by_value)]
fn body_of(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}

#[cfg(test)]
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[cfg(test)]
fn assert_invalid(error: NodeError, expected_field: &str, expected: FieldProblem) {
    match error {
        NodeError::InvalidField { field, problem, .. } => {
            assert_eq!(field, expected_field);
            assert_eq!(problem, expected);
        }
        other => panic!("expected an invalid field, got {other:?}"),
    }
}

#[test]
fn decodes_a_header() {
    let body = answer(100, HASH, "2019-09-03T02:42:55+00:00");
    let header = decode::header(&body, Height::new(100)).unwrap().unwrap();
    assert_eq!(header.height, Height::new(100));
    assert_eq!(header.hash, Hash::from_hex(HASH).unwrap());
    assert_eq!(header.timestamp.as_second(), 1_567_478_575);
}

#[test]
fn not_found_is_none() {
    let body = body_of(json!({"id": 1, "jsonrpc": "2.0", "result": {"Err": "NotFound"}}));
    assert_eq!(decode::header(&body, Height::new(9)).unwrap(), None);
}

#[test]
fn other_node_errors_stay_errors() {
    let body = body_of(json!({"id": 1, "result": {"Err": {"Internal": "chain busy"}}}));
    assert!(matches!(
        decode::header(&body, Height::new(9)),
        Err(NodeError::Rejected { rejection, .. }) if rejection.kind == RejectionKind::Internal
    ));
    let body = body_of(json!({"id": 1, "error": {"code": -32601, "message": "no"}}));
    assert!(matches!(
        decode::header(&body, Height::new(9)),
        Err(NodeError::Rpc { code: -32601, .. })
    ));
}

#[test]
fn rejects_a_bad_hash() {
    for hash in ["", "zz", &HASH[..62], &format!("{HASH}00")] {
        let body = answer(100, hash, "2019-09-03T02:42:55+00:00");
        let error = decode::header(&body, Height::new(100)).unwrap_err();
        assert!(
            matches!(
                error,
                NodeError::InvalidField {
                    field: "hash",
                    problem: FieldProblem::Hash(_),
                    ..
                }
            ),
            "{hash:?}: {error:?}"
        );
    }
}

#[test]
fn rejects_another_height_than_requested() {
    let body = answer(101, HASH, "2019-09-03T02:42:55+00:00");
    let error = decode::header(&body, Height::new(100)).unwrap_err();
    assert_invalid(error, "height", FieldProblem::Contradiction);
}

#[test]
fn rejects_a_timestamp_that_is_not_rfc3339() {
    for timestamp in [
        "",
        "yesterday",
        "2019-09-03 02:42:55",
        "1567478575",
        "2019-13-03T02:42:55Z",
    ] {
        let body = answer(100, HASH, timestamp);
        let error = decode::header(&body, Height::new(100)).unwrap_err();
        assert_invalid(error, "timestamp", FieldProblem::Timestamp);
    }
}

#[test]
fn rejects_a_timestamp_before_any_epic_chain() {
    let body = answer(100, HASH, "2018-12-31T23:59:59Z");
    let error = decode::header(&body, Height::new(100)).unwrap_err();
    assert_invalid(error, "timestamp", FieldProblem::BeforeGenesis);
    let body = answer(100, HASH, "2019-01-01T00:00:00Z");
    assert!(decode::header(&body, Height::new(100)).unwrap().is_some());
}

#[test]
fn rejects_a_missing_field() {
    let body = body_of(json!({"id": 1, "result": {"Ok": {"height": 100, "hash": HASH}}}));
    assert!(matches!(
        decode::header(&body, Height::new(100)),
        Err(NodeError::MalformedResponse { .. })
    ));
}

#[derive(Clone)]
struct FakeTransport {
    requests: Arc<Mutex<Vec<Value>>>,
    replies: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeTransport {
    fn new(replies: Vec<Vec<u8>>) -> Self {
        Self {
            requests: Arc::default(),
            replies: Arc::new(Mutex::new(replies)),
        }
    }
}

impl RpcTransport for FakeTransport {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        assert_eq!(endpoint, "/v2/foreign");
        self.requests
            .lock()
            .unwrap()
            .push(serde_json::from_slice(&body).unwrap());
        Ok(self.replies.lock().unwrap().remove(0))
    }

    fn node_label(&self) -> &str {
        "fake"
    }
}

#[cfg(test)]
fn tip_answer(height: u64) -> Vec<u8> {
    body_of(json!({"id": 1, "jsonrpc": "2.0", "result": {"Ok": {
        "height": height, "last_block_pushed": HASH,
        "prev_block_to_last": HASH, "total_difficulty": {}
    }}}))
}

#[cfg(test)]
fn client(transport: FakeTransport) -> NodeClient<FakeTransport> {
    NodeClient::new(
        transport,
        CallPolicy {
            retry: RetryPolicy::NONE,
            ..CallPolicy::default()
        },
    )
}

#[test]
fn client_sends_height_hash_commit_params_and_returns_the_header() {
    let transport = FakeTransport::new(vec![
        answer(100, HASH, "2019-09-03T02:42:55+00:00"),
        tip_answer(500),
    ]);
    let client = client(transport.clone());
    let header = block_on(client.get_header(Height::new(100)))
        .unwrap()
        .unwrap();
    assert_eq!(header.height, Height::new(100));

    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests[0]["method"], "get_header");
    assert_eq!(requests[0]["params"], json!([100, null, null]));
    assert_eq!(requests[1]["method"], "get_tip");
}

#[test]
fn client_maps_not_found_to_none() {
    let transport = FakeTransport::new(vec![body_of(
        json!({"id": 1, "jsonrpc": "2.0", "result": {"Err": "NotFound"}}),
    )]);
    let client = client(transport.clone());
    assert_eq!(block_on(client.get_header(Height::new(999))).unwrap(), None);
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[test]
fn client_rejects_a_header_above_the_tip() {
    let transport = FakeTransport::new(vec![
        answer(600, HASH, "2019-09-03T02:42:55+00:00"),
        tip_answer(500),
    ]);
    let client = client(transport);
    let error = block_on(client.get_header(Height::new(600))).unwrap_err();
    assert_invalid(error, "height", FieldProblem::AboveTip);
}

#[test]
fn client_accepts_a_header_covered_by_a_known_tip() {
    let transport = FakeTransport::new(vec![answer(100, HASH, "2019-09-03T02:42:55+00:00")]);
    let client =
        client(transport.clone()).with_known_tip(Height::new(200), std::time::Duration::ZERO);
    assert!(
        block_on(client.get_header(Height::new(100)))
            .unwrap()
            .is_some()
    );
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[cfg(test)]
fn mock_node(tip: u64) -> MockNode {
    MockNode::from_chain(ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(tip),
            last_block_pushed: Hash::from_bytes([7; 32]),
        },
    ))
}

#[test]
fn mock_node_dates_blocks_from_genesis_time() {
    let node = mock_node(20);
    let genesis = Timestamp::from_second(1_600_000_000).unwrap();
    node.update_chain(|chain| chain.genesis_time = genesis);
    let client = node.client();

    let zero = block_on(client.get_header(Height::new(0)))
        .unwrap()
        .unwrap();
    assert_eq!(zero.timestamp, genesis);
    let ten = block_on(client.get_header(Height::new(10)))
        .unwrap()
        .unwrap();
    assert_eq!(ten.timestamp.as_second(), 1_600_000_600);
    let tip = block_on(client.get_header(Height::new(20)))
        .unwrap()
        .unwrap();
    assert_eq!(tip.hash, Hash::from_bytes([7; 32]));
    assert!(node.violations().is_empty(), "{:?}", node.violations());
}

#[test]
fn mock_node_honours_a_set_header_time_and_has_no_block_above_the_tip() {
    let node = mock_node(20);
    let chosen = Timestamp::from_second(1_650_000_000).unwrap();
    node.update_chain(|chain| {
        chain.header_times.insert(Height::new(5), chosen);
    });
    let client = node.client();

    let five = block_on(client.get_header(Height::new(5)))
        .unwrap()
        .unwrap();
    assert_eq!(five.timestamp, chosen);
    assert_eq!(block_on(client.get_header(Height::new(21))).unwrap(), None);
}
