//! The HTTP client against a local server: valid recorded answers, and every kind of hostile
//! answer a node or a man in the middle could give. Each must end in a typed error, never a
//! panic, a hang or an unbounded read.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

mod support;

use std::path::PathBuf;
use std::time::Duration;

use lepic_crypto::Commitment;
use lepic_node::{
    CallPolicy, FieldProblem, HttpSettings, HttpTransport, NodeApi, NodeClient, NodeError,
    Propagation, RejectionKind, RetryPolicy, webpki_tls_config,
};
use lepic_primitives::amount::Height;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::Transaction;
use secrecy::SecretString;
use serde_json::{Value, json};
use support::{Received, Reply, TestServer};

const QUICK_RETRY: RetryPolicy = RetryPolicy {
    max_attempts: 3,
    initial_backoff: Duration::from_millis(1),
    max_backoff: Duration::from_millis(2),
};

#[cfg(test)]
fn settings() -> HttpSettings {
    HttpSettings {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        max_response_bytes: 64 * 1024,
        api_secret: None,
    }
}

#[cfg(test)]
fn client_with(
    url: &str,
    settings: &HttpSettings,
    policy: CallPolicy,
) -> NodeClient<HttpTransport> {
    let transport = HttpTransport::new(url, settings, webpki_tls_config().unwrap()).unwrap();
    NodeClient::new(transport, policy)
}

#[cfg(test)]
fn client(server: &TestServer) -> NodeClient<HttpTransport> {
    client_with(
        &server.url(),
        &settings(),
        CallPolicy {
            retry: QUICK_RETRY,
            ..CallPolicy::default()
        },
    )
}

#[cfg(test)]
fn vector(path: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors")
        .join(path);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[cfg(test)]
fn recorded_response(method: &str) -> Value {
    vector("engine/refresh_spent.json")["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|exchange| exchange["method"] == method)
        .unwrap()["response"]
        .clone()
}

#[cfg(test)]
fn ok_body(value: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"id": 1, "jsonrpc": "2.0", "result": {"Ok": value}})).unwrap()
}

#[cfg(test)]
fn method_of(request: &Received) -> String {
    request.json()["method"].as_str().unwrap().to_owned()
}

#[cfg(test)]
fn listing() -> Value {
    recorded_response("get_unspent_outputs")["result"]["Ok"].clone()
}

#[cfg(test)]
fn listed_commitments() -> Vec<Commitment> {
    listing()["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|output| Commitment::from_hex(output["commit"].as_str().unwrap()).unwrap())
        .collect()
}

#[cfg(test)]
fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(test)]
fn valid_transaction() -> (Transaction, Value) {
    let vector = vector("primitives/tx_valid_plain_1_in_2_out.json");
    let bytes = hex_bytes(vector["expected"]["serialized_v2"].as_str().unwrap());
    let transaction = Transaction::decode(&bytes, ProtocolVersion::V2).unwrap();
    (transaction, vector["expected"]["transaction"].clone())
}

#[cfg(test)]
fn assert_invalid_field(error: NodeError, expected_field: &str) -> FieldProblem {
    match error {
        NodeError::InvalidField { field, problem, .. } if field == expected_field => problem,
        other => panic!("expected an invalid {expected_field}, got {other:?}"),
    }
}

#[tokio::test]
async fn reads_recorded_answers_and_sends_upstream_requests() {
    let server = TestServer::start(|request| match method_of(request).as_str() {
        "get_tip" => Reply::json(serde_json::to_vec(&recorded_response("get_tip")).unwrap()),
        _ => Reply::json(serde_json::to_vec(&recorded_response("get_unspent_outputs")).unwrap()),
    })
    .await;
    let client = client_with(
        &server.url(),
        &HttpSettings {
            max_response_bytes: 1024 * 1024,
            ..settings()
        },
        CallPolicy::default(),
    );

    let tip = client.get_tip().await.unwrap();
    let recorded_tip = &recorded_response("get_tip")["result"]["Ok"];
    assert_eq!(tip.height.value(), recorded_tip["height"].as_u64().unwrap());

    let end = listing()["highest_index"].as_u64().unwrap();
    let page = client
        .get_unspent_outputs(1, Some(end), 1000)
        .await
        .unwrap();
    assert_eq!(page.outputs.len(), listed_commitments().len());

    let received = server.received();
    assert_eq!(received.len(), 2);
    for request in &received {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v2/foreign");
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("authorization"), None);
    }
    assert_eq!(
        received[0].json(),
        json!({"jsonrpc": "2.0", "method": "get_tip", "params": null, "id": 1})
    );
    assert_eq!(received[1].json()["params"], json!([1, end, 1000, true]));
}

#[tokio::test]
async fn sends_basic_auth_with_the_epic_user() {
    let server = TestServer::start(|_| Reply::json(ok_body(&json!(null)))).await;
    let settings = HttpSettings {
        api_secret: Some(SecretString::from("secret")),
        ..settings()
    };
    let client = client_with(&server.url(), &settings, CallPolicy::default());
    let (transaction, _) = valid_transaction();
    client
        .push_transaction(&transaction, Propagation::Stem)
        .await
        .unwrap();
    assert_eq!(
        server.received()[0].header("authorization"),
        Some("Basic ZXBpYzpzZWNyZXQ=")
    );
}

#[tokio::test]
async fn pushes_the_transaction_as_node_json() {
    let server = TestServer::start(|_| Reply::json(ok_body(&json!(null)))).await;
    let (transaction, expected) = valid_transaction();
    client(&server)
        .push_transaction(&transaction, Propagation::Fluff)
        .await
        .unwrap();
    let request = server.received()[0].json();
    assert_eq!(request["method"], "push_transaction");
    assert_eq!(request["params"][1], true);
    let sent = &request["params"][0];
    assert_eq!(sent["offset"], expected["offset"]);
    for part in ["inputs", "outputs"] {
        let sent = sent["body"][part].as_array().unwrap();
        let expected = expected[part].as_array().unwrap();
        assert_eq!(sent.len(), expected.len(), "{part}");
        for (sent, expected) in sent.iter().zip(expected) {
            assert_eq!(sent["features"], expected["features"], "{part}");
            assert_eq!(sent["commit"], expected["commit"], "{part}");
            if part == "outputs" {
                assert_eq!(sent["proof"], expected["proof"]);
            }
        }
    }
    let kernel = &sent["body"]["kernels"][0];
    let expected_kernel = &expected["kernels"][0];
    assert_eq!(kernel["excess"], expected_kernel["excess"]);
    assert_eq!(kernel["excess_sig"], expected_kernel["excess_sig"]);
    let fee: u64 = expected_kernel["features"]["fee"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(kernel["features"], json!({"Plain": {"fee": fee}}));
}

#[tokio::test]
async fn rejects_malformed_json() {
    for body in [
        &b"{"[..],
        b"not json",
        b"",
        b"{\"id\":1,\"result\":{\"Ok\":",
    ] {
        let server = TestServer::start(move |_| Reply::json(body.to_vec())).await;
        let error = client(&server).get_tip().await.unwrap_err();
        assert!(
            matches!(
                error,
                NodeError::MalformedResponse {
                    method: "get_tip",
                    ..
                }
            ),
            "{error:?}"
        );
    }
}

#[tokio::test]
async fn rejects_wrong_types() {
    let cases = [
        json!({"height": "9", "last_block_pushed": "00"}),
        json!({"height": -1, "last_block_pushed": "00"}),
        json!({"height": 1.5, "last_block_pushed": "00"}),
        json!({"last_block_pushed": "00"}),
        json!([]),
        json!(null),
    ];
    for value in cases {
        let body = ok_body(&value);
        let server = TestServer::start(move |_| Reply::json(body.clone())).await;
        let error = client(&server).get_tip().await.unwrap_err();
        let NodeError::MalformedResponse { source, .. } = &error else {
            panic!("{value}: {error:?}");
        };
        assert!(source.is_data(), "{value}: {source}");
    }

    let overflow =
        br#"{"id":1,"result":{"Ok":{"height":18446744073709551616,"last_block_pushed":"00"}}}"#;
    let server = TestServer::start(move |_| Reply::json(overflow.to_vec())).await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(
        matches!(error, NodeError::MalformedResponse { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn rejects_invalid_hex_and_curve_values() {
    let body = ok_body(&json!({"height": 3, "last_block_pushed": "zz"}));
    let server = TestServer::start(move |_| Reply::json(body.clone())).await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(matches!(
        assert_invalid_field(error, "last_block_pushed"),
        FieldProblem::Hash(_)
    ));

    let requested = listed_commitments()[0];
    let body = ok_body(&json!([{
        "output_type": "Transaction", "commit": "ff".repeat(33), "spent": false,
        "proof": null, "proof_hash": "", "block_height": 3, "merkle_proof": null, "mmr_index": 4
    }]));
    let server = TestServer::start(move |_| Reply::json(body.clone())).await;
    let error = client(&server).get_outputs(&[requested]).await.unwrap_err();
    assert!(matches!(
        assert_invalid_field(error, "commit"),
        FieldProblem::Crypto(_)
    ));
}

#[cfg(test)]
fn output_json(commit: &Commitment, mmr_index: u64, proof: Option<&str>) -> Value {
    json!({
        "output_type": "Transaction", "commit": commit.to_hex(), "spent": false,
        "proof": proof, "proof_hash": "00", "block_height": 5, "merkle_proof": null,
        "mmr_index": mmr_index
    })
}

#[tokio::test]
async fn rejects_outputs_that_were_not_asked_for() {
    let commitments = listed_commitments();
    let (asked, other) = (commitments[0], commitments[1]);

    let cases = [
        (
            vec![output_json(&other, 1, None)],
            FieldProblem::NotRequested,
        ),
        (
            vec![output_json(&asked, 1, None), output_json(&asked, 1, None)],
            FieldProblem::TooMany,
        ),
    ];
    for (outputs, expected) in cases {
        let body = ok_body(&Value::Array(outputs));
        let server = TestServer::start(move |_| Reply::json(body.clone())).await;
        let error = client(&server).get_outputs(&[asked]).await.unwrap_err();
        let NodeError::InvalidField { problem, .. } = error else {
            panic!("{error:?}");
        };
        assert_eq!(problem, expected);
    }

    let body = ok_body(&json!([
        output_json(&asked, 1, None),
        output_json(&asked, 2, None)
    ]));
    let server = TestServer::start(move |_| Reply::json(body.clone())).await;
    let error = client(&server)
        .get_outputs(&[asked, other])
        .await
        .unwrap_err();
    assert_eq!(
        assert_invalid_field(error, "commit"),
        FieldProblem::Duplicate
    );

    let mut missing_height = output_json(&asked, 1, None);
    missing_height["block_height"] = Value::Null;
    let body = ok_body(&json!([missing_height]));
    let server = TestServer::start(move |_| Reply::json(body.clone())).await;
    let error = client(&server).get_outputs(&[asked]).await.unwrap_err();
    assert_eq!(
        assert_invalid_field(error, "block_height"),
        FieldProblem::Missing
    );
}

#[tokio::test]
async fn rejects_unspent_pages_that_break_the_request() {
    let listed = listing()["outputs"].as_array().unwrap().clone();
    let proof = listed[0]["proof"].as_str().unwrap().to_owned();
    let commit = listed_commitments()[0];
    let page = |outputs: &[Value]| {
        ok_body(&json!({"highest_index": 20, "last_retrieved_index": 20, "outputs": outputs}))
    };
    let cases: Vec<(Vec<u8>, &str, FieldProblem)> = vec![
        (
            page(&[output_json(&commit, 30, Some(&proof))]),
            "mmr_index",
            FieldProblem::OutOfRange,
        ),
        (
            page(&[output_json(&commit, 1, Some(&proof))]),
            "mmr_index",
            FieldProblem::OutOfRange,
        ),
        (
            page(&[
                output_json(&commit, 5, Some(&proof)),
                output_json(&commit, 5, Some(&proof)),
            ]),
            "mmr_index",
            FieldProblem::Duplicate,
        ),
        (
            page(&[
                output_json(&commit, 5, Some(&proof)),
                output_json(&commit, 6, Some(&proof)),
                output_json(&commit, 7, Some(&proof)),
            ]),
            "outputs",
            FieldProblem::TooMany,
        ),
        (
            page(&[output_json(&commit, 5, None)]),
            "proof",
            FieldProblem::Missing,
        ),
    ];
    for (body, field, expected) in cases {
        let server = TestServer::start(move |_| Reply::json(body.clone())).await;
        let error = client(&server)
            .get_unspent_outputs(2, Some(20), 2)
            .await
            .unwrap_err();
        assert_eq!(assert_invalid_field(error, field), expected, "{field}");
    }

    for bad_proof in [
        proof[..proof.len() - 2].to_owned(),
        format!("{proof}00"),
        "zz".repeat(675),
    ] {
        let body = page(&[output_json(&commit, 5, Some(&bad_proof))]);
        let server = TestServer::start(move |_| Reply::json(body.clone())).await;
        let error = client(&server)
            .get_unspent_outputs(2, Some(20), 2)
            .await
            .unwrap_err();
        assert!(matches!(
            assert_invalid_field(error, "proof"),
            FieldProblem::Crypto(_)
        ));
    }
}

#[cfg(test)]
fn kernel_json(excess: &str, sig: &str, height: u64) -> Value {
    json!({
        "tx_kernel": {"features": {"Plain": {"fee": 800000}}, "excess": excess, "excess_sig": sig},
        "height": height,
        "mmr_index": 7
    })
}

#[tokio::test]
async fn finds_validates_and_misses_kernels() {
    let (_, expected) = valid_transaction();
    let excess_hex = expected["kernels"][0]["excess"]
        .as_str()
        .unwrap()
        .to_owned();
    let sig = expected["kernels"][0]["excess_sig"]
        .as_str()
        .unwrap()
        .to_owned();
    let excess = Commitment::from_hex(&excess_hex).unwrap();

    let body = ok_body(&kernel_json(&excess_hex, &sig, 10));
    let server = TestServer::start(move |_| Reply::json(body.clone())).await;
    let located = client(&server)
        .get_kernel(&excess, Some(Height::new(5)), Some(Height::new(15)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(located.kernel.excess, excess);
    assert_eq!(located.kernel.excess_sig.to_compact_hex(), sig);
    assert_eq!(located.height, Height::new(10));
    assert_eq!(
        server.received()[0].json()["params"],
        json!([excess_hex, 5, 15])
    );

    let other = listed_commitments()[0];
    let error = client(&server)
        .get_kernel(&other, None, None)
        .await
        .unwrap_err();
    assert_eq!(
        assert_invalid_field(error, "excess"),
        FieldProblem::NotRequested
    );

    let error = client(&server)
        .get_kernel(&excess, Some(Height::new(11)), None)
        .await
        .unwrap_err();
    assert_eq!(
        assert_invalid_field(error, "height"),
        FieldProblem::OutOfRange
    );

    let body = ok_body(&kernel_json(&excess_hex, &"00".repeat(10), 10));
    let server = TestServer::start(move |_| Reply::json(body.clone())).await;
    let error = client(&server)
        .get_kernel(&excess, None, None)
        .await
        .unwrap_err();
    assert!(matches!(
        assert_invalid_field(error, "excess_sig"),
        FieldProblem::Crypto(_)
    ));

    let not_found = br#"{"id":1,"jsonrpc":"2.0","result":{"Err":"NotFound"}}"#;
    let server = TestServer::start(move |_| Reply::json(not_found.to_vec())).await;
    assert_eq!(
        client(&server)
            .get_kernel(&excess, None, None)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn reports_node_error_objects() {
    let internal = br#"{"id":1,"jsonrpc":"2.0","result":{"Err":{"Internal":"pool full"}}}"#;
    let server = TestServer::start(move |_| Reply::json(internal.to_vec())).await;
    let error = client(&server).get_tip().await.unwrap_err();
    let NodeError::Rejected { rejection, .. } = error else {
        panic!("{error:?}");
    };
    assert_eq!(rejection.kind, RejectionKind::Internal);
    assert_eq!(rejection.message.as_deref(), Some("pool full"));

    let unknown = br#"{"id":1,"jsonrpc":"2.0","result":{"Err":[1,2]}}"#;
    let server = TestServer::start(move |_| Reply::json(unknown.to_vec())).await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(matches!(
        error,
        NodeError::Rejected { ref rejection, .. } if rejection.kind == RejectionKind::Unknown
    ));

    let rpc = br#"{"id":1,"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"}}"#;
    let server = TestServer::start(move |_| Reply::json(rpc.to_vec())).await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(
        matches!(error, NodeError::Rpc { code: -32602, .. }),
        "{error:?}"
    );
    assert_eq!(server.received().len(), 1, "a node answer is not retried");
}

#[tokio::test]
async fn caps_declared_and_streamed_body_size() {
    let server = TestServer::start(|_| Reply::Declared { declared: 1 << 40 }).await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(
        matches!(error, NodeError::ResponseTooLarge { limit: 65536 }),
        "{error:?}"
    );

    let server = TestServer::start(|_| Reply::Chunked {
        chunk_len: 16 * 1024,
        chunks: 1024,
    })
    .await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(
        matches!(error, NodeError::ResponseTooLarge { .. }),
        "{error:?}"
    );
    assert_eq!(
        server.received().len(),
        1,
        "an oversized answer is not retried"
    );
}

#[tokio::test]
async fn times_out_on_stalled_and_dripping_responses() {
    let quick = HttpSettings {
        request_timeout: Duration::from_millis(200),
        ..settings()
    };
    let policy = CallPolicy {
        retry: RetryPolicy::NONE,
        ..CallPolicy::default()
    };

    let server = TestServer::start(|_| Reply::Stall).await;
    let error = client_with(&server.url(), &quick, policy)
        .get_tip()
        .await
        .unwrap_err();
    assert!(matches!(error, NodeError::Timeout), "{error:?}");

    let server = TestServer::start(|_| Reply::Drip {
        body: ok_body(&json!({"height": 1, "last_block_pushed": "00".repeat(32)})),
        interval: Duration::from_millis(50),
    })
    .await;
    let error = client_with(&server.url(), &quick, policy)
        .get_tip()
        .await
        .unwrap_err();
    assert!(matches!(error, NodeError::Timeout), "{error:?}");
}

#[tokio::test]
async fn retries_transient_failures_of_reads_only() {
    let server = TestServer::start(|_| Reply::Body {
        status: 503,
        body: Vec::new(),
    })
    .await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(
        matches!(error, NodeError::HttpStatus { status: 503 }),
        "{error:?}"
    );
    assert_eq!(server.received().len(), 3);

    let (transaction, _) = valid_transaction();
    let server = TestServer::start(|_| Reply::Body {
        status: 503,
        body: Vec::new(),
    })
    .await;
    let error = client(&server)
        .push_transaction(&transaction, Propagation::Fluff)
        .await
        .unwrap_err();
    assert!(
        matches!(error, NodeError::HttpStatus { status: 503 }),
        "{error:?}"
    );
    assert_eq!(server.received().len(), 1);

    let server = TestServer::start(|_| Reply::Hangup).await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(matches!(error, NodeError::Request(_)), "{error:?}");
    assert_eq!(server.received().len(), 3);

    let recovered = std::sync::atomic::AtomicUsize::new(0);
    let tip = ok_body(&json!({"height": 4, "last_block_pushed": "11".repeat(32)}));
    let server = TestServer::start(move |_| {
        if recovered.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Reply::Hangup
        } else {
            Reply::json(tip.clone())
        }
    })
    .await;
    assert_eq!(
        client(&server).get_tip().await.unwrap().height,
        Height::new(4)
    );
    assert_eq!(server.received().len(), 2);
}

#[tokio::test]
async fn reports_unauthorized_without_retrying() {
    let server = TestServer::start(|_| Reply::Body {
        status: 401,
        body: b"Unauthorized".to_vec(),
    })
    .await;
    let error = client(&server).get_tip().await.unwrap_err();
    assert!(matches!(error, NodeError::Unauthorized), "{error:?}");
    assert_eq!(server.received().len(), 1);
}

#[tokio::test]
async fn reports_refused_connections() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let error = client_with(
        &url,
        &settings(),
        CallPolicy {
            retry: QUICK_RETRY,
            ..CallPolicy::default()
        },
    )
    .get_tip()
    .await
    .unwrap_err();
    assert!(matches!(error, NodeError::Connect(_)), "{error:?}");
    assert!(error.is_transient());
}

#[tokio::test]
async fn splits_output_queries_and_caps_concurrency() {
    let server = TestServer::start_with_delay(Duration::from_millis(30), |_| {
        Reply::json(ok_body(&json!([])))
    })
    .await;
    let commitments = listed_commitments();
    assert!(commitments.len() >= 9);
    let client = client_with(
        &server.url(),
        &settings(),
        CallPolicy {
            retry: RetryPolicy::NONE,
            outputs_per_request: 2,
            max_concurrent_requests: 2,
        },
    );
    let mut asked = commitments[..9].to_vec();
    asked.push(commitments[0]);
    assert!(client.get_outputs(&asked).await.unwrap().is_empty());

    let received = server.received();
    assert_eq!(received.len(), 5);
    let mut sent: Vec<String> = received
        .iter()
        .flat_map(|request| {
            let params = request.json()["params"].clone();
            assert_eq!(
                params.as_array().unwrap()[1..],
                [json!(null), json!(null), json!(false), json!(false)]
            );
            params[0].as_array().unwrap().clone()
        })
        .map(|commit| commit.as_str().unwrap().to_owned())
        .collect();
    sent.sort();
    let mut expected: Vec<String> = commitments[..9].iter().map(Commitment::to_hex).collect();
    expected.sort();
    assert_eq!(sent, expected);
    assert!(server.max_in_flight() <= 2, "{}", server.max_in_flight());
}

#[test]
fn rejects_bad_node_urls_before_any_io() {
    let tls = webpki_tls_config().unwrap();
    for url in [
        "",
        "localhost:3413",
        "ftp://node",
        "https://user:pw@node",
        "https://node/?q",
    ] {
        assert!(
            matches!(
                HttpTransport::new(url, &settings(), tls.clone()),
                Err(NodeError::InvalidUrl)
            ),
            "{url}"
        );
    }
}
