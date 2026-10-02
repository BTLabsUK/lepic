//! The live fixtures under `testdata/node/`, replayed offline: through `MockNode`, and as raw
//! HTTP answers from a local server. Both paths must accept every recorded answer and agree.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

mod support;

use std::path::PathBuf;

use lepic_crypto::Commitment;
use lepic_node::mock::MockNode;
use lepic_node::{
    CallPolicy, HttpSettings, HttpTransport, NodeApi, NodeClient, RetryPolicy, webpki_tls_config,
};
use lepic_primitives::amount::Height;
use serde_json::Value;
use support::{Reply, TestServer};

#[cfg(test)]
fn fixtures() -> Vec<(String, String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/node");
    let mut fixtures: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            let fixture: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(fixture["schema"], 1);
            assert_eq!(fixture["network"], "floonet");
            let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
            (name, text, fixture)
        })
        .collect();
    fixtures.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!fixtures.is_empty(), "no fixtures in {dir:?}");
    fixtures
}

#[cfg(test)]
fn height(value: &Value) -> Option<Height> {
    value.as_u64().map(Height::new)
}

/// Repeats every recorded call through `client` and describes what each returned.
#[cfg(test)]
async fn replay<C: NodeApi>(client: &C, fixture: &Value) -> Vec<String> {
    let mut results = Vec::new();
    for exchange in fixture["exchanges"].as_array().unwrap() {
        let params = &exchange["params"];
        let result = match exchange["method"].as_str().unwrap() {
            "get_version" => format!("{:?}", client.get_version().await.unwrap()),
            "get_tip" => format!("{:?}", client.get_tip().await.unwrap()),
            "get_pmmr_indices" => format!(
                "{:?}",
                client
                    .get_pmmr_indices(height(&params[0]).unwrap(), height(&params[1]))
                    .await
                    .unwrap()
            ),
            "get_unspent_outputs" => {
                let page = client
                    .get_unspent_outputs(
                        params[0].as_u64().unwrap(),
                        params[1].as_u64(),
                        params[2].as_u64().unwrap(),
                    )
                    .await
                    .unwrap();
                let recorded = &exchange["response"]["result"]["Ok"]["outputs"];
                assert_eq!(page.outputs.len(), recorded.as_array().unwrap().len());
                format!("{page:?}")
            }
            "get_outputs" => {
                let commitments: Vec<Commitment> = params[0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|commit| Commitment::from_hex(commit.as_str().unwrap()).unwrap())
                    .collect();
                let mut found = client.get_outputs(&commitments).await.unwrap();
                found.sort_by_key(|location| location.commitment);
                let recorded = &exchange["response"]["result"]["Ok"];
                assert_eq!(found.len(), recorded.as_array().unwrap().len());
                format!("{found:?}")
            }
            "get_kernel" => {
                let excess = Commitment::from_hex(params[0].as_str().unwrap()).unwrap();
                let kernel = client
                    .get_kernel(&excess, height(&params[1]), height(&params[2]))
                    .await
                    .unwrap();
                format!("{kernel:?}")
            }
            other => panic!("fixture records unexpected method {other}"),
        };
        results.push(result);
    }
    results
}

#[tokio::test]
async fn fixtures_replay_through_the_mock_and_over_http() {
    for (name, text, fixture) in fixtures() {
        let node = MockNode::from_recording(&text).unwrap();
        let from_mock = replay(&node.client(), &fixture).await;
        assert!(
            node.violations().is_empty(),
            "{name}: {:?}",
            node.violations()
        );

        let exchanges = fixture["exchanges"].as_array().unwrap().clone();
        let server = TestServer::start(move |request| {
            let request = request.json();
            let exchange = exchanges
                .iter()
                .find(|exchange| {
                    exchange["method"] == request["method"]
                        && exchange["params"] == request["params"]
                })
                .unwrap();
            Reply::json(serde_json::to_vec(&exchange["response"]).unwrap())
        })
        .await;
        let transport = HttpTransport::new(
            &server.url(),
            &HttpSettings::default(),
            webpki_tls_config().unwrap(),
        )
        .unwrap();
        let client = NodeClient::new(
            transport,
            CallPolicy {
                retry: RetryPolicy::NONE,
                ..CallPolicy::default()
            },
        );
        let over_http = replay(&client, &fixture).await;
        assert_eq!(from_mock, over_http, "{name}");
        assert_eq!(
            server.received().len(),
            fixture["exchanges"].as_array().unwrap().len(),
            "{name}"
        );
    }
}
