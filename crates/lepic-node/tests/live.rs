// SPDX-License-Identifier: Apache-2.0
//! Opt-in live reads against a public floonet node (docs/rules.md), which also records the
//! fixtures under `testdata/node/`.
//!
//! Runs only with `LEPIC_LIVE_TESTS=1` and `LEPIC_TEST_NODE_URL` set; otherwise it passes
//! without touching the network. With `LEPIC_RECORD_NODE_FIXTURES=1` it also rewrites
//! `testdata/node/floonet_reads.json`. It makes six read calls, over a few recent blocks only.
//! Never point it at mainnet.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use lepic_crypto::Commitment;
use lepic_node::{
    CallPolicy, HttpSettings, HttpTransport, NodeApi, NodeClient, NodeError, RetryPolicy,
    RpcTransport, webpki_tls_config,
};
use lepic_primitives::amount::Height;
use serde_json::{Value, json};

/// Keeps every exchange in the format of `testdata/vectors/README.md`.
#[derive(Clone)]
struct Recorder {
    inner: HttpTransport,
    exchanges: Arc<Mutex<Vec<Value>>>,
}

impl RpcTransport for Recorder {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        let response = self.inner.post(endpoint, body).await?;
        let recorded: Value = serde_json::from_slice(&response).unwrap_or(Value::Null);
        self.exchanges.lock().unwrap().push(json!({
            "endpoint": endpoint,
            "method": request.get("method"),
            "params": request.get("params"),
            "response": recorded,
        }));
        Ok(response)
    }

    fn node_label(&self) -> &str {
        self.inner.node_label()
    }
}

#[cfg(test)]
fn enabled() -> Option<String> {
    if std::env::var("LEPIC_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("live node test skipped: LEPIC_LIVE_TESTS is not 1");
        return None;
    }
    Some(std::env::var("LEPIC_TEST_NODE_URL").expect("LEPIC_TEST_NODE_URL"))
}

/// A valid commitment that no floonet output or kernel has: an output of the G-05 test chain.
#[cfg(test)]
fn foreign_commitment() -> Commitment {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/engine/restore_full_scan.json");
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let listing = vector["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|exchange| exchange["method"] == "get_unspent_outputs")
        .unwrap();
    let commit = listing["response"]["result"]["Ok"]["outputs"][0]["commit"]
        .as_str()
        .unwrap();
    Commitment::from_hex(commit).unwrap()
}

#[tokio::test]
async fn floonet_reads() {
    let Some(url) = enabled() else {
        return;
    };
    let transport =
        HttpTransport::new(&url, &HttpSettings::default(), webpki_tls_config().unwrap()).unwrap();
    let exchanges = Arc::new(Mutex::new(Vec::new()));
    let client = NodeClient::new(
        Recorder {
            inner: transport,
            exchanges: exchanges.clone(),
        },
        CallPolicy {
            retry: RetryPolicy::NONE,
            ..CallPolicy::default()
        },
    );

    let version = client.get_version().await.unwrap();
    let tip = client.get_tip().await.unwrap();
    assert!(tip.height.value() > 3);
    let start = Height::new(tip.height.value() - 2);
    let indices = client
        .get_pmmr_indices(start, Some(tip.height))
        .await
        .unwrap();
    assert!(indices.first_index <= indices.last_index);
    let page = client
        .get_unspent_outputs(indices.first_index, Some(indices.last_index), 100)
        .await
        .unwrap();
    assert_eq!(
        page.last_retrieved_index, page.highest_index,
        "window cut short"
    );

    let foreign = foreign_commitment();
    let mut asked: Vec<Commitment> = page.outputs.iter().take(2).map(|o| o.commitment).collect();
    asked.push(foreign);
    let found = client.get_outputs(&asked).await.unwrap();
    assert_eq!(found.len(), asked.len() - 1);
    assert!(found.iter().all(|location| location.commitment != foreign));

    let kernel = client
        .get_kernel(&foreign, Some(start), Some(tip.height))
        .await
        .unwrap();
    assert_eq!(kernel, None);

    if std::env::var("LEPIC_RECORD_NODE_FIXTURES").as_deref() == Ok("1") {
        let fixture = json!({
            "schema": 1,
            "description": "Read calls of the node client against a public floonet node, over the last three blocks.",
            "network": "floonet",
            "recorded_by": "crates/lepic-node/tests/live.rs",
            "node_version": version.node_version,
            "exchanges": *exchanges.lock().unwrap(),
        });
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/node/floonet_reads.json");
        let mut text = serde_json::to_string_pretty(&fixture).unwrap();
        text.push('\n');
        std::fs::write(path, text).unwrap();
    }
}
