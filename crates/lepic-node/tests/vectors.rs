//! The G-05 node recordings (`testdata/vectors/engine/{restore,refresh}_*.json`), replayed
//! through `MockNode` into the real client, so every recorded node answer passes LEPIC's
//! validation and the LEPIC replay rules serve the calls LEPIC's engine will make.

// Tests may unwrap and use plain arithmetic (docs/rules.md), including in helpers that clippy
// does not treat as test code.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use lepic_crypto::Commitment;
use lepic_node::mock::{MockNode, VIOLATION_CODE};
use lepic_node::{CallPolicy, NodeApi, NodeClient, NodeError, RetryPolicy};
use lepic_primitives::amount::Height;
use serde_json::Value;

const UPSTREAM_REPO: &str = "https://github.com/EpicCash/epic-wallet";
const UPSTREAM_COMMIT: &str = "845b3fcf4df12ed0139929c62157015447a9d063";

#[cfg(test)]
fn sessions() -> Vec<(String, String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/engine");
    let mut sessions: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            name.ends_with(".json")
                && (name.starts_with("restore_") || name.starts_with("refresh_"))
        })
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            let vector: Value = serde_json::from_str(&text).unwrap();
            let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
            assert_eq!(vector["schema"], 1, "{name}");
            assert_eq!(vector["area"], "engine", "{name}");
            assert_eq!(vector["name"], name.as_str());
            assert_eq!(vector["upstream"]["repo"], UPSTREAM_REPO, "{name}");
            assert_eq!(vector["upstream"]["commit"], UPSTREAM_COMMIT, "{name}");
            (name, text, vector)
        })
        .collect();
    sessions.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(sessions.len() >= 4, "expected the G-05 sessions in {dir:?}");
    sessions
}

#[cfg(test)]
fn exchanges<'a>(vector: &'a Value, method: &str) -> Vec<&'a Value> {
    vector["expected"]["exchanges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|exchange| exchange["method"] == method)
        .collect()
}

#[cfg(test)]
fn ok(exchange: &Value) -> &Value {
    &exchange["response"]["result"]["Ok"]
}

#[cfg(test)]
fn commitment(hex: &Value) -> Commitment {
    Commitment::from_hex(hex.as_str().unwrap()).unwrap()
}

#[cfg(test)]
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn recorded_tips_validate_and_replay() {
    for (name, text, vector) in sessions() {
        let node = MockNode::from_recording(&text).unwrap();
        let tip = block_on(node.client().get_tip()).unwrap();
        let recorded = ok(exchanges(&vector, "get_tip")[0]);
        assert_eq!(
            tip.height.value(),
            recorded["height"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            tip.last_block_pushed.to_hex(),
            recorded["last_block_pushed"].as_str().unwrap(),
            "{name}"
        );
        assert!(
            node.violations().is_empty(),
            "{name}: {:?}",
            node.violations()
        );
    }
}

#[test]
fn recorded_pmmr_indices_replay() {
    for (name, text, vector) in sessions() {
        let node = MockNode::from_recording(&text).unwrap();
        for exchange in exchanges(&vector, "get_pmmr_indices") {
            let start = Height::new(exchange["params"][0].as_u64().unwrap());
            let end = exchange["params"][1].as_u64().map(Height::new);
            let indices = block_on(node.client().get_pmmr_indices(start, end)).unwrap();
            let recorded = ok(exchange);
            assert_eq!(
                indices.first_index,
                recorded["last_retrieved_index"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                indices.last_index,
                recorded["highest_index"].as_u64().unwrap(),
                "{name}"
            );
        }
        assert!(
            node.violations().is_empty(),
            "{name}: {:?}",
            node.violations()
        );
    }
}

#[test]
fn recorded_unspent_listing_validates_whole_and_paged() {
    for (name, text, vector) in sessions() {
        // Upstream stopped this session before its scan, so it recorded no listing.
        if vector["expected"]["node_unreachable"] == true {
            assert!(
                exchanges(&vector, "get_unspent_outputs").is_empty(),
                "{name}"
            );
            continue;
        }
        let node = MockNode::from_recording(&text).unwrap();
        let client = node.client();
        let exchange = exchanges(&vector, "get_unspent_outputs")[0];
        let start = exchange["params"][0].as_u64().unwrap();
        let end = exchange["params"][1].as_u64().unwrap();
        let recorded: BTreeSet<Commitment> = ok(exchange)["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|output| output["spent"] == false)
            .map(|output| commitment(&output["commit"]))
            .collect();
        assert!(!recorded.is_empty(), "{name}");

        let whole = block_on(client.get_unspent_outputs(start, Some(end), 1000)).unwrap();
        assert_eq!(whole.highest_index, end, "{name}");
        assert_eq!(whole.last_retrieved_index, end, "{name}");
        let whole_set: BTreeSet<_> = whole.outputs.iter().map(|o| o.commitment).collect();
        assert_eq!(whole_set, recorded, "{name}");

        let mut paged = BTreeSet::new();
        let mut next = start;
        for _ in 0..100 {
            let page = block_on(client.get_unspent_outputs(next, Some(end), 2)).unwrap();
            assert!(page.outputs.len() <= 2, "{name}");
            paged.extend(page.outputs.iter().map(|o| o.commitment));
            if page.last_retrieved_index >= page.highest_index {
                break;
            }
            next = page.last_retrieved_index + 1;
        }
        assert_eq!(paged, recorded, "{name}");
        assert!(
            node.violations().is_empty(),
            "{name}: {:?}",
            node.violations()
        );
    }
}

#[test]
fn recorded_outputs_replay_in_any_chunking_and_order() {
    let mut sessions_with_outputs = 0;
    for (name, text, vector) in sessions() {
        let recorded = exchanges(&vector, "get_outputs");
        if recorded.is_empty() {
            continue;
        }
        sessions_with_outputs += 1;
        let mut requested: Vec<Commitment> = recorded
            .iter()
            .flat_map(|exchange| exchange["params"][0].as_array().unwrap().iter())
            .map(commitment)
            .collect();
        requested.reverse();
        let found: BTreeSet<Commitment> = recorded
            .iter()
            .flat_map(|exchange| ok(exchange).as_array().unwrap().iter())
            .map(|output| commitment(&output["commit"]))
            .collect();
        assert!(found.len() < requested.len() + 1, "{name}");

        let node = MockNode::from_recording(&text).unwrap();
        let client = NodeClient::new(
            node.clone(),
            CallPolicy {
                retry: RetryPolicy::NONE,
                outputs_per_request: 1,
                max_concurrent_requests: 2,
            },
        );
        let locations = block_on(client.get_outputs(&requested)).unwrap();
        let located: BTreeSet<_> = locations.iter().map(|l| l.commitment).collect();
        assert_eq!(located, found, "{name}");
        assert!(locations.iter().all(|l| l.height.value() > 0), "{name}");
        let output_calls = node
            .calls()
            .iter()
            .filter(|method| *method == "get_outputs")
            .count();
        assert_eq!(output_calls, requested.len(), "{name}");
        assert!(
            node.violations().is_empty(),
            "{name}: {:?}",
            node.violations()
        );
    }
    assert!(sessions_with_outputs >= 3);
}

#[test]
fn unrecorded_requests_are_violations() {
    let (name, text, vector) = sessions().remove(0);
    let node = MockNode::from_recording(&text).unwrap();
    let client = node.client();

    // A commitment from the listing that no get_outputs request recorded.
    let listing = ok(exchanges(&vector, "get_unspent_outputs")[0]);
    let asked: BTreeSet<Commitment> = exchanges(&vector, "get_outputs")
        .iter()
        .flat_map(|exchange| exchange["params"][0].as_array().unwrap().iter())
        .map(commitment)
        .collect();
    let stranger = listing["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|output| commitment(&output["commit"]))
        .find(|commit| !asked.contains(commit))
        .unwrap();
    let error = block_on(client.get_outputs(&[stranger])).unwrap_err();
    assert!(
        matches!(
            error,
            NodeError::Rpc {
                code: VIOLATION_CODE,
                ..
            }
        ),
        "{name}: {error:?}"
    );

    let highest = listing["highest_index"].as_u64().unwrap();
    let error = block_on(client.get_unspent_outputs(1, Some(highest + 1), 10)).unwrap_err();
    assert!(matches!(error, NodeError::Rpc { .. }), "{name}: {error:?}");

    let error = block_on(client.get_version()).unwrap_err();
    assert!(matches!(error, NodeError::Rpc { .. }), "{name}: {error:?}");

    let reasons: Vec<_> = node.violations().iter().map(|v| v.method.clone()).collect();
    assert_eq!(
        reasons,
        ["get_outputs", "get_unspent_outputs", "get_version"],
        "{name}"
    );
}
