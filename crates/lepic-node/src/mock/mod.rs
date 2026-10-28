// SPDX-License-Identifier: Apache-2.0
//! An in-memory node for tests of the engine, the CLI and the bindings.
//!
//! [`MockNode`] answers at the JSON-RPC level, so every answer passes through the same decoding
//! and validation as a real node's. It serves either a recorded session (the G-05 golden
//! vectors, or a fixture under `testdata/node/`) or a scripted [`ChainState`]. Requests it
//! cannot answer by its rules are failures of the test, collected in
//! [`MockNode::violations`] and answered with a JSON-RPC error.

mod chain;
mod recording;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lepic_primitives::tx::Transaction;
use serde::Deserialize;
use serde_json::{Value, json};

pub use chain::{ChainOutput, ChainState};
pub use recording::{FixtureError, Recording};

use crate::client::{CallPolicy, NodeClient, RetryPolicy, RpcTransport};
use crate::error::{NodeError, RejectionKind};
use crate::wire::WireTransaction;

/// JSON-RPC error code the mock answers a request with when it breaks the replay rules.
pub const VIOLATION_CODE: i64 = -32099;

/// A request the mock could not answer by its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub method: String,
    pub params: Value,
    pub reason: &'static str,
}

/// A failure the next call of a method gets instead of its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockFailure {
    /// The node could not be reached; a transient error the client may retry.
    Unreachable,
    /// The node's handler returned this error.
    Rejected(RejectionKind),
    /// The node's pool refused a pushed transaction it cannot validate against its chain, as
    /// Epic node 4.1 answers for inputs that are not unspent.
    PoolRefused,
}

#[derive(Debug)]
enum Source {
    Recording(Recording),
    Chain(ChainState),
}

#[derive(Debug)]
struct State {
    source: Source,
    calls: Vec<String>,
    violations: Vec<Violation>,
    pushed: Vec<Transaction>,
    failures: VecDeque<(String, MockFailure)>,
}

/// A mock node. Clones share one state, so a test keeps a handle while a client owns another.
#[derive(Debug, Clone)]
pub struct MockNode {
    state: Arc<Mutex<State>>,
}

enum Answer {
    Ok(Value),
    Rejected(Value),
    Response(Value),
    Violation(&'static str),
}

#[derive(Deserialize)]
struct IncomingRequest {
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Value,
}

impl MockNode {
    /// Serves a recorded session, following the LEPIC replay rules in
    /// `testdata/vectors/README.md`.
    pub fn from_recording(json: &str) -> Result<Self, FixtureError> {
        Ok(Self::with_source(Source::Recording(Recording::parse(
            json,
        )?)))
    }

    pub fn from_chain(chain: ChainState) -> Self {
        Self::with_source(Source::Chain(chain))
    }

    fn with_source(source: Source) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                source,
                calls: Vec::new(),
                violations: Vec::new(),
                pushed: Vec::new(),
                failures: VecDeque::new(),
            })),
        }
    }

    /// A client for this node that does not retry or pause between calls.
    pub fn client(&self) -> NodeClient<Self> {
        NodeClient::new(
            self.clone(),
            CallPolicy {
                retry: RetryPolicy::NONE,
                ..CallPolicy::default()
            },
        )
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next call of `method` fails this way. Several queued failures apply in order.
    pub fn fail_next(&self, method: &str, failure: MockFailure) {
        self.lock().failures.push_back((method.to_owned(), failure));
    }

    /// Changes the scripted chain. Has no effect on a recorded session and returns false then.
    pub fn update_chain(&self, change: impl FnOnce(&mut ChainState)) -> bool {
        match &mut self.lock().source {
            Source::Chain(chain) => {
                change(chain);
                true
            }
            Source::Recording(_) => false,
        }
    }

    /// Methods called so far, in order, including failed calls.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    /// Requests that broke the replay rules. A passing test leaves this empty.
    pub fn violations(&self) -> Vec<Violation> {
        self.lock().violations.clone()
    }

    /// Transactions accepted by `push_transaction`, in order.
    pub fn pushed_transactions(&self) -> Vec<Transaction> {
        self.lock().pushed.clone()
    }

    fn respond(&self, body: &[u8]) -> Result<Vec<u8>, NodeError> {
        let mut state = self.lock();
        let request: IncomingRequest = match serde_json::from_slice(body) {
            Ok(request) => request,
            Err(_) => {
                state.violations.push(Violation {
                    method: String::new(),
                    params: Value::Null,
                    reason: "request is not json-rpc",
                });
                return Ok(error_response(&Value::Null, VIOLATION_CODE));
            }
        };
        state.calls.push(request.method.clone());
        if let Some(position) = state
            .failures
            .iter()
            .position(|(method, _)| *method == request.method)
            && let Some((_, failure)) = state.failures.remove(position)
        {
            return match failure {
                MockFailure::Unreachable => Err(NodeError::Connect(Box::new(
                    std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                ))),
                MockFailure::Rejected(kind) => {
                    Ok(rejected_response(&request.id, &rejection_value(kind)))
                }
                MockFailure::PoolRefused => Ok(rejected_response(
                    &request.id,
                    &json!({"Internal": "Failed to update pool: General pool error: failed to validate tx"}),
                )),
            };
        }
        let answer = match request.method.as_str() {
            "push_transaction" => state.push(&request.params),
            _ => match &state.source {
                Source::Recording(recording) => recording.answer(&request.method, &request.params),
                Source::Chain(chain) => chain.answer(&request.method, &request.params),
            },
        };
        let response = match answer {
            Answer::Ok(value) => ok_response(&request.id, &value),
            Answer::Rejected(error) => rejected_response(&request.id, &error),
            Answer::Response(mut response) => {
                if let Some(object) = response.as_object_mut() {
                    object.insert("id".to_owned(), request.id.clone());
                }
                serde_json::to_vec(&response).unwrap_or_default()
            }
            Answer::Violation(reason) => {
                state.violations.push(Violation {
                    method: request.method.clone(),
                    params: request.params.clone(),
                    reason,
                });
                error_response(&request.id, VIOLATION_CODE)
            }
        };
        Ok(response)
    }
}

impl State {
    fn push(&mut self, params: &Value) -> Answer {
        if let Source::Recording(recording) = &self.source {
            return recording.answer("push_transaction", params);
        }
        let Some(raw) = params.get(0).cloned() else {
            return Answer::Violation("push_transaction without a transaction");
        };
        let Some(transaction) = serde_json::from_value::<WireTransaction>(raw)
            .ok()
            .and_then(WireTransaction::into_transaction)
        else {
            return Answer::Violation("push_transaction with a transaction the node cannot read");
        };
        self.pushed.push(transaction);
        Answer::Ok(Value::Null)
    }
}

impl RpcTransport for MockNode {
    async fn post(&self, _endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        self.respond(&body)
    }

    fn node_label(&self) -> &str {
        "mock"
    }
}

fn rejection_value(kind: RejectionKind) -> Value {
    match kind {
        RejectionKind::NotFound => json!("NotFound"),
        RejectionKind::Internal => json!({"Internal": "mock failure"}),
        RejectionKind::Argument => json!({"Argument": "mock failure"}),
        RejectionKind::Request => json!({"RequestError": "mock failure"}),
        RejectionKind::Response => json!({"ResponseError": "mock failure"}),
        RejectionKind::Router => json!({"Router": {"source": "mock"}}),
        RejectionKind::Unknown => json!({"Unrecognised": "mock failure"}),
    }
}

fn ok_response(id: &Value, value: &Value) -> Vec<u8> {
    let response = json!({"id": id, "jsonrpc": "2.0", "result": {"Ok": value}});
    serde_json::to_vec(&response).unwrap_or_default()
}

fn rejected_response(id: &Value, error: &Value) -> Vec<u8> {
    let response = json!({"id": id, "jsonrpc": "2.0", "result": {"Err": error}});
    serde_json::to_vec(&response).unwrap_or_default()
}

fn error_response(id: &Value, code: i64) -> Vec<u8> {
    let response = json!({
        "id": id,
        "jsonrpc": "2.0",
        "error": {"code": code, "message": "request breaks the mock node's replay rules"},
    });
    serde_json::to_vec(&response).unwrap_or_default()
}
