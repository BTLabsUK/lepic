//! A loopback HTTP server that speaks the node's foreign JSON-RPC API, so upstream wallets talk to
//! the in-process test chain through upstream's own `HTTPNodeClient`.
//!
//! Live mode answers from the chain through the node's own `epic_api::Foreign` handlers and can
//! record every exchange. Replay mode answers only from recorded exchanges, which is the check
//! that a recording is complete enough for `MockNode` to replay.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;

use epic_api::{Foreign, Status};
use epic_chain::Chain;
use epic_core::consensus;
use epic_core::core::{BlockHeader, BlockSums, Transaction, hash::Hash};
use epic_pool::types::NoopAdapter;
use epic_pool::{BlockChain, PoolError};
use epic_util::Mutex;
use serde::Serialize;
use serde_json::{Value, json};

/// Largest request body the server reads. Wallet requests are a few kilobytes.
const MAX_BODY: usize = 1 << 20;

/// One JSON-RPC call as the wallet sent it and the node answered it.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub(crate) struct Exchange {
    pub(crate) endpoint: String,
    pub(crate) method: String,
    pub(crate) params: Value,
    pub(crate) response: Value,
    /// The generator built this answer instead of a node handler serving it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) built: bool,
}

pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}

/// What a replay session left over: recorded exchanges nobody asked for, and requests that had no
/// recorded answer.
#[derive(Debug, Default)]
pub(crate) struct ReplayReport {
    pub(crate) unused: usize,
    pub(crate) unexpected: Vec<String>,
}

enum Backend {
    Live {
        chain: Arc<Chain>,
        recording: Option<Vec<Exchange>>,
    },
    Replay {
        exchanges: Vec<Exchange>,
        used: Vec<bool>,
        unexpected: Vec<String>,
    },
}

pub(crate) struct NodeServer {
    url: String,
    addr: SocketAddr,
    backend: Arc<Mutex<Backend>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl NodeServer {
    pub(crate) fn live(chain: Arc<Chain>) -> std::io::Result<NodeServer> {
        NodeServer::start(Backend::Live {
            chain,
            recording: None,
        })
    }

    pub(crate) fn replay(exchanges: Vec<Exchange>) -> std::io::Result<NodeServer> {
        let used = vec![false; exchanges.len()];
        NodeServer::start(Backend::Replay {
            exchanges,
            used,
            unexpected: Vec::new(),
        })
    }

    fn start(backend: Backend) -> std::io::Result<NodeServer> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let backend = Arc::new(Mutex::new(backend));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let backend = backend.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        // A broken connection only fails that request; the wallet reports it.
                        let _ignored = serve(stream, &backend);
                    }
                }
            })
        };
        Ok(NodeServer {
            url: format!("http://{addr}"),
            addr,
            backend,
            stop,
            thread: Some(thread),
        })
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Answers from `next` from now on, so the wallet sees the node's tip move to `next`'s head.
    pub(crate) fn serve(&self, next: Arc<Chain>) {
        if let Backend::Live { chain, .. } = &mut *self.backend.lock() {
            *chain = next;
        }
    }

    pub(crate) fn start_recording(&self) {
        if let Backend::Live { recording, .. } = &mut *self.backend.lock() {
            *recording = Some(Vec::new());
        }
    }

    pub(crate) fn stop_recording(&self) -> Vec<Exchange> {
        match &mut *self.backend.lock() {
            Backend::Live { recording, .. } => recording.take().unwrap_or_default(),
            Backend::Replay { .. } => Vec::new(),
        }
    }

    pub(crate) fn replay_report(&self) -> ReplayReport {
        match &*self.backend.lock() {
            Backend::Replay {
                used, unexpected, ..
            } => ReplayReport {
                unused: used.iter().filter(|u| !**u).count(),
                unexpected: unexpected.clone(),
            },
            Backend::Live { .. } => ReplayReport::default(),
        }
    }
}

impl Drop for NodeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the accept loop so it sees the stop flag.
        let _ignored = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ignored = thread.join();
        }
    }
}

fn serve(stream: TcpStream, backend: &Mutex<Backend>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut content_length = 0usize;
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    // "POST /v2/foreign HTTP/1.1"
    let endpoint = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length.min(MAX_BODY)];
    reader.read_exact(&mut body)?;
    let reply = match serde_json::from_slice::<Value>(&body) {
        Ok(request) => answer(backend, &endpoint, &request),
        Err(_) => rpc_error(&Value::Null, -32700, "Parse error"),
    };
    let reply = serde_json::to_vec(&reply).unwrap_or_default();
    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.len()
    )?;
    stream.write_all(&reply)?;
    stream.flush()
}

fn answer(backend: &Mutex<Backend>, endpoint: &str, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let params = normalized_params(&method, request.get("params").unwrap_or(&Value::Null));
    match &mut *backend.lock() {
        Backend::Live { chain, recording } => {
            let built = is_built(endpoint, &method);
            let response = match dispatch(chain, endpoint, &method, &params) {
                Dispatch::Result(result) => {
                    json!({ "id": id, "jsonrpc": "2.0", "result": result })
                }
                Dispatch::MethodNotFound => rpc_error(&id, -32601, "Method not found"),
                Dispatch::InvalidParams => rpc_error(&id, -32602, "Invalid params"),
            };
            if let Some(recording) = recording {
                recording.push(Exchange {
                    endpoint: endpoint.to_owned(),
                    method,
                    params,
                    response: response.clone(),
                    built,
                });
            }
            response
        }
        Backend::Replay {
            exchanges,
            used,
            unexpected,
        } => {
            let hit = exchanges.iter().zip(used.iter_mut()).find(|(e, u)| {
                !**u && e.endpoint == endpoint && e.method == method && e.params == params
            });
            match hit {
                Some((exchange, used)) => {
                    *used = true;
                    let mut response = exchange.response.clone();
                    if let Some(object) = response.as_object_mut() {
                        object.insert("id".to_owned(), id);
                    }
                    response
                }
                None => {
                    unexpected.push(format!("{endpoint} {method} {params}"));
                    rpc_error(&id, -32000, "no recorded response")
                }
            }
        }
    }
}

/// `get_outputs` carries commitments in the order upstream's hash map yields them, which changes
/// from run to run. Sorting them makes recordings reproducible. The node answers in request
/// order, so its response is sorted the same way, and upstream reads it into a map.
fn normalized_params(method: &str, params: &Value) -> Value {
    let mut params = params.clone();
    if method == "get_outputs"
        && let Some(commits) = params.get_mut(0).and_then(Value::as_array_mut)
    {
        commits.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    params
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "id": id, "jsonrpc": "2.0", "error": { "code": code, "message": message } })
}

enum Dispatch {
    Result(Value),
    MethodNotFound,
    InvalidParams,
}

/// Calls the node's API handler the way its JSON-RPC layer does: positional parameters, and the
/// handler's `Result` serialized as `{"Ok": ..}` or `{"Err": ..}`.
fn dispatch(chain: &Arc<Chain>, endpoint: &str, method: &str, params: &Value) -> Dispatch {
    match endpoint {
        FOREIGN => dispatch_foreign(chain, method, params),
        OWNER if method == "get_status" => Dispatch::Result(owner_status(chain)),
        _ => Dispatch::MethodNotFound,
    }
}

fn is_built(endpoint: &str, method: &str) -> bool {
    endpoint == OWNER && method == "get_status"
}

const FOREIGN: &str = "/v2/foreign";
const OWNER: &str = "/v2/owner";

/// The owner API's `get_status`, built the way the node's status handler builds it, for a node
/// with no peers that is not syncing. The real handler needs a peer set, which an in-process
/// chain does not have; upstream wallets refresh only when `sync_status` is `no_sync`.
fn owner_status(chain: &Arc<Chain>) -> Value {
    let status = chain.head().map(|head| {
        let height = head.height;
        Status::from_tip_and_peers(
            head,
            0,
            "no_sync".to_owned(),
            None,
            consensus::fast_total_supply(height) / consensus::EPIC_BASE,
            21_000_000,
            consensus::blocks_to_next_halving(height),
        )
    });
    let result: Result<Status, epic_api::Error> =
        status.map_err(|e| epic_api::Error::Internal(format!("can't get head: {e}")));
    serde_json::to_value(result).unwrap_or(Value::Null)
}

fn dispatch_foreign(chain: &Arc<Chain>, method: &str, params: &Value) -> Dispatch {
    let foreign: Foreign<NoPoolChain, NoopAdapter> =
        Foreign::new(Arc::downgrade(chain), Weak::new(), Weak::new());
    let result = match method {
        "get_version" => serde_json::to_value(foreign.get_version()),
        "get_tip" => serde_json::to_value(foreign.get_tip()),
        "get_kernel" => match parse::<(String, Option<u64>, Option<u64>)>(params) {
            Some((excess, min, max)) => serde_json::to_value(foreign.get_kernel(excess, min, max)),
            None => return Dispatch::InvalidParams,
        },
        "get_outputs" => match parse::<(
            Option<Vec<String>>,
            Option<u64>,
            Option<u64>,
            Option<bool>,
            Option<bool>,
        )>(params)
        {
            Some((commits, start, end, proof, merkle)) => {
                serde_json::to_value(foreign.get_outputs(commits, start, end, proof, merkle))
            }
            None => return Dispatch::InvalidParams,
        },
        "get_unspent_outputs" => match parse::<(u64, Option<u64>, u64, Option<bool>)>(params) {
            Some((start, end, max, proof)) => {
                serde_json::to_value(foreign.get_unspent_outputs(start, end, max, proof))
            }
            None => return Dispatch::InvalidParams,
        },
        "get_pmmr_indices" => match parse::<(u64, Option<u64>)>(params) {
            Some((start, end)) => serde_json::to_value(foreign.get_pmmr_indices(start, end)),
            None => return Dispatch::InvalidParams,
        },
        _ => return Dispatch::MethodNotFound,
    };
    match result {
        Ok(value) => Dispatch::Result(value),
        Err(_) => Dispatch::InvalidParams,
    }
}

fn parse<T: serde::de::DeserializeOwned>(params: &Value) -> Option<T> {
    serde_json::from_value(params.clone()).ok()
}

/// Names the transaction pool's chain type for `Foreign`. The pool is never created, because the
/// wallet calls the server makes need no pool.
struct NoPoolChain;

impl BlockChain for NoPoolChain {
    fn verify_coinbase_maturity(&self, _tx: &Transaction) -> Result<(), PoolError> {
        Err(PoolError::Other("no pool".to_owned()))
    }
    fn verify_tx_lock_height(&self, _tx: &Transaction) -> Result<(), PoolError> {
        Err(PoolError::Other("no pool".to_owned()))
    }
    fn validate_tx(&self, _tx: &Transaction) -> Result<(), PoolError> {
        Err(PoolError::Other("no pool".to_owned()))
    }
    fn chain_head(&self) -> Result<BlockHeader, PoolError> {
        Err(PoolError::Other("no pool".to_owned()))
    }
    fn get_block_header(&self, _hash: &Hash) -> Result<BlockHeader, PoolError> {
        Err(PoolError::Other("no pool".to_owned()))
    }
    fn get_block_sums(&self, _hash: &Hash) -> Result<BlockSums, PoolError> {
        Err(PoolError::Other("no pool".to_owned()))
    }
}
