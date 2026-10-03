//! The upstream in-process test chain behind a loopback HTTP server that speaks the node's foreign
//! JSON-RPC API. Both wallets reach the chain through it: upstream with its `HTTPNodeClient`,
//! LEPIC with its `HttpTransport`. Reads go to the node's own `epic_api::Foreign` handlers.
//! Pushed transactions are checked as the node's pool checks them and wait until the next block.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;

use epic_api::{Foreign, Status};
use epic_chain::Chain;
use epic_chain::types::NoopAdapter;
use epic_core::consensus;
use epic_core::core::hash::Hash;
use epic_core::core::transaction::Weighting;
use epic_core::core::{BlockHeader, BlockSums, Output, Transaction, TxKernel};
use epic_core::global::{self, ChainTypes};
use epic_core::pow;
use epic_pool::{BlockChain, PoolError};
use epic_util::Mutex;
use epic_wallet_impls::test_framework;
use serde_json::{Value, json};

const MAX_BODY: usize = 1 << 22;
const FOREIGN: &str = "/v2/foreign";
const OWNER: &str = "/v2/owner";

/// Upstream reads chain parameters from process-wide settings. Every test sets the same values.
pub fn use_test_chain_settings(scratch: &Path) {
    global::set_mining_mode(ChainTypes::AutomatedTesting);
    // A path that does not exist makes upstream use its embedded foundation outputs.
    global::set_foundation_path(
        scratch
            .join("no-foundation-file.json")
            .to_string_lossy()
            .into_owned(),
    );
}

struct State {
    chain: Arc<Chain>,
    pool: Vec<Transaction>,
}

pub struct TestNode {
    url: String,
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TestNode {
    pub fn start(dir: &Path) -> TestNode {
        let genesis = pow::mine_genesis_block().unwrap();
        let chain = Chain::init(
            dir.join(".epic").to_string_lossy().into_owned(),
            Arc::new(NoopAdapter {}),
            genesis,
            pow::verify_size,
            false,
        )
        .unwrap();
        let state = Arc::new(Mutex::new(State {
            chain: Arc::new(chain),
            pool: Vec::new(),
        }));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let state = state.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        // A broken connection fails only that request; the wallet reports it.
                        let _ignored = serve(stream, &state);
                    }
                }
            })
        };
        TestNode {
            url: format!("http://{addr}"),
            addr,
            state,
            stop,
            thread: Some(thread),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn height(&self) -> u64 {
        self.state.lock().chain.head().unwrap().height
    }

    pub fn pool_len(&self) -> usize {
        self.state.lock().pool.len()
    }

    /// Mines one block holding every pooled transaction, with the given reward, and empties the
    /// pool. Returns the mined transactions.
    pub fn mine(&self, reward: (Output, TxKernel)) -> Vec<Transaction> {
        let mut state = self.state.lock();
        let txs = std::mem::take(&mut state.pool);
        let refs: Vec<&Transaction> = txs.iter().collect();
        test_framework::add_block_with_reward(&state.chain, refs, reward.0, reward.1);
        txs
    }

    pub fn total_fees(&self) -> u64 {
        self.state.lock().pool.iter().map(Transaction::fee).sum()
    }

    pub fn next_height(&self) -> u64 {
        self.height() + 1
    }

    /// The height the kernel with this excess was mined at, if it was.
    pub fn kernel_height(&self, excess: &epic_util::secp::pedersen::Commitment) -> Option<u64> {
        let state = self.state.lock();
        state
            .chain
            .get_kernel_height(excess, None, None)
            .unwrap()
            .map(|(_, height, _)| height)
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the accept loop so it sees the stop flag.
        let _ignored = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ignored = thread.join();
        }
    }
}

fn serve(stream: TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
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
        Ok(request) => answer(state, &endpoint, &request),
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

fn answer(state: &Mutex<State>, endpoint: &str, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let mut state = state.lock();
    let result = match (endpoint, method) {
        (FOREIGN, "push_transaction") => push_transaction(&mut state, &params),
        (FOREIGN, _) => dispatch_foreign(&state.chain, method, &params),
        (OWNER, "get_status") => Dispatch::Result(owner_status(&state.chain)),
        _ => Dispatch::MethodNotFound,
    };
    match result {
        Dispatch::Result(result) => json!({ "id": id, "jsonrpc": "2.0", "result": result }),
        Dispatch::MethodNotFound => rpc_error(&id, -32601, "Method not found"),
        Dispatch::InvalidParams => rpc_error(&id, -32602, "Invalid params"),
    }
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "id": id, "jsonrpc": "2.0", "error": { "code": code, "message": message } })
}

enum Dispatch {
    Result(Value),
    MethodNotFound,
    InvalidParams,
}

/// The checks the node's pool makes before it accepts a transaction: the transaction validates
/// on its own, its inputs are unspent, coinbase inputs are mature and lock heights are reached.
/// An accepted transaction is answered as `Ok`, a refused one as the handler's `Err`.
fn push_transaction(state: &mut State, params: &Value) -> Dispatch {
    let Some(tx) = params
        .get(0)
        .and_then(|tx| serde_json::from_value::<Transaction>(tx.clone()).ok())
    else {
        return Dispatch::InvalidParams;
    };
    if state
        .pool
        .iter()
        .any(|pooled| pooled.kernels() == tx.kernels())
    {
        return Dispatch::Result(json!({ "Ok": null }));
    }
    let checked = tx
        .validate(Weighting::AsTransaction)
        .map_err(|e| e.to_string())
        .and_then(|()| state.chain.validate_tx(&tx).map_err(|e| e.to_string()))
        .and_then(|()| {
            state
                .chain
                .verify_coinbase_maturity(&tx)
                .map_err(|e| e.to_string())
        })
        .and_then(|()| {
            state
                .chain
                .verify_tx_lock_height(&tx)
                .map_err(|e| e.to_string())
        });
    match checked {
        Ok(()) => {
            state.pool.push(tx);
            Dispatch::Result(json!({ "Ok": null }))
        }
        Err(reason) => Dispatch::Result(json!({ "Err": { "Internal": reason } })),
    }
}

/// The owner API's `get_status` for a node with no peers that is not syncing, built the way the
/// node's status handler builds it. Upstream wallets refresh only when `sync_status` is
/// `no_sync`.
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

/// Calls the node's API handler the way its JSON-RPC layer does: positional parameters, and the
/// handler's `Result` serialized as `{"Ok": ..}` or `{"Err": ..}`.
fn dispatch_foreign(chain: &Arc<Chain>, method: &str, params: &Value) -> Dispatch {
    let foreign: Foreign<NoPoolChain, epic_pool::types::NoopAdapter> =
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

/// Names the pool's chain type for `Foreign`. The handlers the server calls need no pool.
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
