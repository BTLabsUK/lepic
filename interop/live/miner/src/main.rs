// SPDX-License-Identifier: Apache-2.0
//! Mines floonet blocks through a public node's foreign API, with the coinbase built by an
//! epic-wallet foreign API, so no local node is needed.
//!
//! Each job follows the reference node's own stratum flow (`build_block` in the node's
//! `servers/src/mining/mine_block.rs`):
//!
//! 1. `get_block_template` gives the next height, the mineable transactions, the next block
//!    difficulty and the header fields the chain decides: RandomX seed, secondary scaling,
//!    policy and bottles.
//! 2. The wallet's `build_coinbase` builds the reward output and kernel for those fees and that
//!    height, exactly as it does for a node's stratum server.
//! 3. `finalize_block_template` returns the header with the transaction roots and MMR sizes the
//!    node computed for that body.
//! 4. The header takes the template's chain fields, and its total difficulty becomes the previous
//!    total plus the next block difficulty, as the stratum server sets it. The block is checked
//!    locally with the node's own validation before any hashing.
//! 5. A solution is submitted with `submit_block`, which validates the block in full.
//!
//! Hashing: every thread keeps its own light-mode RandomX state with the JIT compiler, through the
//! RandomX binding the node pins, and checks difficulty with the node's own code.
//!
//! Requests to the public node are at least `NODE_REQUEST_GAP` apart, and a 429 answer backs off
//! exponentially. The miner refuses foundation heights, whose block needs the foundation output
//! that only a node can add.
//!
//! Usage: `lepic-live-miner <node foreign API URL> <wallet foreign API URL> [threads]`.

use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, sleep};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use epic_core::consensus::is_foundation_height;
use epic_core::core::block_fees::BlockFees;
use epic_core::core::foundation::CbData;
use epic_core::core::{Block, BlockHeader, Output, Transaction, TxKernel};
use epic_core::global::{self, ChainTypes};
use epic_core::pow::{Difficulty, PoWType, Proof, ProofOfWork};
use randomx::{RxState, slow_hash};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// How long one job is hashed before a fresh template is fetched.
const JOB_TIME: Duration = Duration::from_secs(20);
/// Pause after a found block, so the chain and the wallets catch up and blocks stay spaced.
const BLOCK_PAUSE: Duration = Duration::from_secs(10);
/// Minimum time between two requests to the public node.
const NODE_REQUEST_GAP: Duration = Duration::from_secs(2);
const BACKOFF_START: Duration = Duration::from_secs(10);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// How often the hash rate is reported.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// `get_block_template`: the next block without its coinbase.
#[derive(Deserialize)]
struct Template {
    header: BlockHeader,
    transactions: Vec<Transaction>,
    height: u64,
    algorithm: String,
    block_difficulty: Difficulty,
}

/// `finalize_block_template`'s argument.
#[derive(Serialize)]
struct CoinbaseData<'a> {
    output: &'a Output,
    kernel: &'a TxKernel,
}

/// `finalize_block_template`: the header with the roots for the body with this coinbase.
#[derive(Deserialize)]
struct Finalized {
    header: BlockHeader,
    height: u64,
    transactions: Vec<Transaction>,
}

/// A JSON-RPC endpoint reached through curl, which handles TLS for the public node.
struct Rpc {
    url: String,
    gap: Duration,
    last: Option<Instant>,
    backoff: Duration,
}

impl Rpc {
    fn new(url: &str, gap: Duration) -> Self {
        Self {
            url: url.to_owned(),
            gap,
            last: None,
            backoff: BACKOFF_START,
        }
    }

    /// Calls a method and returns the `Ok` value of its result.
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        loop {
            if let Some(wait) = self
                .last
                .and_then(|last| self.gap.checked_sub(last.elapsed()))
            {
                sleep(wait);
            }
            self.last = Some(Instant::now());
            let (status, text) = self.post(&body.to_string())?;
            if status == 429 {
                eprintln!(
                    "miner: {method} rate limited, backing off {}s",
                    self.backoff.as_secs()
                );
                sleep(self.backoff);
                self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
                continue;
            }
            self.backoff = BACKOFF_START;
            if status != 200 {
                return Err(format!("{method}: HTTP {status}: {}", text.trim()).into());
            }
            let reply: Value = serde_json::from_str(&text)?;
            if let Some(error) = reply.get("error").filter(|error| !error.is_null()) {
                return Err(format!("{method} failed: {error}").into());
            }
            let result = reply.get("result").cloned().unwrap_or(Value::Null);
            if let Some(error) = result.get("Err") {
                return Err(format!("{method} failed: {error}").into());
            }
            return Ok(result.get("Ok").cloned().unwrap_or(result));
        }
    }

    fn post(&self, body: &str) -> Result<(u16, String)> {
        let mut child = Command::new("curl")
            .args(["-sS", "-m", "60", "-X", "POST"])
            .args(["-H", "content-type: application/json"])
            .args(["--data-binary", "@-", "-w", "\n%{http_code}"])
            .arg(&self.url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("curl has no stdin")?
            .write_all(body.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(format!("curl to {} failed: {}", self.url, output.status).into());
        }
        let text = String::from_utf8(output.stdout)?;
        let (reply, status) = text.rsplit_once('\n').ok_or("curl printed no status")?;
        Ok((status.trim().parse()?, reply.to_owned()))
    }
}

/// One block being hashed.
struct Job {
    height: u64,
    transactions: String,
    block: Block,
    /// The header's pre-PoW bytes without the trailing nonce.
    prefix: Vec<u8>,
    seed: [u8; 32],
    target: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(node_url), Some(wallet_url)) = (args.first(), args.get(1)) else {
        eprintln!(
            "usage: lepic-live-miner <node foreign API URL> <wallet foreign API URL> [threads]"
        );
        std::process::exit(2);
    };
    let threads = args
        .get(2)
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|threads| *threads > 0)
        .unwrap_or(1);

    global::set_mining_mode(ChainTypes::Floonet);
    let mut node = Rpc::new(node_url, NODE_REQUEST_GAP);
    let mut wallet = Rpc::new(wallet_url, Duration::ZERO);
    let mut states: Vec<RxState> = (0..threads)
        .map(|_| {
            let mut state = RxState::new();
            state.jit_compiler = true;
            state.hard_aes = true;
            state
        })
        .collect();
    eprintln!("miner: mining through {node_url} with {threads} threads");
    let mut job: Option<Job> = None;
    let mut hashes = 0u64;
    let mut since = Instant::now();
    loop {
        match step(&mut node, &mut wallet, &mut states, &mut job, &mut hashes) {
            Ok(true) => sleep(BLOCK_PAUSE),
            Ok(false) => {}
            Err(error) => {
                eprintln!("miner: {error}");
                job = None;
                sleep(Duration::from_secs(15));
            }
        }
        if since.elapsed() >= REPORT_EVERY {
            let rate = hashes as f64 / since.elapsed().as_secs_f64();
            eprintln!("miner: {rate:.0} H/s");
            hashes = 0;
            since = Instant::now();
        }
    }
}

/// Fetches the template, keeps or rebuilds the job, hashes one round and submits a solution.
/// Returns whether a block was accepted.
fn step(
    node: &mut Rpc,
    wallet: &mut Rpc,
    states: &mut [RxState],
    job: &mut Option<Job>,
    hashes: &mut u64,
) -> Result<bool> {
    let template: Template = serde_json::from_value(node.call("get_block_template", json!([]))?)?;
    let transactions = serde_json::to_string(&template.transactions)?;
    let current = job
        .as_ref()
        .is_some_and(|job| job.height == template.height && job.transactions == transactions);
    if !current {
        *job = Some(build_job(node, wallet, template, transactions)?);
    }
    let job_ref = job.as_ref().ok_or("no job")?;
    let (found, done) = solve(job_ref, states)?;
    *hashes += done;
    let Some((nonce, hash)) = found else {
        return Ok(false);
    };
    let mut block = job.take().ok_or("no job")?.block;
    block.header.pow.nonce = nonce;
    block.header.pow.proof = Proof::RandomXProof { hash };
    node.call("submit_block", json!([block]))?;
    eprintln!(
        "miner: block {} accepted ({} transactions)",
        block.header.height,
        block.kernels().len().saturating_sub(1)
    );
    Ok(true)
}

fn build_job(
    node: &mut Rpc,
    wallet: &mut Rpc,
    template: Template,
    transactions: String,
) -> Result<Job> {
    if template.algorithm != "randomx" {
        return Err(format!("node asks for {}, not randomx", template.algorithm).into());
    }
    if is_foundation_height(template.height) {
        return Err(format!("height {} needs a foundation output", template.height).into());
    }
    let fees = template.transactions.iter().map(Transaction::fee).sum();
    let block_fees = BlockFees {
        fees,
        height: template.height,
        key_id: None,
    };
    let coinbase: CbData = serde_json::from_value(
        wallet.call("build_coinbase", json!({ "block_fees": block_fees }))?,
    )?;
    let finalized: Finalized = serde_json::from_value(node.call(
        "finalize_block_template",
        json!([CoinbaseData {
            output: &coinbase.output,
            kernel: &coinbase.kernel,
        }]),
    )?)?;
    if finalized.height != template.height
        || finalized.header.prev_hash != template.header.prev_hash
        || serde_json::to_string(&finalized.transactions)? != transactions
    {
        return Err("the tip or the pool changed between template and finalize".into());
    }

    // The body as the node built it for those roots: same transactions, same coinbase, same code.
    let mut block = Block::from_reward(
        &template.header,
        finalized.transactions,
        coinbase.output,
        coinbase.kernel,
        Difficulty::zero(),
    )?;
    let mut header = finalized.header;
    header.pow.total_difficulty =
        template.header.pow.total_difficulty.clone() + template.block_difficulty.clone();
    header.pow.seed = template.header.pow.seed;
    header.pow.secondary_scaling = template.header.pow.secondary_scaling;
    header.policy = template.header.policy;
    header.bottles = template.header.bottles.clone();
    block.header = header;
    block.validate(&template.header.total_kernel_offset)?;

    let mut prefix = block.header.pre_pow();
    prefix.truncate(prefix.len().saturating_sub(8));
    eprintln!(
        "miner: job for height {} with {} transactions, difficulty {}",
        template.height,
        template.transactions.len(),
        template.block_difficulty.to_num(PoWType::RandomX)
    );
    Ok(Job {
        height: template.height,
        transactions,
        seed: block.header.pow.seed,
        target: template.block_difficulty.to_num(PoWType::RandomX),
        block,
        prefix,
    })
}

/// A nonce and the RandomX hash that meets the block difficulty with it.
type Solution = (u64, [u8; 32]);

/// Hashes nonces for one job on every thread until one meets the block difficulty or the round
/// ends. Returns the solution, if any, and the number of hashes computed.
fn solve(job: &Job, states: &mut [RxState]) -> Result<(Option<Solution>, u64)> {
    let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let step = states.len() as u64;
    let stop = AtomicBool::new(false);
    let started = Instant::now();

    let results: Vec<(Option<Solution>, u64)> = thread::scope(|scope| {
        let workers: Vec<_> = states
            .iter_mut()
            .enumerate()
            .map(|(index, state)| {
                let stop = &stop;
                scope.spawn(move || {
                    let mut nonce = start.wrapping_add(index as u64);
                    let mut done = 0u64;
                    while !stop.load(Ordering::Relaxed) && started.elapsed() < JOB_TIME {
                        let mut header = job.prefix.clone();
                        header.extend_from_slice(&nonce.to_be_bytes());
                        // The node takes the hash as RandomX returns it.
                        let hash = slow_hash(state, &header, &job.seed);
                        done += 1;
                        let pow = ProofOfWork {
                            proof: Proof::RandomXProof { hash },
                            nonce,
                            seed: job.seed,
                            ..ProofOfWork::default()
                        };
                        let difficulty = pow
                            .to_difficulty(&header, job.height, nonce)
                            .to_num(PoWType::RandomX);
                        if difficulty >= job.target {
                            stop.store(true, Ordering::Relaxed);
                            return (Some((nonce, hash)), done);
                        }
                        nonce = nonce.wrapping_add(step);
                    }
                    (None, done)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap_or((None, 0)))
            .collect()
    });

    let done = results.iter().map(|(_, done)| done).sum();
    let found = results.into_iter().find_map(|(found, _)| found);
    Ok((found, done))
}
