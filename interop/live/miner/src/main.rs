//! Mines floonet blocks through the local reference node's stratum server, so the node pays each
//! coinbase to the wallet it is configured with.
//!
//! Floonet is RandomX only. Every thread keeps its own light-mode RandomX state with the JIT
//! compiler on, because the reference node's shared state hashes on one thread with the
//! interpreter, which is far too slow for floonet difficulty. Hashing goes through the same
//! RandomX binding the node uses, and the difficulty check through the node's own code, so the
//! node accepts what this finds.
//!
//! Usage: `lepic-live-miner <stratum host:port> [threads]`. It runs until killed and reconnects
//! whenever the node goes away.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, sleep};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use epic_core::global::{self, ChainTypes};
use epic_core::pow::{PoWType, Proof, ProofOfWork};
use randomx::{RxState, slow_hash};
use serde::Deserialize;
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// How long one job is worked on before a fresh template is fetched, so new transactions in
/// the pool make it into the next block and a block found elsewhere ends the round.
const JOB_TIME: Duration = Duration::from_secs(5);

/// How often the hash rate is reported.
const REPORT_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
struct JobTemplate {
    height: u64,
    job_id: u64,
    block_difficulty: Vec<(String, u64)>,
    pre_pow: String,
    epochs: Vec<(u64, u64, [u8; 32])>,
    algorithm: String,
}

struct Stratum {
    writer: TcpStream,
    reader: BufReader<TcpStream>,
    next_id: u64,
}

impl Stratum {
    fn connect(address: &str) -> Result<Self> {
        let stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        let reader = BufReader::new(stream.try_clone()?);
        let mut stratum = Self {
            writer: stream,
            reader,
            next_id: 1,
        };
        stratum.call(
            "login",
            json!({"login": "lepic-live", "pass": "", "agent": "lepic-live-miner"}),
        )?;
        Ok(stratum)
    }

    /// Sends one request and returns its result, skipping the job notifications the server
    /// pushes in between.
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.to_string();
        self.next_id += 1;
        let request = json!({"id": id, "jsonrpc": "2.0", "method": method, "params": params});
        writeln!(self.writer, "{request}")?;
        self.writer.flush()?;
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Err("stratum connection closed".into());
            }
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if message.get("id").and_then(Value::as_str) != Some(id.as_str()) {
                continue;
            }
            if let Some(error) = message.get("error").filter(|error| !error.is_null()) {
                return Err(format!("{method} failed: {error}").into());
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(address) = args.next() else {
        eprintln!("usage: lepic-live-miner <stratum host:port> [threads]");
        std::process::exit(2);
    };
    let threads = args
        .next()
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|threads| *threads > 0)
        .unwrap_or(1);

    global::set_mining_mode(ChainTypes::Floonet);
    let mut states: Vec<RxState> = (0..threads)
        .map(|_| {
            let mut state = RxState::new();
            state.jit_compiler = true;
            state.hard_aes = true;
            state
        })
        .collect();
    loop {
        if let Err(error) = mine(&address, &mut states) {
            eprintln!("miner: {error}; reconnecting");
        }
        sleep(Duration::from_secs(2));
    }
}

fn mine(address: &str, states: &mut [RxState]) -> Result<()> {
    let mut stratum = Stratum::connect(address)?;
    eprintln!(
        "miner: connected to {address} with {} threads",
        states.len()
    );
    let mut last_found = 0;
    let mut hashes = 0u64;
    let mut since = Instant::now();
    loop {
        let job: JobTemplate = serde_json::from_value(
            stratum.call("getjobtemplate", json!({"algorithm": "randomx"}))?,
        )?;
        if job.algorithm != "randomx" {
            return Err(
                format!("node asks for {}; run it with only_randomx", job.algorithm).into(),
            );
        }
        // The template lags the new tip briefly; mining it again would fork our own block.
        if job.height <= last_found {
            sleep(Duration::from_millis(500));
            continue;
        }
        let (found, done) = solve(&job, states)?;
        hashes += done;
        if since.elapsed() >= REPORT_EVERY {
            let rate = hashes as f64 / since.elapsed().as_secs_f64();
            eprintln!("miner: height {} at {rate:.0} H/s", job.height);
            hashes = 0;
            since = Instant::now();
        }
        if let Some((nonce, hash)) = found {
            let result = stratum.call(
                "submit",
                json!({
                    "height": job.height,
                    "job_id": job.job_id,
                    "nonce": nonce,
                    "pow": {"RandomX": hash},
                }),
            )?;
            eprintln!("miner: height {} {result}", job.height);
            if result
                .as_str()
                .is_some_and(|text| text.starts_with("blockfound"))
            {
                last_found = job.height;
            }
        }
    }
}

/// A nonce and the RandomX hash that meets the block difficulty with it.
type Solution = (u64, [u8; 32]);

/// Hashes nonces for one job on every thread until one meets the block difficulty or the round
/// ends. Returns the solution, if any, and the number of hashes computed.
fn solve(job: &JobTemplate, states: &mut [RxState]) -> Result<(Option<Solution>, u64)> {
    let target = job
        .block_difficulty
        .iter()
        .find(|(algorithm, _)| algorithm == "randomx")
        .map(|(_, difficulty)| *difficulty)
        .ok_or("job has no randomx difficulty")?;
    let seed = job
        .epochs
        .iter()
        .find(|(start, end, _)| (*start..=*end).contains(&job.height))
        .or(job.epochs.first())
        .map(|(_, _, seed)| *seed)
        .ok_or("job has no randomx seed")?;
    let pre_pow = epic_util::from_hex(job.pre_pow.clone())?;
    let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let step = states.len() as u64;
    let stop = AtomicBool::new(false);
    let started = Instant::now();

    let results: Vec<(Option<Solution>, u64)> = thread::scope(|scope| {
        let workers: Vec<_> = states
            .iter_mut()
            .enumerate()
            .map(|(index, state)| {
                let (pre_pow, stop) = (&pre_pow, &stop);
                scope.spawn(move || {
                    let mut nonce = start.wrapping_add(index as u64);
                    let mut done = 0u64;
                    while !stop.load(Ordering::Relaxed) && started.elapsed() < JOB_TIME {
                        let mut header = pre_pow.clone();
                        header.extend_from_slice(&nonce.to_be_bytes());
                        let hash = to_hash_bytes(&slow_hash(state, &header, &seed).to_bytes_be());
                        done += 1;
                        let pow = ProofOfWork {
                            proof: Proof::RandomXProof { hash },
                            nonce,
                            seed,
                            ..ProofOfWork::default()
                        };
                        let difficulty = pow
                            .to_difficulty(&header, job.height, nonce)
                            .to_num(PoWType::RandomX);
                        if difficulty >= target {
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

/// The 32-byte big-endian form of a RandomX hash, as the node encodes it in a proof.
fn to_hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let skip = bytes.len().saturating_sub(32);
    let tail = &bytes[skip..];
    hash[32 - tail.len()..].copy_from_slice(tail);
    hash
}
