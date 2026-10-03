//! Mines the interop stack's local test-mode chain through the reference node's stratum server.
//!
//! The node's built-in test miner solves only Cuckatoo, which the node's proof-of-work policy
//! rejects whenever the policy calls for RandomX. With `only_randomx` set every block is RandomX,
//! and at test-mode difficulty a few light-mode RandomX hashes find one. The hashing is the
//! reference node's own code, so the node accepts what this finds.
//!
//! Usage: `lepic-interop-miner <stratum host:port> [seconds between blocks]`. It runs until
//! killed and reconnects whenever the node goes away.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use epic_core::global::{self, ChainTypes};
use epic_core::pow::{PoWType, Proof, ProofOfWork, new_randomx_ctx};
use serde::Deserialize;
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// How long one job is worked on before a fresh template is fetched, so new transactions in
/// the pool make it into the next block.
const JOB_TIME: Duration = Duration::from_secs(2);

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
            json!({"login": "interop", "pass": "", "agent": "lepic-interop-miner"}),
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
        eprintln!("usage: lepic-interop-miner <stratum host:port> [seconds between blocks]");
        std::process::exit(2);
    };
    let pause = args
        .next()
        .and_then(|text| text.parse::<f64>().ok())
        .map_or(Duration::from_secs(1), Duration::from_secs_f64);

    global::set_mining_mode(ChainTypes::UserTesting);
    loop {
        if let Err(error) = mine(&address, pause) {
            eprintln!("miner: {error}; reconnecting");
        }
        sleep(Duration::from_secs(2));
    }
}

fn mine(address: &str, pause: Duration) -> Result<()> {
    let mut stratum = Stratum::connect(address)?;
    eprintln!("miner: connected to {address}");
    let mut nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let mut last_found = 0;
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
            sleep(Duration::from_millis(200));
            continue;
        }
        if let Some((nonce_found, hash)) = solve(&job, &mut nonce)? {
            let result = stratum.call(
                "submit",
                json!({
                    "height": job.height,
                    "job_id": job.job_id,
                    "nonce": nonce_found,
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
            sleep(pause);
        }
    }
}

/// Hashes nonces for one job until one meets the block difficulty or the job is stale.
fn solve(job: &JobTemplate, nonce: &mut u64) -> Result<Option<(u64, [u8; 32])>> {
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
    let mut context = new_randomx_ctx::<u32>(seed)?;
    let started = Instant::now();
    while started.elapsed() < JOB_TIME {
        *nonce = nonce.wrapping_add(1);
        let mut header = pre_pow.clone();
        header.extend_from_slice(&nonce.to_be_bytes());
        context.set_header_nonce(header.clone(), Some(*nonce), Some(job.height), true)?;
        for proof in context.pow_solve()? {
            let Proof::RandomXProof { hash } = proof else {
                continue;
            };
            let proof = Proof::RandomXProof { hash };
            let pow = ProofOfWork {
                proof,
                nonce: *nonce,
                seed,
                ..ProofOfWork::default()
            };
            let difficulty = pow
                .to_difficulty(&header, job.height, *nonce)
                .to_num(PoWType::RandomX);
            if difficulty >= target {
                return Ok(Some((*nonce, hash)));
            }
        }
    }
    Ok(None)
}
