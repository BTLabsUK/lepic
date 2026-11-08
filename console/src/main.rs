// SPDX-License-Identifier: Apache-2.0
//! `lepic-console`: a local page that shows one LEPIC wallet through `lepic serve`'s API.
//!
//! The console depends on no LEPIC crate. It reaches serve over its Unix socket and answers
//! one page on a loopback address. At launch it draws a token and prints a link that carries it.
//! The browser that opens the link gets a cookie with the token; a request without that cookie
//! is answered with 401. `Host` must be the console's own address, and a write must come from
//! the console's own origin.

mod policy;
mod proxy;

use std::fs::File;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use proxy::Console;

const DEFAULT_LISTEN: &str = "127.0.0.1:7421";
const TOKEN_BYTES: usize = 32;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "lepic-console", version, about)]
struct Args {
    /// The socket `lepic serve` answers on. Default: the socket in the default data dir.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// The network whose default data dir holds the socket, when `--socket` is not given.
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network,
    /// The loopback address and port the page is served on.
    #[arg(long, value_name = "ADDR", default_value = DEFAULT_LISTEN)]
    listen: SocketAddr,
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Floonet,
}

impl Network {
    fn default_socket(self) -> Option<PathBuf> {
        let dir = match self {
            Self::Mainnet => "mainnet",
            Self::Floonet => "floonet",
        };
        std::env::home_dir().map(|home| home.join(".lepic").join(dir).join("lepic.sock"))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lepic-console: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Draws the launch token from the system's random source, as lower-case hex.
fn draw_token() -> Result<String, String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| format!("cannot draw a token from /dev/urandom: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn run(args: Args) -> Result<(), String> {
    if !args.listen.ip().is_loopback() {
        return Err(format!(
            "{} is not a loopback address; the console serves this machine only",
            args.listen
        ));
    }
    let socket = match args.socket.or_else(|| args.network.default_socket()) {
        Some(socket) => socket,
        None => {
            return Err("no home directory to find the default socket in; pass --socket".into());
        }
    };
    let token = draw_token()?;
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|error| format!("cannot listen on {}: {error}", args.listen))?;
    let listen = listener
        .local_addr()
        .map_err(|error| format!("cannot read the listen address: {error}"))?;
    let console = Arc::new(Console::new(listen.to_string(), socket, token));
    println!(
        "lepic-console on http://{listen}/?token={} for {}",
        console.token(),
        console.socket().display()
    );
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("lepic-console: accept failed: {error}");
                continue;
            }
        };
        let console = Arc::clone(&console);
        tokio::spawn(async move {
            let service = service_fn(|request| {
                let console = Arc::clone(&console);
                async move { Ok::<_, hyper::Error>(console.answer(request).await) }
            });
            let served = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await;
            if let Err(error) = served
                && !error.is_incomplete_message()
            {
                eprintln!("lepic-console: connection ended: {error}");
            }
        });
    }
}
