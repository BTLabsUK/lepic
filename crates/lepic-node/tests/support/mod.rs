//! A local HTTP/1.1 server that answers each request with whatever a test scripts, including
//! answers no well-behaved node would give.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One request as the server read it.
#[derive(Debug, Clone)]
pub struct Received {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// What the server does with a request.
pub enum Reply {
    /// A complete response with `Content-Length`.
    Body { status: u16, body: Vec<u8> },
    /// A chunked response of `chunks` chunks of `chunk_len` bytes, without `Content-Length`.
    Chunked { chunk_len: usize, chunks: usize },
    /// Headers that declare `declared` bytes; no body follows.
    Declared { declared: u64 },
    /// Read the request, then never answer.
    Stall,
    /// Headers, then the body one byte per `interval`.
    Drip { body: Vec<u8>, interval: Duration },
    /// Close the connection without answering.
    Hangup,
}

impl Reply {
    pub fn json(body: impl Into<Vec<u8>>) -> Self {
        Self::Body {
            status: 200,
            body: body.into(),
        }
    }
}

type Handler = dyn Fn(&Received) -> Reply + Send + Sync;

pub struct TestServer {
    pub addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    in_flight_max: Arc<AtomicUsize>,
}

impl TestServer {
    pub async fn start(handler: impl Fn(&Received) -> Reply + Send + Sync + 'static) -> Self {
        Self::start_with_delay(Duration::ZERO, handler).await
    }

    /// Every reply waits `delay` first, so concurrent requests overlap.
    pub async fn start_with_delay(
        delay: Duration,
        handler: impl Fn(&Received) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let in_flight_max = Arc::new(AtomicUsize::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        {
            let received = received.clone();
            let in_flight_max = in_flight_max.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let handler = handler.clone();
                    let received = received.clone();
                    let in_flight = in_flight.clone();
                    let in_flight_max = in_flight_max.clone();
                    tokio::spawn(async move {
                        serve(stream, handler, received, in_flight, in_flight_max, delay).await;
                    });
                }
            });
        }
        Self {
            addr,
            received,
            in_flight_max,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    pub fn max_in_flight(&self) -> usize {
        self.in_flight_max.load(Ordering::SeqCst)
    }
}

async fn serve(
    mut stream: TcpStream,
    handler: Arc<Handler>,
    received: Arc<Mutex<Vec<Received>>>,
    in_flight: Arc<AtomicUsize>,
    in_flight_max: Arc<AtomicUsize>,
    delay: Duration,
) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    in_flight_max.fetch_max(now, Ordering::SeqCst);
    received.lock().unwrap().push(request.clone());
    let reply = handler(&request);
    tokio::time::sleep(delay).await;
    in_flight.fetch_sub(1, Ordering::SeqCst);
    match reply {
        Reply::Body { status, body } => {
            let head = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
        Reply::Chunked { chunk_len, chunks } => {
            let head = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
            let _ = stream.write_all(head.as_bytes()).await;
            let chunk = vec![b' '; chunk_len];
            for _ in 0..chunks {
                let size = format!("{chunk_len:x}\r\n");
                if stream.write_all(size.as_bytes()).await.is_err()
                    || stream.write_all(&chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        }
        Reply::Declared { declared } => {
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {declared}\r\nconnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes()).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        Reply::Stall => {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        Reply::Drip { body, interval } => {
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            for byte in body {
                tokio::time::sleep(interval).await;
                if stream.write_all(&[byte]).await.is_err() {
                    return;
                }
            }
        }
        Reply::Hangup => {}
    }
    let _ = stream.shutdown().await;
}

async fn read_request(stream: &mut TcpStream) -> Option<Received> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_owned();
    let path = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Received {
        method,
        path,
        headers,
        body,
    })
}

/// A server that keeps connections open between requests, as nginx does, and gives up on a
/// connection idle for `idle_close`. Its close is modelled as crossing the next request in
/// flight, the race a client meets when it reuses a connection at the server's timeout: a
/// request that arrives on a connection idle that long is read and dropped unanswered. Every
/// other request gets `body`.
pub struct KeepAliveServer {
    pub addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

impl KeepAliveServer {
    pub async fn start(idle_close: Duration, body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let body = Arc::new(body);
        {
            let connections = connections.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let body = body.clone();
                    tokio::spawn(async move {
                        let mut answered = None::<tokio::time::Instant>;
                        while read_request(&mut stream).await.is_some() {
                            if answered.is_some_and(|at| at.elapsed() >= idle_close) {
                                return;
                            }
                            let head = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                                body.len()
                            );
                            if stream.write_all(head.as_bytes()).await.is_err()
                                || stream.write_all(&body).await.is_err()
                            {
                                return;
                            }
                            answered = Some(tokio::time::Instant::now());
                        }
                    });
                }
            });
        }
        Self { addr, connections }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}
