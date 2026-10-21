//! The listener: serves `check_version` and `receive_tx` at `/v2/foreign`, as
//! `epic-wallet listen -m http` does, so any wallet that sends over HTTP can pay this one.
//!
//! Everything a caller sends is untrusted and its cost is bounded: connections at once, time
//! to send the headers and the body, body size, and payments taken per minute. Only payments
//! are served; invoices and the owner API are not.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use lepic_slate::codec::WireSlate;
use lepic_transport::transport::BoxFuture;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tracing::{debug, info, warn};

use crate::error::ListenError;
use crate::rpc::{self, Call, MAX_BODY_LEN};

const ENDPOINT: &str = "/v2/foreign";

/// Who can reach the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exposure {
    /// This computer only: `127.0.0.1`.
    LocalOnly,
    /// Every network interface: `0.0.0.0`, for a port forwarded from the internet.
    Internet,
}

impl Exposure {
    const fn address(self) -> IpAddr {
        match self {
            Self::LocalOnly => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Self::Internet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local",
            Self::Internet => "internet",
        }
    }
}

/// Where the listener listens and what it allows.
#[derive(Debug, Clone, Copy)]
pub struct ListenSettings {
    pub exposure: Exposure,
    /// 0 picks a free port, for tests.
    pub port: u16,
    pub max_connections: usize,
    /// For the request line and headers.
    pub header_timeout: Duration,
    /// From the first byte of a request to the last byte of its answer, the wallet's work
    /// included.
    pub request_timeout: Duration,
    /// `receive_tx` calls taken in any one minute; more are refused as busy.
    pub receives_per_minute: u32,
}

impl ListenSettings {
    pub const fn new(exposure: Exposure, port: u16) -> Self {
        Self {
            exposure,
            port,
            max_connections: 16,
            header_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            receives_per_minute: 30,
        }
    }
}

/// Why the wallet did not answer a `receive_tx` with an S2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The slate was checked and refused for good.
    Rejected,
    /// The wallet cannot take payments now (locked, node not ready); the sender may retry.
    Unavailable,
}

impl Refusal {
    const fn reason(self) -> &'static str {
        match self {
            Self::Rejected => "slate refused",
            Self::Unavailable => "wallet not ready",
        }
    }
}

/// The wallet behind the listener: receives one S1 and returns the S2 to answer with. The same
/// S1 sent again must return the same S2, so a sender whose answer was lost can retry.
pub trait ReceiveHandler: Send + Sync + 'static {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>>;
}

/// A running listener. Stops when [`ListenerHandle::stop`] is called or the handle is dropped.
#[derive(Debug)]
pub struct ListenerHandle {
    local_addr: SocketAddr,
    exposure: Exposure,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl ListenerHandle {
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }

    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }

    /// Stops taking connections. Requests already in progress finish within their timeout.
    pub fn stop(&self) {
        self.shutdown.send_replace(true);
    }

    /// Stops, and waits until the listening socket is closed.
    pub async fn shutdown(self) {
        self.stop();
        let _ = (&mut { self }.task).await;
    }
}

impl Drop for ListenerHandle {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

/// Binds the listener and starts serving on the current Tokio runtime. Fails with
/// [`ListenError::PortInUse`] when another program holds the port.
pub async fn listen(
    settings: ListenSettings,
    handler: Arc<dyn ReceiveHandler>,
) -> Result<ListenerHandle, ListenError> {
    let address = SocketAddr::new(settings.exposure.address(), settings.port);
    let listener = TcpListener::bind(address).await.map_err(|source| {
        if source.kind() == std::io::ErrorKind::AddrInUse {
            ListenError::PortInUse {
                port: settings.port,
            }
        } else {
            ListenError::Bind {
                port: settings.port,
                source,
            }
        }
    })?;
    let local_addr = listener.local_addr().map_err(|source| ListenError::Bind {
        port: settings.port,
        source,
    })?;
    let (shutdown, stopped) = watch::channel(false);
    let state = Arc::new(Served {
        handler,
        settings,
        window: Mutex::new(Window::new()),
    });
    let task = tokio::spawn(accept_loop(listener, state, stopped));
    info!(
        port = local_addr.port(),
        exposure = settings.exposure.as_str(),
        "foreign api listening"
    );
    Ok(ListenerHandle {
        local_addr,
        exposure: settings.exposure,
        shutdown,
        task,
    })
}

struct Served {
    handler: Arc<dyn ReceiveHandler>,
    settings: ListenSettings,
    window: Mutex<Window>,
}

/// `receive_tx` calls counted in the current minute.
struct Window {
    started: Instant,
    taken: u32,
}

impl Window {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            taken: 0,
        }
    }

    fn take(&mut self, limit: u32) -> bool {
        if self.started.elapsed() >= Duration::from_secs(60) {
            *self = Self::new();
        }
        if self.taken >= limit {
            return false;
        }
        self.taken = self.taken.saturating_add(1);
        true
    }
}

async fn accept_loop(
    listener: TcpListener,
    state: Arc<Served>,
    mut stopped: watch::Receiver<bool>,
) {
    let permits = Arc::new(Semaphore::new(state.settings.max_connections));
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = stopped.wait_for(|stop| *stop) => break,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                debug!(%error, "accept failed");
                // Out of descriptors and similar: give the system a moment instead of spinning.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Over the connection limit the connection is closed at once, unanswered.
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            debug!("connection limit reached");
            continue;
        };
        let state = Arc::clone(&state);
        let header_timeout = state.settings.header_timeout;
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(answer(&state, request).await) }
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            if let Err(error) = connection.await {
                debug!(%error, "connection ended");
            }
            drop(permit);
        });
    }
    info!("foreign api stopped");
}

async fn answer(state: &Served, request: Request<Incoming>) -> Response<Full<Bytes>> {
    if request.uri().path() != ENDPOINT {
        return status(StatusCode::NOT_FOUND);
    }
    if request.method() != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    match tokio::time::timeout(state.settings.request_timeout, serve(state, request)).await {
        Ok(response) => response,
        Err(_) => {
            debug!("request timed out");
            status(StatusCode::REQUEST_TIMEOUT)
        }
    }
}

async fn serve(state: &Served, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > u64::try_from(MAX_BODY_LEN).unwrap_or(u64::MAX)) {
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let body = match Limited::new(request.into_body(), MAX_BODY_LEN)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return status(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let request = match rpc::decode_request(&body) {
        Ok(request) => request,
        Err(unanswerable) => return json(rpc::encode_error_response(&unanswerable)),
    };
    match request.call {
        Call::CheckVersion => json(rpc::encode_version_response(&request.id)),
        Call::ReceiveTx(slate) => {
            let allowed = state
                .window
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(state.settings.receives_per_minute);
            if !allowed {
                debug!("receive limit reached");
                return json(rpc::encode_refusal_response(
                    &request.id,
                    Refusal::Unavailable.reason(),
                ));
            }
            match state.handler.receive(slate).await {
                Ok(reply) => match rpc::encode_slate_response(&request.id, &reply) {
                    Ok(body) => json(body),
                    Err(error) => {
                        warn!(%error, "reply could not be encoded");
                        status(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                },
                Err(refusal) => {
                    debug!(reason = refusal.reason(), "slate not received");
                    json(rpc::encode_refusal_response(&request.id, refusal.reason()))
                }
            }
        }
    }
}

fn json(body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = code;
    response
}
