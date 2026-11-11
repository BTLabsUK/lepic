// SPDX-License-Identifier: Apache-2.0
//! The listener: serves `check_version` and `receive_tx` at `/v2/foreign`, as
//! `epic-wallet listen -m http` does, so any wallet that sends over HTTP can pay this one. A
//! listener can also serve a mining node's `build_coinbase` (ADR 0046, ADR 0048); by default it
//! answers that method as unknown.
//!
//! Everything a caller sends is untrusted and its cost is bounded: connections at once, in all
//! and from one address, time to send the headers and the body and to take the answer, body
//! size, requests per minute, and payments taken per minute. Only payments are served;
//! invoices and the owner API are not.
//!
//! The per-minute budgets cannot tell callers apart (behind an onion every caller is
//! `127.0.0.1`), so they are shaped to keep one caller's junk from blocking another's
//! payment: requests that are not payments cannot use up the room payments have (a request read
//! past the request budget holds a payment's place only until it turns out not to be one), and a
//! payment the wallet refuses as invalid gives its share of the payment budget back, up to the
//! budget again each minute.
//!
//! On a listener that serves `build_coinbase`, loopback peers have connections of their own and
//! their `build_coinbase` spends no budget: a node that is refused retries for as long as it
//! takes and gets no new job meanwhile, so nothing other callers do may hold it back.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use lepic_peer::{PeerEndpoint, PeerRoute, ProblemCode, problem_response};
use lepic_slate::codec::WireSlate;
use lepic_transport::transport::BoxFuture;
use serde::Deserialize;
use serde::de::IgnoredAny;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, watch};
use tracing::{debug, info, warn};

use crate::error::ListenError;
use crate::rpc::{self, BlockFees, Call, CoinbaseAnswer, MAX_BODY_LEN, Unanswerable};

const ENDPOINT: &str = "/v2/foreign";

/// Who can reach the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exposure {
    /// This computer only: `127.0.0.1`.
    LocalOnly,
    /// Every IPv4 network interface: `0.0.0.0`, for a port forwarded from the internet.
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

/// Who `build_coinbase` is served to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoinbaseAccess {
    /// Nobody: the method is answered as unknown.
    Off,
    /// Loopback peers, a node on this computer or a tunnel to it. Every other caller gets the
    /// answer of [`Self::Off`].
    LocalOnly,
    /// Every peer. Those beyond this computer stay under the listener's limits.
    Remote,
}

impl CoinbaseAccess {
    const fn serves(self, loopback: bool) -> bool {
        match self {
            Self::Off => false,
            Self::LocalOnly => loopback,
            Self::Remote => true,
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
    /// Connections at once from one remote address.
    pub max_connections_per_address: usize,
    /// For the request line and headers.
    pub header_timeout: Duration,
    /// For the body, once the headers are in. A sender posts its slate in one go.
    pub body_timeout: Duration,
    /// From the first byte of a request to the last byte of its answer, the wallet's work
    /// included.
    pub request_timeout: Duration,
    /// For the caller to take the answer. A connection ends at the latest after
    /// `header_timeout + request_timeout + answer_timeout`, whatever it is doing.
    pub answer_timeout: Duration,
    /// Requests of any kind taken in any one minute; past it only as many more as
    /// `receives_per_minute` are read, and served only if they are payments. The rest are
    /// answered `503`.
    pub requests_per_minute: u32,
    /// `receive_tx` calls carrying an S1 taken in any one minute; more are refused as busy.
    /// One the wallet refuses as [`Refusal::Rejected`] does not count, for as many such
    /// refusals a minute: the wallet may refuse a slate only after costly checks, so at most
    /// twice this many reach it in a minute.
    pub receives_per_minute: u32,
    /// Who `build_coinbase` is served to, for a mining node to pay its block rewards to this
    /// wallet. Off unless the host turns it on.
    pub coinbase: CoinbaseAccess,
}

/// The caller's limits of a listener, as [`ListenSettings`] describes each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenLimits {
    pub max_connections: usize,
    pub max_connections_per_address: usize,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub request_timeout: Duration,
    pub answer_timeout: Duration,
    pub requests_per_minute: u32,
    pub receives_per_minute: u32,
}

impl ListenSettings {
    pub const fn new(exposure: Exposure, port: u16, limits: ListenLimits) -> Self {
        Self {
            exposure,
            port,
            max_connections: limits.max_connections,
            max_connections_per_address: limits.max_connections_per_address,
            header_timeout: limits.header_timeout,
            body_timeout: limits.body_timeout,
            request_timeout: limits.request_timeout,
            answer_timeout: limits.answer_timeout,
            requests_per_minute: limits.requests_per_minute,
            receives_per_minute: limits.receives_per_minute,
            coinbase: CoinbaseAccess::Off,
        }
    }

    /// These settings with `build_coinbase` served to `coinbase`.
    #[must_use]
    pub const fn with_coinbase(mut self, coinbase: CoinbaseAccess) -> Self {
        self.coinbase = coinbase;
        self
    }

    /// The longest a connection is served.
    fn connection_deadline(&self) -> Duration {
        self.header_timeout
            .saturating_add(self.request_timeout)
            .saturating_add(self.answer_timeout)
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

    /// Told of a payment the listener refused before handing it to [`Self::receive`], as
    /// it does over the per-minute limits.
    fn refused(&self, _refusal: Refusal) {}

    /// Builds the reward output and kernel a mining node asks for, when
    /// [`ListenSettings::coinbase`] serves the caller. A wallet that cannot build one refuses.
    fn build_coinbase(&self, _fees: BlockFees) -> BoxFuture<'_, Result<CoinbaseAnswer, Refusal>> {
        Box::pin(async { Err(Refusal::Unavailable) })
    }
}

/// A running listener. Stops when [`ListenerHandle::stop`] is called or the handle is dropped.
#[derive(Debug)]
pub struct ListenerHandle {
    local_addr: SocketAddr,
    #[cfg(unix)]
    socket: Option<PathBuf>,
    exposure: Exposure,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl ListenerHandle {
    /// The TCP address it listens on; `127.0.0.1:0` for a listener on a Unix socket
    /// ([`listen_unix`]).
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The Unix socket it listens on, for a listener of [`listen_unix`].
    #[cfg(unix)]
    pub fn socket_path(&self) -> Option<&Path> {
        self.socket.as_deref()
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
    listen_with(settings, handler, None).await
}

/// As [`listen`], and with `peer` the socket also serves the native endpoint (ADR 0052) at
/// `/api/v1/inbox` and advertises it in `check_version` under `peer`'s seal key. Without `peer`
/// those routes are not found and `check_version` carries no advert.
pub async fn listen_with(
    settings: ListenSettings,
    handler: Arc<dyn ReceiveHandler>,
    peer: Option<Arc<PeerEndpoint>>,
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
    let task = tokio::spawn(accept_loop(
        Bound::Tcp(listener),
        served(settings, handler, peer),
        stopped,
    ));
    info!(
        port = local_addr.port(),
        exposure = settings.exposure.as_str(),
        "foreign api listening"
    );
    Ok(ListenerHandle {
        local_addr,
        #[cfg(unix)]
        socket: None,
        exposure: settings.exposure,
        shutdown,
        task,
    })
}

/// Binds the listener on a Unix-domain socket at `path` and starts serving, with the limits of
/// `settings` (its exposure and port are not used). For a listener only a local tor reaches: a
/// socket in a folder of the wallet's own is out of other programs' and apps' reach, where any of
/// them can connect to a loopback port. A file left at `path` by an earlier run is replaced; the
/// socket file is removed when the listener stops. Every connection counts as one address, as
/// every sender does behind an onion.
#[cfg(unix)]
pub async fn listen_unix(
    path: &Path,
    settings: ListenSettings,
    handler: Arc<dyn ReceiveHandler>,
) -> Result<ListenerHandle, ListenError> {
    listen_unix_with(path, settings, handler, None).await
}

/// As [`listen_unix`], serving and advertising the native endpoint as [`listen_with`] does.
#[cfg(unix)]
pub async fn listen_unix_with(
    path: &Path,
    settings: ListenSettings,
    handler: Arc<dyn ReceiveHandler>,
    peer: Option<Arc<PeerEndpoint>>,
) -> Result<ListenerHandle, ListenError> {
    let bind_error = |source| ListenError::Bind { port: 0, source };
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(bind_error(error));
        }
        _ => {}
    }
    let listener = UnixListener::bind(path).map_err(bind_error)?;
    let (shutdown, stopped) = watch::channel(false);
    let task = tokio::spawn(accept_loop(
        Bound::Unix(listener, path.to_owned()),
        served(settings, handler, peer),
        stopped,
    ));
    info!(
        exposure = settings.exposure.as_str(),
        "foreign api listening on a unix socket"
    );
    Ok(ListenerHandle {
        local_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        socket: Some(path.to_owned()),
        exposure: settings.exposure,
        shutdown,
        task,
    })
}

fn served(
    settings: ListenSettings,
    handler: Arc<dyn ReceiveHandler>,
    peer: Option<Arc<PeerEndpoint>>,
) -> Arc<Served> {
    Arc::new(Served {
        handler,
        peer,
        settings,
        requests: Mutex::new(Window::new()),
        payments_only: Mutex::new(Window::new()),
        receives: Mutex::new(Window::new()),
        per_address: Mutex::new(HashMap::new()),
    })
}

/// The socket a listener takes connections on.
enum Bound {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener, PathBuf),
}

/// One accepted connection.
enum Accepted {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl Bound {
    /// The next connection and the address its per-address limit counts it under: a Unix
    /// socket's callers all count as `127.0.0.1`.
    async fn accept(&self) -> std::io::Result<(Accepted, IpAddr)> {
        match self {
            Self::Tcp(listener) => listener
                .accept()
                .await
                .map(|(stream, remote)| (Accepted::Tcp(stream), remote.ip().to_canonical())),
            #[cfg(unix)]
            Self::Unix(listener, _) => listener
                .accept()
                .await
                .map(|(stream, _)| (Accepted::Unix(stream), IpAddr::V4(Ipv4Addr::LOCALHOST))),
        }
    }

    /// Closes the socket, and removes a Unix socket's file.
    fn close(self) {
        match self {
            Self::Tcp(_) => {}
            #[cfg(unix)]
            Self::Unix(listener, path) => {
                drop(listener);
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

struct Served {
    handler: Arc<dyn ReceiveHandler>,
    /// The native endpoint of this socket: its key is the one this socket was given, whatever
    /// host a request names.
    peer: Option<Arc<PeerEndpoint>>,
    settings: ListenSettings,
    requests: Mutex<Window>,
    /// Requests read once `requests` is spent, served only if they are payments.
    payments_only: Mutex<Window>,
    receives: Mutex<Window>,
    /// Open connections by remote address. Kept in memory only and never logged.
    per_address: Mutex<HashMap<IpAddr, usize>>,
}

impl Served {
    fn take(window: &Mutex<Window>, limit: u32) -> bool {
        Self::take_slot(window, limit).is_some()
    }

    /// Takes one call from `window`; the slot can be given back while its minute lasts.
    fn take_slot(window: &Mutex<Window>, limit: u32) -> Option<Slot> {
        window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_slot(limit)
    }

    fn give_back(window: &Mutex<Window>, slot: Slot, limit: u32) {
        window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .give_back(slot, limit);
    }

    /// What a new request may be, or `None` when it is over every budget.
    fn admit_request(&self) -> Option<Admission<'_>> {
        if Self::take(&self.requests, self.settings.requests_per_minute) {
            Some(Admission::Any)
        } else {
            let slot = Self::take_slot(&self.payments_only, self.settings.receives_per_minute)?;
            Some(Admission::PaymentOnly(PaymentPlace {
                served: self,
                slot: Some(slot),
            }))
        }
    }

    /// A share of the connections for `address`, or `None` when it holds its most.
    fn admit(self: &Arc<Self>, address: IpAddr) -> Option<AddressShare> {
        let mut open = self
            .per_address
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = open.entry(address).or_default();
        if *count >= self.settings.max_connections_per_address {
            return None;
        }
        *count = count.saturating_add(1);
        Some(AddressShare {
            served: Arc::clone(self),
            address,
        })
    }
}

/// One connection's share of its remote address's connections, given back on drop.
struct AddressShare {
    served: Arc<Served>,
    address: IpAddr,
}

impl Drop for AddressShare {
    fn drop(&mut self) {
        let mut open = self
            .served
            .per_address
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = open.get_mut(&self.address) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.address);
            }
        }
    }
}

enum Admission<'a> {
    /// A loopback peer of a listener that serves `build_coinbase`. That call is free; any other
    /// is admitted as any caller's once it is read.
    Loopback,
    Any,
    /// Read past the request budget: served only if it is a payment.
    PaymentOnly(PaymentPlace<'a>),
}

/// A place in the payments-only budget, given back on drop unless the request was a payment.
struct PaymentPlace<'a> {
    served: &'a Served,
    slot: Option<Slot>,
}

impl PaymentPlace<'_> {
    fn keep(&mut self) {
        self.slot = None;
    }
}

impl Drop for PaymentPlace<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            self.served
                .payments_only
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .release(slot);
        }
    }
}

/// One call taken from a [`Window`] in the minute that began at `minute`.
#[derive(Debug, Clone, Copy)]
struct Slot {
    minute: Instant,
}

/// Calls counted in the current minute.
struct Window {
    started: Instant,
    taken: u32,
    given_back: u32,
}

impl Window {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            taken: 0,
            given_back: 0,
        }
    }

    fn take_slot(&mut self, limit: u32) -> Option<Slot> {
        if self.started.elapsed() >= Duration::from_secs(60) {
            *self = Self::new();
        }
        if self.taken >= limit {
            return None;
        }
        self.taken = self.taken.saturating_add(1);
        Some(Slot {
            minute: self.started,
        })
    }

    /// Gives `slot` back whatever was given back already; for calls that cost nothing.
    fn release(&mut self, slot: Slot) {
        if slot.minute == self.started {
            self.taken = self.taken.saturating_sub(1);
        }
    }

    /// Gives `slot` back unless `limit` slots were already given back this minute, so at most
    /// twice the window's limit is taken in a minute. A slot of a minute that has ended is not
    /// given back: the new minute never counted it.
    fn give_back(&mut self, slot: Slot, limit: u32) {
        if slot.minute == self.started && self.given_back < limit {
            self.taken = self.taken.saturating_sub(1);
            self.given_back = self.given_back.saturating_add(1);
        }
    }
}

async fn accept_loop(listener: Bound, state: Arc<Served>, mut stopped: watch::Receiver<bool>) {
    let permits = Arc::new(Semaphore::new(state.settings.max_connections));
    let loopback_permits = Arc::new(Semaphore::new(state.settings.max_connections));
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = stopped.wait_for(|stop| *stop) => break,
        };
        let (stream, remote) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                debug!(%error, "accept failed");
                // Out of descriptors and similar: give the system a moment instead of spinning.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // A Unix socket's callers are whoever came in over an onion, whatever `remote` says.
        let loopback = state.settings.coinbase != CoinbaseAccess::Off
            && matches!(stream, Accepted::Tcp(_))
            && remote.is_loopback();
        let pool = if loopback {
            &loopback_permits
        } else {
            &permits
        };
        // Over the connection limit the connection is closed at once, unanswered.
        let Ok(permit) = Arc::clone(pool).try_acquire_owned() else {
            debug!("connection limit reached");
            continue;
        };
        let Some(share) = state.admit(remote) else {
            debug!("connection limit of one address reached");
            continue;
        };
        let state = Arc::clone(&state);
        match stream {
            Accepted::Tcp(stream) => {
                tokio::spawn(serve_connection(stream, state, loopback, share, permit));
            }
            #[cfg(unix)]
            Accepted::Unix(stream) => {
                tokio::spawn(serve_connection(stream, state, loopback, share, permit));
            }
        }
    }
    listener.close();
    info!("foreign api stopped");
}

async fn serve_connection<S>(
    stream: S,
    state: Arc<Served>,
    loopback: bool,
    share: AddressShare,
    permit: tokio::sync::OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let header_timeout = state.settings.header_timeout;
    let deadline = state.settings.connection_deadline();
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(answer(&state, loopback, request).await) }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service);
    // A caller that stops reading its answer would otherwise hold the slot forever.
    match tokio::time::timeout(deadline, connection).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => debug!(%error, "connection ended"),
        Err(_) => debug!("connection timed out"),
    }
    drop(share);
    drop(permit);
}

async fn answer(
    state: &Served,
    loopback: bool,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let admission = if loopback {
        Some(Admission::Loopback)
    } else {
        state.admit_request()
    };
    if let Some(peer) = &state.peer
        && PeerRoute::is_path(request.uri().path())
    {
        let Some(route) = PeerRoute::from_request(request.uri().path(), request.method()) else {
            return status(StatusCode::METHOD_NOT_ALLOWED);
        };
        return answer_peer(state, peer, admission, route, request).await;
    }
    let Some(admission) = admission else {
        debug!("request limit reached");
        return status(StatusCode::SERVICE_UNAVAILABLE);
    };
    if request.uri().path() != ENDPOINT {
        return status(StatusCode::NOT_FOUND);
    }
    if request.method() != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    let serving = serve(state, loopback, admission, request);
    match tokio::time::timeout(state.settings.request_timeout, serving).await {
        Ok(response) => response,
        Err(_) => {
            debug!("request timed out");
            status(StatusCode::REQUEST_TIMEOUT)
        }
    }
}

async fn serve(
    state: &Served,
    loopback: bool,
    mut admission: Admission<'_>,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > u64::try_from(MAX_BODY_LEN).unwrap_or(u64::MAX)) {
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let collecting = Limited::new(request.into_body(), MAX_BODY_LEN).collect();
    let body = match tokio::time::timeout(state.settings.body_timeout, collecting).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(_)) => return status(StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => {
            debug!("body timed out");
            return status(StatusCode::REQUEST_TIMEOUT);
        }
    };
    let decoded = rpc::decode_request(&body);
    let coinbase =
        matches!(&decoded, Ok(request) if matches!(request.call, Call::BuildCoinbase(_)));
    if matches!(admission, Admission::Loopback) && !coinbase {
        let Some(shared) = state.admit_request() else {
            debug!("request limit reached");
            return status(StatusCode::SERVICE_UNAVAILABLE);
        };
        admission = shared;
    }
    let request = match decoded {
        Ok(request) => request,
        Err(_) if matches!(admission, Admission::PaymentOnly(_)) => {
            return status(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(unanswerable) => return json(rpc::encode_error_response(&unanswerable)),
    };
    let payment = matches!(&request.call, Call::ReceiveTx(slate) if looks_like_s1(slate));
    if let Admission::PaymentOnly(place) = &mut admission {
        if !payment {
            debug!("request limit reached");
            return status(StatusCode::SERVICE_UNAVAILABLE);
        }
        place.keep();
    }
    match request.call {
        Call::CheckVersion => json(state.version_response(&request.id)),
        Call::ReceiveTx(slate) => {
            // Only what could be a payment spends the payment budget.
            let slot = if payment {
                let slot = Served::take_slot(&state.receives, state.settings.receives_per_minute);
                if slot.is_none() {
                    debug!("receive limit reached");
                    state.handler.refused(Refusal::Unavailable);
                    return json(rpc::encode_refusal_response(
                        &request.id,
                        Refusal::Unavailable.reason(),
                    ));
                }
                slot
            } else {
                None
            };
            let received = state.handler.receive(slate).await;
            // A slate refused as invalid mostly cost a check, not a payment's work: junk does
            // not use up the room of real payments. Some refusals come only after the wallet's
            // costlier checks, so only so many a minute are given back.
            if let (Err(Refusal::Rejected), Some(slot)) = (&received, slot) {
                Served::give_back(&state.receives, slot, state.settings.receives_per_minute);
            }
            match received {
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
        Call::BuildCoinbase(_) if !state.settings.coinbase.serves(loopback) => {
            json(rpc::encode_error_response(&Unanswerable {
                id: request.id,
                code: rpc::METHOD_NOT_FOUND,
            }))
        }
        Call::BuildCoinbase(fees) => match state.handler.build_coinbase(fees).await {
            Ok(answer) => {
                info!(height = fees.height, "coinbase built");
                json(rpc::encode_coinbase_response(&request.id, &answer))
            }
            Err(refusal) => {
                debug!(reason = refusal.reason(), "coinbase not built");
                json(rpc::encode_refusal_response(&request.id, refusal.reason()))
            }
        },
    }
}

impl Served {
    /// The `check_version` answer, with the advert of this socket's native endpoint if it has
    /// one.
    fn version_response(&self, id: &str) -> Vec<u8> {
        let advert = self.peer.as_ref().map(|peer| peer.advert());
        rpc::encode_version_response_with(id, advert.as_ref())
    }
}

/// How long a caller over a budget is told to wait: the budgets are per minute.
const BUDGET_RETRY: Duration = Duration::from_secs(60);

/// A request for a route of the native endpoint. It spends the same budgets as the foreign
/// API: past the request budget only a posted envelope is read, as a payment, and each envelope
/// the wallet takes spends the payment budget. Over a budget the answer is `rate_limited`.
async fn answer_peer(
    state: &Served,
    peer: &PeerEndpoint,
    admission: Option<Admission<'_>>,
    route: PeerRoute,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let rate_limited = || problem_response(ProblemCode::RateLimited, Some(BUDGET_RETRY));
    // Loopback connections are set apart for a mining node; this route is not one of its.
    let admission = match admission {
        Some(Admission::Loopback) => state.admit_request(),
        other => other,
    };
    let Some(mut admission) = admission else {
        debug!("request limit reached");
        return rate_limited();
    };
    if let Admission::PaymentOnly(place) = &mut admission {
        if route != PeerRoute::Slates {
            debug!("request limit reached");
            return rate_limited();
        }
        place.keep();
    }
    if route == PeerRoute::Info {
        return peer.info_response();
    }
    let limit = state.settings.receives_per_minute;
    let answering = async {
        // The headers, the body and the envelope's layout are checked before a payment's
        // budget is held: a body that is not an envelope never holds a payment's place.
        let envelope = match peer.read(request, state.settings.body_timeout).await {
            Ok(envelope) => envelope,
            Err(response) => return *response,
        };
        let Some(slot) = Served::take_slot(&state.receives, limit) else {
            debug!("receive limit reached");
            return rate_limited();
        };
        let answer = peer.receive(envelope).await;
        // Only an envelope the wallet took spends the payment budget.
        if !answer.received {
            Served::give_back(&state.receives, slot, limit);
        }
        answer.response
    };
    match tokio::time::timeout(state.settings.request_timeout, answering).await {
        Ok(response) => response,
        Err(_) => {
            debug!("request timed out");
            problem_response(ProblemCode::NotReady, Some(BUDGET_RETRY))
        }
    }
}

#[derive(Deserialize)]
struct S1Shape {
    #[serde(rename = "id")]
    _id: IgnoredAny,
    #[serde(rename = "amount")]
    _amount: IgnoredAny,
    #[serde(rename = "participant_data")]
    _participant_data: IgnoredAny,
}

/// Whether `slate` is a JSON object with the fields every S1 carries, checked without decoding
/// the slate.
fn looks_like_s1(slate: &WireSlate) -> bool {
    slate
        .as_text()
        .is_some_and(|text| serde_json::from_str::<S1Shape>(text).is_ok())
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
