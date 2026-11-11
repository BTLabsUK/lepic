// SPDX-License-Identifier: Apache-2.0
//! The wallet API `lepic serve` answers under `/api/v1` on its socket, and with `--owner-tls` on
//! a TLS listener too: HTTP/1.1 with JSON bodies (ADR 0055). `docs/api/openapi.json` is the
//! contract and the router is built from it ([`spec`]); the handler of each operation is serve's
//! ([`Owner::operate`]).
//!
//! The socket answers its own user with the `full` role. The TLS listener answers the clients
//! `api-clients` lists, each with its role, read again on every request. An operation above the
//! caller's role is refused with 403 `role_required`, one marked `x-socket-only` with 403
//! `socket_only` over TLS, both before the body is read.

mod caller;
mod codes;
mod events;
pub(crate) mod idempotency;
pub(crate) mod list;
pub(crate) mod model;
mod ops;
mod problem;
pub(crate) mod spec;
mod tls;

use std::cell::Cell;
use std::convert::Infallible;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use zeroize::Zeroizing;

pub(crate) use caller::{Caller, VERSION, VERSION_HEADER};
pub(crate) use events::{epicbox_state, keep_alive_frame, sse_frame};
pub(crate) use idempotency::InProgress;
pub(crate) use list::{ListQuery, Order, Page, Query};
pub(crate) use ops::Op;
pub(crate) use problem::{Category, Problem};
pub(crate) use tls::{OwnerTls, Shaken};

use crate::api_clients::{Clients, Fingerprint, Role};
use crate::app_config::ApiLimits;
use crate::output::RequestsReport;

/// Where a connection came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Listener {
    Socket,
    Tls,
}

/// The path of the CLI's private channel on the socket (ADR 0053).
const CLI_RUN: &str = "/cli/run";

/// A response body. Not `Send`: serve answers on one thread, and an event stream holds the
/// wallet.
pub(crate) type Body = Pin<Box<dyn hyper::body::Body<Data = Bytes, Error = Infallible>>>;
pub(crate) type Answer<'a> = Pin<Box<dyn Future<Output = Result<Response<Body>, Problem>> + 'a>>;

/// The wallet behind the API.
pub(crate) trait Owner {
    /// Answers `request`, routed to `op`, whose least role the caller has.
    fn operate<'a>(&'a self, op: Op, request: Request, context: &'a Context) -> Answer<'a>;

    /// Runs the command the CLI sent on `POST /cli/run`, a private route of the socket.
    fn command_line<'a>(&'a self, request: Request) -> Answer<'a>;
}

/// A request, routed: its path parameters, query, headers and body, the caller's role and the
/// listener it came in on.
pub(crate) struct Request {
    params: Vec<(String, String)>,
    query: Query,
    headers: HeaderMap,
    /// Wiped when the request is done: a body can hold a password or a slate.
    body: Zeroizing<Vec<u8>>,
    role: Role,
    listener: Listener,
    /// Turns true when its connection is closing: serve stops, or a TLS connection reached its
    /// age limit.
    closing: watch::Receiver<bool>,
}

impl Request {
    /// The path parameter `name`.
    pub(crate) fn param(&self, name: &str) -> Result<&str, Problem> {
        self.params
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
            .ok_or_else(|| Problem::usage(format!("missing path parameter {name}")))
    }

    pub(crate) const fn query(&self) -> &Query {
        &self.query
    }

    /// The header `name`, when it is visible ASCII.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    /// The body as JSON `T`; an empty body is `{}`.
    pub(crate) fn json<T: DeserializeOwned>(&self) -> Result<T, Problem> {
        let body: &[u8] = if self.body.iter().all(u8::is_ascii_whitespace) {
            b"{}"
        } else {
            &self.body
        };
        serde_json::from_slice(body)
            .map_err(|error| Problem::bad_request("invalid_body", format!("request body: {error}")))
    }

    /// 403 `role_required` unless the caller has `role`. For calls whose body decides the role
    /// they need (`x-role-note`).
    pub(crate) fn require(&self, role: Role) -> Result<(), Problem> {
        if self.role >= role {
            Ok(())
        } else {
            Err(Problem::role_required(role))
        }
    }

    pub(crate) const fn listener(&self) -> Listener {
        self.listener
    }

    /// Turns true when the connection is closing; an event stream ends on it.
    pub(crate) fn closing(&self) -> watch::Receiver<bool> {
        self.closing.clone()
    }
}

/// Percent-decodes a path segment (`plus` false) or a query key or value (`plus` true, `+` is a
/// space).
fn decode(text: &str, plus: bool) -> Result<String, Problem> {
    let invalid = || Problem::usage("the path or query is not percent-encoded UTF-8");
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.bytes();
    while let Some(byte) = rest.next() {
        bytes.push(match byte {
            b'+' if plus => b' ',
            b'%' => {
                let digits = [
                    rest.next().ok_or_else(invalid)?,
                    rest.next().ok_or_else(invalid)?,
                ];
                std::str::from_utf8(&digits)
                    .ok()
                    .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                    .ok_or_else(invalid)?
            }
            other => other,
        });
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}

/// Counts a request, or an event stream, while it is answered.
pub(crate) struct InFlight(Arc<AtomicU64>);

impl InFlight {
    fn new(count: &Arc<AtomicU64>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(count))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What handlers share: the limits, the counts and the creates in progress.
pub(crate) struct Context {
    limits: ApiLimits,
    served: Cell<u64>,
    in_flight: Arc<AtomicU64>,
    refused: Cell<u64>,
    in_progress: InProgress,
}

impl Context {
    pub(crate) fn requests(&self) -> RequestsReport {
        RequestsReport {
            served: self.served.get(),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            refused: self.refused.get(),
        }
    }

    /// Counts an answer that goes on after its handler returned, an event stream, until the
    /// guard drops.
    pub(crate) fn in_flight(&self) -> InFlight {
        InFlight::new(&self.in_flight)
    }

    pub(crate) const fn in_progress(&self) -> &InProgress {
        &self.in_progress
    }
}

/// The API over the wallet `owner` holds.
pub(crate) struct Api<'o, O: Owner> {
    owner: &'o O,
    context: Context,
    /// Turns true when serve stops: connections close once their answer is out.
    stop: watch::Receiver<bool>,
    /// The wallet's data directory, where `api-clients` lists the TLS clients.
    data_dir: PathBuf,
    /// The run a command forwarded to the socket must share.
    caller: Caller,
    router: spec::Router,
}

impl<'o, O: Owner> Api<'o, O> {
    pub(crate) fn new(
        owner: &'o O,
        limits: ApiLimits,
        stop: watch::Receiver<bool>,
        data_dir: PathBuf,
        caller: Caller,
    ) -> Self {
        Self {
            owner,
            context: Context {
                limits,
                served: Cell::new(0),
                in_flight: Arc::new(AtomicU64::new(0)),
                refused: Cell::new(0),
                in_progress: InProgress::default(),
            },
            stop,
            data_dir,
            caller,
            router: spec::Router::new(),
        }
    }

    pub(crate) const fn limits(&self) -> &ApiLimits {
        &self.context.limits
    }

    pub(crate) const fn context(&self) -> &Context {
        &self.context
    }

    /// Counts a connection closed unanswered.
    pub(crate) fn refuse(&self) {
        let refused = &self.context.refused;
        refused.set(refused.get().saturating_add(1));
    }

    /// Answers the requests on `stream` until the client closes it or serve stops, and on the
    /// TLS listener until the connection's age limit. `client` is the TLS client's key, checked
    /// against `api-clients` again on each request; the socket has none.
    pub(crate) async fn connection<S>(
        &self,
        stream: S,
        listener: Listener,
        client: Option<Fingerprint>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (closing, closed) = watch::channel(false);
        let service = service_fn(move |request| {
            let closed = closed.clone();
            async move { Ok::<_, Infallible>(self.answer(request, listener, client, closed).await) }
        });
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(self.limits().header_timeout)
            .serve_connection(TokioIo::new(stream), service);
        tokio::pin!(connection);
        let mut stop = self.stop.clone();
        let aged = async {
            match listener {
                Listener::Tls => tokio::time::sleep(self.limits().tls_max_age).await,
                Listener::Socket => std::future::pending().await,
            }
        };
        let ended = tokio::select! {
            result = connection.as_mut() => Some(result),
            // Not the guard `wait_for` returns: held through the drain, it would block serve's
            // own stop.
            _ = async { stop.wait_for(|stopped| *stopped).await.map(drop) } => None,
            () = aged => None,
        };
        let result = match ended {
            Some(result) => result,
            None => {
                // Ends an event stream, whose answer has no end of its own.
                closing.send_replace(true);
                connection.as_mut().graceful_shutdown();
                connection.await
            }
        };
        if let Err(error) = result {
            tracing::debug!(error = %lepic_telemetry::ErrorChain(&error), "api connection ended");
        }
    }

    async fn answer(
        &self,
        request: hyper::Request<Incoming>,
        listener: Listener,
        client: Option<Fingerprint>,
        closing: watch::Receiver<bool>,
    ) -> Response<Body> {
        let guard = self.context.in_flight();
        let role = match client {
            None => Some(Role::Full),
            Some(client) => self.role_of(client),
        };
        let mut response = match role {
            None => {
                let mut response = problem(&Problem::no_longer_listed());
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                response
            }
            Some(role) => self
                .route(request, listener, role, closing)
                .await
                .unwrap_or_else(|error| problem(&error)),
        };
        drop(guard);
        let served = &self.context.served;
        served.set(served.get().saturating_add(1));
        response.headers_mut().insert(
            caller::VERSION_HEADER,
            HeaderValue::from_static(caller::VERSION),
        );
        response
    }

    /// The role `api-clients` gives the TLS client `client`; `None` when it does not list it.
    /// An unreadable file lists none.
    fn role_of(&self, client: Fingerprint) -> Option<Role> {
        match Clients::read(&self.data_dir) {
            Ok(clients) => clients.role(client),
            Err(error) => {
                tracing::warn!(
                    error = %lepic_telemetry::ErrorChain(&error),
                    "api-clients is unreadable, so every client is refused"
                );
                None
            }
        }
    }

    async fn route(
        &self,
        request: hyper::Request<Incoming>,
        listener: Listener,
        role: Role,
        closing: watch::Receiver<bool>,
    ) -> Result<Response<Body>, Problem> {
        if listener == Listener::Socket {
            self.caller.check(request.headers())?;
            // The CLI's private channel: not an operation of the API document.
            if request.method() == Method::POST && request.uri().path() == CLI_RUN {
                let request = self
                    .request(request, Vec::new(), role, listener, closing)
                    .await?;
                return self.owner.command_line(request).await;
            }
        }
        let (operation, params) = self.router.find(request.method(), request.uri().path())?;
        if operation.socket_only && listener == Listener::Tls {
            return Err(Problem::socket_only());
        }
        if role < operation.role {
            return Err(Problem::role_required(operation.role));
        }
        let op = operation.op;
        let request = self
            .request(request, params, role, listener, closing)
            .await?;
        self.owner.operate(op, request, &self.context).await
    }

    /// `request` with its query and body read, as a routed request.
    async fn request(
        &self,
        request: hyper::Request<Incoming>,
        params: Vec<(String, String)>,
        role: Role,
        listener: Listener,
        closing: watch::Receiver<bool>,
    ) -> Result<Request, Problem> {
        let query = Query::parse(request.uri().query())?;
        let headers = request.headers().clone();
        let body = self.body(request).await?;
        Ok(Request {
            params,
            query,
            headers,
            body,
            role,
            listener,
            closing,
        })
    }

    /// The request body, within the size limit and the body deadline.
    async fn body(&self, request: hyper::Request<Incoming>) -> Result<Zeroizing<Vec<u8>>, Problem> {
        let max = self.limits().max_body;
        let declared = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|length| length.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX)) {
            return Err(Problem::too_large());
        }
        let body = Limited::new(request.into_body(), max).collect();
        match tokio::time::timeout(self.limits().body_timeout, body).await {
            Ok(Ok(collected)) => Ok(Zeroizing::new(collected.to_bytes().to_vec())),
            Ok(Err(error)) if error.downcast_ref::<LengthLimitError>().is_some() => {
                Err(Problem::too_large())
            }
            Ok(Err(error)) => Err(Problem::usage(format!("request body: {error}"))),
            Err(_) => Err(Problem::too_slow()),
        }
    }
}

/// A response with `body` of `content_type`.
pub(crate) fn response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> Response<Body> {
    let mut response: Response<Body> = Response::new(Box::pin(Full::new(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

/// `value` as JSON, with `status`.
pub(crate) fn json(status: StatusCode, value: &impl Serialize) -> Result<Response<Body>, Problem> {
    let mut body = serde_json::to_vec(value)
        .map_err(|error| Problem::of(Category::Internal, "internal", format!("answer: {error}")))?;
    body.push(b'\n');
    Ok(response(status, "application/json", body.into()))
}

/// 200 with `value`.
pub(crate) fn ok(value: &impl Serialize) -> Result<Response<Body>, Problem> {
    json(StatusCode::OK, value)
}

/// 201 with the object a create made.
pub(crate) fn created(value: &impl Serialize) -> Result<Response<Body>, Problem> {
    json(StatusCode::CREATED, value)
}

/// 202 with the object of work that goes on.
pub(crate) fn accepted(value: &impl Serialize) -> Result<Response<Body>, Problem> {
    json(StatusCode::ACCEPTED, value)
}

/// 204.
pub(crate) fn no_content() -> Result<Response<Body>, Problem> {
    let mut response: Response<Body> = Response::new(Box::pin(Full::new(Bytes::new())));
    *response.status_mut() = StatusCode::NO_CONTENT;
    Ok(response)
}

/// The problem document of `problem`, with `Allow` on a 405 and `Retry-After` when it is worth
/// trying again.
pub(crate) fn problem(problem: &Problem) -> Response<Body> {
    // Serializing this plain struct cannot fail.
    let mut body = serde_json::to_vec(problem).unwrap_or_default();
    body.push(b'\n');
    let mut response = response(problem.status(), "application/problem+json", body.into());
    let headers = response.headers_mut();
    if let Some(allow) = problem
        .allow()
        .and_then(|allow| HeaderValue::from_str(allow).ok())
    {
        headers.insert(header::ALLOW, allow);
    }
    if let Some(seconds) = problem.retry_after() {
        headers.insert(header::RETRY_AFTER, HeaderValue::from(seconds));
    }
    response
}
