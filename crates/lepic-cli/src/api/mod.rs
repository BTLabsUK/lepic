// SPDX-License-Identifier: Apache-2.0
//! The wallet API `lepic serve` answers on its socket, and with `--owner-tls` on a TLS listener
//! too: HTTP/1.1 with JSON bodies, described by one OpenAPI document (ADR 0050). A handler turns
//! a request into the arguments of a CLI command and answers with that command's JSON report.
//!
//! Adding a route: write its handler in `routes`, with `#[utoipa::path]` and a doc comment, and
//! name it in [`api!`]. The router and the document are both built from that list. A route whose
//! operation has the [`SOCKET_ONLY`] extension is refused on the TLS listener.
//!
//! A request with `Accept: text/plain` gets the report as the text `lepic` prints without
//! `--output json`; `lepic` asks for it when it runs a command through a running serve
//! (ADR 0053).

mod caller;
mod events;
mod openapi;
mod problem;
mod routes;
mod tls;

use std::cell::Cell;
use std::convert::Infallible;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use lepic_wallet::event::Event;
use lepic_wallet::slate::WireSlate;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

pub(crate) use caller::{Caller, VERSION, VERSION_HEADER};
pub(crate) use events::epicbox_state;
pub(crate) use problem::Problem;
pub(crate) use tls::OwnerTls;

use openapi::{Problems, Security};

use crate::api_clients::{Clients, Fingerprint};
use crate::app_config::ApiLimits;
use crate::cli::Command;
use crate::exit::CliError;
use crate::output::{Report, RequestsReport, render};
use crate::settings::OutputFormat;

/// The routes, in the order the document lists their operations.
macro_rules! api {
    ($($route:ident),* $(,)?) => {
        /// The OpenAPI document of the wallet API.
        #[derive(utoipa::OpenApi)]
        #[openapi(
            info(
                title = "LEPIC wallet API",
                version = "1.0.0",
                description = "The owner API of `lepic serve`, on its Unix socket, and the \
                    payment endpoint of `lepic serve --http`. Response bodies are the JSON \
                    `lepic --output json` prints. Amounts are decimal strings in EPIC. The owner \
                    routes are answered on the socket to its own user, and with `--owner-tls` \
                    over mutual TLS to the clients `api-clients` lists; an operation marked \
                    `x-socket-only` is refused over TLS. A request with `Accept: text/plain` \
                    gets a report as the text `lepic` prints without `--output json`; errors \
                    are problem documents either way.",
                license(name = "Apache-2.0"),
            ),
            paths(
                openapi::foreign::foreign,
                openapi::peer::peer_info,
                openapi::peer::peer_slates,
                $(routes::$route),*
            ),
            tags(
                (
                    name = "legacy",
                    description = "Receiving V2 and V3 slates from Epic wallets over the \
                        JSON-RPC foreign API (ADR 0052), and slate envelopes from LEPIC wallets \
                        at the native endpoint.",
                ),
            ),
            components(schemas(Problem)),
            modifiers(&Problems, &Security),
        )]
        pub(crate) struct Document;

        const HANDLERS: &[(&str, Handler)] = &[$((stringify!($route), {
            fn handler<'a>(api: &'a Api<'a>, request: Request) -> Answer<'a> {
                Box::pin(routes::$route(api, request))
            }
            handler
        })),*];
    };
}

api!(
    openapi_document,
    status,
    methods,
    events,
    wallet_info,
    wallet_address,
    change_password,
    outputs,
    node_status,
    transactions,
    transaction,
    send,
    receive,
    finalize,
    transaction_cancel,
    transaction_release,
    transaction_post,
    wallet_scan,
    epicbox_status,
    epicbox_peer,
    peer_pins,
    peer_pin_forget,
    profile_show,
    profile_set,
    profile_domain,
    profile_domain_file,
    profile_domain_attach,
    contacts,
    contact_remove,
    contact_update,
    contact_invite,
    contact_request,
    contact_requests,
    contact_request_accept,
    contact_request_dismiss,
    contact_request_cancel,
    contact_preview,
    contact_accept,
    contact_enter,
    contact_collect,
    contact_sas,
    contact_check,
    contact_key_check,
    contact_keys,
    contact_move,
    contact_move_home,
    contact_card,
    contact_scan_card,
    contact_quarantine,
    contact_invoices,
    contact_export,
    contact_import,
    payload_post,
    payloads,
    payload_ack,
    in_person_invoice,
    in_person_send,
    in_person_read,
    in_person_pay,
    in_person_receive,
    in_person_post,
    in_person_take,
    in_person_answers,
    in_person_finalize,
    epic1_address,
    epic1_new_address,
    epic1_issue_here,
    epic1_addresses,
    epic1_link,
    epic1_links,
    epic1_retire,
    epic1_read,
    epic1_pay,
    epic1_post_next,
    epic1_answers,
    epic1_post_answer,
    epic1_restore,
    epictx_open,
);

tokio::task_local! {
    /// Whether the request being answered asked for its report as text (`Accept: text/plain`).
    static TEXT: bool;
}

/// Whether `headers` ask for the report as text: `text/plain` is the first media type `Accept`
/// lists.
fn wants_text(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|accept| accept.to_str().ok())
        .and_then(|accept| accept.split(',').next())
        .and_then(|first| first.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/plain"))
}

/// The operation extension that keeps a route off the TLS listener.
const SOCKET_ONLY: &str = "x-socket-only";

/// Where a connection came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Listener {
    Socket,
    Tls,
}

type Body = UnsyncBoxBody<Bytes, Infallible>;
type Answer<'a> = Pin<Box<dyn Future<Output = Result<Response<Body>, Problem>> + 'a>>;
type Handler = for<'a> fn(&'a Api<'a>, Request) -> Answer<'a>;

/// What a request asks of the wallet serve holds.
pub(crate) enum Call {
    /// A CLI command, run as `lepic` runs it.
    Command(Command),
    Receive {
        wire: WireSlate,
        account: String,
        message: Option<String>,
    },
    Finalize {
        wire: WireSlate,
        fluff: bool,
    },
    Password {
        current: Zeroizing<String>,
        new: Zeroizing<String>,
    },
    /// `contact export`, answering the backup document instead of writing a file.
    ContactExport,
    /// `contact import`, from the backup document instead of a file.
    ContactImport {
        document: String,
    },
    /// The methods the registry holds, read when asked.
    Methods,
    /// `profile domain file`, answering the file's text instead of writing it.
    DomainFile {
        relays: Vec<String>,
    },
}

/// The wallet behind the API.
pub(crate) trait Owner {
    fn call(&self, call: Call) -> Pin<Box<dyn Future<Output = Result<Report, CliError>> + '_>>;
    fn events(&self) -> broadcast::Receiver<Event>;
    /// What to try after `error`, as `lepic` prints it after the error for people.
    fn hint(&self, error: &CliError) -> Option<String>;
    fn status(&self, requests: RequestsReport) -> Result<Report, CliError>;
}

/// A request, routed: its path parameters, query and body, and the listener it came in on.
pub(crate) struct Request {
    params: Vec<(String, String)>,
    query: Option<String>,
    /// Wiped when the request is done: a body can hold a password or a slate.
    body: Zeroizing<Vec<u8>>,
    listener: Listener,
    /// Turns true when its connection is closing: serve stops, or a TLS connection reached its
    /// age limit.
    closing: watch::Receiver<bool>,
}

impl Request {
    fn param(&self, name: &str) -> Result<&str, Problem> {
        self.params
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
            .ok_or_else(|| Problem::usage(format!("missing path parameter {name}")))
    }

    /// The query string, as `T`'s fields; every value is a string.
    fn query<T: DeserializeOwned>(&self) -> Result<T, Problem> {
        let mut fields = serde_json::Map::new();
        for pair in self.query.iter().flat_map(|query| query.split('&')) {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let (key, value) = (decode(key)?, decode(value)?);
            if fields.contains_key(&key) {
                return Err(Problem::usage(format!("query parameter {key} given twice")));
            }
            fields.insert(key, serde_json::Value::String(value));
        }
        serde_json::from_value(serde_json::Value::Object(fields))
            .map_err(|error| Problem::usage(format!("query: {error}")))
    }

    /// The body, as JSON `T`.
    fn json<T: DeserializeOwned>(&self) -> Result<T, Problem> {
        serde_json::from_slice(&self.body)
            .map_err(|error| Problem::usage(format!("request body: {error}")))
    }
}

/// Percent-decodes a query key or value, with `+` for a space.
fn decode(text: &str) -> Result<String, Problem> {
    let invalid = || Problem::usage("the query is not percent-encoded UTF-8");
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.bytes();
    while let Some(byte) = rest.next() {
        bytes.push(match byte {
            b'+' => b' ',
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

enum Segment {
    Literal(String),
    Param(String),
}

struct Operation {
    method: Method,
    handler: Handler,
    socket_only: bool,
}

struct Route {
    segments: Vec<Segment>,
    operations: Vec<Operation>,
}

impl Route {
    /// The path parameters, when `path` is this route's.
    fn matches(&self, path: &str) -> Option<Vec<(String, String)>> {
        let mut parts = path.strip_prefix('/')?.split('/');
        let mut params = Vec::new();
        for segment in &self.segments {
            let part = parts.next()?;
            match segment {
                Segment::Literal(literal) if literal == part => {}
                Segment::Literal(_) => return None,
                Segment::Param(_) if part.is_empty() => return None,
                Segment::Param(name) => params.push((name.clone(), decode(part).ok()?)),
            }
        }
        parts.next().is_none().then_some(params)
    }
}

/// The handlers by path and method, from the document's operations.
struct Router(Vec<Route>);

impl Router {
    fn new(document: &utoipa::openapi::OpenApi) -> Self {
        let operation = |method, operation: &Option<utoipa::openapi::path::Operation>| {
            let operation = operation.as_ref()?;
            let id = operation.operation_id.as_deref()?;
            let handler = HANDLERS
                .iter()
                .find_map(|(name, handler)| (*name == id).then_some(*handler))?;
            let socket_only = operation
                .extensions
                .as_ref()
                .and_then(|extensions| extensions.get(SOCKET_ONLY))
                .is_some_and(|value| *value == serde_json::Value::Bool(true));
            Some(Operation {
                method,
                handler,
                socket_only,
            })
        };
        let routes = document.paths.paths.iter().filter_map(|(path, item)| {
            let operations: Vec<_> = [
                (Method::GET, &item.get),
                (Method::PUT, &item.put),
                (Method::POST, &item.post),
                (Method::DELETE, &item.delete),
                (Method::PATCH, &item.patch),
            ]
            .into_iter()
            .filter_map(|(method, item)| operation(method, item))
            .collect();
            let segments = path
                .trim_start_matches('/')
                .split('/')
                .map(|segment| match segment.strip_prefix('{') {
                    Some(param) => Segment::Param(param.trim_end_matches('}').to_owned()),
                    None => Segment::Literal(segment.to_owned()),
                })
                .collect();
            (!operations.is_empty()).then_some(Route {
                segments,
                operations,
            })
        });
        Self(routes.collect())
    }

    fn find(
        &self,
        method: &Method,
        path: &str,
        listener: Listener,
    ) -> Result<(Handler, Vec<(String, String)>), Problem> {
        let (route, params) = self
            .0
            .iter()
            .find_map(|route| Some((route, route.matches(path)?)))
            .ok_or_else(Problem::not_found)?;
        match route.operations.iter().find(|known| known.method == method) {
            Some(operation) if operation.socket_only && listener == Listener::Tls => {
                Err(Problem::socket_only())
            }
            Some(operation) => Ok((operation.handler, params)),
            None => {
                let allow: Vec<_> = route
                    .operations
                    .iter()
                    .map(|known| known.method.as_str())
                    .collect();
                Err(Problem::method_not_allowed(allow.join(", ")))
            }
        }
    }
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

/// The API over the wallet `owner` holds, with its counts.
pub(crate) struct Api<'o> {
    owner: &'o dyn Owner,
    limits: ApiLimits,
    /// Turns true when serve stops: connections close once their answer is out.
    stop: watch::Receiver<bool>,
    /// The wallet's data directory, where `api-clients` lists the TLS clients.
    data_dir: PathBuf,
    /// The run a command forwarded to the socket must share.
    caller: Caller,
    router: Router,
    /// The OpenAPI document, rendered once.
    document: Bytes,
    served: Cell<u64>,
    in_flight: Arc<AtomicU64>,
    refused: Cell<u64>,
}

impl<'o> Api<'o> {
    pub(crate) fn new(
        owner: &'o dyn Owner,
        limits: ApiLimits,
        stop: watch::Receiver<bool>,
        data_dir: PathBuf,
        caller: Caller,
    ) -> Self {
        Self {
            owner,
            limits,
            stop,
            data_dir,
            caller,
            router: Router::new(&openapi::document()),
            document: openapi::rendered(),
            served: Cell::new(0),
            in_flight: Arc::new(AtomicU64::new(0)),
            refused: Cell::new(0),
        }
    }

    pub(crate) const fn limits(&self) -> &ApiLimits {
        &self.limits
    }

    pub(crate) fn requests(&self) -> RequestsReport {
        RequestsReport {
            served: self.served.get(),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            refused: self.refused.get(),
        }
    }

    /// Counts a connection closed unanswered.
    pub(crate) fn refuse(&self) {
        self.refused.set(self.refused.get().saturating_add(1));
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
            .header_read_timeout(self.limits.header_timeout)
            .serve_connection(TokioIo::new(stream), service);
        tokio::pin!(connection);
        let mut stop = self.stop.clone();
        let aged = async {
            match listener {
                Listener::Tls => tokio::time::sleep(self.limits.tls_max_age).await,
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
        let guard = InFlight::new(&self.in_flight);
        let response = match client {
            Some(client) if !self.lists(client) => {
                let mut response = problem(&Problem::no_longer_listed());
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                response
            }
            _ => self
                .route(request, listener, closing)
                .await
                .unwrap_or_else(|error| problem(&error)),
        };
        drop(guard);
        self.served.set(self.served.get().saturating_add(1));
        let mut response = response;
        response.headers_mut().insert(
            caller::VERSION_HEADER,
            HeaderValue::from_static(caller::VERSION),
        );
        response
    }

    /// Whether `api-clients` still lists the TLS client `client`. An unreadable file lists none.
    fn lists(&self, client: Fingerprint) -> bool {
        match Clients::read(&self.data_dir) {
            Ok(clients) => clients.lists(client),
            Err(error) => {
                tracing::warn!(
                    error = %lepic_telemetry::ErrorChain(&error),
                    "api-clients is unreadable, so every client is refused"
                );
                false
            }
        }
    }

    async fn route(
        &self,
        request: hyper::Request<Incoming>,
        listener: Listener,
        closing: watch::Receiver<bool>,
    ) -> Result<Response<Body>, Problem> {
        if listener == Listener::Socket {
            self.caller.check(request.headers())?;
        }
        let (handler, params) =
            self.router
                .find(request.method(), request.uri().path(), listener)?;
        let query = request.uri().query().map(str::to_owned);
        let text = wants_text(request.headers());
        let body = self.body(request).await?;
        let answer = handler(
            self,
            Request {
                params,
                query,
                body,
                listener,
                closing,
            },
        );
        TEXT.scope(text, answer).await
    }

    /// The request body, within the size limit and the body deadline.
    async fn body(&self, request: hyper::Request<Incoming>) -> Result<Zeroizing<Vec<u8>>, Problem> {
        let max = self.limits.max_body;
        let declared = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|length| length.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX)) {
            return Err(Problem::too_large());
        }
        let body = Limited::new(request.into_body(), max).collect();
        match tokio::time::timeout(self.limits.body_timeout, body).await {
            Ok(Ok(collected)) => Ok(Zeroizing::new(collected.to_bytes().to_vec())),
            Ok(Err(error)) if error.downcast_ref::<LengthLimitError>().is_some() => {
                Err(Problem::too_large())
            }
            Ok(Err(error)) => Err(Problem::usage(format!("request body: {error}"))),
            Err(_) => Err(Problem::too_slow()),
        }
    }

    /// The problem document for `error`. It carries the hint only when the request asked for
    /// text: the hint is for people, and the JSON error has none.
    fn failed(&self, error: CliError) -> Problem {
        let hint = if TEXT.try_with(|text| *text).unwrap_or(false) {
            self.owner.hint(&error)
        } else {
            None
        };
        Problem::from(error).with_hint(hint)
    }

    async fn run(&self, call: Call) -> Result<Response<Body>, Problem> {
        match self.owner.call(call).await {
            Ok(done) => Ok(report(&done)),
            Err(error) => Err(self.failed(error)),
        }
    }
}

fn response(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Body> {
    let mut response = Response::new(Full::new(body).boxed_unsync());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

/// A command's report, as `--output json` prints it, or as text when the request asked for it.
fn report(report: &Report) -> Response<Body> {
    if TEXT.try_with(|text| *text).unwrap_or(false) {
        let text = render(report, OutputFormat::Human);
        let body = Bytes::copy_from_slice(text.as_bytes());
        return response(StatusCode::OK, "text/plain; charset=utf-8", body);
    }
    let text = render(report, OutputFormat::Json);
    let body = Bytes::copy_from_slice(text.as_bytes());
    response(StatusCode::OK, "application/json", body)
}

fn problem(problem: &Problem) -> Response<Body> {
    // Serializing this plain struct cannot fail.
    let mut body = serde_json::to_vec(problem).unwrap_or_default();
    body.push(b'\n');
    let mut response = response(problem.status(), "application/problem+json", body.into());
    if let Some(allow) = problem
        .allow
        .as_deref()
        .and_then(|allow| HeaderValue::from_str(allow).ok())
    {
        response.headers_mut().insert(header::ALLOW, allow);
    }
    response
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn every_handler_has_a_route_and_only_the_payment_endpoints_have_none() {
        let document = openapi::document();
        let router = Router::new(&document);
        for (name, _) in HANDLERS {
            let routed = document.paths.paths.values().any(|item| {
                [&item.get, &item.put, &item.post, &item.delete, &item.patch]
                    .into_iter()
                    .flatten()
                    .any(|operation| operation.operation_id.as_deref() == Some(*name))
            });
            assert!(routed, "{name} is not in the document");
        }
        let unrouted: Vec<_> = document
            .paths
            .paths
            .keys()
            .filter(|path| {
                router
                    .find(&Method::GET, path, Listener::Socket)
                    .is_err_and(|p| p.status() == StatusCode::NOT_FOUND)
            })
            .filter(|path| {
                router
                    .find(&Method::POST, path, Listener::Socket)
                    .is_err_and(|p| p.status() == StatusCode::NOT_FOUND)
            })
            .collect();
        assert_eq!(unrouted, ["/v1/peer", "/v1/peer/slates", "/v2/foreign"]);
    }

    #[test]
    fn a_path_parameter_is_matched_and_a_wrong_method_names_the_allowed_ones() {
        let router = Router::new(&openapi::document());
        let (_, params) = router
            .find(&Method::GET, "/v1/transactions/7", Listener::Socket)
            .unwrap();
        assert_eq!(params, [("tx_id".to_owned(), "7".to_owned())]);
        let refused = router
            .find(&Method::DELETE, "/v1/transactions", Listener::Socket)
            .err()
            .unwrap();
        assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            refused.allow.as_deref().map(String::as_str),
            Some("GET, POST")
        );
        assert!(
            router
                .find(&Method::GET, "/v1/transactions/", Listener::Socket)
                .is_err()
        );
        assert!(
            router
                .find(&Method::GET, "/v1/nothing", Listener::Socket)
                .is_err()
        );
    }

    #[test]
    fn a_literal_contact_route_wins_over_the_id_route() {
        let router = Router::new(&openapi::document());
        let (_, params) = router
            .find(&Method::GET, "/v1/contacts/quarantine", Listener::Socket)
            .unwrap();
        assert!(params.is_empty());
        let (_, params) = router
            .find(&Method::DELETE, "/v1/contacts/ab12", Listener::Socket)
            .unwrap();
        assert_eq!(params, [("id".to_owned(), "ab12".to_owned())]);
        let (_, params) = router
            .find(&Method::PATCH, "/v1/contacts/ab12", Listener::Socket)
            .unwrap();
        assert_eq!(params, [("id".to_owned(), "ab12".to_owned())]);
    }

    #[test]
    fn the_tls_listener_refuses_the_password_and_contact_backup_routes() {
        let router = Router::new(&openapi::document());
        let routes = [
            (Method::PUT, "/v1/wallet/password"),
            (Method::POST, "/v1/contacts/export"),
            (Method::POST, "/v1/contacts/import"),
        ];
        for (method, path) in &routes {
            let refused = router.find(method, path, Listener::Tls).err().unwrap();
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
            assert!(
                router.find(method, path, Listener::Socket).is_ok(),
                "{path}"
            );
        }
        let socket_only = router
            .0
            .iter()
            .flat_map(|route| &route.operations)
            .filter(|operation| operation.socket_only)
            .count();
        assert_eq!(socket_only, routes.len());
    }

    #[test]
    fn a_query_is_percent_decoded() {
        let request = Request {
            params: Vec::new(),
            query: Some("account=my+savings%21".to_owned()),
            body: Zeroizing::new(Vec::new()),
            listener: Listener::Socket,
            closing: watch::channel(false).1,
        };
        let fields: std::collections::BTreeMap<String, String> = request.query().unwrap();
        assert_eq!(fields["account"], "my savings!");
        assert!(decode("%zz").is_err());
    }
}
