// SPDX-License-Identifier: Apache-2.0
//! The wallet API `lepic serve` answers on its socket: HTTP/1.1 with JSON bodies, described by
//! one OpenAPI document (ADR 0050). A handler turns a request into the arguments of a CLI
//! command and answers with that command's JSON report.
//!
//! Adding a route: write its handler in `routes`, with `#[utoipa::path]` and a doc comment, and
//! name it in [`api!`]. The router and the document are both built from that list.

mod events;
mod openapi;
mod problem;
mod routes;

use std::cell::Cell;
use std::convert::Infallible;
use std::future::Future;
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
use tokio::net::UnixStream;
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

pub(crate) use events::epicbox_state;
pub(crate) use problem::Problem;

use openapi::Problems;

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
                    `lepic --output json` prints. Amounts are decimal strings in EPIC.",
                license(name = "Apache-2.0"),
            ),
            paths(openapi::foreign::foreign, $(routes::$route),*),
            components(schemas(Problem)),
            modifiers(&Problems),
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
);

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
}

/// The wallet behind the API.
pub(crate) trait Owner {
    fn call(&self, call: Call) -> Pin<Box<dyn Future<Output = Result<Report, CliError>> + '_>>;
    fn events(&self) -> broadcast::Receiver<Event>;
    fn status(&self, requests: RequestsReport) -> Result<Report, CliError>;
}

/// A request, routed: its path parameters, query and body.
pub(crate) struct Request {
    params: Vec<(String, String)>,
    query: Option<String>,
    body: Bytes,
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

struct Route {
    segments: Vec<Segment>,
    methods: Vec<(Method, Handler)>,
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
        let handler = |operation: &Option<utoipa::openapi::path::Operation>| {
            let id = operation.as_ref()?.operation_id.as_deref()?;
            HANDLERS
                .iter()
                .find_map(|(name, handler)| (*name == id).then_some(*handler))
        };
        let routes = document.paths.paths.iter().filter_map(|(path, item)| {
            let methods: Vec<_> = [
                (Method::GET, &item.get),
                (Method::PUT, &item.put),
                (Method::POST, &item.post),
                (Method::DELETE, &item.delete),
                (Method::PATCH, &item.patch),
            ]
            .into_iter()
            .filter_map(|(method, operation)| Some((method, handler(operation)?)))
            .collect();
            let segments = path
                .trim_start_matches('/')
                .split('/')
                .map(|segment| match segment.strip_prefix('{') {
                    Some(param) => Segment::Param(param.trim_end_matches('}').to_owned()),
                    None => Segment::Literal(segment.to_owned()),
                })
                .collect();
            (!methods.is_empty()).then_some(Route { segments, methods })
        });
        Self(routes.collect())
    }

    fn find(
        &self,
        method: &Method,
        path: &str,
    ) -> Result<(Handler, Vec<(String, String)>), Problem> {
        let (route, params) = self
            .0
            .iter()
            .find_map(|route| Some((route, route.matches(path)?)))
            .ok_or_else(Problem::not_found)?;
        match route.methods.iter().find(|(known, _)| known == method) {
            Some((_, handler)) => Ok((*handler, params)),
            None => {
                let allow: Vec<_> = route
                    .methods
                    .iter()
                    .map(|(known, _)| known.as_str())
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
    ) -> Self {
        Self {
            owner,
            limits,
            stop,
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

    /// Answers the requests on `stream` until the client closes it or serve stops.
    pub(crate) async fn connection(&self, stream: UnixStream) {
        let service =
            service_fn(|request| async move { Ok::<_, Infallible>(self.answer(request).await) });
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(self.limits.header_timeout)
            .serve_connection(TokioIo::new(stream), service);
        tokio::pin!(connection);
        let mut stop = self.stop.clone();
        let result = tokio::select! {
            result = connection.as_mut() => result,
            // Not the guard `wait_for` returns: held through the drain, it would block serve's
            // own stop.
            _ = async { stop.wait_for(|stopped| *stopped).await.map(drop) } => {
                connection.as_mut().graceful_shutdown();
                connection.await
            }
        };
        if let Err(error) = result {
            tracing::debug!(error = %lepic_telemetry::ErrorChain(&error), "api connection ended");
        }
    }

    async fn answer(&self, request: hyper::Request<Incoming>) -> Response<Body> {
        let guard = InFlight::new(&self.in_flight);
        let response = self
            .route(request)
            .await
            .unwrap_or_else(|error| problem(&error));
        drop(guard);
        self.served.set(self.served.get().saturating_add(1));
        response
    }

    async fn route(&self, request: hyper::Request<Incoming>) -> Result<Response<Body>, Problem> {
        let (handler, params) = self.router.find(request.method(), request.uri().path())?;
        let query = request.uri().query().map(str::to_owned);
        let body = self.body(request).await?;
        handler(
            self,
            Request {
                params,
                query,
                body,
            },
        )
        .await
    }

    /// The request body, within the size limit and the body deadline.
    async fn body(&self, request: hyper::Request<Incoming>) -> Result<Bytes, Problem> {
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
            Ok(Ok(collected)) => Ok(collected.to_bytes()),
            Ok(Err(error)) if error.downcast_ref::<LengthLimitError>().is_some() => {
                Err(Problem::too_large())
            }
            Ok(Err(error)) => Err(Problem::usage(format!("request body: {error}"))),
            Err(_) => Err(Problem::too_slow()),
        }
    }

    async fn run(&self, call: Call) -> Result<Response<Body>, Problem> {
        Ok(report(&self.owner.call(call).await?))
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

/// A command's report, as `--output json` prints it.
fn report(report: &Report) -> Response<Body> {
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
    fn every_handler_has_a_route_and_only_the_payment_endpoint_has_none() {
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
                    .find(&Method::GET, path)
                    .is_err_and(|p| p.status() == StatusCode::NOT_FOUND)
            })
            .filter(|path| {
                router
                    .find(&Method::POST, path)
                    .is_err_and(|p| p.status() == StatusCode::NOT_FOUND)
            })
            .collect();
        assert_eq!(unrouted, ["/v2/foreign"]);
    }

    #[test]
    fn a_path_parameter_is_matched_and_a_wrong_method_names_the_allowed_ones() {
        let router = Router::new(&openapi::document());
        let (_, params) = router.find(&Method::GET, "/v1/transactions/7").unwrap();
        assert_eq!(params, [("tx_id".to_owned(), "7".to_owned())]);
        let refused = router
            .find(&Method::DELETE, "/v1/transactions")
            .err()
            .unwrap();
        assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(refused.allow.as_deref(), Some("GET, POST"));
        assert!(router.find(&Method::GET, "/v1/transactions/").is_err());
        assert!(router.find(&Method::GET, "/v1/nothing").is_err());
    }

    #[test]
    fn a_query_is_percent_decoded() {
        let request = Request {
            params: Vec::new(),
            query: Some("account=my+savings%21".to_owned()),
            body: Bytes::new(),
        };
        let fields: std::collections::BTreeMap<String, String> = request.query().unwrap();
        assert_eq!(fields["account"], "my savings!");
        assert!(decode("%zz").is_err());
    }
}
