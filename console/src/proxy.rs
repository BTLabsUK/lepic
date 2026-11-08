// SPDX-License-Identifier: Apache-2.0
//! The page, its assets, and the API routes the page may call, forwarded to serve's socket.

use std::path::{Path, PathBuf};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use crate::policy::{self, Refusal};

const INDEX: &str = include_str!("../ui/index.html");
const STYLE: &str = include_str!("../ui/console.css");
const SCRIPT: &str = include_str!("../ui/console.js");
const SCALAR: &str = include_str!("../ui/vendor/scalar.js");

/// Scripts and styles from the console itself, connections to it alone, no frames, no forms.
/// Inline styles are allowed because the API reference sets them from script.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; \
    connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The prefix under which the page reaches the proxied routes.
const API_PREFIX: &str = "/api";

type Body = BoxBody<Bytes, hyper::Error>;

/// The console: its own listen address, the socket of the serve it is a client of, and the
/// token the browser must present.
pub(crate) struct Console {
    listen: String,
    socket: PathBuf,
    token: String,
}

/// Why serve did not answer.
#[derive(Debug)]
enum Unreachable {
    Connect(std::io::Error),
    Http(hyper::Error),
    Request(hyper::http::Error),
}

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(error) => write!(f, "could not connect: {error}"),
            Self::Http(error) => write!(f, "{error}"),
            Self::Request(error) => write!(f, "{error}"),
        }
    }
}

impl Console {
    pub(crate) fn new(listen: String, socket: PathBuf, token: String) -> Self {
        Self {
            listen,
            socket,
            token,
        }
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// Answers one request, with the security headers on every response.
    pub(crate) async fn answer<B>(&self, request: Request<B>) -> Response<Body> {
        let mut response = if let Some(redirect) = self.accept_link(&request) {
            redirect
        } else {
            self.admitted(&request).await
        };
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }

    /// The redirect that hands the browser its cookie, for `GET /` with the launch token in the
    /// query and the console's own `Host`.
    fn accept_link<B>(&self, request: &Request<B>) -> Option<Response<Body>> {
        if request.method() != Method::GET
            || request.uri().path() != "/"
            || !policy::host_is_own(&self.listen, request.headers())
        {
            return None;
        }
        let offered = policy::query_token(request.uri().query())?;
        if !policy::same_token(offered, &self.token) {
            return None;
        }
        let mut response = with_body(
            StatusCode::SEE_OTHER,
            "text/plain; charset=utf-8",
            String::new(),
        );
        let headers = response.headers_mut();
        headers.insert(header::LOCATION, HeaderValue::from_static("/"));
        let cookie = format!(
            "{}={}; HttpOnly; SameSite=Strict; Path=/",
            policy::COOKIE_NAME,
            self.token
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            headers.insert(header::SET_COOKIE, value);
        }
        Some(response)
    }

    async fn admitted<B>(&self, request: &Request<B>) -> Response<Body> {
        match policy::admit(
            &self.listen,
            &self.token,
            request.method(),
            request.headers(),
        ) {
            Err(Refusal::WrongHost) => text(
                StatusCode::MISDIRECTED_REQUEST,
                "this console answers requests to its own address only",
            ),
            Err(Refusal::NoToken) => text(
                StatusCode::UNAUTHORIZED,
                "open the console with the link lepic-console printed",
            ),
            Err(Refusal::ForeignOrigin) => text(
                StatusCode::FORBIDDEN,
                "a write needs the console's own origin",
            ),
            Ok(()) => self.route(request).await,
        }
    }

    async fn route<B>(&self, request: &Request<B>) -> Response<Body> {
        let path = request.uri().path();
        if let Some(api_path) = path.strip_prefix(API_PREFIX) {
            return self
                .api(request.method(), api_path, request.uri().query())
                .await;
        }
        if request.method() != Method::GET {
            return text(StatusCode::METHOD_NOT_ALLOWED, "pages are read only");
        }
        match path {
            "/" => asset("text/html; charset=utf-8", INDEX),
            "/console.css" => asset("text/css; charset=utf-8", STYLE),
            "/console.js" => asset("text/javascript; charset=utf-8", SCRIPT),
            "/vendor/scalar.js" => asset("text/javascript; charset=utf-8", SCALAR),
            _ => text(StatusCode::NOT_FOUND, "no such page"),
        }
    }

    async fn api(&self, method: &Method, path: &str, query: Option<&str>) -> Response<Body> {
        if !policy::allowed(method, path) {
            return problem(
                StatusCode::NOT_FOUND,
                "not_found",
                "the console does not proxy this route",
            );
        }
        self.forward(method, path, query)
            .await
            .unwrap_or_else(|error| self.unreachable(&error))
    }

    /// Sends the request to serve on a fresh connection and streams its answer back, so an
    /// event stream flows as long as the browser listens.
    async fn forward(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> Result<Response<Body>, Unreachable> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(Unreachable::Connect)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(Unreachable::Http)?;
        tokio::spawn(connection);
        let uri = match query {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        };
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "lepic")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Empty::<Bytes>::new())
            .map_err(Unreachable::Request)?;
        let upstream = sender
            .send_request(request)
            .await
            .map_err(Unreachable::Http)?;
        let mut response = Response::builder().status(upstream.status());
        for name in [header::CONTENT_TYPE, header::CACHE_CONTROL] {
            if let Some(value) = upstream.headers().get(&name) {
                response = response.header(name, value);
            }
        }
        response
            .body(upstream.into_body().boxed())
            .map_err(Unreachable::Request)
    }

    fn unreachable(&self, error: &Unreachable) -> Response<Body> {
        problem(
            StatusCode::BAD_GATEWAY,
            "unreachable",
            &format!(
                "lepic serve did not answer at {}: {error}",
                self.socket.display()
            ),
        )
    }
}

fn asset(content_type: &'static str, content: &'static str) -> Response<Body> {
    let body = Full::new(Bytes::from_static(content.as_bytes()))
        .map_err(|never| match never {})
        .boxed();
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn text(status: StatusCode, message: &str) -> Response<Body> {
    with_body(status, "text/plain; charset=utf-8", message.to_owned())
}

/// A problem of the console's own, in the shape serve's problems have, so the page handles one.
fn problem(status: StatusCode, code: &str, detail: &str) -> Response<Body> {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": status.canonical_reason().unwrap_or_default(),
        "status": status.as_u16(),
        "detail": detail,
        "code": code,
    });
    with_body(status, "application/problem+json", body.to_string())
}

fn with_body(status: StatusCode, content_type: &'static str, body: String) -> Response<Body> {
    let body = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}
