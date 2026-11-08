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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::sync::{Arc, Mutex};

    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use tokio::net::UnixListener;

    use super::*;

    const LISTEN: &str = "127.0.0.1:7421";
    const TOKEN: &str = "0123456789abcdef";
    const COOKIE: &str = "lepic-console=0123456789abcdef";
    const SERVE_BODY: &str = r#"{"state":"running"}"#;

    /// A directory under the temp dir that is removed when the test ends.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("serve.sock"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    /// Serves a fixed JSON body on a Unix socket and records the path of every request.
    async fn stand_in(name: &str) -> (Console, Arc<Mutex<Vec<String>>>, Scratch) {
        let dir = std::env::temp_dir().join(format!("lepic-console-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let scratch = Scratch(dir.clone());
        let socket = dir.join("serve.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                        let recorded = Arc::clone(&recorded);
                        async move {
                            let path = request
                                .uri()
                                .path_and_query()
                                .map(ToString::to_string)
                                .unwrap_or_default();
                            recorded.lock().unwrap().push(path);
                            let mut response = Response::new(Full::new(Bytes::from(SERVE_BODY)));
                            response.headers_mut().insert(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            );
                            Ok::<_, hyper::Error>(response)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let console = Console::new(LISTEN.to_owned(), socket, TOKEN.to_owned());
        (console, seen, scratch)
    }

    fn get(uri: &str, cookie: Option<&str>) -> Request<Empty<Bytes>> {
        let mut builder = Request::builder().method(Method::GET).uri(uri);
        builder = builder.header(header::HOST, LISTEN);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder.body(Empty::new()).unwrap()
    }

    async fn body_of(response: Response<Body>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn an_allowed_route_is_forwarded_to_serve() {
        let (console, seen, _scratch) = stand_in("forward").await;
        let response = console
            .answer(get("/api/v1/status?verbose=1", Some(COOKIE)))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, SERVE_BODY);
        assert_eq!(*seen.lock().unwrap(), ["/v1/status?verbose=1"]);
    }

    #[tokio::test]
    async fn a_route_off_the_list_is_not_forwarded() {
        let (console, seen, _scratch) = stand_in("unlisted").await;
        let response = console.answer(get("/api/v1/nothing", Some(COOKIE))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_request_without_the_cookie_is_not_forwarded() {
        let (console, seen, _scratch) = stand_in("nocookie").await;
        let api = console.answer(get("/api/v1/status", None)).await;
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_of(api).await,
            "open the console with the link lepic-console printed"
        );
        let page = console.answer(get("/", None)).await;
        assert_eq!(page.status(), StatusCode::UNAUTHORIZED);
        let wrong = console
            .answer(get("/api/v1/status", Some("lepic-console=nope")))
            .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_printed_link_sets_the_cookie() {
        let (console, _seen, _scratch) = stand_in("link").await;
        let response = console.answer(get(&format!("/?token={TOKEN}"), None)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/");
        assert_eq!(
            response.headers()[header::SET_COOKIE],
            "lepic-console=0123456789abcdef; HttpOnly; SameSite=Strict; Path=/"
        );
        let page = console.answer(get("/", Some(COOKIE))).await;
        assert_eq!(page.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_wrong_token_in_the_link_gets_no_cookie() {
        let (console, _seen, _scratch) = stand_in("wrong").await;
        let response = console.answer(get("/?token=0123456789abcdee", None)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }
}
