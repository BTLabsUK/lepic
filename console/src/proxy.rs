// SPDX-License-Identifier: Apache-2.0
//! The page and its assets, the session exchange, and the API routes the page may call,
//! forwarded to serve's socket.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{self, HeaderMap, HeaderValue};
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

/// The route where the page trades the link token for a session.
const SESSION_PATH: &str = "/session";

/// How many sessions the console keeps; the oldest is dropped for a new one.
const MAX_SESSIONS: usize = 16;

type Body = BoxBody<Bytes, hyper::Error>;

/// The console: its own listen address, the socket of the serve it is a client of, and the
/// secrets it has handed out.
pub(crate) struct Console {
    listen: String,
    socket: PathBuf,
    state: Mutex<Admission>,
}

/// The link token that can be traded for a session now, and the sessions already traded.
struct Admission {
    link: String,
    sessions: VecDeque<String>,
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
    pub(crate) fn new(listen: String, socket: PathBuf, link: String) -> Self {
        Self {
            listen,
            socket,
            state: Mutex::new(Admission {
                link,
                sessions: VecDeque::new(),
            }),
        }
    }

    /// The link token that is valid now.
    pub(crate) fn link(&self) -> String {
        self.admission().link.clone()
    }

    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// The admission state. Never held across an await.
    fn admission(&self) -> MutexGuard<'_, Admission> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Answers one request, with the security headers on every response.
    pub(crate) async fn answer<B>(&self, request: Request<B>) -> Response<Body> {
        let mut response = self.route(&request).await;
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

    async fn route<B>(&self, request: &Request<B>) -> Response<Body> {
        let path = request.uri().path();
        if let Some(api_path) = path.strip_prefix(API_PREFIX) {
            let admitted = policy::admit_api(
                &self.listen,
                request.method(),
                request.headers(),
                |offered| self.is_session(offered),
            );
            return match admitted {
                Ok(()) => {
                    self.api(request.method(), api_path, request.uri().query())
                        .await
                }
                Err(refusal) => refused(&refusal),
            };
        }
        if path == SESSION_PATH {
            if request.method() != Method::POST {
                return text(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "the session is made with POST",
                );
            }
            return match policy::admit_exchange(&self.listen, request.headers()) {
                Ok(()) => self.exchange(request.headers()),
                Err(refusal) => refused(&refusal),
            };
        }
        if let Err(refusal) = policy::admit_page(&self.listen, request.headers()) {
            return refused(&refusal);
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

    /// Whether `offered` is one of the sessions handed out. Every stored session is compared.
    fn is_session(&self, offered: &str) -> bool {
        self.admission()
            .sessions
            .iter()
            .fold(false, |found, session| {
                policy::same_token(session, offered) | found
            })
    }

    /// Trades the link token for a session, once: the link is replaced by a new one, which is
    /// printed. The lock is held from the comparison to the replacement, so of concurrent
    /// exchanges of one link exactly one wins.
    fn exchange(&self, headers: &HeaderMap) -> Response<Body> {
        let mut admission = self.admission();
        let offered = policy::offered_link(headers).unwrap_or_default();
        if !policy::same_token(offered, &admission.link) {
            return text(StatusCode::UNAUTHORIZED, LINK_REFUSED);
        }
        let (session, link) = match (crate::draw_token(), crate::draw_token()) {
            (Ok(session), Ok(link)) => (session, link),
            (Err(error), _) | (_, Err(error)) => {
                return text(StatusCode::INTERNAL_SERVER_ERROR, &error);
            }
        };
        if admission.sessions.len() >= MAX_SESSIONS {
            admission.sessions.pop_front();
        }
        admission.sessions.push_back(session.clone());
        admission.link = link;
        eprintln!(
            "lepic-console: the link was used; for another tab open http://{}/#token={}",
            self.listen, admission.link
        );
        drop(admission);
        let body = serde_json::json!({ "session": session });
        with_body(StatusCode::OK, "application/json", body.to_string())
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

const LINK_REFUSED: &str = "open the console with the link lepic-console printed";

fn refused(refusal: &Refusal) -> Response<Body> {
    match refusal {
        Refusal::WrongHost => text(
            StatusCode::MISDIRECTED_REQUEST,
            "this console answers requests to its own address only",
        ),
        Refusal::NoSession => text(StatusCode::UNAUTHORIZED, LINK_REFUSED),
        Refusal::ForeignOrigin => text(
            StatusCode::FORBIDDEN,
            "a write needs the console's own origin",
        ),
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
    const LINK: &str = "0123456789abcdef";
    const ORIGIN: &str = "http://127.0.0.1:7421";
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
        let console = Console::new(LISTEN.to_owned(), socket, LINK.to_owned());
        (console, seen, scratch)
    }

    fn get(uri: &str, bearer: Option<&str>) -> Request<Empty<Bytes>> {
        let mut builder = Request::builder().method(Method::GET).uri(uri);
        builder = builder.header(header::HOST, LISTEN);
        if let Some(bearer) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        builder.body(Empty::new()).unwrap()
    }

    /// A `POST /session` with the given host, origin and link token.
    fn exchange(host: &str, origin: Option<&str>, link: Option<&str>) -> Request<Empty<Bytes>> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/session")
            .header(header::HOST, host);
        if let Some(origin) = origin {
            builder = builder.header(header::ORIGIN, origin);
        }
        if let Some(link) = link {
            builder = builder.header(policy::LINK_HEADER, link);
        }
        builder.body(Empty::new()).unwrap()
    }

    /// Trades `link` for a session and returns the session.
    async fn open_session(console: &Console, link: &str) -> String {
        let response = console
            .answer(exchange(LISTEN, Some(ORIGIN), Some(link)))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let body: serde_json::Value = serde_json::from_str(&body_of(response).await).unwrap();
        body["session"].as_str().unwrap().to_owned()
    }

    async fn body_of(response: Response<Body>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn an_allowed_route_is_forwarded_to_serve() {
        let (console, seen, _scratch) = stand_in("forward").await;
        let session = open_session(&console, LINK).await;
        let response = console
            .answer(get("/api/v1/status?verbose=1", Some(&session)))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, SERVE_BODY);
        assert_eq!(*seen.lock().unwrap(), ["/v1/status?verbose=1"]);
    }

    #[tokio::test]
    async fn a_route_off_the_list_is_not_forwarded() {
        let (console, seen, _scratch) = stand_in("unlisted").await;
        let session = open_session(&console, LINK).await;
        let response = console.answer(get("/api/v1/nothing", Some(&session))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_page_and_its_assets_need_no_session() {
        let (console, _seen, _scratch) = stand_in("pages").await;
        for (path, content_type) in [
            ("/", "text/html; charset=utf-8"),
            ("/console.css", "text/css; charset=utf-8"),
            ("/console.js", "text/javascript; charset=utf-8"),
            ("/vendor/scalar.js", "text/javascript; charset=utf-8"),
        ] {
            let response = console.answer(get(path, None)).await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
            assert!(
                response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .contains("connect-src 'self'")
            );
            assert!(response.headers().get(header::SET_COOKIE).is_none());
        }
        let missing = console.answer(get("/nothing", None)).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let wrong_host = Request::builder()
            .uri("/")
            .header(header::HOST, "localhost:7421")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let refused = console.answer(wrong_host).await;
        assert_eq!(refused.status(), StatusCode::MISDIRECTED_REQUEST);
        let post = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(header::HOST, LISTEN)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let post = console.answer(post).await;
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn an_api_request_without_a_session_is_not_forwarded() {
        let (console, seen, _scratch) = stand_in("nosession").await;
        let api = console.answer(get("/api/v1/status", None)).await;
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_of(api).await,
            "open the console with the link lepic-console printed"
        );
        let wrong = console.answer(get("/api/v1/status", Some("nope"))).await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let session = open_session(&console, LINK).await;
        // The link is not a session, and a session is not the link.
        let link = console.answer(get("/api/v1/status", Some(LINK))).await;
        assert_eq!(link.status(), StatusCode::UNAUTHORIZED);
        let near = console
            .answer(get("/api/v1/status", Some(&session[..session.len() - 1])))
            .await;
        assert_eq!(near.status(), StatusCode::UNAUTHORIZED);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_api_write_needs_a_session_and_the_own_origin() {
        let (console, seen, _scratch) = stand_in("write").await;
        let session = open_session(&console, LINK).await;
        let post = |origin: Option<&str>, bearer: &str| {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/transactions/7/cancel")
                .header(header::HOST, LISTEN)
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
            if let Some(origin) = origin {
                builder = builder.header(header::ORIGIN, origin);
            }
            builder.body(Empty::<Bytes>::new()).unwrap()
        };
        let foreign = console
            .answer(post(Some("http://evil.example"), &session))
            .await;
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
        let absent = console.answer(post(None, &session)).await;
        assert_eq!(absent.status(), StatusCode::FORBIDDEN);
        let anonymous = console.answer(post(Some(ORIGIN), "nope")).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        assert!(seen.lock().unwrap().is_empty());
        let allowed = console.answer(post(Some(ORIGIN), &session)).await;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(*seen.lock().unwrap(), ["/v1/transactions/7/cancel"]);
    }

    #[tokio::test]
    async fn the_link_is_used_once_and_a_new_one_takes_its_place() {
        let (console, seen, _scratch) = stand_in("once").await;
        let session = open_session(&console, LINK).await;
        assert_eq!(session.len(), 64);
        let admitted = console.answer(get("/api/v1/status", Some(&session))).await;
        assert_eq!(admitted.status(), StatusCode::OK);
        assert_eq!(seen.lock().unwrap().len(), 1);
        let again = console
            .answer(exchange(LISTEN, Some(ORIGIN), Some(LINK)))
            .await;
        assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
        assert!(!body_of(again).await.contains("session"));
        let next = console.link();
        assert_eq!(next.len(), 64);
        assert_ne!(next, LINK);
        let second = open_session(&console, &next).await;
        assert_ne!(second, session);
        assert_ne!(console.link(), next);
        // The first session still works beside the second.
        for session in [&session, &second] {
            let response = console.answer(get("/api/v1/status", Some(session))).await;
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn a_wrong_or_missing_link_changes_nothing() {
        let (console, _seen, _scratch) = stand_in("wrong").await;
        for link in [
            None,
            Some("0123456789abcdee"),
            Some("0123456789abcde"),
            Some(""),
        ] {
            let response = console.answer(exchange(LISTEN, Some(ORIGIN), link)).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{link:?}");
        }
        assert_eq!(console.link(), LINK);
        assert!(console.admission().sessions.is_empty());
        open_session(&console, LINK).await;
    }

    #[tokio::test]
    async fn an_exchange_needs_its_own_origin_and_host() {
        let (console, _seen, _scratch) = stand_in("exchange").await;
        for origin in [None, Some("http://evil.example"), Some("null")] {
            let response = console.answer(exchange(LISTEN, origin, Some(LINK))).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin:?}");
        }
        let other_host = console
            .answer(exchange("localhost:7421", Some(ORIGIN), Some(LINK)))
            .await;
        assert_eq!(other_host.status(), StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(console.link(), LINK);
        assert!(console.admission().sessions.is_empty());
        let get = console.answer(get("/session", None)).await;
        assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn sessions_are_capped_and_the_oldest_is_dropped() {
        let (console, _seen, _scratch) = stand_in("cap").await;
        let mut sessions = Vec::new();
        for _ in 0..=MAX_SESSIONS {
            let link = console.link();
            sessions.push(open_session(&console, &link).await);
        }
        assert_eq!(console.admission().sessions.len(), MAX_SESSIONS);
        let status = |session: &str| {
            let response = console.answer(get("/api/v1/status", Some(session)));
            async move { response.await.status() }
        };
        assert_eq!(status(&sessions[0]).await, StatusCode::UNAUTHORIZED);
        for session in &sessions[1..] {
            assert_eq!(status(session).await, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn of_concurrent_exchanges_of_one_link_one_wins() {
        let (console, _seen, _scratch) = stand_in("race").await;
        let console = Arc::new(console);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let console = Arc::clone(&console);
            tasks.push(tokio::spawn(async move {
                console
                    .answer(exchange(LISTEN, Some(ORIGIN), Some(LINK)))
                    .await
                    .status()
            }));
        }
        let mut won = 0;
        for task in tasks {
            if task.await.unwrap() == StatusCode::OK {
                won += 1;
            }
        }
        assert_eq!(won, 1);
        assert_eq!(console.admission().sessions.len(), 1);
    }
}
