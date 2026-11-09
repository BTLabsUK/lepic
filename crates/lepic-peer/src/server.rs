// SPDX-License-Identifier: Apache-2.0
//! The listener's side of the endpoint: the routes, the body rules and the replies. The socket,
//! the admission of connections and the request budgets are the listener's; it hands a request
//! for one of [`PeerRoute`]'s paths to a [`PeerEndpoint`].

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use hyper::{Method, Request, Response, StatusCode};
use lepic_primitives::params::Network;
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tracing::debug;

use crate::problem::{PROBLEM_MEDIA_TYPE, Problem, ProblemCode};
use crate::{
    Advert, ENVELOPE_MEDIA_TYPE, FORMAT_LEPIC_V1, MAX_ENVELOPE_LEN, PEER_PATH, PROTOCOL, PeerInfo,
    SEAL_KEY_LEN, SLATES_PATH, to_hex,
};

/// How many replies are kept to answer a repeated envelope with. The oldest goes first.
pub const MAX_CACHED_REPLIES: usize = 64;

/// The future a [`SlateHandler`] answers with.
pub type HandlerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, PeerRefusal>> + Send + 'a>>;

/// The wallet behind the endpoint. It opens the envelope, receives the slate and seals the
/// reply; the endpoint moves bytes only.
pub trait SlateHandler: Send + Sync {
    /// The reply envelope to `envelope`, or why there is none.
    fn receive(&self, envelope: Vec<u8>) -> HandlerFuture<'_>;
}

/// Why a [`SlateHandler`] gives no reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerRefusal {
    /// The wallet did not take the slate, such as an invoice: 422 `refused`.
    Refused,
    /// The wallet cannot take a payment now: 503 `not_ready` with `Retry-After`.
    NotReady { retry_after: Duration },
    /// Not an envelope of a format the wallet reads: 415 `unsupported_format`.
    UnsupportedFormat,
}

impl PeerRefusal {
    fn response(self) -> Response<Full<Bytes>> {
        match self {
            Self::Refused => problem_response(ProblemCode::Refused, None),
            Self::NotReady { retry_after } => {
                problem_response(ProblemCode::NotReady, Some(retry_after))
            }
            Self::UnsupportedFormat => problem_response(ProblemCode::UnsupportedFormat, None),
        }
    }
}

/// The endpoint's routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRoute {
    /// `GET /v1/peer`: the endpoint's description.
    Info,
    /// `POST /v1/peer/slates`: an envelope in, its reply out.
    Slates,
}

impl PeerRoute {
    /// The route at `path`, if it is one of the endpoint's.
    pub fn from_path(path: &str) -> Option<Self> {
        match path {
            PEER_PATH => Some(Self::Info),
            SLATES_PATH => Some(Self::Slates),
            _ => None,
        }
    }

    /// The one method the route answers.
    pub fn method(self) -> Method {
        match self {
            Self::Info => Method::GET,
            Self::Slates => Method::POST,
        }
    }
}

/// What [`PeerEndpoint::answer`] gives back.
#[derive(Debug)]
pub struct PeerAnswer {
    pub response: Response<Full<Bytes>>,
    /// The wallet received a slate it had not seen: the request spent a payment's work. A
    /// refusal, a body the endpoint did not read and a repeated envelope did not.
    pub received: bool,
}

type ReplyCell = Arc<OnceCell<Vec<u8>>>;

/// The replies kept by envelope digest, oldest first.
#[derive(Default)]
struct Replies {
    cells: HashMap<[u8; 32], ReplyCell>,
    order: VecDeque<[u8; 32]>,
}

impl Replies {
    fn cell(&mut self, digest: [u8; 32]) -> ReplyCell {
        if let Some(cell) = self.cells.get(&digest) {
            return Arc::clone(cell);
        }
        while self.order.len() >= MAX_CACHED_REPLIES {
            if let Some(oldest) = self.order.pop_front() {
                self.cells.remove(&oldest);
            }
        }
        let cell = ReplyCell::default();
        self.cells.insert(digest, Arc::clone(&cell));
        self.order.push_back(digest);
        cell
    }
}

/// The endpoint of one listener: its wallet, the seal key the listener was given and the
/// network it serves.
pub struct PeerEndpoint {
    handler: Arc<dyn SlateHandler>,
    seal: [u8; SEAL_KEY_LEN],
    network: Network,
    replies: Mutex<Replies>,
}

impl std::fmt::Debug for PeerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerEndpoint")
            .field("seal", &to_hex(&self.seal))
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl PeerEndpoint {
    pub fn new(handler: Arc<dyn SlateHandler>, seal: [u8; SEAL_KEY_LEN], network: Network) -> Self {
        Self {
            handler,
            seal,
            network,
            replies: Mutex::default(),
        }
    }

    pub const fn seal_key(&self) -> [u8; SEAL_KEY_LEN] {
        self.seal
    }

    /// The `lepic` key of the listener's `check_version` answer.
    pub fn advert(&self) -> Advert {
        Advert::new(self.seal)
    }

    /// The answer of `GET /v1/peer`.
    pub fn info(&self) -> PeerInfo {
        PeerInfo {
            protocol: PROTOCOL,
            formats: vec![FORMAT_LEPIC_V1.to_owned()],
            network: self.network.as_str().to_owned(),
            key: to_hex(&self.seal),
        }
    }

    /// The response to a `GET` of [`PeerRoute::Info`].
    pub fn info_response(&self) -> Response<Full<Bytes>> {
        let body = serde_json::to_vec(&self.info()).unwrap_or_default();
        with_type(
            Response::new(Full::new(Bytes::from(body))),
            "application/json",
        )
    }

    /// Answers a request for `route` whose method the listener has checked. The slates route
    /// reads the body within `body_timeout`, refusing a declared length over
    /// [`MAX_ENVELOPE_LEN`] before it reads any of it, and passes the envelope to the wallet;
    /// a repeated envelope gets the reply its first copy got.
    pub async fn answer<B>(
        &self,
        route: PeerRoute,
        request: Request<B>,
        body_timeout: Duration,
    ) -> PeerAnswer
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let response = match route {
            PeerRoute::Info => self.info_response(),
            PeerRoute::Slates => match read_envelope(request, body_timeout).await {
                Ok(envelope) => return self.receive(envelope).await,
                Err(response) => *response,
            },
        };
        PeerAnswer {
            response,
            received: false,
        }
    }

    /// The reply to `envelope`. Only a reply is kept: a refused envelope is asked again.
    pub async fn receive(&self, envelope: Vec<u8>) -> PeerAnswer {
        let digest: [u8; 32] = Sha256::digest(&envelope).into();
        let cell = self
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cell(digest);
        let mut received = false;
        let reply = cell
            .get_or_try_init(|| {
                received = true;
                self.handler.receive(envelope)
            })
            .await;
        let response = match reply {
            Ok(reply) => with_type(
                Response::new(Full::new(Bytes::from(reply.clone()))),
                ENVELOPE_MEDIA_TYPE,
            ),
            Err(refusal) => {
                debug!(?refusal, "envelope not received");
                received = false;
                refusal.response()
            }
        };
        PeerAnswer { response, received }
    }
}

/// The envelope a slates request carries, or the response refusing it: 415 for another media
/// type, 413 for a body over [`MAX_ENVELOPE_LEN`], a bare 408 for one that does not arrive in
/// `body_timeout`.
async fn read_envelope<B>(
    request: Request<B>,
    body_timeout: Duration,
) -> Result<Vec<u8>, Box<Response<Full<Bytes>>>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if !is_envelope_type(request.headers().get(CONTENT_TYPE)) {
        return Err(Box::new(problem_response(
            ProblemCode::UnsupportedFormat,
            None,
        )));
    }
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let max = u64::try_from(MAX_ENVELOPE_LEN).unwrap_or(u64::MAX);
    if declared.is_some_and(|length| length > max) {
        return Err(Box::new(problem_response(ProblemCode::TooLarge, None)));
    }
    let collecting = Limited::new(request.into_body(), MAX_ENVELOPE_LEN).collect();
    match tokio::time::timeout(body_timeout, collecting).await {
        Ok(Ok(collected)) => Ok(collected.to_bytes().to_vec()),
        Ok(Err(_)) => Err(Box::new(problem_response(ProblemCode::TooLarge, None))),
        Err(_) => {
            debug!("body timed out");
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::REQUEST_TIMEOUT;
            Err(Box::new(response))
        }
    }
}

/// Whether a `Content-Type` names [`ENVELOPE_MEDIA_TYPE`], parameters aside.
fn is_envelope_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(ENVELOPE_MEDIA_TYPE))
}

/// A problem answer, with `Retry-After` in whole seconds when given.
pub fn problem_response(code: ProblemCode, retry_after: Option<Duration>) -> Response<Full<Bytes>> {
    let mut response = with_type(
        Response::new(Full::new(Bytes::from(Problem::new(code).to_bytes()))),
        PROBLEM_MEDIA_TYPE,
    );
    *response.status_mut() =
        StatusCode::from_u16(code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if let Some(after) = retry_after {
        let seconds = after.as_secs().max(1);
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
    }
    response
}

fn with_type(mut response: Response<Full<Bytes>>, media: &'static str) -> Response<Full<Bytes>> {
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(media));
    response
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct Counting {
        calls: AtomicUsize,
        refuse: Option<PeerRefusal>,
    }

    impl SlateHandler for Counting {
        fn receive(&self, envelope: Vec<u8>) -> HandlerFuture<'_> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let refuse = self.refuse;
            Box::pin(async move {
                match refuse {
                    Some(refusal) => Err(refusal),
                    None => Ok([envelope, format!(" reply {call}").into_bytes()].concat()),
                }
            })
        }
    }

    fn endpoint(refuse: Option<PeerRefusal>) -> (Arc<Counting>, PeerEndpoint) {
        let handler = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            refuse,
        });
        let endpoint = PeerEndpoint::new(handler.clone(), [9; 32], Network::Floonet);
        (handler, endpoint)
    }

    fn post(body: &[u8], media: &str) -> Request<Full<Bytes>> {
        Request::post(SLATES_PATH)
            .header(CONTENT_TYPE, media)
            .header(CONTENT_LENGTH, body.len())
            .body(Full::new(Bytes::copy_from_slice(body)))
            .unwrap()
    }

    async fn body(response: Response<Full<Bytes>>) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    async fn problem(response: Response<Full<Bytes>>) -> Problem {
        assert_eq!(response.headers()[CONTENT_TYPE], PROBLEM_MEDIA_TYPE);
        serde_json::from_slice(&body(response).await).unwrap()
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn routes_are_the_two_paths() {
        assert_eq!(PeerRoute::from_path("/v1/peer"), Some(PeerRoute::Info));
        assert_eq!(
            PeerRoute::from_path("/v1/peer/slates"),
            Some(PeerRoute::Slates)
        );
        assert_eq!(PeerRoute::from_path("/v1/peer/"), None);
        assert_eq!(PeerRoute::from_path("/v2/foreign"), None);
        assert_eq!(PeerRoute::Info.method(), Method::GET);
        assert_eq!(PeerRoute::Slates.method(), Method::POST);
    }

    #[tokio::test]
    async fn describes_itself_with_the_key_and_network() {
        let (_, endpoint) = endpoint(None);
        let request = Request::get(PEER_PATH)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let answer = endpoint.answer(PeerRoute::Info, request, TIMEOUT).await;
        assert!(!answer.received);
        assert_eq!(answer.response.status(), StatusCode::OK);
        let text = String::from_utf8(body(answer.response).await).unwrap();
        assert_eq!(
            text,
            format!(
                r#"{{"protocol":1,"formats":["lepic.v1"],"network":"floonet","key":"{}"}}"#,
                "09".repeat(32)
            )
        );
        assert_eq!(endpoint.advert(), Advert::new([9; 32]));
    }

    #[tokio::test]
    async fn a_repeated_envelope_gets_the_same_reply() {
        let (handler, endpoint) = endpoint(None);
        let first = endpoint
            .answer(
                PeerRoute::Slates,
                post(b"env", ENVELOPE_MEDIA_TYPE),
                TIMEOUT,
            )
            .await;
        assert!(first.received);
        assert_eq!(first.response.status(), StatusCode::OK);
        assert_eq!(first.response.headers()[CONTENT_TYPE], ENVELOPE_MEDIA_TYPE);
        let again = endpoint
            .answer(
                PeerRoute::Slates,
                post(b"env", "Application/Vnd.Lepic.Epictx; v=1"),
                TIMEOUT,
            )
            .await;
        assert!(!again.received);
        assert_eq!(body(first.response).await, b"env reply 0");
        assert_eq!(body(again.response).await, b"env reply 0");
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
        let other = endpoint.receive(b"other".to_vec()).await;
        assert_eq!(body(other.response).await, b"other reply 1");
    }

    #[tokio::test]
    async fn keeps_only_so_many_replies() {
        let (handler, endpoint) = endpoint(None);
        for index in 0..=MAX_CACHED_REPLIES {
            endpoint.receive(index.to_string().into_bytes()).await;
        }
        let calls = handler.calls.load(Ordering::SeqCst);
        endpoint
            .receive(MAX_CACHED_REPLIES.to_string().into_bytes())
            .await;
        assert_eq!(handler.calls.load(Ordering::SeqCst), calls);
        endpoint.receive(b"0".to_vec()).await;
        assert_eq!(handler.calls.load(Ordering::SeqCst), calls + 1);
    }

    #[tokio::test]
    async fn refusals_are_problems_and_are_asked_again() {
        for (refusal, code, retry) in [
            (PeerRefusal::Refused, ProblemCode::Refused, None),
            (
                PeerRefusal::UnsupportedFormat,
                ProblemCode::UnsupportedFormat,
                None,
            ),
            (
                PeerRefusal::NotReady {
                    retry_after: Duration::from_secs(30),
                },
                ProblemCode::NotReady,
                Some("30"),
            ),
        ] {
            let (handler, endpoint) = endpoint(Some(refusal));
            for _ in 0..2 {
                let answer = endpoint.receive(b"i1".to_vec()).await;
                assert!(!answer.received);
                assert_eq!(answer.response.status().as_u16(), code.status());
                assert_eq!(
                    answer
                        .response
                        .headers()
                        .get(RETRY_AFTER)
                        .map(|value| value.to_str().unwrap()),
                    retry
                );
                assert_eq!(problem(answer.response).await.known_code(), Some(code));
            }
            assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn refuses_other_media_types_and_long_bodies_unread() {
        let (handler, endpoint) = endpoint(None);
        for media in ["application/json", "application/vnd.lepic.epictx2", ""] {
            let answer = endpoint
                .answer(PeerRoute::Slates, post(b"env", media), TIMEOUT)
                .await;
            assert_eq!(answer.response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            let problem = problem(answer.response).await;
            assert_eq!(problem.known_code(), Some(ProblemCode::UnsupportedFormat));
        }
        let long = vec![0; MAX_ENVELOPE_LEN + 1];
        let answer = endpoint
            .answer(PeerRoute::Slates, post(&long, ENVELOPE_MEDIA_TYPE), TIMEOUT)
            .await;
        assert_eq!(answer.response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let undeclared = Request::post(SLATES_PATH)
            .header(CONTENT_TYPE, ENVELOPE_MEDIA_TYPE)
            .body(Full::new(Bytes::from(long)))
            .unwrap();
        let answer = endpoint
            .answer(PeerRoute::Slates, undeclared, TIMEOUT)
            .await;
        assert_eq!(answer.response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        let exact = vec![1; MAX_ENVELOPE_LEN];
        let answer = endpoint
            .answer(
                PeerRoute::Slates,
                post(&exact, ENVELOPE_MEDIA_TYPE),
                TIMEOUT,
            )
            .await;
        assert_eq!(answer.response.status(), StatusCode::OK);
    }
}
