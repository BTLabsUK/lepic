// SPDX-License-Identifier: Apache-2.0
//! The listener's side of the endpoint: the body rules and the replies. The socket, the
//! admission of connections and the request budgets are the listener's; it hands a `POST` to
//! [`crate::PEER_PATH`] to a [`PeerEndpoint`].

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use hyper::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tracing::debug;

use crate::problem::{PROBLEM_MEDIA_TYPE, Problem, ProblemCode};
use crate::{ENVELOPE_MEDIA_TYPE, MAX_ENVELOPE_LEN};

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

    /// Whether `envelope` is laid out as one the wallet reads, checked without opening it. A
    /// listener checks before it spends a payment's budget on the envelope. The default takes
    /// any bytes.
    fn check(&self, envelope: &[u8]) -> Result<(), PeerRefusal> {
        let _ = envelope;
        Ok(())
    }
}

/// Why a [`SlateHandler`] gives no reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerRefusal {
    /// The wallet did not take the slate, such as an invoice: 422 `refused`.
    Refused,
    /// The wallet did not take the slate and says why: 422 `refused` with `reason`. A reason
    /// that is not 1 to [`crate::MAX_REASON_LEN`] characters of `a`-`z` and `_` is left out.
    RefusedFor { reason: &'static str },
    /// The wallet cannot take a payment now: 503 `not_ready` with `Retry-After`.
    NotReady { retry_after: Duration },
    /// Not an envelope of a format the wallet reads: 415 `unsupported_format`.
    UnsupportedFormat,
}

impl PeerRefusal {
    fn response(self) -> Response<Full<Bytes>> {
        match self {
            Self::Refused => problem_response(ProblemCode::Refused, None),
            Self::RefusedFor { reason } => refused_response(reason),
            Self::NotReady { retry_after } => {
                problem_response(ProblemCode::NotReady, Some(retry_after))
            }
            Self::UnsupportedFormat => problem_response(ProblemCode::UnsupportedFormat, None),
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

/// The endpoint of one listener: its wallet and the replies it gave.
pub struct PeerEndpoint {
    handler: Arc<dyn SlateHandler>,
    replies: Mutex<Replies>,
}

impl std::fmt::Debug for PeerEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerEndpoint").finish_non_exhaustive()
    }
}

impl PeerEndpoint {
    /// An endpoint that passes each new envelope to `handler`.
    pub fn new(handler: Arc<dyn SlateHandler>) -> Self {
        Self {
            handler,
            replies: Mutex::default(),
        }
    }

    /// Answers a `POST` the listener has checked: reads the body within `body_timeout`,
    /// refusing a declared length over [`MAX_ENVELOPE_LEN`] before it reads any of it, and
    /// passes the envelope to the wallet; a repeated envelope gets the reply its first copy got.
    pub async fn answer<B>(&self, request: Request<B>, body_timeout: Duration) -> PeerAnswer
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        match self.read(request, body_timeout).await {
            Ok(envelope) => self.receive(envelope).await,
            Err(response) => PeerAnswer {
                response: *response,
                received: false,
            },
        }
    }

    /// The envelope a slates request carries, read within `body_timeout` and checked by the
    /// wallet without opening it, or the response refusing it: 415 for another media type or
    /// an envelope the wallet does not read, 413 for a body over [`MAX_ENVELOPE_LEN`], a bare
    /// 408 for one that does not arrive in time. A listener reads the envelope this way before
    /// it spends a payment's budget, then passes it to [`Self::receive`].
    pub async fn read<B>(
        &self,
        request: Request<B>,
        body_timeout: Duration,
    ) -> Result<Vec<u8>, Box<Response<Full<Bytes>>>>
    where
        B: Body<Data = Bytes>,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let envelope = read_envelope(request, body_timeout).await?;
        if let Err(refusal) = self.handler.check(&envelope) {
            debug!(?refusal, "envelope not read");
            return Err(Box::new(refusal.response()));
        }
        Ok(envelope)
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

/// A 422 `refused` answer that names its reason.
fn refused_response(reason: &str) -> Response<Full<Bytes>> {
    let mut problem = Problem::new(ProblemCode::Refused);
    if crate::problem::reason_is_valid(reason) {
        problem.reason = Some(reason.to_owned());
    }
    let mut response = with_type(
        Response::new(Full::new(Bytes::from(problem.to_bytes()))),
        PROBLEM_MEDIA_TYPE,
    );
    *response.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
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
    use crate::PEER_PATH;

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

        /// Bytes that start with `X` are not an envelope.
        fn check(&self, envelope: &[u8]) -> Result<(), PeerRefusal> {
            if envelope.first() == Some(&b'X') {
                return Err(PeerRefusal::UnsupportedFormat);
            }
            Ok(())
        }
    }

    fn endpoint(refuse: Option<PeerRefusal>) -> (Arc<Counting>, PeerEndpoint) {
        let handler = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            refuse,
        });
        let endpoint = PeerEndpoint::new(handler.clone());
        (handler, endpoint)
    }

    fn post(body: &[u8], media: &str) -> Request<Full<Bytes>> {
        Request::post(PEER_PATH)
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

    #[tokio::test]
    async fn a_repeated_envelope_gets_the_same_reply() {
        let (handler, endpoint) = endpoint(None);
        let first = endpoint
            .answer(post(b"env", ENVELOPE_MEDIA_TYPE), TIMEOUT)
            .await;
        assert!(first.received);
        assert_eq!(first.response.status(), StatusCode::OK);
        assert_eq!(first.response.headers()[CONTENT_TYPE], ENVELOPE_MEDIA_TYPE);
        let again = endpoint
            .answer(post(b"env", "Application/Vnd.Lepic.Epictx; v=1"), TIMEOUT)
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
    async fn a_refusal_names_its_reason_when_it_is_a_plain_word() {
        for (reason, sent) in [
            ("already_finalized", Some("already_finalized")),
            ("Not A Reason", None),
            ("", None),
        ] {
            let (_, endpoint) = endpoint(Some(PeerRefusal::RefusedFor { reason }));
            let answer = endpoint.receive(b"i1".to_vec()).await;
            assert!(!answer.received);
            assert_eq!(answer.response.status().as_u16(), 422);
            let problem = problem(answer.response).await;
            assert_eq!(problem.known_code(), Some(ProblemCode::Refused));
            assert_eq!(problem.refusal_reason(), sent, "{reason:?}");
        }
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
            let answer = endpoint.answer(post(b"env", media), TIMEOUT).await;
            assert_eq!(answer.response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            let problem = problem(answer.response).await;
            assert_eq!(problem.known_code(), Some(ProblemCode::UnsupportedFormat));
        }
        let long = vec![0; MAX_ENVELOPE_LEN + 1];
        let answer = endpoint
            .answer(post(&long, ENVELOPE_MEDIA_TYPE), TIMEOUT)
            .await;
        assert_eq!(answer.response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let undeclared = Request::post(PEER_PATH)
            .header(CONTENT_TYPE, ENVELOPE_MEDIA_TYPE)
            .body(Full::new(Bytes::from(long)))
            .unwrap();
        let answer = endpoint.answer(undeclared, TIMEOUT).await;
        assert_eq!(answer.response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        let exact = vec![1; MAX_ENVELOPE_LEN];
        let answer = endpoint
            .answer(post(&exact, ENVELOPE_MEDIA_TYPE), TIMEOUT)
            .await;
        assert_eq!(answer.response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_envelope_the_wallet_does_not_read_is_refused_before_it_is_received() {
        let (handler, endpoint) = endpoint(None);
        let refused = endpoint
            .read(post(b"X not an envelope", ENVELOPE_MEDIA_TYPE), TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(refused.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let answer = endpoint
            .answer(post(b"X not an envelope", ENVELOPE_MEDIA_TYPE), TIMEOUT)
            .await;
        assert!(!answer.received);
        assert_eq!(
            problem(answer.response).await.known_code(),
            Some(ProblemCode::UnsupportedFormat)
        );
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
        let read = endpoint
            .read(post(b"env", ENVELOPE_MEDIA_TYPE), TIMEOUT)
            .await
            .unwrap();
        assert_eq!(read, b"env");
        assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    }
}
