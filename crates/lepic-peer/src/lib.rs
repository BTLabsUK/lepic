// SPDX-License-Identifier: Apache-2.0
//! The epic1 inbox endpoint between LEPIC wallets: the `/api/v1/inbox` route a listener serves
//! next to the foreign API, and the client that posts an envelope to it. The crate moves
//! envelope bytes only.
//!
//! The crate's `README.md` describes the route and the problem codes.

pub mod client;
pub mod error;
pub mod origin;
pub mod problem;
pub mod server;

pub use client::{
    AddressClass, PeerClient, PeerClientSettings, PeerDialFuture, PeerDialer, PeerStream,
};
pub use error::{PeerClientError, PeerFormatError};
pub use origin::{Origin, OriginError, PeerTarget, WebScheme};
pub use problem::{MAX_REASON_LEN, Problem, ProblemCode};
pub use server::{
    HandlerFuture, MAX_CACHED_REPLIES, PeerAnswer, PeerEndpoint, PeerRefusal, SlateHandler,
    problem_response,
};

/// The endpoint's one path: `POST` takes an envelope.
pub const PEER_PATH: &str = "/api/v1/inbox";
/// The media type of an envelope posted to [`PEER_PATH`] and of its reply (D4).
pub const ENVELOPE_MEDIA_TYPE: &str = "application/vnd.lepic.epictx";
/// The largest body [`PEER_PATH`] takes: the largest slate envelope, rounded up to 68 KiB.
pub const MAX_ENVELOPE_LEN: usize = 69_632;
/// The longest endpoint path a target is made with.
const MAX_PATH_LEN: usize = 256;

/// Whether `path` is an absolute path of printable ASCII with no query or fragment.
pub(crate) fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_PATH_LEN
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'?' && byte != b'#')
}
