// SPDX-License-Identifier: Apache-2.0
//! Posting an envelope on an `http` or `tor` route.
//!
//! The post is one request: the sealed envelope to the native endpoint ([`PEER_PATH`]) of the
//! link's host, answered with the reply envelope in the same exchange. No version check, advert
//! or pin comes first: the address in the link is the key the envelope was sealed to.

use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lepic_epic1::{MethodId, RouteEntry};
use lepic_peer::{
    PEER_PATH, PeerClient, PeerClientError, PeerClientSettings, PeerDialFuture, PeerDialer,
    PeerTarget, WebScheme,
};
use lepic_primitives::error_chain::ErrorChain;
use lepic_transport::host_rule::{HostClass, classify_addr};
use lepic_transport::transport::BoxFuture;
use thiserror::Error;
use tracing::warn;

use super::carrier::Carrier;
use super::epicbox::{
    Envelope, PostError, Posted, RefusalCode, RouteAddressError, Unanswered, Unsent,
};
use crate::{ContactError, Epic1Refusal};
use crate::{ContactRelays, OnionCheck, RelayMode, TorPosting};

/// Why an address check refused a host.
pub(crate) type AddressRefusal = Box<dyn Error + Send + Sync>;

/// Posts one envelope to the native endpoint of a host from a link. The host gives one for
/// `http` routes and one for `tor` routes.
pub(crate) trait PeerPoster: Send + Sync {
    /// Posts `envelope` in one request to [`PEER_PATH`] on `host:port` and returns the reply
    /// envelope as it came.
    fn post<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        envelope: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, PeerPostError>>;
}

/// Why a [`PeerPoster`] got no reply envelope.
#[derive(Debug, Error)]
pub(crate) enum PeerPostError {
    /// The poster does not take the address, such as an onion whose checksum does not match.
    /// Nothing was sent.
    #[error("the address is not one the poster takes")]
    Address(#[source] AddressRefusal),
    #[error(transparent)]
    Client(#[from] PeerClientError),
    /// No connection of the post opened, so nothing was written.
    #[error("no connection opened")]
    NotConnected(#[source] PeerClientError),
}

/// A [`PeerPoster`] for `http` routes over a [`PeerClient`].
pub(crate) struct ClientPoster {
    client: PeerClient,
    scheme: WebScheme,
}

impl ClientPoster {
    /// HTTPS, on a client built by [`PeerClient::to_link_hosts`] with [`is_local_network`].
    pub(crate) fn https(client: PeerClient) -> Self {
        Self {
            client,
            scheme: WebScheme::Https,
        }
    }
}

impl PeerPoster for ClientPoster {
    fn post<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        envelope: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, PeerPostError>> {
        Box::pin(async move {
            let target = PeerTarget::new(self.scheme, host, port, PEER_PATH)
                .map_err(PeerClientError::Target)?;
            Ok(self.client.post_slate(&target, envelope).await?)
        })
    }
}

/// Builds a client whose connections `dialer` opens.
pub(crate) type DialedClient = Box<dyn Fn(Arc<dyn PeerDialer>) -> PeerClient + Send + Sync>;

/// A [`PeerPoster`] for `tor` routes: plain HTTP through the wallet's Tor dialer, after the
/// host's check took the onion; the link reader checked its form only.
///
/// Each post has a client of its own, so no connection is shared: a post none of whose
/// connections opened, such as while Tor is not running, wrote nothing and is not sent.
pub(crate) struct TorPoster {
    dialer: Arc<dyn PeerDialer>,
    check_onion: OnionCheck,
    client: DialedClient,
}

impl TorPoster {
    pub(crate) fn new(posting: &TorPosting, client: DialedClient) -> Self {
        Self {
            dialer: Arc::clone(&posting.dialer),
            check_onion: posting.check_onion,
            client,
        }
    }
}

impl PeerPoster for TorPoster {
    fn post<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        envelope: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, PeerPostError>> {
        Box::pin(async move {
            (self.check_onion)(host).map_err(PeerPostError::Address)?;
            let target = PeerTarget::new(WebScheme::Http, host, port, PEER_PATH)
                .map_err(PeerClientError::Target)?;
            let dialer = Arc::new(Opened {
                dialer: Arc::clone(&self.dialer),
                any: AtomicBool::new(false),
            });
            let client = (self.client)(Arc::clone(&dialer) as Arc<dyn PeerDialer>);
            match client.post_slate(&target, envelope).await {
                Ok(reply) => Ok(reply),
                Err(error) if !dialer.any.load(Ordering::Acquire) => {
                    Err(PeerPostError::NotConnected(error))
                }
                Err(error) => Err(PeerPostError::Client(error)),
            }
        })
    }
}

/// A dialer that notes whether any connection it was asked for opened.
struct Opened {
    dialer: Arc<dyn PeerDialer>,
    any: AtomicBool,
}

impl PeerDialer for Opened {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> PeerDialFuture<'a> {
        Box::pin(async move {
            let stream = self.dialer.dial(host, port).await?;
            self.any.store(true, Ordering::Release);
            Ok(stream)
        })
    }
}

/// Whether an address a link's host resolved to is on the local network, by RFC 0003 5.14.
/// The wallet keeps no list of its own `http` hosts, so every such address is refused.
pub(crate) fn is_local_network(ip: IpAddr) -> bool {
    classify_addr(ip) == Ok(HostClass::LocalNetwork)
}

/// A poster of `http` or `tor` routes.
pub(crate) type Poster = Arc<dyn PeerPoster>;

/// A host's posters for `http` and `tor` routes, as a [`Carrier`] takes them: HTTPS to hosts
/// on other computers outside the local network, and plain HTTP through the wallet's Tor dialer
/// when `relays` has one. Without TLS roots there is no poster, so such a route has no carrier.
pub(crate) fn link_posters(relays: &ContactRelays) -> (Option<Poster>, Option<Poster>) {
    let tls = match lepic_node::webpki_tls_config() {
        Ok(tls) => tls,
        Err(error) => {
            warn!(error = %ErrorChain(&error), "no TLS roots: http and tor routes are not posted");
            return (None, None);
        }
    };
    let tor = relays.tor.as_ref().map(|posting| {
        let tls = Arc::clone(&tls);
        let client: DialedClient = Box::new(move |dialer| {
            PeerClient::with_dialer(PeerClientSettings::default(), Arc::clone(&tls), dialer)
        });
        Arc::new(TorPoster::new(posting, client)) as Arc<dyn PeerPoster>
    });
    let http = ClientPoster::https(PeerClient::to_link_hosts(
        PeerClientSettings::default(),
        tls,
        is_local_network,
    ));
    (Some(Arc::new(http)), tor)
}

impl Carrier {
    /// Posts a sealed envelope on an `http` or `tor` route with the host's poster for it.
    pub(crate) async fn post_to_peer(
        &self,
        envelope: &Envelope,
        route: &RouteEntry,
    ) -> Result<Posted, PostError> {
        let method = route.method;
        let Some(poster) = self.poster(method) else {
            return Err(PostError::NoCarrier(method));
        };
        let Envelope::Sealed(body) = envelope else {
            return Err(PostError::Envelope(method));
        };
        if self.relays().mode == RelayMode::Offline {
            return Err(PostError::NotSent(Unsent::Relay(ContactError::Offline)));
        }
        if method == MethodId::Http && self.relays().tor_expected {
            return Err(PostError::NotSent(Unsent::Relay(ContactError::Epic1(
                Epic1Refusal::TorExpected,
            ))));
        }
        let (host, port) = route
            .host_port()
            .ok_or(PostError::Address(RouteAddressError::HostPort))?;
        match poster.post(&host, port, body).await {
            Ok(reply) => Ok(Posted::Reply(reply)),
            Err(PeerPostError::Address(error)) => {
                Err(PostError::Address(RouteAddressError::Peer(error)))
            }
            Err(PeerPostError::Client(error)) => Err(peer_failure(error)),
            Err(PeerPostError::NotConnected(error)) => Err(PostError::NotSent(Unsent::Peer(error))),
        }
    }

    fn poster(&self, method: MethodId) -> Option<&dyn PeerPoster> {
        let (http, tor) = self.posters();
        match method {
            MethodId::Http => http,
            MethodId::Tor => tor,
            MethodId::Epicbox => None,
        }
    }
}

/// How a failed post to a native endpoint counts. A request that may have left the wallet is
/// uncertain, and so is any failure this layer does not know.
pub(crate) fn peer_failure(error: PeerClientError) -> PostError {
    let refused = |code: PeerRefusal, retry_after| {
        PostError::refused(Some(RefusalCode::Peer(code)), retry_after, None)
    };
    match error {
        PeerClientError::TlsConfig(_)
        | PeerClientError::Target(_)
        | PeerClientError::EnvelopeTooLarge { .. }
        | PeerClientError::ThisComputer { .. }
        | PeerClientError::LocalNetwork => PostError::NotSent(Unsent::Peer(error)),
        PeerClientError::NotReady { retry_after } => refused(PeerRefusal::NotReady, retry_after),
        PeerClientError::Refused => refused(PeerRefusal::Refused, None),
        PeerClientError::RefusedFor { reason } => PostError::refused(
            Some(RefusalCode::Peer(PeerRefusal::Refused)),
            None,
            Some(reason),
        ),
        PeerClientError::TooLarge => refused(PeerRefusal::TooLarge, None),
        PeerClientError::RateLimited { retry_after } => {
            refused(PeerRefusal::RateLimited, retry_after)
        }
        PeerClientError::UnsupportedFormat => refused(PeerRefusal::UnsupportedFormat, None),
        PeerClientError::NotFound => refused(PeerRefusal::NotFound, None),
        PeerClientError::Status { status } => refused(PeerRefusal::Status(status), None),
        // The client does not tell a failed connection from a request lost after it was
        // written, nor a timeout before the request from one after it.
        PeerClientError::Unreachable(_)
        | PeerClientError::Timeout
        | PeerClientError::ResponseTooLarge { .. }
        | PeerClientError::Format(_)
        | PeerClientError::NotEnvelope => PostError::Uncertain(Unanswered::Peer(error)),
        error => PostError::Uncertain(Unanswered::Peer(error)),
    }
}

/// What a native endpoint's refusal said, by its problem code or status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerRefusal {
    /// 503 `not_ready`.
    NotReady,
    /// 422 `refused`.
    Refused,
    /// 413 `too_large`.
    TooLarge,
    /// 429 `rate_limited`.
    RateLimited,
    /// 415 `unsupported_format`.
    UnsupportedFormat,
    /// 404: the host serves no native endpoint.
    NotFound,
    /// Any other status that is not a success.
    Status(u16),
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use lepic_epicbox::Network;
    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_peer::{ENVELOPE_MEDIA_TYPE, PeerClientSettings, PeerDialFuture, PeerDialer};
    use rustls::{ClientConfig, RootCertStore};

    use super::*;
    use crate::delivery::testing::{identity, relays};
    use crate::delivery::transport::Transport;
    use crate::error_samples::peer_client_errors;

    const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    const REPLY: &[u8] = b"reply envelope";

    /// Each request a listener read: its request line and body.
    type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// A plain HTTP/1.1 listener on loopback that records every request and answers each with
    /// [`REPLY`] as an envelope.
    fn listen() -> (u16, Requests) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Requests::default();
        let seen = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let seen = Arc::clone(&seen);
                std::thread::spawn(move || answer(stream, &seen));
            }
        });
        (port, requests)
    }

    fn answer(mut stream: TcpStream, seen: &Requests) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header == "\r\n" {
                    break;
                }
                if let Some((name, value)) = header.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            seen.lock()
                .unwrap()
                .push((line.trim_end().to_owned(), body));
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ENVELOPE_MEDIA_TYPE}\r\nContent-Length: {}\r\n\r\n",
                REPLY.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(REPLY).unwrap();
        }
    }

    /// Sends every dial to the loopback listener on `port` and records what was dialed.
    struct ToListener {
        port: u16,
        dialed: Mutex<Vec<(String, u16)>>,
    }

    impl PeerDialer for ToListener {
        fn dial<'a>(&'a self, host: &'a str, port: u16) -> PeerDialFuture<'a> {
            self.dialed.lock().unwrap().push((host.to_owned(), port));
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port)).await?;
                Ok(Box::new(stream) as Box<dyn lepic_peer::PeerStream>)
            })
        }
    }

    fn tls() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    fn settings() -> PeerClientSettings {
        PeerClientSettings {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            ..PeerClientSettings::default()
        }
    }

    fn carrier(http: Option<Arc<dyn PeerPoster>>, tor: Option<Arc<dyn PeerPoster>>) -> Carrier {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        Carrier::new(relays(&relay, &classic, &[]).0).with_posters(http, tor)
    }

    fn tor_poster(dialer: Arc<dyn PeerDialer>, check_onion: OnionCheck) -> TorPoster {
        let posting = TorPosting {
            dialer,
            check_onion,
        };
        TorPoster::new(
            &posting,
            Box::new(|dialer| PeerClient::with_dialer(settings(), tls(), dialer)),
        )
    }

    fn sealed() -> Envelope {
        Envelope::Sealed(b"sealed envelope".to_vec())
    }

    fn route(method: MethodId, value: &str) -> RouteEntry {
        RouteEntry {
            method,
            value: value.to_owned(),
        }
    }

    /// Answers every post with a copy of the error it was given, and counts the posts.
    struct Failing {
        make: fn() -> PeerPostError,
        posts: Mutex<Vec<(String, u16)>>,
    }

    impl PeerPoster for Failing {
        fn post<'a>(
            &'a self,
            host: &'a str,
            port: u16,
            _envelope: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, PeerPostError>> {
            self.posts.lock().unwrap().push((host.to_owned(), port));
            Box::pin(async move { Err((self.make)()) })
        }
    }

    #[tokio::test]
    async fn an_http_route_is_one_request_to_the_native_endpoint_answered_with_the_reply() {
        let (port, requests) = listen();
        let poster = ClientPoster {
            client: PeerClient::new(settings(), tls()),
            scheme: WebScheme::Http,
        };
        let carrier = carrier(Some(Arc::new(poster)), None);

        let posted = carrier
            .post(
                &sealed(),
                &route(MethodId::Http, &format!("127.0.0.1:{port}")),
                None,
            )
            .await;

        assert_eq!(posted.unwrap(), Posted::Reply(REPLY.to_vec()));
        assert_eq!(
            *requests.lock().unwrap(),
            [(
                format!("POST {PEER_PATH} HTTP/1.1"),
                b"sealed envelope".to_vec()
            )]
        );
    }

    #[tokio::test]
    async fn a_tor_route_is_one_request_through_the_dialer_to_the_onion() {
        let (port, requests) = listen();
        let dialer = Arc::new(ToListener {
            port,
            dialed: Mutex::new(Vec::new()),
        });
        let poster = tor_poster(dialer.clone(), |_| Ok(()));
        let carrier = carrier(None, Some(Arc::new(poster)));

        let posted = carrier
            .post(
                &sealed(),
                &route(MethodId::Tor, &format!("{ONION}:8080")),
                None,
            )
            .await;

        assert_eq!(posted.unwrap(), Posted::Reply(REPLY.to_vec()));
        assert_eq!(*dialer.dialed.lock().unwrap(), [(ONION.to_owned(), 8080)]);
        assert_eq!(
            *requests.lock().unwrap(),
            [(
                format!("POST {PEER_PATH} HTTP/1.1"),
                b"sealed envelope".to_vec()
            )]
        );
    }

    /// Refuses every dial, as a dialer does while Tor is not running, and counts the dials.
    struct NoTor(Mutex<usize>);

    impl PeerDialer for NoTor {
        fn dial<'a>(&'a self, _host: &'a str, _port: u16) -> PeerDialFuture<'a> {
            *self.0.lock().unwrap() += 1;
            Box::pin(async { Err(std::io::ErrorKind::ConnectionRefused.into()) })
        }
    }

    #[tokio::test]
    async fn a_tor_route_without_a_connection_is_not_sent_and_nothing_goes_over_clear_net() {
        let dialer = Arc::new(NoTor(Mutex::new(0)));
        let http = Arc::new(Failing {
            make: || PeerPostError::Client(PeerClientError::Timeout),
            posts: Mutex::new(Vec::new()),
        });
        let tor = tor_poster(dialer.clone(), |_| Ok(()));
        let carrier = carrier(Some(http.clone()), Some(Arc::new(tor)));

        let posted = carrier
            .post(&sealed(), &route(MethodId::Tor, ONION), None)
            .await;

        assert!(
            matches!(posted, Err(PostError::NotSent(Unsent::Peer(_)))),
            "{posted:?}"
        );
        assert!(*dialer.0.lock().unwrap() > 0);
        assert!(http.posts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn with_tor_expected_an_http_route_is_not_sent_and_nothing_goes_direct() {
        let http = Arc::new(Failing {
            make: || PeerPostError::Client(PeerClientError::Timeout),
            posts: Mutex::new(Vec::new()),
        });
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        let relays = relays(&relay, &classic, &[]).0.with_tor_expected(true);
        let carrier = Carrier::new(relays).with_posters(Some(http.clone()), None);

        let posted = carrier
            .post(&sealed(), &route(MethodId::Http, "pay.example.com"), None)
            .await;

        assert!(
            matches!(
                posted,
                Err(PostError::NotSent(Unsent::Relay(ContactError::Epic1(
                    Epic1Refusal::TorExpected
                ))))
            ),
            "{posted:?}"
        );
        assert!(http.posts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_onion_the_poster_does_not_take_is_an_address_error_and_nothing_is_dialed() {
        let (port, requests) = listen();
        let dialer = Arc::new(ToListener {
            port,
            dialed: Mutex::new(Vec::new()),
        });
        let poster = tor_poster(
            dialer.clone(),
            |_| Err("the checksum does not match".into()),
        );
        let carrier = carrier(None, Some(Arc::new(poster)));

        let posted = carrier
            .post(&sealed(), &route(MethodId::Tor, ONION), None)
            .await;

        assert!(
            matches!(posted, Err(PostError::Address(RouteAddressError::Peer(_)))),
            "{posted:?}"
        );
        assert!(dialer.dialed.lock().unwrap().is_empty());
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_link_host_on_this_computer_or_the_local_network_is_not_sent() {
        let poster = ClientPoster::https(PeerClient::to_link_hosts(
            settings(),
            tls(),
            is_local_network,
        ));
        let carrier = carrier(Some(Arc::new(poster)), None);

        let local = carrier
            .post(&sealed(), &route(MethodId::Http, "192.168.1.10"), None)
            .await;
        let this = carrier
            .post(&sealed(), &route(MethodId::Http, "127.0.0.1"), None)
            .await;

        assert!(
            matches!(
                local,
                Err(PostError::NotSent(Unsent::Peer(
                    PeerClientError::LocalNetwork
                )))
            ),
            "{local:?}"
        );
        assert!(
            matches!(
                this,
                Err(PostError::NotSent(Unsent::Peer(
                    PeerClientError::ThisComputer { .. }
                )))
            ),
            "{this:?}"
        );
    }

    #[test]
    fn the_local_network_rule_is_the_host_rule() {
        for local in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.10",
            "169.254.1.1",
            "100.64.0.1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(is_local_network(local.parse().unwrap()), "{local}");
        }
        for other in ["93.184.216.34", "2606:4700::1111", "127.0.0.1", "::1"] {
            assert!(!is_local_network(other.parse().unwrap()), "{other}");
        }
    }

    #[tokio::test]
    async fn a_route_without_a_poster_has_no_carrier_and_nothing_is_posted() {
        let failing = Arc::new(Failing {
            make: || PeerPostError::Client(PeerClientError::Refused),
            posts: Mutex::new(Vec::new()),
        });
        let only_http = carrier(Some(failing.clone()), None);
        let only_tor = carrier(None, Some(failing.clone()));

        let tor = only_http
            .post(&sealed(), &route(MethodId::Tor, ONION), None)
            .await;
        let http = only_tor
            .post(&sealed(), &route(MethodId::Http, "pay.example.org"), None)
            .await;

        assert!(
            matches!(tor, Err(PostError::NoCarrier(MethodId::Tor))),
            "{tor:?}"
        );
        assert!(
            matches!(http, Err(PostError::NoCarrier(MethodId::Http))),
            "{http:?}"
        );
        assert!(failing.posts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_mailbox_envelope_on_an_http_route_is_not_posted() {
        let failing = Arc::new(Failing {
            make: || PeerPostError::Client(PeerClientError::Refused),
            posts: Mutex::new(Vec::new()),
        });
        let carrier = carrier(Some(failing.clone()), None);
        let envelope = Envelope::Mailbox {
            from: identity(1),
            payload: "armored".to_owned(),
            relay: None,
            txid: None,
            list: None,
        };

        let posted = carrier
            .post(&envelope, &route(MethodId::Http, "pay.example.org"), None)
            .await;

        assert!(
            matches!(posted, Err(PostError::Envelope(MethodId::Http))),
            "{posted:?}"
        );
        assert!(failing.posts.lock().unwrap().is_empty());
    }

    /// The class of a post's failure, by name.
    fn class(failure: &PostError) -> &'static str {
        match failure {
            PostError::NotSent(_) => "NotSent",
            PostError::Uncertain(_) => "Uncertain",
            PostError::Refused { .. } => "Refused",
            _ => "other",
        }
    }

    #[test]
    fn every_client_error_has_its_failure_class() {
        let expected = [
            ("TlsConfig", "NotSent"),
            ("Target", "NotSent"),
            ("EnvelopeTooLarge", "NotSent"),
            ("ThisComputer", "NotSent"),
            ("LocalNetwork", "NotSent"),
            ("Unreachable", "Uncertain"),
            ("Timeout", "Uncertain"),
            ("NotReady", "Refused"),
            ("NotReady", "Refused"),
            ("Refused", "Refused"),
            ("RefusedFor", "Refused"),
            ("TooLarge", "Refused"),
            ("RateLimited", "Refused"),
            ("RateLimited", "Refused"),
            ("UnsupportedFormat", "Refused"),
            ("NotFound", "Refused"),
            ("Status", "Refused"),
            ("ResponseTooLarge", "Uncertain"),
            ("Format", "Uncertain"),
            ("NotEnvelope", "Uncertain"),
        ];
        let errors = peer_client_errors();
        assert_eq!(errors.len(), expected.len());
        for (error, (name, want)) in errors.into_iter().zip(expected) {
            let debug = format!("{error:?}");
            assert!(debug.starts_with(name), "{debug} is not {name}");
            let failure = peer_failure(error);
            assert_eq!(class(&failure), want, "{name}: {failure:?}");
        }
    }

    #[test]
    fn a_refusal_carries_its_code_and_retry_hint() {
        let wait = Some(Duration::from_secs(7));
        let cases = [
            (
                PeerClientError::NotReady { retry_after: wait },
                PeerRefusal::NotReady,
                wait,
            ),
            (
                PeerClientError::RateLimited { retry_after: wait },
                PeerRefusal::RateLimited,
                wait,
            ),
            (PeerClientError::Refused, PeerRefusal::Refused, None),
            (PeerClientError::TooLarge, PeerRefusal::TooLarge, None),
            (
                PeerClientError::UnsupportedFormat,
                PeerRefusal::UnsupportedFormat,
                None,
            ),
            (PeerClientError::NotFound, PeerRefusal::NotFound, None),
            (
                PeerClientError::Status { status: 502 },
                PeerRefusal::Status(502),
                None,
            ),
        ];
        for (error, code, wait) in cases {
            let failure = peer_failure(error);
            let PostError::Refused {
                code: Some(RefusalCode::Peer(got)),
                retry_after,
                ..
            } = failure
            else {
                panic!("{failure:?}");
            };
            assert_eq!((got, retry_after), (code, wait));
        }
        let failure = peer_failure(PeerClientError::RefusedFor {
            reason: "inputs_spent".to_owned(),
        });
        let PostError::Refused {
            code: Some(RefusalCode::Peer(PeerRefusal::Refused)),
            reason: Some(reason),
            retryable: false,
            ..
        } = failure
        else {
            panic!("{failure:?}");
        };
        assert_eq!(reason, "inputs_spent");
    }

    #[tokio::test]
    async fn a_failure_through_the_carrier_keeps_its_class() {
        let failing = Arc::new(Failing {
            make: || PeerPostError::Client(PeerClientError::Timeout),
            posts: Mutex::new(Vec::new()),
        });
        let carrier = carrier(Some(failing.clone()), None);

        let posted = carrier
            .post(&sealed(), &route(MethodId::Http, "pay.example.org"), None)
            .await;

        assert!(
            matches!(
                posted,
                Err(PostError::Uncertain(Unanswered::Peer(
                    PeerClientError::Timeout
                )))
            ),
            "{posted:?}"
        );
        assert_eq!(
            *failing.posts.lock().unwrap(),
            [("pay.example.org".to_owned(), 443)]
        );
    }
}
