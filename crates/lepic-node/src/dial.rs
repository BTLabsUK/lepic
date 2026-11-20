// SPDX-License-Identifier: Apache-2.0
//! How an HTTP transport opens its byte streams. By default hyper's own connector resolves the
//! node's host and connects; a [`NodeDialer`] takes that over, so the app can send the bytes
//! another way, such as through tor. TLS and the `Host` header stay those of the node's URL
//! whatever the dialer connects to.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;

use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep_until, timeout};
use tower_service::Service;

/// A byte stream to a node, before TLS.
pub trait NodeStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> NodeStream for T {}

pub type DialFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn NodeStream>>> + Send + 'a>>;

/// Opens the stream for each new connection to the node. The dialer chooses where the bytes go
/// and bounds the time it takes; `host` and `port` are those of the node's URL.
pub trait NodeDialer: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a>;
}

/// What hyper-rustls wraps: either hyper's own connector or a [`NodeDialer`].
#[derive(Clone)]
pub(crate) enum NodeConnector {
    Direct(HttpConnector),
    Dialed(Arc<dyn NodeDialer>),
}

pub(crate) struct Dialed(TokioIo<Box<dyn NodeStream>>);

impl Connection for Dialed {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for Dialed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for Dialed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Service<Uri> for NodeConnector {
    type Response = Dialed;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Dialed>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Direct(http) => http.poll_ready(cx).map_err(io::Error::other),
            Self::Dialed(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        match self {
            Self::Direct(http) => {
                let connecting = http.call(uri);
                Box::pin(async move {
                    let stream = connecting.await.map_err(io::Error::other)?.into_inner();
                    Ok(Dialed(
                        TokioIo::new(Box::new(stream) as Box<dyn NodeStream>),
                    ))
                })
            }
            Self::Dialed(dialer) => {
                let dialer = Arc::clone(dialer);
                Box::pin(async move {
                    let (host, port) = dial_target(&uri)?;
                    let stream = dialer.dial(&host, port).await?;
                    Ok(Dialed(TokioIo::new(stream)))
                })
            }
        }
    }
}

/// How long a connection attempt runs alone before the next address is tried beside it: the
/// value RFC 8305 recommends.
const CONNECT_STAGGER: Duration = Duration::from_millis(250);

/// A TCP connection to `host:port`, with `TCP_NODELAY` set. A name is looked up within
/// `budget`, and the connect phase has a `budget` of its own from the end of the lookup. The
/// addresses are tried as RFC 8305 (Happy Eyeballs v2) says: alternating between the address
/// families in the order the system gave them, each attempt [`CONNECT_STAGGER`] after the
/// one before or as soon as one fails, the first connection winning.
///
/// Fails with [`io::ErrorKind::TimedOut`] when the lookup or the connect phase runs out of its
/// budget, with the lookup's error, and, when every address fails, with the last failure.
pub async fn connect_tcp(host: &str, port: u16, budget: Duration) -> io::Result<TcpStream> {
    let stream = connect_with(
        host,
        port,
        budget,
        || async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) },
        TcpStream::connect,
    )
    .await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn connect_with<S, L, C, CF>(
    host: &str,
    port: u16,
    budget: Duration,
    lookup: impl FnOnce() -> L,
    connect: C,
) -> io::Result<S>
where
    L: Future<Output = io::Result<Vec<SocketAddr>>>,
    C: Fn(SocketAddr) -> CF,
    CF: Future<Output = io::Result<S>>,
{
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => within(budget, lookup()).await??,
    };
    within(budget, first_connection(interleaved(addresses), connect)).await?
}

async fn within<T>(budget: Duration, work: impl Future<Output = T>) -> io::Result<T> {
    timeout(budget, work)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
}

/// The addresses alternating between the families, starting with that of the first, each
/// family in the order given.
fn interleaved(addresses: Vec<SocketAddr>) -> VecDeque<SocketAddr> {
    let first_is_v6 = addresses.first().is_some_and(SocketAddr::is_ipv6);
    let (mut first, mut other): (VecDeque<_>, VecDeque<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == first_is_v6);
    let mut order = VecDeque::with_capacity(first.len().saturating_add(other.len()));
    while !first.is_empty() || !other.is_empty() {
        order.extend(first.pop_front());
        order.extend(other.pop_front());
    }
    order
}

async fn first_connection<S, C, CF>(mut waiting: VecDeque<SocketAddr>, connect: C) -> io::Result<S>
where
    C: Fn(SocketAddr) -> CF,
    CF: Future<Output = io::Result<S>>,
{
    let mut running = FuturesUnordered::new();
    let mut last_error = None;
    let mut next_start = Instant::now();
    loop {
        if running.is_empty() || Instant::now() >= next_start {
            match waiting.pop_front() {
                Some(address) => {
                    running.push(connect(address));
                    next_start = Instant::now()
                        .checked_add(CONNECT_STAGGER)
                        .unwrap_or_else(Instant::now);
                }
                None if running.is_empty() => {
                    return Err(last_error.unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "could not resolve to any address",
                        )
                    }));
                }
                None => {}
            }
        }
        tokio::select! {
            Some(attempt) = running.next() => match attempt {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    last_error = Some(error);
                    next_start = Instant::now();
                }
            },
            () = sleep_until(next_start), if !waiting.is_empty() => {}
        }
    }
}

/// The host, without brackets around an IPv6 literal, and the port, the scheme's default when
/// the URL gives none.
fn dial_target(uri: &Uri) -> io::Result<(String, u16)> {
    let host = uri
        .host()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .filter(|host| !host.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "url has no host"))?;
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("http") => 80,
        _ => 443,
    });
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    const BUDGET: Duration = Duration::from_secs(5);

    fn v4(last: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, last], 443))
    }

    fn v6(last: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, last], 443))
    }

    /// What one address does when it is connected to.
    #[derive(Clone, Copy)]
    enum Answer {
        After(Duration),
        RefusedAfter(Duration),
        ResetAfter(Duration),
        Never,
    }

    /// A fake network: each address answers as `answers` says, and the addresses asked are
    /// kept in order.
    struct Network {
        answers: Vec<(SocketAddr, Answer)>,
        asked: Mutex<Vec<SocketAddr>>,
    }

    impl Network {
        fn new(answers: &[(SocketAddr, Answer)]) -> Self {
            Self {
                answers: answers.to_vec(),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn addresses(&self) -> Vec<SocketAddr> {
            self.answers.iter().map(|(address, _)| *address).collect()
        }

        fn connect(&self, address: SocketAddr) -> impl Future<Output = io::Result<SocketAddr>> {
            self.asked.lock().unwrap().push(address);
            let answer = self
                .answers
                .iter()
                .find(|(known, _)| *known == address)
                .unwrap()
                .1;
            async move {
                match answer {
                    Answer::After(delay) => {
                        tokio::time::sleep(delay).await;
                        Ok(address)
                    }
                    Answer::RefusedAfter(delay) => {
                        tokio::time::sleep(delay).await;
                        Err(io::ErrorKind::ConnectionRefused.into())
                    }
                    Answer::ResetAfter(delay) => {
                        tokio::time::sleep(delay).await;
                        Err(io::ErrorKind::ConnectionReset.into())
                    }
                    Answer::Never => std::future::pending().await,
                }
            }
        }

        fn asked(&self) -> Vec<SocketAddr> {
            self.asked.lock().unwrap().clone()
        }
    }

    /// Connects to `node.example` through `network`, its lookup taking `lookup_delay`, and
    /// returns the outcome with the time it took.
    async fn connect_through(
        network: &Network,
        lookup_delay: Option<Duration>,
    ) -> (io::Result<SocketAddr>, Duration) {
        let started = Instant::now();
        let addresses = network.addresses();
        let outcome = connect_with(
            "node.example",
            443,
            BUDGET,
            || async move {
                match lookup_delay {
                    Some(delay) => tokio::time::sleep(delay).await,
                    None => std::future::pending().await,
                }
                Ok(addresses)
            },
            |address| network.connect(address),
        )
        .await;
        (outcome, started.elapsed())
    }

    const ALMOST_ALL: Duration = Duration::from_millis(4_900);

    #[tokio::test(start_paused = true)]
    async fn a_slow_lookup_leaves_the_connect_its_own_budget() {
        let network = Network::new(&[(v4(1), Answer::After(ALMOST_ALL))]);
        let (outcome, took) = connect_through(&network, Some(ALMOST_ALL)).await;
        assert_eq!(outcome.unwrap(), v4(1));
        assert_eq!(took, ALMOST_ALL * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_never_ends_times_out_at_its_budget() {
        let network = Network::new(&[(v4(1), Answer::After(Duration::ZERO))]);
        let (outcome, took) = connect_through(&network, None).await;
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(took, BUDGET);
        assert!(network.asked().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_first_address_does_not_hide_a_working_second() {
        let network = Network::new(&[
            (v6(1), Answer::Never),
            (v4(1), Answer::After(Duration::from_millis(10))),
        ]);
        let (outcome, took) = connect_through(&network, Some(Duration::ZERO)).await;
        assert_eq!(outcome.unwrap(), v4(1));
        assert_eq!(took, CONNECT_STAGGER + Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_address_moves_on_to_the_next_at_once() {
        let network = Network::new(&[
            (v4(1), Answer::RefusedAfter(Duration::ZERO)),
            (v4(2), Answer::After(Duration::from_millis(10))),
        ]);
        let (outcome, took) = connect_through(&network, Some(Duration::ZERO)).await;
        assert_eq!(outcome.unwrap(), v4(2));
        assert_eq!(took, Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn when_every_address_fails_the_last_failure_is_returned() {
        let network = Network::new(&[
            (v4(1), Answer::RefusedAfter(Duration::ZERO)),
            (v4(2), Answer::ResetAfter(Duration::from_millis(10))),
        ]);
        let (outcome, _) = connect_through(&network, Some(Duration::ZERO)).await;
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test(start_paused = true)]
    async fn when_no_address_answers_the_connect_times_out_at_its_budget() {
        let network = Network::new(&[(v4(1), Answer::Never), (v4(2), Answer::Never)]);
        let lookup = Duration::from_secs(1);
        let (outcome, took) = connect_through(&network, Some(lookup)).await;
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(took, lookup + BUDGET);
        assert_eq!(network.asked(), [v4(1), v4(2)]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_attempts_alternate_between_the_families_in_the_order_given() {
        let network = Network::new(&[
            (v6(1), Answer::Never),
            (v6(2), Answer::Never),
            (v6(3), Answer::Never),
            (v4(1), Answer::Never),
        ]);
        connect_through(&network, Some(Duration::ZERO))
            .await
            .0
            .unwrap_err();
        assert_eq!(network.asked(), [v6(1), v4(1), v6(2), v6(3)]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_ip_literal_is_connected_to_without_a_lookup() {
        let outcome = connect_with(
            "::1",
            3413,
            BUDGET,
            || async { Err(io::Error::other("an address needs no lookup")) },
            |address| async move { Ok(address) },
        )
        .await;
        assert_eq!(outcome.unwrap(), "[::1]:3413".parse().unwrap());
    }

    #[test]
    fn takes_the_port_of_the_url_or_the_default_of_its_scheme() {
        for (url, expected) in [
            ("https://node.example/v1", ("node.example", 443)),
            ("https://node.example:3413/v1", ("node.example", 3413)),
            ("http://127.0.0.1/v1", ("127.0.0.1", 80)),
            ("http://[::1]:3413/v1", ("::1", 3413)),
        ] {
            let target = dial_target(&url.parse().unwrap()).unwrap();
            assert_eq!(target, (expected.0.to_owned(), expected.1), "{url}");
        }
    }
}
