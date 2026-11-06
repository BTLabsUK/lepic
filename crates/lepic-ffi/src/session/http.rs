// SPDX-License-Identifier: Apache-2.0
//! Direct transactions over HTTP (ADR 0017): sends answered in the same exchange, and the
//! listener that answers payments sent to this wallet.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Duration;

use lepic_foreign::{
    Exposure, ForeignClient, ForeignDialFuture, ForeignDialer, ForeignStream, ForeignUrl,
    HttpTransport, ListenError, ListenSettings, ListenerHandle, PlainHttp, ReceiveHandler, Refusal,
    TRANSPORT_ID, UrlError, webpki_tls_config,
};
use lepic_node::{Propagation, is_loopback_host};
use lepic_store::TxId;
use lepic_transport::transport::{BoxFuture, Destination, TransportId};
use lepic_wallet::send::Delivery;
use lepic_wallet::slate::WireSlate;
use lepic_wallet::{ProofKey, ReceiveError, ReceiveRequest};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{DEFAULT_ACCOUNT, Session, invalid, lock};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::http::{
    HttpExposure, HttpListenerEvent, HttpListenerEventKind, HttpListenerInfo, HttpRefusal,
    HttpResentTx, HttpSentTx,
};
use crate::api::types::SendOptions;
use crate::node::{RelayTor, RelayTorError};
use crate::tuning::Tuning;

/// Where the HTTP listener's events go.
pub(crate) type HttpReport = Arc<dyn Fn(HttpListenerEvent) + Send + Sync>;

/// The HTTP listener of a session.
#[derive(Default)]
pub(super) enum HttpListener {
    #[default]
    Idle,
    /// Binding; the number tells this start from a later one.
    Starting(u64),
    Running {
        handle: ListenerHandle,
        report: HttpReport,
    },
}

pub(super) fn http_transport(
    tuning: &Tuning,
    tor: &Arc<RelayTor>,
) -> Result<HttpTransport, WalletError> {
    let tls = webpki_tls_config()
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
    let dialer = Arc::new(SendDialer {
        tor: Arc::clone(tor),
        connect_timeout: tuning.send.connect_timeout,
    });
    Ok(HttpTransport::new(ForeignClient::with_dialer(
        tuning.send,
        tls,
        dialer,
    )))
}

/// Opens connections to other wallets through the wallet's tor while it runs or is expected,
/// and directly otherwise. Through tor the wallet's host is resolved by tor, never by the
/// system. A loopback wallet stays direct. A tor that fails is an error: nothing goes around
/// it.
struct SendDialer {
    tor: Arc<RelayTor>,
    connect_timeout: Duration,
}

impl SendDialer {
    async fn connect_directly(&self, host: &str, port: u16) -> io::Result<Box<dyn ForeignStream>> {
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}

impl ForeignDialer for SendDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> ForeignDialFuture<'a> {
        Box::pin(async move {
            if is_loopback_host(host) {
                return self.connect_directly(host, port).await;
            }
            match self.tor.open(host, port).await {
                Ok(stream) => Ok(Box::new(stream) as Box<dyn ForeignStream>),
                // An onion has no address to resolve without tor.
                Err(RelayTorError::Off)
                    if !host
                        .rsplit('.')
                        .next()
                        .is_some_and(|label| label.eq_ignore_ascii_case("onion")) =>
                {
                    self.connect_directly(host, port).await
                }
                Err(error) => Err(io::Error::other(error)),
            }
        })
    }
}

fn foreign_url(url: &str, allow_plain_http: bool) -> Result<ForeignUrl, WalletError> {
    let plain = if allow_plain_http {
        PlainHttp::Allowed
    } else {
        PlainHttp::LoopbackOnly
    };
    ForeignUrl::parse(url, plain).map_err(|error| {
        let kind = match error {
            UrlError::PlainHttpNotAllowed => WalletErrorKind::PlainHttpNotAllowed,
            _ => WalletErrorKind::HttpUrlInvalid,
        };
        WalletError::new(kind, error.to_string())
    })
}

fn delivery(url: &ForeignUrl) -> Delivery {
    Delivery::Deliver {
        transport: TRANSPORT_ID,
        to: Destination::new(url.as_uri()),
    }
}

const fn exposure(exposure: HttpExposure) -> Exposure {
    match exposure {
        HttpExposure::LocalOnly => Exposure::LocalOnly,
        HttpExposure::Internet => Exposure::Internet,
    }
}

const fn http_exposure(exposure: Exposure) -> HttpExposure {
    match exposure {
        Exposure::LocalOnly => HttpExposure::LocalOnly,
        Exposure::Internet => HttpExposure::Internet,
    }
}

/// Whether the sender may try again: the wallet could not take the payment now, but nothing
/// about the slate was wrong.
const fn refusal(kind: WalletErrorKind) -> Refusal {
    match kind {
        WalletErrorKind::Locked
        | WalletErrorKind::NodeUnreachable
        | WalletErrorKind::RestoreScanRequired
        | WalletErrorKind::WalletBusy
        | WalletErrorKind::Io
        | WalletErrorKind::DamagedDatabase
        | WalletErrorKind::Panic
        | WalletErrorKind::Cancelled => Refusal::Unavailable,
        _ => Refusal::Rejected,
    }
}

const fn http_refusal(refusal: Refusal) -> HttpRefusal {
    match refusal {
        Refusal::Unavailable => HttpRefusal::Unavailable,
        _ => HttpRefusal::Rejected,
    }
}

fn stopped(report: &HttpReport) {
    report(HttpListenerEvent::of(HttpListenerEventKind::Stopped));
}

impl Session {
    #[cfg(test)]
    pub(crate) async fn send_http(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        url: &str,
        allow_plain_http: bool,
        message: Option<String>,
    ) -> Result<HttpSentTx, WalletError> {
        self.send_http_with(
            amount,
            minimum_confirmations,
            url,
            allow_plain_http,
            message,
            None,
        )
        .await
    }

    pub(crate) async fn send_http_with(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        url: &str,
        allow_plain_http: bool,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<HttpSentTx, WalletError> {
        let request =
            self.policy
                .send_request_with(amount, minimum_confirmations, message, options)?;
        let url = foreign_url(url, allow_plain_http)?;
        let sent = self.engine.send(request, delivery(&url)).await?;
        let slate_id = sent.slate_id.to_string();
        let posted = self.finalize_http_reply(&slate_id).await?;
        Ok(HttpSentTx {
            tx_id: sent.tx_id.0,
            slate_id,
            amount: sent.amount.value(),
            fee: sent.fee.value(),
            posted,
        })
    }

    pub(crate) async fn resend_http(
        &self,
        tx_id: u32,
        url: &str,
        allow_plain_http: bool,
    ) -> Result<HttpResentTx, WalletError> {
        let url = foreign_url(url, allow_plain_http)?;
        let details = self.engine.transaction_details(TxId(tx_id)).await?;
        let entry = &details.transaction.entry;
        let slate_id = match entry.slate_id {
            Some(slate_id) if entry.account == DEFAULT_ACCOUNT => slate_id.to_string(),
            _ => {
                return Err(invalid(
                    "the transaction is not a send waiting for its answer",
                ));
            }
        };
        self.engine.resend(TxId(tx_id), delivery(&url)).await?;
        let posted = self.finalize_http_reply(&slate_id).await?;
        Ok(HttpResentTx {
            tx_id,
            slate_id,
            posted,
        })
    }

    /// Finalizes the answer the HTTP transport kept for `slate_id` and posts it. Returns
    /// whether the node accepted the transaction.
    async fn finalize_http_reply(&self, slate_id: &str) -> Result<bool, WalletError> {
        self.finalize_direct_reply(TRANSPORT_ID, self.http.take_reply(slate_id))
            .await
    }

    /// Finalizes `reply`, the answer a direct send over `transport` kept, and posts it.
    /// Returns whether the node accepted the transaction.
    pub(super) async fn finalize_direct_reply(
        &self,
        transport: TransportId,
        reply: Option<WireSlate>,
    ) -> Result<bool, WalletError> {
        let reply = reply.ok_or_else(|| {
            WalletError::new(
                WalletErrorKind::TransportFailed,
                "the other wallet's answer was not kept; send it again",
            )
        })?;
        match self
            .engine
            .finalize(transport, &reply, Propagation::Fluff)
            .await
        {
            Ok(_) => Ok(true),
            Err(error) => {
                let error = WalletError::from(error);
                if error.kind == WalletErrorKind::NotPosted {
                    warn!(error = %error, "transaction not posted");
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Starts the HTTP listener unless one runs or starts, and reports its start or why it
    /// could not to `report`.
    pub(crate) async fn start_http_listener(
        self: &Arc<Self>,
        exposure: HttpExposure,
        port: u16,
        report: HttpReport,
    ) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let generation = self.http_starts.fetch_add(1, Ordering::Relaxed);
        {
            let mut slot = lock(&self.http_listener);
            // Checked again under the slot lock: a lock that ran since stops only a listener
            // it finds in the slot.
            self.ensure_unlocked()?;
            let busy = match &*slot {
                HttpListener::Idle => false,
                HttpListener::Starting(_) => true,
                HttpListener::Running { handle, .. } => handle.is_running(),
            };
            if busy {
                return Ok(());
            }
            *slot = HttpListener::Starting(generation);
        }
        let receiver = self.http_receiver(Arc::clone(&report), TRANSPORT_ID, ProofKey::Payments);
        let settings = ListenSettings::new(self::exposure(exposure), port, self.tuning.listen);
        let listening = lepic_foreign::listen(settings, receiver).await;
        let handle = match listening {
            Ok(handle) => handle,
            Err(error) => {
                let mut slot = lock(&self.http_listener);
                if matches!(&*slot, HttpListener::Starting(started) if *started == generation) {
                    *slot = HttpListener::Idle;
                }
                drop(slot);
                let kind = match error {
                    ListenError::PortInUse { .. } => HttpListenerEventKind::PortInUse,
                    _ => HttpListenerEventKind::BindFailed,
                };
                debug!(error = %error, "http listener not started");
                report(HttpListenerEvent {
                    port: Some(port),
                    ..HttpListenerEvent::of(kind)
                });
                return Ok(());
            }
        };
        let unclaimed = {
            let mut slot = lock(&self.http_listener);
            if matches!(&*slot, HttpListener::Starting(started) if *started == generation) {
                // Reported under the lock, so a stop that follows cannot report `Stopped`
                // first.
                report(HttpListenerEvent {
                    port: Some(handle.local_addr().port()),
                    exposure: Some(exposure),
                    ..HttpListenerEvent::of(HttpListenerEventKind::Started)
                });
                *slot = HttpListener::Running {
                    handle,
                    report: Arc::clone(&report),
                };
                None
            } else {
                Some(handle)
            }
        };
        // Stopped or locked while it was binding.
        if let Some(handle) = unclaimed {
            handle.shutdown().await;
            stopped(&report);
        }
        Ok(())
    }

    /// What the HTTP listener hands each payment to.
    /// The wallet behind a listener of the foreign API, recording receipts as `transport`'s:
    /// HTTP's, or Tor's for the listener behind the onion. Each has its own open receipts.
    pub(crate) fn http_receiver(
        self: &Arc<Self>,
        report: HttpReport,
        transport: TransportId,
        proof_key: ProofKey,
    ) -> Arc<dyn ReceiveHandler> {
        Arc::new(HttpReceiver {
            session: Arc::downgrade(self),
            report,
            transport,
            proof_key,
        })
    }

    /// Stops the HTTP listener. `Stopped` is reported once its port is free.
    pub(crate) fn stop_http_listener(&self) {
        let previous = std::mem::take(&mut *lock(&self.http_listener));
        if let HttpListener::Running { handle, report } = previous {
            handle.stop();
            // A runtime that is shutting down drops the task, and with it the report: the
            // stream then ends without `Stopped`, and the socket closes with the runtime.
            drop(self.runtime().boundary.handle.spawn(async move {
                handle.shutdown().await;
                stopped(&report);
            }));
        }
    }

    pub(crate) fn http_listener_status(&self) -> Option<HttpListenerInfo> {
        match &*lock(&self.http_listener) {
            HttpListener::Running { handle, .. } if handle.is_running() => Some(HttpListenerInfo {
                port: handle.local_addr().port(),
                exposure: http_exposure(handle.exposure()),
            }),
            _ => None,
        }
    }
}

/// The wallet behind the HTTP listener. It holds the session weakly, so a running listener
/// never keeps a dropped wallet open. Payment proofs are signed with `proof_key`, the key of
/// the address the listener serves.
struct HttpReceiver {
    session: Weak<Session>,
    report: HttpReport,
    transport: TransportId,
    proof_key: ProofKey,
}

impl ReceiveHandler for HttpReceiver {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async move {
            let Some(session) = self.session.upgrade() else {
                return Err(Refusal::Unavailable);
            };
            let boundary = session.runtime().boundary.clone();
            let transport = self.transport;
            let request = ReceiveRequest {
                proof_key: self.proof_key,
                ..ReceiveRequest::default()
            };
            let received = boundary
                .run("http_receive", async move {
                    match session
                        .engine
                        .receive_unsolicited(transport, &slate, request)
                        .await
                    {
                        Err(ReceiveError::OpenReceipts(cause)) => Ok(Err(cause)),
                        received => Ok(Ok(received?)),
                    }
                })
                .await;
            match received {
                Ok(Err(cause)) => {
                    debug!(
                        transport = %self.transport,
                        error = cause.as_ref().map(tracing::field::display),
                        "payment refused at the open receipt cap"
                    );
                    self.refused(Refusal::Unavailable);
                    Err(Refusal::Unavailable)
                }
                Ok(Ok(received)) => {
                    (self.report)(HttpListenerEvent {
                        tx_id: Some(received.tx_id.0),
                        amount: Some(received.slate.amount().value()),
                        repeated: received.repeated,
                        ..HttpListenerEvent::of(HttpListenerEventKind::Received)
                    });
                    Ok(received.reply)
                }
                Err(error) => {
                    let refusal = refusal(error.kind);
                    debug!(transport = %self.transport, error = %error, "payment refused");
                    self.refused(refusal);
                    Err(refusal)
                }
            }
        })
    }

    fn refused(&self, refusal: Refusal) {
        (self.report)(HttpListenerEvent {
            refusal: Some(http_refusal(refusal)),
            ..HttpListenerEvent::of(HttpListenerEventKind::Refused)
        });
    }
}

#[cfg(test)]
#[cfg(feature = "tor")]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use lepic_tor::FixedSocks;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn dialer(tor: &Arc<RelayTor>) -> SendDialer {
        SendDialer {
            tor: Arc::clone(tor),
            connect_timeout: Duration::from_secs(5),
        }
    }

    /// A SOCKS5 server that accepts one connection and returns what it was asked to connect to.
    async fn socks_server() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0u8; 2 + 32 + 1 + 32];
            stream.read_exact(&mut auth).await.unwrap();
            stream.write_all(&[1, 0]).await.unwrap();
            let mut request = vec![0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            let mut name_len = [0u8; 1];
            stream.read_exact(&mut name_len).await.unwrap();
            let mut rest = vec![0u8; usize::from(name_len[0]) + 2];
            stream.read_exact(&mut rest).await.unwrap();
            request.extend_from_slice(&name_len);
            request.extend(rest);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            request
        });
        (address, served)
    }

    #[tokio::test]
    async fn a_wallet_is_asked_of_tor_by_name_so_tor_resolves_it() {
        let (socks, served) = socks_server().await;
        let tor = Arc::new(RelayTor::new(true, Duration::from_secs(75)));
        tor.attach_socks(FixedSocks(socks));
        dialer(&tor).dial("wallet.example", 443).await.unwrap();
        assert_eq!(
            served.await.unwrap(),
            lepic_tor::socks::encode_connect("wallet.example", 443).unwrap()
        );
    }

    #[tokio::test]
    async fn a_send_waits_for_a_tor_that_is_wanted_and_never_goes_direct() {
        // Wanted from the open: no tor attached yet, nothing expected by the app.
        let tor = Arc::new(RelayTor::new(true, Duration::from_secs(75)));
        let waiting = tokio::time::timeout(
            Duration::from_millis(200),
            dialer(&tor).dial("wallet.example", 443),
        )
        .await;
        assert!(waiting.is_err(), "waits for tor");
    }

    #[tokio::test]
    async fn a_tor_that_cannot_connect_is_an_error_and_not_a_direct_connection() {
        let closed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socks = closed.local_addr().unwrap();
        drop(closed);
        let tor = Arc::new(RelayTor::new(true, Duration::from_secs(75)));
        tor.attach_socks(FixedSocks(socks));
        assert!(dialer(&tor).dial("wallet.example", 443).await.is_err());
    }

    #[tokio::test]
    async fn a_wallet_on_this_device_stays_direct_while_tor_is_expected() {
        let wallet = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = wallet.local_addr().unwrap().port();
        let tor = Arc::new(RelayTor::new(true, Duration::from_secs(75)));
        tor.expect();
        dialer(&tor).dial("127.0.0.1", port).await.unwrap();
        wallet.accept().await.unwrap();
    }

    #[tokio::test]
    async fn with_tor_not_wanted_a_wallet_is_reached_directly() {
        let wallet = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = wallet.local_addr().unwrap().port();
        let tor = Arc::new(RelayTor::direct(true, Duration::from_secs(75)));
        // Not routed through tor: the dialer falls back to a direct connection only here.
        assert!(matches!(
            tor.open("wallet.example", 443).await,
            Err(RelayTorError::Off)
        ));
        dialer(&tor).dial("127.0.0.1", port).await.unwrap();
        wallet.accept().await.unwrap();
    }

    /// Manual: `LEPIC_TEST_TOR_SOCKS=127.0.0.1:19150 LEPIC_TEST_WALLET_URL=<https url> cargo
    /// test -p lepic-ffi live_send_client_through_tor -- --ignored` with a tor listening there.
    /// Asks the wallet's foreign API for its version through a Tor exit, with TLS for its name.
    #[tokio::test]
    #[ignore = "needs a running tor and a listening wallet"]
    async fn live_send_client_through_tor() {
        let socks: SocketAddr = std::env::var("LEPIC_TEST_TOR_SOCKS")
            .unwrap()
            .parse()
            .unwrap();
        let url = std::env::var("LEPIC_TEST_WALLET_URL").unwrap();
        let tor = Arc::new(RelayTor::new(true, Duration::from_secs(75)));
        tor.attach_socks(FixedSocks(socks));
        let tuning = Tuning::check(&crate::tuning::shipped()).unwrap();
        let client = ForeignClient::with_dialer(
            tuning.send,
            webpki_tls_config().unwrap(),
            Arc::new(dialer(&tor)),
        );
        let url = ForeignUrl::parse(&url, PlainHttp::LoopbackOnly).unwrap();
        let version = client.check_version(&url).await.unwrap();
        println!("v2 {} v3 {}", version.v2, version.v3);
    }

    /// Manual: `LEPIC_TEST_TOR_SOCKS=127.0.0.1:19150 LEPIC_TEST_GET_URLS=<https url>[,...]
    /// cargo test -p lepic-ffi live_get_through_tor -- --ignored --nocapture` with a tor
    /// listening there. GETs each URL over a stream the send dialer opens, which hands tor the
    /// host name, with TLS for that name, and prints the status line and the body.
    #[tokio::test]
    #[ignore = "needs a running tor and the network"]
    async fn live_get_through_tor() {
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::pki_types::ServerName;

        let socks: SocketAddr = std::env::var("LEPIC_TEST_TOR_SOCKS")
            .unwrap()
            .parse()
            .unwrap();
        let tor = Arc::new(RelayTor::new(true, Duration::from_secs(75)));
        tor.attach_socks(FixedSocks(socks));
        let tls = TlsConnector::from(webpki_tls_config().unwrap());
        let dialer = SendDialer {
            tor: Arc::clone(&tor),
            connect_timeout: Duration::from_secs(60),
        };
        for url in std::env::var("LEPIC_TEST_GET_URLS").unwrap().split(',') {
            let rest = url.strip_prefix("https://").unwrap();
            let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
            let stream = dialer.dial(host, 443).await.unwrap();
            let name = ServerName::try_from(host.to_owned()).unwrap();
            let mut stream = tls.connect(name, stream).await.unwrap();
            let request =
                format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut answer = Vec::new();
            // A server may end TLS without close_notify; what arrived is enough.
            let _ = stream.read_to_end(&mut answer).await;
            let answer = String::from_utf8_lossy(&answer);
            let status = answer.lines().next().unwrap_or_default();
            let body = answer.split_once("\r\n\r\n").map_or("", |(_, body)| body);
            println!(
                "{url}: {status}\n{}",
                body.chars().take(400).collect::<String>()
            );
        }
    }
}
