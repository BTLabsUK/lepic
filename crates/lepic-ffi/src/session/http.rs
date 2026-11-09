// SPDX-License-Identifier: Apache-2.0
//! Direct transactions over HTTP (ADR 0017): sends answered in the same exchange, and the
//! listener that answers payments sent to this wallet.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Duration;

use lepic_methods::http::{
    AddressClass, CoinbaseAccess, Exposure, Host, Http, HttpPeer, ListenError, ListenSettings,
    ListenerHandle, ListenerUrl, PeerClient, PeerClientSettings, PeerDialFuture, PeerDialer,
    PeerEndpoint, PeerStream, PlainHttp, ReceiveHandler, Receiver, Refusal, RpcClient,
    RpcDialFuture, RpcDialer, RpcStream, TRANSPORT_ID, UrlError, listen_with, refuse,
    webpki_tls_config,
};
use lepic_node::{Propagation, is_loopback_host};
use lepic_store::TxId;
use lepic_transport::method::Method;
use lepic_transport::transport::{BoxFuture, Destination, TransportId};
use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};
use lepic_wallet::namespace::SealKeyKind;
use lepic_wallet::ports::SharedRng;
use lepic_wallet::send::{SendError, SentSlate};
use lepic_wallet::slate::WireSlate;
use lepic_wallet::{FinalizeError, ProofKey, ReceiveError, ReceiveRequest, Received, SlateFormat};
use lepic_wallet_contacts::{Dialect, DirectHandler, WalletContacts};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::contact::hex;
use super::{DEFAULT_ACCOUNT, Session, invalid, lock, os_rng};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::http::{
    HttpCoinbase, HttpExposure, HttpListenerEvent, HttpListenerEventKind, HttpListenerInfo,
    HttpRefusal, HttpResentTx, HttpSentTx, PeerPinView,
};
use crate::api::types::{SendDialect, SendOptions, SlateWire};
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

/// The HTTP method of a session, and the native endpoints of listeners it reaches.
pub(super) fn http_transport(
    tuning: &Tuning,
    tor: &Arc<RelayTor>,
) -> Result<(Http, HttpPeer), WalletError> {
    let tls = webpki_tls_config()
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
    let dialer = Arc::new(SendDialer {
        tor: Arc::clone(tor),
        connect_timeout: tuning.send.connect_timeout,
    });
    let http = Http::new(RpcClient::with_dialer(
        tuning.send,
        Arc::clone(&tls),
        dialer,
    ));
    let settings = PeerClientSettings {
        connect_timeout: tuning.send.connect_timeout,
        request_timeout: tuning.send.request_timeout,
        ..PeerClientSettings::default()
    };
    let native = Arc::new(NativeDialer {
        tor: Arc::clone(tor),
        connect_timeout: tuning.send.connect_timeout,
    });
    let peer = HttpPeer::new(http.clone(), PeerClient::with_dialer(settings, tls, native))
        .to_other_computers_only();
    Ok((http, peer))
}

fn is_onion_host(host: &str) -> bool {
    host.rsplit('.')
        .next()
        .is_some_and(|label| label.eq_ignore_ascii_case("onion"))
}

/// The refusal of a native post that would reach this device. A native post goes to the host
/// the user named, so it only ever reaches other computers.
#[derive(Debug)]
pub(crate) struct ThisDevice;

impl fmt::Display for ThisDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the address is one of this device's own")
    }
}

impl std::error::Error for ThisDevice {}

/// Opens the connections of native posts as [`SendDialer`] does, except that it never
/// connects to this device: a loopback host is refused, and a host reached directly is
/// connected at the first of its addresses that is not this device's own.
struct NativeDialer {
    tor: Arc<RelayTor>,
    connect_timeout: Duration,
}

impl NativeDialer {
    async fn connect_to_other_computer(
        &self,
        host: &str,
        port: u16,
    ) -> io::Result<Box<dyn PeerStream>> {
        let connect = async {
            let others: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
                .await?
                .filter(|address| AddressClass::of_this_computer(address.ip()).is_none())
                .collect();
            if others.is_empty() {
                return Err(io::Error::other(ThisDevice));
            }
            let mut last = None;
            for address in others {
                match TcpStream::connect(address).await {
                    Ok(stream) => {
                        stream.set_nodelay(true)?;
                        return Ok(Box::new(stream) as Box<dyn PeerStream>);
                    }
                    Err(error) => last = Some(error),
                }
            }
            Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
        };
        tokio::time::timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }
}

impl PeerDialer for NativeDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> PeerDialFuture<'a> {
        Box::pin(async move {
            if is_loopback_host(host) {
                return Err(io::Error::other(ThisDevice));
            }
            match self.tor.open(host, port).await {
                Ok(stream) => Ok(Box::new(stream) as Box<dyn PeerStream>),
                // An onion has no address to resolve without tor.
                Err(RelayTorError::Off) if !is_onion_host(host) => {
                    self.connect_to_other_computer(host, port).await
                }
                Err(error) => Err(io::Error::other(error)),
            }
        })
    }
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
    async fn connect_directly(&self, host: &str, port: u16) -> io::Result<Box<dyn RpcStream>> {
        let stream = tokio::time::timeout(self.connect_timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
}

impl RpcDialer for SendDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> RpcDialFuture<'a> {
        Box::pin(async move {
            if is_loopback_host(host) {
                return self.connect_directly(host, port).await;
            }
            match self.tor.open(host, port).await {
                Ok(stream) => Ok(Box::new(stream) as Box<dyn RpcStream>),
                // An onion has no address to resolve without tor.
                Err(RelayTorError::Off) if !is_onion_host(host) => {
                    self.connect_directly(host, port).await
                }
                Err(error) => Err(io::Error::other(error)),
            }
        })
    }
}

fn foreign_url(url: &str, allow_plain_http: bool) -> Result<ListenerUrl, WalletError> {
    let plain = if allow_plain_http {
        PlainHttp::Allowed
    } else {
        PlainHttp::LoopbackOnly
    };
    ListenerUrl::parse(url, plain).map_err(|error| {
        let kind = match error {
            UrlError::PlainHttpNotAllowed => WalletErrorKind::PlainHttpNotAllowed,
            _ => WalletErrorKind::HttpUrlInvalid,
        };
        WalletError::new(kind, error.to_string())
    })
}

fn destination(url: &ListenerUrl) -> Destination {
    Destination::new(url.as_uri())
}

/// The dialect a direct send took, as the binding reports it.
pub(super) const fn send_dialect(dialect: Dialect) -> SendDialect {
    match dialect {
        Dialect::Native => SendDialect::Native,
        Dialect::Legacy => SendDialect::Legacy,
    }
}

/// How a slate went out, as the binding reports it.
pub(super) const fn slate_wire(format: SlateFormat) -> SlateWire {
    match format {
        SlateFormat::Native => SlateWire::Native,
        SlateFormat::Legacy => SlateWire::Legacy,
    }
}

/// How the S1 of a direct send went out: a native exchange stores its S1 as a legacy slate, so
/// its format is the dialect's.
pub(super) const fn direct_wire(dialect: Dialect, stored: SlateFormat) -> SlateWire {
    match dialect {
        Dialect::Native => SlateWire::Native,
        Dialect::Legacy => slate_wire(stored),
    }
}

/// The report of a direct send of `sent` in `dialect`. A native exchange stores its S1 as a
/// legacy slate, so its format is the dialect's.
pub(super) fn http_sent(
    sent: &SentSlate,
    dialect: Dialect,
    slate_id: String,
    posted: bool,
) -> HttpSentTx {
    let format = direct_wire(dialect, sent.format);
    HttpSentTx {
        tx_id: sent.tx_id.0,
        slate_id,
        amount: sent.amount.value(),
        fee: sent.fee.value(),
        posted,
        dialect: send_dialect(dialect),
        format,
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
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)] // The app's send form, one value per field.
    pub(crate) async fn send_http_with(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        url: &str,
        allow_plain_http: bool,
        message: Option<String>,
        options: Option<SendOptions>,
        legacy: bool,
    ) -> Result<HttpSentTx, WalletError> {
        let request =
            self.policy
                .send_request_with(amount, minimum_confirmations, message, options)?;
        let url = foreign_url(url, allow_plain_http)?;
        let method = self
            .method(TRANSPORT_ID)
            .ok_or(SendError::UnknownTransport {
                transport: TRANSPORT_ID,
            })?;
        let direct = self
            .engine
            .contact_book()
            .direct_send(&self.http_peer, method, request, destination(&url), legacy)
            .await?;
        let slate_id = direct.sent.slate_id.to_string();
        let posted = self
            .finalize_sent_reply(TRANSPORT_ID, &slate_id, direct.reply)
            .await?;
        Ok(http_sent(&direct.sent, direct.dialect, slate_id, posted))
    }

    pub(crate) async fn resend_http(
        &self,
        tx_id: u32,
        url: &str,
        allow_plain_http: bool,
        legacy: bool,
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
        let method = self
            .method(TRANSPORT_ID)
            .ok_or(SendError::UnknownTransport {
                transport: TRANSPORT_ID,
            })?;
        let direct = self
            .engine
            .contact_book()
            .direct_resend(
                &self.http_peer,
                method,
                TxId(tx_id),
                destination(&url),
                legacy,
            )
            .await?;
        let posted = self
            .finalize_sent_reply(TRANSPORT_ID, &slate_id, direct.reply)
            .await?;
        Ok(HttpResentTx {
            tx_id,
            slate_id,
            posted,
            dialect: send_dialect(direct.dialect),
            format: direct_wire(direct.dialect, direct.sent),
        })
    }

    /// Finalizes the answer of the direct send of `slate_id` over `transport` and posts it:
    /// `reply`, the answer a native exchange brought back, or else the one the method kept
    /// from a legacy exchange. Returns whether the node accepted the transaction.
    pub(super) async fn finalize_sent_reply(
        &self,
        transport: TransportId,
        slate_id: &str,
        reply: Option<WireSlate>,
    ) -> Result<bool, WalletError> {
        let reply = match reply {
            Some(reply) => Some(reply),
            None => self.kept_reply(transport, slate_id),
        };
        self.finalize_direct_reply(transport, reply).await
    }

    /// The answer the method of `transport` kept for `slate_id` from a legacy exchange.
    fn kept_reply(&self, transport: TransportId, slate_id: &str) -> Option<WireSlate> {
        #[cfg(feature = "tor")]
        if transport == lepic_methods::tor::TRANSPORT_ID {
            return self.tor.take_reply(slate_id);
        }
        if transport == TRANSPORT_ID {
            return self.http.take_reply(slate_id);
        }
        None
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
        let method = self
            .method(transport)
            .ok_or(FinalizeError::UnknownTransport { transport })?;
        match self
            .engine
            .finalize(method, &reply, Propagation::Fluff)
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
    /// could not to `report`. `coinbase` says who it builds block rewards for.
    pub(crate) async fn start_http_listener(
        self: &Arc<Self>,
        exposure: HttpExposure,
        port: u16,
        coinbase: HttpCoinbase,
        report: HttpReport,
    ) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let peer = self.peer_endpoint(
            Arc::clone(&report),
            TRANSPORT_ID,
            ProofKey::Payments,
            SealKeyKind::Web,
        )?;
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
        let settings = ListenSettings::new(self::exposure(exposure), port, self.tuning.listen)
            .with_coinbase(self::coinbase_access(coinbase));
        let listening = listen_with(settings, receiver, peer).await;
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

    /// The wallet behind a listener of the foreign API, recording receipts as `transport`'s:
    /// HTTP's, or Tor's for the listener behind the onion. Each has its own open receipts.
    pub(crate) fn http_receiver(
        self: &Arc<Self>,
        report: HttpReport,
        transport: TransportId,
        proof_key: ProofKey,
    ) -> Arc<dyn ReceiveHandler> {
        let host = Arc::new(SessionHost {
            session: Arc::downgrade(self),
            report,
            transport,
        });
        Arc::new(Receiver::new(
            host,
            self.receiving_method(transport),
            proof_key,
        ))
    }

    /// The native endpoint (ADR 0052) of a listener socket: payments in envelopes sealed to the
    /// wallet's listener key of `kind`, received over `transport` as [`Session::http_receiver`]
    /// receives them, with payment proofs signed by `proof_key`. None while native slates are
    /// off, so the socket answers as it does without them: no advert, no native routes.
    pub(crate) fn peer_endpoint(
        self: &Arc<Self>,
        report: HttpReport,
        transport: TransportId,
        proof_key: ProofKey,
        kind: SealKeyKind,
    ) -> Result<Option<Arc<PeerEndpoint>>, WalletError> {
        if !self.native_direct_active() {
            return Ok(None);
        }
        let key = self.engine.listener_seal_key(kind)?;
        let seal = *key.public_key().as_bytes();
        let network = self.engine.config().network;
        let host = Arc::new(SessionHost {
            session: Arc::downgrade(self),
            report,
            transport,
        });
        let handler = DirectHandler::new(
            host,
            self.receiving_method(transport),
            proof_key,
            key,
            network,
            SharedRng::new(os_rng()?),
        );
        Ok(Some(Arc::new(PeerEndpoint::new(
            Arc::new(handler),
            seal,
            network,
        ))))
    }

    /// The method receipts over `transport` are recorded as.
    fn receiving_method(&self, transport: TransportId) -> Arc<dyn Method> {
        self.method(transport)
            .cloned()
            .unwrap_or_else(|| Arc::new(self.http.clone()))
    }

    pub(crate) fn peer_pins(&self) -> Result<Vec<PeerPinView>, WalletError> {
        Ok(self
            .engine
            .peer_pins(DEFAULT_ACCOUNT)?
            .into_iter()
            .map(|pin| PeerPinView {
                origin: pin.origin,
                seal_key: hex(&pin.seal_key),
                first_seen_ms: pin.first_seen.as_millisecond(),
                last_seen_ms: pin.last_seen.as_millisecond(),
            })
            .collect())
    }

    pub(crate) fn forget_peer_pin(&self, origin: &str) -> Result<bool, WalletError> {
        Ok(self.engine.forget_peer_pin(DEFAULT_ACCOUNT, origin)?)
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
/// never keeps a dropped wallet open. The method is looked up by `transport` on every receipt,
/// so a receipt always goes over the method the session holds under that id.
struct SessionHost {
    session: Weak<Session>,
    report: HttpReport,
    transport: TransportId,
}

impl Host for SessionHost {
    fn receive(
        &self,
        _method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> BoxFuture<'_, Result<Received, Refusal>> {
        let wire = wire.clone();
        Box::pin(async move {
            let Some(session) = self.session.upgrade() else {
                return Err(Refusal::Unavailable);
            };
            let boundary = session.runtime().boundary.clone();
            let transport = self.transport;
            let Some(method) = session.method(transport).cloned() else {
                let error = ReceiveError::UnknownTransport { transport };
                debug!(transport = %transport, error = %error, "payment refused");
                return Err(refuse(&error));
            };
            let received = boundary
                .run("http_receive", async move {
                    Ok(session
                        .engine
                        .receive_unsolicited(&method, &wire, request)
                        .await)
                })
                .await;
            match received {
                Ok(Ok(received)) => Ok(received),
                Ok(Err(ReceiveError::OpenReceipts(cause))) => {
                    debug!(
                        transport = %transport,
                        error = cause.as_ref().map(tracing::field::display),
                        "payment refused at the open receipt cap"
                    );
                    Err(Refusal::Unavailable)
                }
                Ok(Err(error)) => {
                    debug!(
                        transport = %transport,
                        error = %lepic_telemetry::ErrorChain(&error),
                        "payment refused"
                    );
                    Err(refuse(&error))
                }
                Err(error) => {
                    debug!(transport = %transport, error = %error, "payment refused");
                    Err(Refusal::Unavailable)
                }
            }
        })
    }

    fn build_coinbase(&self, request: CoinbaseRequest) -> BoxFuture<'_, Result<Coinbase, Refusal>> {
        Box::pin(async move {
            let Some(session) = self.session.upgrade() else {
                return Err(Refusal::Unavailable);
            };
            let boundary = session.runtime().boundary.clone();
            let built = boundary
                .run("http_build_coinbase", async move {
                    Ok(session.engine.build_coinbase(request).await)
                })
                .await;
            match built {
                Ok(Ok(coinbase)) => Ok(coinbase),
                Ok(Err(error)) => {
                    warn!(
                        error = %lepic_telemetry::ErrorChain(&error),
                        "coinbase refused"
                    );
                    Err(Refusal::Unavailable)
                }
                Err(error) => {
                    warn!(error = %error, "coinbase refused");
                    Err(Refusal::Unavailable)
                }
            }
        })
    }

    fn received(&self, received: &Received) {
        (self.report)(HttpListenerEvent {
            tx_id: Some(received.tx_id.0),
            amount: Some(received.slate.amount().value()),
            repeated: received.repeated,
            ..HttpListenerEvent::of(HttpListenerEventKind::Received)
        });
    }

    fn refused(&self, refusal: Refusal) {
        (self.report)(HttpListenerEvent {
            refusal: Some(http_refusal(refusal)),
            ..HttpListenerEvent::of(HttpListenerEventKind::Refused)
        });
    }
}

fn coinbase_access(coinbase: HttpCoinbase) -> CoinbaseAccess {
    match coinbase {
        HttpCoinbase::Off => CoinbaseAccess::Off,
        HttpCoinbase::LocalOnly => CoinbaseAccess::LocalOnly,
        HttpCoinbase::Remote => CoinbaseAccess::Remote,
    }
}

#[cfg(test)]
#[cfg(feature = "tor")]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use lepic_methods::tor::FixedSocks;
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
        let client = RpcClient::with_dialer(
            tuning.send,
            webpki_tls_config().unwrap(),
            Arc::new(dialer(&tor)),
        );
        let url = ListenerUrl::parse(&url, PlainHttp::LoopbackOnly).unwrap();
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
