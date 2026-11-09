// SPDX-License-Identifier: Apache-2.0
//! The Tor method as a transport: the foreign API exchange of `lepic-legacy-rpc` (`check_version`,
//! then `receive_tx`) over a SOCKS stream to `<onion>:80`, through the wallet's own tor.
//!
//! As over HTTP, the receiver answers `receive_tx` with its S2 in the same exchange. The
//! outbound side keeps that answer, keyed by the id of the slate it answers, until the caller
//! takes it with [`Tor::take_reply`] to finalize it. There is no inbound side:
//! payments to this wallet reach the listener behind the onion.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST};
use hyper::{Method as HttpMethod, Request, StatusCode};
use hyper_util::rt::TokioIo;
use lepic_legacy_rpc::error::RpcError;
use lepic_legacy_rpc::rpc::{self, VersionInfo};
use lepic_slate::codec::WireSlate;
use lepic_transport::error::TransportError;
use lepic_transport::method::{Carries, Method};
use lepic_transport::policy::FormatPolicy;
use lepic_transport::transport::{
    BoxFuture, Destination, Inbound, Outbound, Transport, TransportId,
};
use thiserror::Error;
use tracing::debug;

use lepic_tor::socks::{self, SocksCredentials};

use crate::http::{HttpPolicy, slate_id_of};

pub use lepic_tor::{
    ControlError, FailureKind, FixedSocks, MAX_STREAMS_PER_CIRCUIT, ONION_NAME_LEN, ONION_SOCKET,
    OnionAddress, OnionClientSettings, OnionError, OnionTarget, PREVIOUS_ONION_SOCKET, RelayTor,
    RelayTorError, SendFailure, SocksError, SocksProxy, StreamGroup, TorFailure, TorNetworkTimings,
    TorProcess, TorSettings, TorState, TorTimings, expanded_secret, listen_settings, onion_address,
    onion_socket_path, parse_onion, previous_onion_socket_path, public_key_of_seed,
};

/// The transport id of the Tor method, stored with its transactions.
pub const TRANSPORT_ID: TransportId = TransportId::new("tor");

const ENDPOINT: &str = "/v2/foreign";
const ONION_PORT: u16 = 80;
const MAX_HELD_REPLIES: usize = 64;

/// Why a slate could not be sent over Tor.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TorSendError {
    #[error("tor is not running")]
    NotRunning,
    #[error("invalid onion address")]
    Address(#[from] OnionError),
    #[error("could not reach the other wallet over tor")]
    Socks(#[from] SocksError),
    #[error("the exchange with the other wallet failed")]
    Exchange(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("the other wallet did not answer in time")]
    Timeout,
    #[error("the other wallet answered with http status {status}")]
    Status { status: u16 },
    #[error("the other wallet has no foreign api at this address")]
    NotFound,
    #[error("the answer is larger than {max} bytes")]
    ResponseTooLarge { max: usize },
    #[error("the answer could not be read")]
    Rpc(#[from] RpcError),
    #[error("the other wallet offers no slate version this wallet sends")]
    NoCommonVersion,
}

impl TorSendError {
    /// What the failure means for the person sending.
    pub const fn class(&self) -> SendFailure {
        match self {
            Self::NotRunning => SendFailure::TorOff,
            Self::Address(_) => SendFailure::InvalidAddress,
            Self::Socks(error) => error.class(),
            Self::Exchange(_) | Self::Timeout => SendFailure::Broken,
            Self::Status { .. }
            | Self::NotFound
            | Self::ResponseTooLarge { .. }
            | Self::Rpc(RpcError::Malformed | RpcError::NotJson | RpcError::TooLarge) => {
                SendFailure::NotEpic
            }
            Self::Rpc(RpcError::Refused) => SendFailure::Refused,
            Self::Rpc(_) | Self::NoCommonVersion => SendFailure::TooOld,
        }
    }
}

/// Talks to other wallets' foreign APIs at their onions, through a SOCKS proxy.
#[derive(Debug, Clone, Copy)]
pub struct OnionClient {
    settings: OnionClientSettings,
}

impl OnionClient {
    /// A client with the limits in `settings`.
    pub const fn new(settings: OnionClientSettings) -> Self {
        Self { settings }
    }

    /// Asks which slate versions the wallet at `onion` accepts.
    pub async fn check_version(
        &self,
        proxy: SocketAddr,
        onion: &OnionAddress,
        credentials: &SocksCredentials,
    ) -> Result<VersionInfo, TorSendError> {
        let body = self
            .post(proxy, onion, credentials, rpc::encode_version_request())
            .await?;
        let info = rpc::decode_version_response(&body)?;
        debug!(
            transport = "tor",
            v3 = info.v3,
            v2 = info.v2,
            "foreign api version checked"
        );
        Ok(info)
    }

    /// Posts the S1 in `slate` to `onion` and returns the receiver's S2 as it came.
    pub async fn receive_tx(
        &self,
        proxy: SocketAddr,
        onion: &OnionAddress,
        credentials: &SocksCredentials,
        slate: &WireSlate,
    ) -> Result<WireSlate, TorSendError> {
        let body = self
            .post(
                proxy,
                onion,
                credentials,
                rpc::encode_receive_request(slate)?,
            )
            .await?;
        Ok(rpc::decode_slate_response(&body)?)
    }

    async fn post(
        &self,
        proxy: SocketAddr,
        onion: &OnionAddress,
        credentials: &SocksCredentials,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, TorSendError> {
        let host = onion.host();
        let stream = socks::connect(
            proxy,
            &host,
            ONION_PORT,
            credentials,
            self.settings.connect_timeout,
        )
        .await?;
        tokio::time::timeout(
            self.settings.request_timeout,
            exchange(stream, &host, body, self.settings.max_response_bytes),
        )
        .await
        .map_err(|_| TorSendError::Timeout)?
    }
}

/// One HTTP/1.1 `POST /v2/foreign` over an established stream.
pub async fn exchange<S>(
    stream: S,
    host: &str,
    body: Vec<u8>,
    max_response_bytes: usize,
) -> Result<Vec<u8>, TorSendError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let exchange_failed = |error: hyper::Error| TorSendError::Exchange(Box::new(error));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(exchange_failed)?;
    let driver = tokio::spawn(async move {
        if let Err(error) = connection.await {
            debug!(transport = "tor", error = %error, "foreign api connection ended");
        }
    });
    let result = async {
        let request = Request::builder()
            .method(HttpMethod::POST)
            .uri(ENDPOINT)
            .header(HOST, host)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| TorSendError::Exchange(Box::new(error)))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(exchange_failed)?;
        match response.status() {
            StatusCode::NOT_FOUND => return Err(TorSendError::NotFound),
            status if !status.is_success() => {
                return Err(TorSendError::Status {
                    status: status.as_u16(),
                });
            }
            _ => {}
        }
        let max = max_response_bytes;
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX)) {
            return Err(TorSendError::ResponseTooLarge { max });
        }
        let collected = Limited::new(response.into_body(), max)
            .collect()
            .await
            .map_err(|error| {
                if error.downcast_ref::<LengthLimitError>().is_some() {
                    TorSendError::ResponseTooLarge { max }
                } else {
                    TorSendError::Exchange(error)
                }
            })?;
        Ok(collected.to_bytes().to_vec())
    }
    .await;
    driver.abort();
    result
}

type SharedProxy = Arc<RwLock<Option<Arc<dyn SocksProxy>>>>;

/// The Tor method. Clones share the attached tor and the held answers.
#[derive(Clone)]
pub struct Tor {
    client: OnionClient,
    proxy: SharedProxy,
    held: Arc<Mutex<VecDeque<Held>>>,
}

impl std::fmt::Debug for Tor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tor")
            .field("attached", &self.is_attached())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Held {
    slate_id: String,
    wire: WireSlate,
}

impl Tor {
    /// A transport with no tor attached: sends fail with [`TorSendError::NotRunning`].
    pub fn new(client: OnionClient) -> Self {
        Self {
            client,
            proxy: Arc::new(RwLock::new(None)),
            held: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Sends go through `proxy` from now on, usually the wallet's [`TorProcess`].
    pub fn attach(&self, proxy: Arc<dyn SocksProxy>) {
        *self.proxy.write().unwrap_or_else(PoisonError::into_inner) = Some(proxy);
    }

    /// Sends fail with [`TorSendError::NotRunning`] until a tor is attached again.
    pub fn detach(&self) {
        *self.proxy.write().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Whether a tor is attached.
    pub fn is_attached(&self) -> bool {
        self.proxy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn socks_address(&self) -> Option<SocketAddr> {
        self.proxy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|proxy| proxy.socks_address())
    }

    /// The receiver's answer to the slate with `slate_id`, removed from the held answers.
    pub fn take_reply(&self, slate_id: &str) -> Option<WireSlate> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let position = held
            .iter()
            .position(|reply| reply.slate_id.eq_ignore_ascii_case(slate_id))?;
        held.remove(position).map(|reply| reply.wire)
    }

    fn hold(&self, slate_id: String, wire: WireSlate) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.retain(|reply| !reply.slate_id.eq_ignore_ascii_case(&slate_id));
        if held.len() >= MAX_HELD_REPLIES {
            held.pop_front();
        }
        held.push_back(Held { slate_id, wire });
    }

    /// `check_version`, then `receive_tx` on the same circuit; the S2 is held for the caller
    /// under the S1's slate id. An answer for another slate is refused as malformed and not
    /// held.
    pub async fn send(&self, to: &str, wire: &WireSlate) -> Result<(), TorSendError> {
        let onion = OnionAddress::parse(to)?;
        let slate_id = slate_id_of(wire).ok_or(TorSendError::Rpc(RpcError::NotJson))?;
        let proxy = self.socks_address().ok_or(TorSendError::NotRunning)?;
        let mut credentials = SocksCredentials::random()?;
        let version = match self.client.check_version(proxy, &onion, &credentials).await {
            // The first circuit to an onion can take much longer than the next one.
            Err(TorSendError::Socks(SocksError::Timeout)) => {
                debug!(
                    transport = "tor",
                    attempt = 2,
                    "onion connect timed out, retrying"
                );
                credentials = SocksCredentials::random()?;
                self.client
                    .check_version(proxy, &onion, &credentials)
                    .await?
            }
            other => other?,
        };
        if !version.v2 {
            return Err(TorSendError::NoCommonVersion);
        }
        let reply = self
            .client
            .receive_tx(proxy, &onion, &credentials, wire)
            .await?;
        if !slate_id_of(&reply).is_some_and(|answered| answered.eq_ignore_ascii_case(&slate_id)) {
            return Err(TorSendError::Rpc(RpcError::Malformed));
        }
        debug!(transport = "tor", %slate_id, "answer received");
        self.hold(slate_id, reply);
        Ok(())
    }
}

impl Outbound for Tor {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            self.send(to.as_str(), wire)
                .await
                .map_err(|error| TransportError::Backend {
                    transport: TRANSPORT_ID,
                    source: Box::new(error),
                })
        })
    }
}

impl Method for Tor {
    fn carries(&self) -> Carries {
        Carries::default()
    }

    fn notice_lengths(&self) -> &'static [usize] {
        &[]
    }
}

impl Transport for Tor {
    fn id(&self) -> TransportId {
        TRANSPORT_ID
    }

    /// The HTTP method's policy: the same foreign API answers over Tor.
    fn policy(&self) -> &dyn FormatPolicy {
        &HttpPolicy
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }

    fn inbound(&self) -> Option<&dyn Inbound> {
        None
    }
}

/// Waits until `tor` fails or stops on its own.
pub async fn ended(tor: &TorProcess) -> TorFailure {
    let mut states = tor.subscribe();
    loop {
        if let TorState::Failed(failure) = &*states.borrow_and_update() {
            return failure.clone();
        }
        if states.changed().await.is_err() {
            break;
        }
    }
    match tor.wait_bootstrapped().await {
        Err(failure) => failure,
        Ok(_) => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_are_grouped_for_the_person_sending() {
        assert_eq!(TorSendError::NotRunning.class(), SendFailure::TorOff);
        assert_eq!(
            TorSendError::Address(OnionError::Checksum).class(),
            SendFailure::InvalidAddress
        );
        assert_eq!(
            TorSendError::Socks(SocksError::Timeout).class(),
            SendFailure::Unreachable
        );
        assert_eq!(
            TorSendError::Status { status: 500 }.class(),
            SendFailure::NotEpic
        );
        assert_eq!(TorSendError::NotFound.class(), SendFailure::NotEpic);
        assert_eq!(
            TorSendError::Rpc(RpcError::Malformed).class(),
            SendFailure::NotEpic
        );
        assert_eq!(
            TorSendError::Rpc(RpcError::Refused).class(),
            SendFailure::Refused
        );
        assert_eq!(
            TorSendError::Rpc(RpcError::Incompatible).class(),
            SendFailure::TooOld
        );
        assert_eq!(TorSendError::NoCommonVersion.class(), SendFailure::TooOld);
        assert_eq!(TorSendError::Timeout.class(), SendFailure::Broken);
    }
}
