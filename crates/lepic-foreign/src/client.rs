// SPDX-License-Identifier: Apache-2.0
//! Posts to a listening wallet's foreign API: hyper over rustls with the Mozilla roots, bounded
//! answers and timeouts, no redirects.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use lepic_slate::codec::WireSlate;
use rustls::ClientConfig;
use tracing::debug;

use crate::dial::{ForeignConnector, ForeignDialer, refused_this_computer};
use crate::error::ClientError;
use crate::rpc::{self, VersionInfo};
use crate::url::ForeignUrl;

/// Limits of [`ForeignClient`].
#[derive(Debug, Clone, Copy)]
pub struct ClientSettings {
    pub connect_timeout: Duration,
    /// From sending a request to the last byte of its answer. The receiver asks its node for
    /// the tip before it answers `receive_tx`, so this is longer than a node call.
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

/// A rustls client configuration with the ring provider and the Mozilla roots, built without
/// touching any process-wide default.
pub fn webpki_tls_config() -> Result<Arc<ClientConfig>, ClientError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(ClientError::TlsConfig)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Talks to other wallets' foreign APIs. Cheap to clone; clones share the connection pool.
#[derive(Clone)]
pub struct ForeignClient {
    client: Client<HttpsConnector<ForeignConnector>, Full<Bytes>>,
    settings: ClientSettings,
}

impl std::fmt::Debug for ForeignClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForeignClient").finish_non_exhaustive()
    }
}

impl ForeignClient {
    /// Construction does no I/O; requests need a Tokio runtime.
    pub fn new(settings: ClientSettings, tls: Arc<ClientConfig>) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(settings.connect_timeout));
        http.set_nodelay(true);
        Self::build(settings, tls, ForeignConnector::Direct(http))
    }

    /// As [`ForeignClient::new`], but it never connects to this computer: a host that is, or
    /// resolves to, a loopback or unspecified address fails with [`ClientError::ThisComputer`].
    /// The check is made on the addresses each connection resolves. Private and link-local
    /// addresses are other computers and are connected to. The client has its own connection
    /// pool, so it never reuses a connection another client opened.
    pub fn to_other_computers(settings: ClientSettings, tls: Arc<ClientConfig>) -> Self {
        let route = ForeignConnector::OtherComputers {
            connect_timeout: settings.connect_timeout,
        };
        Self::build(settings, tls, route)
    }

    /// As [`ForeignClient::new`], but every connection is opened by `dialer`, which the
    /// connect timeout of `settings` does not bound. TLS and the `Host` header still use the
    /// host of the wallet's URL, wherever the dialer connects.
    pub fn with_dialer(
        settings: ClientSettings,
        tls: Arc<ClientConfig>,
        dialer: Arc<dyn ForeignDialer>,
    ) -> Self {
        Self::build(settings, tls, ForeignConnector::Dialed(dialer))
    }

    fn build(settings: ClientSettings, tls: Arc<ClientConfig>, route: ForeignConnector) -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(Arc::unwrap_or_clone(tls))
            .https_or_http()
            .enable_http1()
            .wrap_connector(route);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self { client, settings }
    }

    /// Asks which slate versions the wallet at `url` accepts.
    pub async fn check_version(&self, url: &ForeignUrl) -> Result<VersionInfo, ClientError> {
        let body = self.post(url, rpc::encode_version_request()).await?;
        let info = rpc::decode_version_response(&body)?;
        debug!(v3 = info.v3, v2 = info.v2, "foreign api version checked");
        Ok(info)
    }

    /// Posts the S1 in `slate` to `url` and returns the receiver's S2 as it came.
    pub async fn receive_tx(
        &self,
        url: &ForeignUrl,
        slate: &WireSlate,
    ) -> Result<WireSlate, ClientError> {
        let body = self.post(url, rpc::encode_receive_request(slate)?).await?;
        Ok(rpc::decode_slate_response(&body)?)
    }

    async fn post(&self, url: &ForeignUrl, body: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let uri: Uri = url
            .as_uri()
            .parse()
            .map_err(|_| ClientError::Url(crate::error::UrlError::NoHost))?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| ClientError::Unreachable(Box::new(error)))?;
        tokio::time::timeout(self.settings.request_timeout, self.exchange(request))
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    async fn exchange(&self, request: Request<Full<Bytes>>) -> Result<Vec<u8>, ClientError> {
        let response = self.client.request(request).await.map_err(|error| {
            if refused_this_computer(&error) {
                ClientError::ThisComputer
            } else {
                ClientError::Unreachable(Box::new(error))
            }
        })?;
        match response.status() {
            StatusCode::NOT_FOUND => return Err(ClientError::NotFound),
            status if !status.is_success() => {
                return Err(ClientError::Status {
                    status: status.as_u16(),
                });
            }
            _ => {}
        }
        let max = self.settings.max_response_bytes;
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX)) {
            return Err(ClientError::ResponseTooLarge { max });
        }
        let collected = Limited::new(response.into_body(), max)
            .collect()
            .await
            .map_err(|error| {
                if error.downcast_ref::<LengthLimitError>().is_some() {
                    ClientError::ResponseTooLarge { max }
                } else {
                    ClientError::Unreachable(error)
                }
            })?;
        Ok(collected.to_bytes().to_vec())
    }
}
