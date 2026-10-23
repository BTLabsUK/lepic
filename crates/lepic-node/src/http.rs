//! The HTTP transport: hyper over rustls (ADR 0006), with the limits the node client relies on.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::client::RpcTransport;
use crate::dial::{NodeConnector, NodeDialer};
use crate::error::NodeError;

// The node's foreign API accepts Basic auth with this fixed user name.
const BASIC_AUTH_USER: &str = "epic";

/// Limits and credentials for [`HttpTransport`].
#[derive(Debug, Clone)]
pub struct HttpSettings {
    pub connect_timeout: Duration,
    /// From sending the request to the last byte of the response.
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    /// The node's foreign API secret, when it requires one.
    pub api_secret: Option<SecretString>,
}

impl Default for HttpSettings {
    // The cap leaves room for a full `get_unspent_outputs` page, the largest answer the wallet
    // asks for, because every output in it carries a range proof.
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_response_bytes: 8 * 1024 * 1024,
            api_secret: None,
        }
    }
}

/// A rustls client configuration with the ring provider and the Mozilla roots from
/// `webpki-roots`, built without touching any process-wide default.
pub fn webpki_tls_config() -> Result<Arc<ClientConfig>, NodeError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(NodeError::TlsConfig)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Posts JSON-RPC requests to one node over HTTP/1.1, plain or TLS.
#[derive(Clone)]
pub struct HttpTransport {
    client: Client<HttpsConnector<NodeConnector>, Full<Bytes>>,
    base_url: String,
    host: String,
    authorization: Option<HeaderValue>,
    request_timeout: Duration,
    max_response_bytes: usize,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// `node_url` is the node's API root, such as `https://node.example:3413`. Credentials go
    /// in `settings.api_secret`, never in the URL. Plain `http` is refused with
    /// [`NodeError::PlainHttpToRemoteHost`] unless the host is loopback, so the secret never
    /// crosses a network unencrypted.
    ///
    /// Must be called inside a Tokio runtime only when requests are made; construction itself
    /// does no I/O.
    pub fn new(
        node_url: &str,
        settings: &HttpSettings,
        tls: Arc<ClientConfig>,
    ) -> Result<Self, NodeError> {
        Self::build(node_url, settings, tls, None)
    }

    /// As [`HttpTransport::new`], but every connection is opened by `dialer`, which the
    /// connect timeout of `settings` does not bound. TLS and the `Host` header still use the
    /// host of `node_url`, wherever the dialer connects.
    pub fn with_dialer(
        node_url: &str,
        settings: &HttpSettings,
        tls: Arc<ClientConfig>,
        dialer: Arc<dyn NodeDialer>,
    ) -> Result<Self, NodeError> {
        Self::build(node_url, settings, tls, Some(dialer))
    }

    fn build(
        node_url: &str,
        settings: &HttpSettings,
        tls: Arc<ClientConfig>,
        dialer: Option<Arc<dyn NodeDialer>>,
    ) -> Result<Self, NodeError> {
        let (base_url, host) = parse_node_url(node_url, dialer.is_some())?;
        let route = dialer.map_or_else(
            || {
                let mut http = HttpConnector::new();
                http.enforce_http(false);
                http.set_connect_timeout(Some(settings.connect_timeout));
                http.set_nodelay(true);
                NodeConnector::Direct(http)
            },
            NodeConnector::Dialed,
        );
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(Arc::unwrap_or_clone(tls))
            .https_or_http()
            .enable_http1()
            .wrap_connector(route);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        let authorization = settings
            .api_secret
            .as_ref()
            .map(basic_authorization)
            .transpose()?;
        Ok(Self {
            client,
            base_url,
            host,
            authorization,
            request_timeout: settings.request_timeout,
            max_response_bytes: settings.max_response_bytes,
        })
    }

    fn build_request(
        &self,
        endpoint: &str,
        body: Vec<u8>,
    ) -> Result<Request<Full<Bytes>>, NodeError> {
        let uri: Uri = format!("{}{endpoint}", self.base_url)
            .parse()
            .map_err(|_| NodeError::InvalidUrl)?;
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json");
        if let Some(authorization) = &self.authorization {
            builder = builder.header(AUTHORIZATION, authorization.clone());
        }
        builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|error| NodeError::Request(Box::new(error)))
    }

    async fn exchange(&self, request: Request<Full<Bytes>>) -> Result<Vec<u8>, NodeError> {
        let response = self.client.request(request).await.map_err(|error| {
            if error.is_connect() {
                NodeError::Connect(Box::new(error))
            } else {
                NodeError::Request(Box::new(error))
            }
        })?;
        match response.status() {
            StatusCode::UNAUTHORIZED => return Err(NodeError::Unauthorized),
            status if !status.is_success() => {
                return Err(NodeError::HttpStatus {
                    status: status.as_u16(),
                });
            }
            _ => {}
        }
        let too_large = NodeError::ResponseTooLarge {
            limit: self.max_response_bytes,
        };
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let limit = u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX);
        if declared.is_some_and(|length| length > limit) {
            return Err(too_large);
        }
        let collected = Limited::new(response.into_body(), self.max_response_bytes)
            .collect()
            .await
            .map_err(|error| {
                if error.downcast_ref::<LengthLimitError>().is_some() {
                    too_large
                } else {
                    NodeError::Request(error)
                }
            })?;
        Ok(collected.to_bytes().to_vec())
    }
}

impl RpcTransport for HttpTransport {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        let request = self.build_request(endpoint, body)?;
        tokio::time::timeout(self.request_timeout, self.exchange(request))
            .await
            .map_err(|_| NodeError::Timeout)?
    }

    fn node_label(&self) -> &str {
        &self.host
    }
}

/// Accepts `https` URLs, and `http` URLs to a loopback host, or to an onion when `onion_over_http`
/// says a dialer takes the connection to tor, which encrypts it to the onion, with a host and an optional path
/// prefix, and nothing that could carry credentials or change the endpoint: no user info, query
/// or fragment.
///
/// Plain HTTP is limited to loopback because the API secret and every answer the wallet acts on
/// would otherwise cross the network unprotected.
fn parse_node_url(node_url: &str, onion_over_http: bool) -> Result<(String, String), NodeError> {
    let uri: Uri = node_url.trim().parse().map_err(|_| NodeError::InvalidUrl)?;
    let scheme = uri.scheme_str().ok_or(NodeError::InvalidUrl)?;
    if scheme != "http" && scheme != "https" {
        return Err(NodeError::InvalidUrl);
    }
    let authority = uri.authority().ok_or(NodeError::InvalidUrl)?;
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return Err(NodeError::InvalidUrl);
    }
    if uri.query().is_some() || node_url.contains('#') {
        return Err(NodeError::InvalidUrl);
    }
    let onion = onion_over_http && is_onion_host(authority.host());
    if scheme == "http" && !onion && !is_loopback_host(authority.host()) {
        return Err(NodeError::PlainHttpToRemoteHost);
    }
    let path = uri.path().trim_end_matches('/');
    let base_url = format!("{scheme}://{}{path}", authority.as_str());
    Ok((base_url, authority.host().to_owned()))
}

fn is_onion_host(host: &str) -> bool {
    host.rsplit('.')
        .next()
        .is_some_and(|label| label.eq_ignore_ascii_case("onion"))
}

/// `localhost` or a loopback IP literal. `localhost` relies on the resolver keeping the name on
/// loopback, as RFC 6761 requires; any other name could resolve anywhere.
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    literal
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

const BASIC_SCHEME: &[u8] = b"Basic ";

/// The header the transport sends with every request. The header itself cannot be wiped, so it
/// is the only copy of the secret left once this returns.
fn basic_authorization(secret: &SecretString) -> Result<HeaderValue, NodeError> {
    let credentials = basic_credentials(secret)?;
    let header = basic_header(&credentials)?;
    let mut value = HeaderValue::from_bytes(&header).map_err(|_| NodeError::InvalidApiSecret)?;
    value.set_sensitive(true);
    Ok(value)
}

/// `epic:<secret>`, in a buffer sized for it up front: a buffer that grows leaves the bytes it
/// moved out of in freed memory, where `Zeroizing` cannot wipe them.
fn basic_credentials(secret: &SecretString) -> Result<Zeroizing<Vec<u8>>, NodeError> {
    let secret = secret.expose_secret().as_bytes();
    let len = BASIC_AUTH_USER
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_add(secret.len()))
        .ok_or(NodeError::InvalidApiSecret)?;
    let mut credentials = Zeroizing::new(Vec::with_capacity(len));
    credentials.extend_from_slice(BASIC_AUTH_USER.as_bytes());
    credentials.push(b':');
    credentials.extend_from_slice(secret);
    Ok(credentials)
}

/// `Basic <base64 of credentials>`, sized up front for the same reason.
fn basic_header(credentials: &[u8]) -> Result<Zeroizing<Vec<u8>>, NodeError> {
    let encoded_len =
        base64::encoded_len(credentials.len(), true).ok_or(NodeError::InvalidApiSecret)?;
    let len = BASIC_SCHEME
        .len()
        .checked_add(encoded_len)
        .ok_or(NodeError::InvalidApiSecret)?;
    let mut header = Zeroizing::new(Vec::with_capacity(len));
    header.extend_from_slice(BASIC_SCHEME);
    header.resize(len, 0);
    let encoded = header
        .get_mut(BASIC_SCHEME.len()..)
        .ok_or(NodeError::InvalidApiSecret)?;
    BASE64
        .encode_slice(credentials, encoded)
        .map_err(|_| NodeError::InvalidApiSecret)?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_scheme_host_port_and_path_prefix() {
        let (base, host) = parse_node_url("https://node.example:3413/api/", false).unwrap();
        assert_eq!(base, "https://node.example:3413/api");
        assert_eq!(host, "node.example");
    }

    #[test]
    fn rejects_urls_that_are_not_plain_node_roots() {
        for url in [
            "ftp://node.example",
            "node.example:3413",
            "https://user:pw@node.example",
            "https://node.example/?x=1",
            "https://node.example/#frag",
            "",
        ] {
            assert!(
                matches!(parse_node_url(url, false), Err(NodeError::InvalidUrl)),
                "{url}"
            );
        }
    }

    #[test]
    fn basic_auth_uses_the_epic_user_and_is_sensitive() {
        let value = basic_authorization(&SecretString::from("s3cret")).unwrap();
        assert!(value.is_sensitive());
        assert_eq!(value.to_str().unwrap(), "Basic ZXBpYzpzM2NyZXQ=");
    }

    #[test]
    fn basic_auth_buffers_are_sized_before_the_secret_is_written() {
        for len in [0, 1, 2, 3, 63, 64, 1000] {
            let secret = SecretString::from("k".repeat(len));
            let credentials = basic_credentials(&secret).unwrap();
            assert_eq!(credentials.capacity(), credentials.len(), "{len}");
            let header = basic_header(&credentials).unwrap();
            assert_eq!(header.capacity(), header.len(), "{len}");
            let expected = format!(
                "Basic {}",
                BASE64.encode(format!("epic:{}", secret.expose_secret()))
            );
            assert_eq!(header.as_slice(), expected.as_bytes(), "{len}");
        }
    }
}

#[cfg(test)]
mod onion_tests {
    use super::*;

    #[test]
    fn plain_http_to_an_onion_needs_a_dialer_and_to_a_remote_host_is_never_allowed() {
        let onion = "http://abc.onion:3413";
        assert!(parse_node_url(onion, true).is_ok());
        assert!(matches!(
            parse_node_url(onion, false),
            Err(NodeError::PlainHttpToRemoteHost)
        ));
        for url in [
            "http://node.example",
            "http://onion.example",
            "http://1.2.3.4",
        ] {
            assert!(
                matches!(
                    parse_node_url(url, true),
                    Err(NodeError::PlainHttpToRemoteHost)
                ),
                "{url}"
            );
        }
    }
}
