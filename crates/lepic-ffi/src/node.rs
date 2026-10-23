//! How node requests leave the binding: over HTTP to the configured node, or, in a `mock` build,
//! to an in-process scripted chain.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use lepic_node::{
    CallPolicy, HttpSettings, HttpTransport, NodeClient, NodeError, RpcTransport, webpki_tls_config,
};

use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::WalletConfig;

pub(crate) type Node = NodeClient<SwitchableBackend>;

/// The node a session talks to, which [`SwitchableBackend::replace`] changes while the
/// session stays open. Clones share it. A request goes to the node set when it starts.
#[derive(Clone)]
pub(crate) struct SwitchableBackend(Arc<RwLock<NodeBackend>>);

impl SwitchableBackend {
    pub(crate) fn new(backend: NodeBackend) -> Self {
        Self(Arc::new(RwLock::new(backend)))
    }

    pub(crate) fn replace(&self, backend: NodeBackend) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = backend;
    }

    fn current(&self) -> NodeBackend {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RpcTransport for SwitchableBackend {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        self.current().post(endpoint, body).await
    }

    // The label is borrowed from the backend, which a switch may replace while it is
    // borrowed; the switch logs the host it moves to instead.
    fn node_label(&self) -> &str {
        "configured node"
    }
}

#[derive(Clone)]
pub(crate) enum NodeBackend {
    Http(Box<HttpTransport>),
    #[cfg(feature = "mock")]
    Mock(crate::mock::MockBackend),
}

impl RpcTransport for NodeBackend {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        match self {
            Self::Http(http) => http.post(endpoint, body).await,
            #[cfg(feature = "mock")]
            Self::Mock(mock) => mock.post(endpoint, body).await,
        }
    }

    fn node_label(&self) -> &str {
        match self {
            Self::Http(http) => http.node_label(),
            #[cfg(feature = "mock")]
            Self::Mock(mock) => mock.node_label(),
        }
    }
}

/// Where the runtime sends node requests.
#[derive(Clone)]
pub(crate) enum NodeFactory {
    Http,
    #[cfg(feature = "mock")]
    Mock(crate::mock::MockBackend),
}

/// The node API secret of a [`WalletConfig`], in a buffer wiped on drop.
pub(crate) struct NodeSecret(Zeroizing<Option<String>>);

impl NodeSecret {
    /// Moves the secret out of `config`. Every binding call that receives a config does this
    /// first, so no early return leaves the secret behind in a buffer that is not wiped.
    pub(crate) fn take(config: &mut WalletConfig) -> Self {
        Self(Zeroizing::new(config.node_api_secret.take()))
    }
}

impl NodeFactory {
    /// A client for the node `config` names, authenticating with `secret`.
    pub(crate) fn client(
        &self,
        config: &WalletConfig,
        secret: &NodeSecret,
    ) -> Result<Node, WalletError> {
        let backend = SwitchableBackend::new(self.backend(config, secret)?);
        Ok(NodeClient::new(backend, self.policy()))
    }

    /// The backend for the node `config` names: `InvalidArgument` for a URL that is not one
    /// of a node.
    pub(crate) fn backend(
        &self,
        config: &WalletConfig,
        secret: &NodeSecret,
    ) -> Result<NodeBackend, WalletError> {
        match self {
            Self::Http => {
                let settings = HttpSettings {
                    api_secret: secret.0.as_deref().map(Into::into),
                    connect_timeout: Duration::from_secs(15),
                    ..HttpSettings::default()
                };
                let tls = webpki_tls_config().map_err(|error| node_config_error(&error))?;
                let http = HttpTransport::new(&config.node_url, &settings, tls)
                    .map_err(|error| node_config_error(&error))?;
                Ok(NodeBackend::Http(Box::new(http)))
            }
            #[cfg(feature = "mock")]
            Self::Mock(mock) => Ok(NodeBackend::Mock(mock.at(&config.node_url))),
        }
    }

    fn policy(&self) -> CallPolicy {
        match self {
            Self::Http => CallPolicy::default(),
            #[cfg(feature = "mock")]
            Self::Mock(_) => crate::mock::MockBackend::policy(),
        }
    }
}

fn node_config_error(error: &NodeError) -> WalletError {
    WalletError::new(
        WalletErrorKind::InvalidArgument,
        lepic_telemetry::ErrorChain(error).to_string(),
    )
}

/// The node's error as a binding error.
pub(crate) fn node_error(error: &NodeError) -> WalletError {
    WalletError::new(
        WalletErrorKind::NodeUnreachable,
        lepic_telemetry::ErrorChain(error).to_string(),
    )
}
