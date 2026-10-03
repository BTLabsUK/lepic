//! How node requests leave the binding: over HTTP to the configured node, or, in a `mock` build,
//! to an in-process scripted chain.

use std::time::Duration;

use lepic_node::{
    CallPolicy, HttpSettings, HttpTransport, NodeClient, NodeError, RpcTransport, webpki_tls_config,
};

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::WalletConfig;

pub(crate) type Node = NodeClient<NodeBackend>;

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

impl NodeFactory {
    pub(crate) fn client(&self, config: &WalletConfig) -> Result<Node, WalletError> {
        match self {
            Self::Http => {
                let settings = HttpSettings {
                    api_secret: config.node_api_secret.clone().map(Into::into),
                    connect_timeout: Duration::from_secs(15),
                    ..HttpSettings::default()
                };
                let tls = webpki_tls_config().map_err(|error| node_config_error(&error))?;
                let http = HttpTransport::new(&config.node_url, &settings, tls)
                    .map_err(|error| node_config_error(&error))?;
                Ok(NodeClient::new(
                    NodeBackend::Http(Box::new(http)),
                    CallPolicy::default(),
                ))
            }
            #[cfg(feature = "mock")]
            Self::Mock(mock) => Ok(mock.client()),
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
