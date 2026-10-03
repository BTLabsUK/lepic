//! What the CLI takes from the machine it runs on.

use std::future::Future;
use std::io::Read as _;
use std::pin::Pin;
use std::sync::Arc;

use lepic_epicbox::{Connector, TcpConnector};
use lepic_keychain::KdfParams;
use lepic_node::{CallPolicy, HttpNodeClient, HttpSettings, HttpTransport, NodeApi, NodeClient};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::exit::CliError;
use crate::settings::Settings;

pub type Interrupt = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Longer than any node API secret.
const MAX_API_SECRET_LEN: u64 = 1024;

/// The outside world of one command. [`ProcessHost`] is the real one; tests substitute a mock
/// node, an in-memory relay and a cheap key derivation.
pub trait Host {
    type Node: NodeApi + 'static;

    fn node(&self, settings: &Settings) -> Result<Self::Node, CliError>;

    fn relay_connector(&self) -> Result<Arc<dyn Connector>, CliError>;

    /// The Argon2 setting of a new vault. Opening a vault reads the setting from the file.
    fn vault_kdf(&self) -> KdfParams;

    /// Resolves when the user asks the command to stop. Called once per command, inside its
    /// runtime, before anything is read, so that an interrupt at a prompt reaches the CLI.
    fn interrupted(&self) -> Interrupt;
}

/// The node over HTTP, the relay over TCP and TLS, Ctrl-C.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessHost;

impl Host for ProcessHost {
    type Node = HttpNodeClient;

    fn node(&self, settings: &Settings) -> Result<HttpNodeClient, CliError> {
        let api_secret = match &settings.node_api_secret_file {
            Some(path) => Some(read_api_secret(path)?),
            None => None,
        };
        let http = HttpSettings {
            api_secret,
            ..HttpSettings::default()
        };
        let transport = HttpTransport::new(
            settings.node.as_str(),
            &http,
            lepic_node::webpki_tls_config()?,
        )?;
        Ok(NodeClient::new(transport, CallPolicy::default()))
    }

    fn relay_connector(&self) -> Result<Arc<dyn Connector>, CliError> {
        Ok(Arc::new(
            TcpConnector::new(lepic_node::webpki_tls_config()?),
        ))
    }

    fn vault_kdf(&self) -> KdfParams {
        KdfParams::DEFAULT
    }

    /// The handler is installed here, not on first poll, so no Ctrl-C between this call and
    /// the first prompt can end the process with echo off. Without a handler the command runs
    /// until it ends on its own.
    #[cfg(unix)]
    fn interrupted(&self) -> Interrupt {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::interrupt()) {
            Ok(mut interrupt) => Box::pin(async move {
                if interrupt.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
            }),
            Err(_) => Box::pin(std::future::pending()),
        }
    }

    #[cfg(not(unix))]
    fn interrupted(&self) -> Interrupt {
        Box::pin(async {
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        })
    }
}

/// The node's `.foreign_api_secret`, as `epic-wallet` reads it: the file's text, trimmed.
fn read_api_secret(path: &std::path::Path) -> Result<SecretString, CliError> {
    let file = std::fs::File::open(path).map_err(CliError::io("read the node api secret file"))?;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_API_SECRET_LEN)
        .read_to_string(&mut text)
        .map_err(CliError::io("read the node api secret file"))?;
    Ok(SecretString::from(text.trim().to_owned()))
}
