//! What the CLI takes from the machine it runs on.

use std::future::Future;
use std::io::Read as _;
use std::pin::Pin;
use std::sync::Arc;

use lepic_epicbox::{Connector, TcpConnector};
use lepic_keychain::KdfParams;
use lepic_node::{CallPolicy, HttpSettings, HttpTransport, NodeClient, RpcTransport};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::exit::CliError;
use crate::settings::Settings;

pub type Interrupt = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The node client a [`Host`] hands out.
pub type HostNode<H> = NodeClient<<H as Host>::Transport>;

/// Longer than any node API secret.
const MAX_API_SECRET_LEN: u64 = 1024;

/// The outside world of one command. [`ProcessHost`] is the real one; tests substitute a mock
/// node, an in-memory relay and a cheap key derivation.
pub trait Host {
    /// How node requests leave the process. The client around it is always a [`NodeClient`],
    /// so a command can start it from the tip the wallet stored.
    type Transport: RpcTransport + Clone + 'static;

    fn node(&self, settings: &Settings) -> Result<HostNode<Self>, CliError>;

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
    type Transport = HttpTransport;

    fn node(&self, settings: &Settings) -> Result<HostNode<Self>, CliError> {
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

/// The node's `.foreign_api_secret`, as `epic-wallet` reads it: the file's text, trimmed, cut at
/// [`MAX_API_SECRET_LEN`] bytes.
fn read_api_secret(path: &std::path::Path) -> Result<SecretString, CliError> {
    let file = std::fs::File::open(path).map_err(CliError::io("read the node api secret file"))?;
    let mut bytes = api_secret_buffer();
    file.take(MAX_API_SECRET_LEN)
        .read_to_end(&mut bytes)
        .map_err(CliError::io("read the node api secret file"))?;
    api_secret_from(&bytes)
}

/// Holds the most a read takes from the start, and one byte more so a full read never makes the
/// reader grow it: a growing `Vec` leaves the bytes it moved out of in freed memory, where
/// `Zeroizing` cannot wipe them.
fn api_secret_buffer() -> Zeroizing<Vec<u8>> {
    let capacity = usize::try_from(MAX_API_SECRET_LEN)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    Zeroizing::new(Vec::with_capacity(capacity))
}

/// The one copy that leaves is sized exactly, so the secret type keeps it without moving it.
fn api_secret_from(bytes: &[u8]) -> Result<SecretString, CliError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        CliError::io("read the node api secret file")(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the node api secret is not valid utf-8",
        ))
    })?;
    Ok(SecretString::from(text.trim()))
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use secrecy::ExposeSecret as _;

    use super::*;

    #[test]
    fn the_longest_api_secret_is_read_without_moving_the_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".foreign_api_secret");
        let limit = usize::try_from(MAX_API_SECRET_LEN).unwrap();
        std::fs::write(&path, "k".repeat(limit + 10)).unwrap();
        let mut bytes = api_secret_buffer();
        let start = bytes.as_ptr();
        std::fs::File::open(&path)
            .unwrap()
            .take(MAX_API_SECRET_LEN)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), limit);
        assert_eq!(bytes.as_ptr(), start);
    }

    #[test]
    fn reads_the_api_secret_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".foreign_api_secret");
        std::fs::write(&path, "  s3cret\r\n").unwrap();
        assert_eq!(read_api_secret(&path).unwrap().expose_secret(), "s3cret");
        std::fs::write(&path, [0xff, b'\n']).unwrap();
        assert!(matches!(
            read_api_secret(&path),
            Err(CliError::Io { source, .. }) if source.kind() == std::io::ErrorKind::InvalidData
        ));
    }
}
