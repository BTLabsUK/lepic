// SPDX-License-Identifier: Apache-2.0
//! How a [`crate::ForeignClient`] opens its byte streams. By default hyper's own connector
//! resolves the wallet's host and connects; a [`ForeignDialer`] takes that over, so the app can
//! send the bytes another way, such as through tor. TLS and the `Host` header stay those of the
//! wallet's URL whatever the dialer connects to.

use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tower_service::Service;

use crate::url::is_this_computer;

/// A byte stream to a wallet, before TLS.
pub trait ForeignStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> ForeignStream for T {}

pub type ForeignDialFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn ForeignStream>>> + Send + 'a>>;

/// Opens the stream for each new connection to a wallet. The dialer chooses where the bytes go
/// and bounds the time it takes; `host` and `port` are those of the wallet's URL.
pub trait ForeignDialer: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> ForeignDialFuture<'a>;
}

/// What hyper-rustls wraps: hyper's own connector, one that connects only to other computers,
/// or a [`ForeignDialer`].
#[derive(Clone)]
pub(crate) enum ForeignConnector {
    Direct(HttpConnector),
    OtherComputers { connect_timeout: Duration },
    Dialed(Arc<dyn ForeignDialer>),
}

/// The refusal of an address that is this computer's own, carried inside the connector's
/// [`io::Error`] until the client turns it into [`crate::ClientError::ThisComputer`].
#[derive(Debug, thiserror::Error)]
#[error("the address is one of this computer's own")]
pub(crate) struct ThisComputer;

/// Whether `error` or one of its causes is a [`ThisComputer`] refusal.
pub(crate) fn refused_this_computer(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        let inner = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .map(|inner| inner as &(dyn Error + 'static));
        if error.is::<ThisComputer>() || inner.is_some_and(<dyn Error>::is::<ThisComputer>) {
            return true;
        }
        cause = error.source();
    }
    false
}

/// Resolves `host` and connects to the first of its addresses that is not this computer's own.
/// The check is on the resolved addresses, the ones connected to, so an answer that names this
/// computer is never connected to whatever an earlier lookup said.
pub(crate) async fn connect_to_other_computer(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut refused = false;
    let mut failed = None;
    for address in tokio::net::lookup_host((host, port)).await? {
        if is_this_computer(address.ip()) {
            refused = true;
            continue;
        }
        match TcpStream::connect(address).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => failed = Some(error),
        }
    }
    Err(failed.unwrap_or_else(|| {
        if refused {
            io::Error::new(io::ErrorKind::PermissionDenied, ThisComputer)
        } else {
            io::Error::new(io::ErrorKind::NotFound, "the host has no address")
        }
    }))
}

pub(crate) struct Dialed(TokioIo<Box<dyn ForeignStream>>);

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

impl Service<Uri> for ForeignConnector {
    type Response = Dialed;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Dialed>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Direct(http) => http.poll_ready(cx).map_err(io::Error::other),
            Self::OtherComputers { .. } | Self::Dialed(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        match self {
            Self::Direct(http) => {
                let connecting = http.call(uri);
                Box::pin(async move {
                    let stream = connecting.await.map_err(io::Error::other)?.into_inner();
                    Ok(Dialed(TokioIo::new(
                        Box::new(stream) as Box<dyn ForeignStream>
                    )))
                })
            }
            Self::OtherComputers { connect_timeout } => {
                let connect_timeout = *connect_timeout;
                Box::pin(async move {
                    let (host, port) = dial_target(&uri)?;
                    let stream = tokio::time::timeout(
                        connect_timeout,
                        connect_to_other_computer(&host, port),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "connecting took too long")
                    })??;
                    Ok(Dialed(TokioIo::new(
                        Box::new(stream) as Box<dyn ForeignStream>
                    )))
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
    use tokio::net::TcpListener;

    use super::*;

    /// A listener on `address` and a check that nothing connected to it.
    async fn untouched(address: &str) -> (u16, impl FnOnce()) {
        let listener = TcpListener::bind((address, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let check = move || {
            let waker = std::task::Waker::noop();
            let mut cx = Context::from_waker(waker);
            assert!(
                listener.poll_accept(&mut cx).is_pending(),
                "a connection reached {address}"
            );
        };
        (port, check)
    }

    #[tokio::test]
    async fn refuses_names_and_literals_that_resolve_to_this_computer() {
        let (port, nothing_connected) = untouched("127.0.0.1").await;
        for host in [
            "127.0.0.1",
            "localhost",
            "127.1",
            "0.0.0.0",
            "::ffff:127.0.0.1",
        ] {
            let error = connect_to_other_computer(host, port).await.unwrap_err();
            assert!(refused_this_computer(&error), "{host}: {error}");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{host}");
        }
        nothing_connected();
    }

    #[test]
    fn takes_the_port_of_the_url_or_the_default_of_its_scheme() {
        for (url, expected) in [
            ("https://wallet.example/v2/foreign", ("wallet.example", 443)),
            (
                "https://wallet.example:3415/v2/foreign",
                ("wallet.example", 3415),
            ),
            ("http://127.0.0.1/v2/foreign", ("127.0.0.1", 80)),
            ("http://[::1]:3415/v2/foreign", ("::1", 3415)),
        ] {
            let target = dial_target(&url.parse().unwrap()).unwrap();
            assert_eq!(target, (expected.0.to_owned(), expected.1), "{url}");
        }
    }
}
