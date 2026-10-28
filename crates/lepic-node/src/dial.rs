// SPDX-License-Identifier: Apache-2.0
//! How an HTTP transport opens its byte streams. By default hyper's own connector resolves the
//! node's host and connects; a [`NodeDialer`] takes that over, so the app can send the bytes
//! another way, such as through tor. TLS and the `Host` header stay those of the node's URL
//! whatever the dialer connects to.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;

/// A byte stream to a node, before TLS.
pub trait NodeStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> NodeStream for T {}

pub type DialFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn NodeStream>>> + Send + 'a>>;

/// Opens the stream for each new connection to the node. The dialer chooses where the bytes go
/// and bounds the time it takes; `host` and `port` are those of the node's URL.
pub trait NodeDialer: Send + Sync {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> DialFuture<'a>;
}

/// What hyper-rustls wraps: either hyper's own connector or a [`NodeDialer`].
#[derive(Clone)]
pub(crate) enum NodeConnector {
    Direct(HttpConnector),
    Dialed(Arc<dyn NodeDialer>),
}

pub(crate) struct Dialed(TokioIo<Box<dyn NodeStream>>);

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

impl Service<Uri> for NodeConnector {
    type Response = Dialed;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Dialed>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Direct(http) => http.poll_ready(cx).map_err(io::Error::other),
            Self::Dialed(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        match self {
            Self::Direct(http) => {
                let connecting = http.call(uri);
                Box::pin(async move {
                    let stream = connecting.await.map_err(io::Error::other)?.into_inner();
                    Ok(Dialed(
                        TokioIo::new(Box::new(stream) as Box<dyn NodeStream>),
                    ))
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
    use super::*;

    #[test]
    fn takes_the_port_of_the_url_or_the_default_of_its_scheme() {
        for (url, expected) in [
            ("https://node.example/v1", ("node.example", 443)),
            ("https://node.example:3413/v1", ("node.example", 3413)),
            ("http://127.0.0.1/v1", ("127.0.0.1", 80)),
            ("http://[::1]:3413/v1", ("::1", 3413)),
        ] {
            let target = dial_target(&url.parse().unwrap()).unwrap();
            assert_eq!(target, (expected.0.to_owned(), expected.1), "{url}");
        }
    }
}
