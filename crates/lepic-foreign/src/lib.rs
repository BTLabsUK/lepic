// SPDX-License-Identifier: Apache-2.0
//! The wallet foreign API over HTTP (ADR 0017): send a slate to a wallet listening at an
//! `http(s)://` address and get its answer in the same exchange, and listen for payments the
//! same way. Wire-compatible with `epic-wallet` `v4.1.0` `send -m http` and `listen -m http`.

pub mod client;
pub mod error;
pub mod rpc;
pub mod server;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod transport;
pub mod url;

pub use client::{ClientSettings, ForeignClient, webpki_tls_config};
pub use error::{ClientError, ListenError, RpcError, UrlError};
pub use server::{
    Exposure, ListenLimits, ListenSettings, ListenerHandle, ReceiveHandler, Refusal, listen,
};
pub use transport::{HttpPolicy, HttpTransport, TRANSPORT_ID};
pub use url::{DEFAULT_LISTEN_PORT, ForeignUrl, PlainHttp, Scheme};
