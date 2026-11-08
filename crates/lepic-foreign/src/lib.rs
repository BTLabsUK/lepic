// SPDX-License-Identifier: Apache-2.0
//! The wallet foreign API over HTTP (ADR 0017), the wire side: the JSON-RPC messages, the client
//! that posts a slate to a wallet listening at an `http(s)://` address, and the listener. The
//! method over it is `lepic_methods::http`. Wire-compatible with `epic-wallet` `v4.1.0` `send -m http` and `listen -m http`.

pub mod client;
pub mod dial;
pub mod error;
pub mod rpc;
pub mod server;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod url;

pub use client::{ClientSettings, ForeignClient, webpki_tls_config};
pub use dial::{ForeignDialFuture, ForeignDialer, ForeignStream};
pub use error::{ClientError, ListenError, RpcError, UrlError};
pub use rpc::{BlockFees, CoinbaseAnswer};
#[cfg(unix)]
pub use server::listen_unix;
pub use server::{
    CoinbaseAccess, Exposure, ListenLimits, ListenSettings, ListenerHandle, ReceiveHandler,
    Refusal, listen,
};
pub use url::{DEFAULT_LISTEN_PORT, ForeignUrl, PlainHttp, Scheme};
