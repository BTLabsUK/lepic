// SPDX-License-Identifier: Apache-2.0
//! The wallet foreign API of `epic-wallet` over HTTP (ADR 0017): the JSON-RPC messages, the
//! client that posts a slate to a listening wallet, and the listener, which can serve another
//! route on the same socket. Wire-compatible with `epic-wallet` `v4.1.0`
//! `send -m http` and `listen -m http`; the method over it is `lepic_methods::http`.
//!
//! The crate's `README.md` describes the messages, the addresses and the listener's limits.

pub mod client;
pub mod dial;
pub mod error;
pub mod rpc;
pub mod server;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod url;

pub use client::{ClientSettings, RpcClient, webpki_tls_config};
pub use dial::{RpcDialFuture, RpcDialer, RpcStream};
pub use error::{ClientError, ListenError, RpcError, UrlError};
pub use rpc::{BlockFees, CoinbaseAnswer};
pub use server::{
    Busy, CoinbaseAccess, Exposure, ListenLimits, ListenSettings, ListenerHandle, ReceiveHandler,
    Refusal, RouteRequest, RouteResponse, SocketRoute, listen, listen_with,
};
#[cfg(unix)]
pub use server::{listen_unix, listen_unix_with};
pub use url::{DEFAULT_LISTEN_PORT, ListenerUrl, PlainHttp, Scheme, is_this_computer};
