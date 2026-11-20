// SPDX-License-Identifier: Apache-2.0
//! Tor on desktop and Android (ADR 0018), the wire side: the wallet's onion service, sends to
//! other onions over SOCKS, and Tor streams for the Epicbox relay and the node. The host bundles
//! a `tor` binary; [`TorProcess`] runs it as one child process per open wallet and drives it over
//! its control port.
//!
//! The crate's `README.md` describes the process states, the onion keys and [`RelayTor`].

pub mod client;
pub mod control;
pub mod listen;
pub mod onion;
pub mod process;
pub mod relay;
pub mod socks;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use client::OnionClientSettings;
pub use control::{ControlError, MAX_STREAMS_PER_CIRCUIT};
pub use listen::{
    ONION_SOCKET, OnionTarget, PREVIOUS_ONION_SOCKET, listen_settings, onion_socket_path,
    previous_onion_socket_path,
};
pub use onion::{
    ONION_NAME_LEN, OnionAddress, OnionError, expanded_secret, onion_address, parse_onion,
    public_key_of_seed,
};
pub use process::{
    FailureKind, FixedSocks, SocksProxy, TorFailure, TorNetworkTimings, TorProcess, TorSettings,
    TorState, TorTimings,
};
pub use relay::{RelayTor, RelayTorError, StreamGroup};
pub use socks::{SendFailure, SocksError, SocksReply};
