// SPDX-License-Identifier: Apache-2.0
//! Tor on desktop and Android (ADR 0018): the wallet's onion service and sending to onion
//! addresses, over a `tor` binary the host bundles and runs as a child process per open wallet.

pub mod control;
pub mod listen;
pub mod onion;
pub mod process;
pub mod relay;
pub mod socks;
pub mod transport;

pub use control::{ControlError, MAX_STREAMS_PER_CIRCUIT};
pub use listen::listen_settings;
pub use onion::{
    ONION_NAME_LEN, OnionAddress, OnionError, expanded_secret, onion_address, parse_onion,
    public_key_of_seed,
};
pub use process::{
    FailureKind, FixedSocks, SocksProxy, TorFailure, TorProcess, TorSettings, TorState, TorTimings,
};
pub use relay::{RelayTor, RelayTorError};
pub use socks::{SendFailure, SocksError, SocksReply};
pub use transport::{OnionClient, OnionClientSettings, TRANSPORT_ID, TorSendError, TorTransport};
