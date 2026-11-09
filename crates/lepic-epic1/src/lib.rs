// SPDX-License-Identifier: Apache-2.0
//! The epic1 address and the epic1 payment link (RFC 0003 §5.13, §5.14, Appendix B): pure
//! codes. No wallet, store, engine, network I/O or FFI.
//!
//! - [`bech32m`]: BIP 350 written for this crate.
//! - [`Epic1Address`]: two keys, the proof key and the seal key, on one network.
//! - [`Epic1Link`]: the address plus transport entries (`epicbox=`), an amount, a message and a
//!   label. Hosts in a link come from untrusted input; the host rule that classifies them lives
//!   in `lepic-transport`.

pub mod address;
mod amount;
pub mod bech32m;
mod link;
mod relay;

pub use address::{DATA_LEN, Epic1Address, Epic1Error, VERSION, hrp};
pub use amount::{AmountError, format_amount, parse_amount};
pub use lepic_epicbox::Network;
pub use link::{
    Delivery, Epic1Link, EpicboxTransport, LinkError, MAX_LINK_LEN, MAX_TRANSPORTS, MAX_VALUE_LEN,
    Skipped, TransportFault,
};
pub use relay::{MAX_HOST_PORT_LEN, RelayHost, RelayHostError, parse_host_port};
