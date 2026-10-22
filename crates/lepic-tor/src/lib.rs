//! Tor on desktop (ADR 0018): the wallet's onion service and sending to onion addresses, over a
//! `tor` binary the host bundles and runs as a child process per open wallet.

pub mod onion;

pub use onion::{
    ONION_NAME_LEN, OnionAddress, OnionError, expanded_secret, onion_address, parse_onion,
    public_key_of_seed,
};
