//! Epicbox addresses, message crypto, protocol frames and relay transport.

mod address;

pub use address::{
    AddressError, DEFAULT_DOMAIN, DEFAULT_PORT, Domain, EpicboxAddress, MAX_ADDRESS_LEN,
    MAX_DOMAIN_LEN, Network,
};
