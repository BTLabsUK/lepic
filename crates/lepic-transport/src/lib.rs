//! Transport traits, transport registry, format policy and the file transport.

pub mod error;
pub mod file;
#[cfg(any(test, feature = "loopback"))]
pub mod loopback;
pub mod policy;
pub mod registry;
pub mod transport;
