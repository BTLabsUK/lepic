// SPDX-License-Identifier: Apache-2.0
//! Transport traits, the method port, format policy and, with the `legacy` feature, the legacy
//! codec registries and the file transport.

#[cfg(feature = "legacy")]
pub mod codecs;
pub mod error;
#[cfg(feature = "legacy")]
pub mod file;
#[cfg(any(test, feature = "loopback"))]
pub mod loopback;
pub mod marker;
pub mod method;
pub mod policy;
pub mod transport;
