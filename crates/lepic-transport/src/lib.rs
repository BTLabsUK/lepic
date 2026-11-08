// SPDX-License-Identifier: Apache-2.0
//! Transport traits, transport registry, format policy and the file transport.

pub mod codecs;
pub mod error;
pub mod file;
#[cfg(any(test, feature = "loopback"))]
pub mod loopback;
pub mod marker;
pub mod method;
pub mod policy;
pub mod registry;
pub mod transport;
