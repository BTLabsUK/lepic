// SPDX-License-Identifier: Apache-2.0
//! Transaction methods: the registry a consumer builds its methods into, and one module per
//! method, each behind a feature of the same name.

pub use lepic_transport::{codecs, error, method, policy, transport};

pub mod registry;

/// The file method.
#[cfg(feature = "file")]
pub mod file {
    pub use lepic_transport::file::*;
}

#[cfg(feature = "epicbox")]
pub mod epicbox;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "tor")]
pub mod tor;
