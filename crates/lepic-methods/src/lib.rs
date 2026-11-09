// SPDX-License-Identifier: Apache-2.0
//! Transaction methods: the registry a consumer builds its methods into, and one module per
//! method, each behind a feature of the same name. Every method speaks the legacy wire formats,
//! so each needs the `legacy` feature; without it only the registry is built and no method is
//! found in it.

#[cfg(feature = "legacy")]
pub use lepic_transport::codecs;
pub use lepic_transport::{error, method, policy, transport};

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
