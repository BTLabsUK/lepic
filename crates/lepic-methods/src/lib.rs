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

/// The Epicbox method.
#[cfg(feature = "epicbox")]
pub mod epicbox {
    pub use lepic_epicbox::TRANSPORT_ID;
    pub use lepic_epicbox::transport::*;
}

/// The HTTP method.
#[cfg(feature = "http")]
pub mod http {
    pub use lepic_foreign::{HttpPolicy, HttpTransport, TRANSPORT_ID};
}

/// The Tor method.
#[cfg(feature = "tor")]
pub mod tor {
    pub use lepic_tor::{
        OnionClient, OnionClientSettings, TRANSPORT_ID, TorSendError, TorTransport,
    };
}
