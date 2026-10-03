//! Client for the Epic node foreign JSON-RPC API.
//!
//! [`NodeApi`] is the port the wallet engine uses. [`NodeClient`] implements it over any
//! [`RpcTransport`]: [`HttpTransport`] for real nodes and, with the `mock` feature,
//! [`mock::MockNode`] for tests.

mod api;
mod client;
pub mod decode;
mod error;
mod http;
#[cfg(feature = "mock")]
pub mod mock;
mod plausible;
mod rpc;
mod wire;

pub use api::{
    LocatedKernel, NodeApi, NodeVersion, OutputLocation, PmmrIndices, Propagation, Tip,
    UnspentOutput, UnspentOutputs,
};
pub use client::{CallPolicy, NodeClient, RetryPolicy, RpcTransport};
pub use error::{FieldProblem, NodeError, NodeRejection, RejectionKind};
pub use http::{HttpSettings, HttpTransport, webpki_tls_config};

/// A client for a real node over HTTP or HTTPS.
pub type HttpNodeClient = NodeClient<HttpTransport>;
