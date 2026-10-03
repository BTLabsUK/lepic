//! flutter_rust_bridge API over the LEPIC wallet engine for the Flutter frontend (ADR 0007).
//!
//! `api` is what Dart sees; `bindings/flutter` holds the generated Dart package. Everything else
//! is glue between the engine's ports and the app.

pub mod api;
mod boundary;
// flutter_rust_bridge writes this file; its glue needs unsafe code and does not follow the
// workspace lints.
#[allow(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction
)]
mod frb_generated;
mod log;
#[cfg(feature = "mock")]
mod mock;
mod node;
mod session;
mod vault_port;
