//! flutter_rust_bridge API over the LEPIC wallet engine for the app (ADR 0007, ADR 0023).
//!
//! `api` is what the app sees. The binding's own repository, gitlab.com/btlabs/lepic-flutter,
//! generates `frb_generated.rs` here and the matching package there in one run, and records in
//! `bridge.sha256` what it generated from; `cargo xtask repo-lint` fails when `api` or the
//! generated module changes without a new run. Everything else is glue between the engine's ports
//! and the app.
//!
//! # The app's secret store
//!
//! LEPIC writes these keys to the store the app passes in: `lepic.vault`, the seed encrypted under
//! the wallet password; `lepic.vault-next` while a password change runs; `lepic.pin-failures` after
//! a failed password or PIN attempt; and for a PIN wallet `lepic.pin-key` and, while a PIN change
//! is pending, `lepic.pin-key-pending`.

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
mod inspect;
mod log;
#[cfg(feature = "mock")]
mod mock;
#[cfg(not(feature = "tor"))]
mod no_tor;
mod node;
mod password;
mod pin;
mod session;
#[cfg(test)]
mod tests;
mod ur_slate;
mod vault_port;
