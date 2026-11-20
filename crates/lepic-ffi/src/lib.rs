// SPDX-License-Identifier: Apache-2.0
//! The LEPIC wallet engine for Flutter apps, through flutter_rust_bridge (ADR 0007, ADR 0023).
//!
//! `api` is what the app calls. The binding's repository, lepic-flutter, generates
//! `frb_generated.rs` here and the Dart package there in one run and records their fingerprint
//! in `bridge.sha256`; `cargo xtask repo-lint` fails when `api` or the generated module changes
//! without a new run. The other modules connect the engine's ports to the app's runtime and
//! secret store.
//!
//! See `README.md` in this crate and `docs/ffi.md` for the session model, the store keys, the
//! secrets that cross into Dart and the error codes.

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
mod migration;
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
mod tuning;
mod ur_slate;
mod vault_port;
