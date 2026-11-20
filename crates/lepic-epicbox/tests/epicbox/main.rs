// SPDX-License-Identifier: Apache-2.0
//! The integration tests of `lepic-epicbox`, built as one test binary: every file below was once a
//! binary of its own, and each of those linked the whole crate again. Run one former file by
//! its module name, `cargo nextest run -p lepic-epicbox -E 'test(/^<module>::/)'`.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in the
// shared helpers that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod client_support;

mod address;
mod bounded_frames;
mod cancel;
mod challenge_watchdog;
mod client;
mod crypto;
mod frame;
mod host_logs;
mod identities;
mod mailbox;
mod mock_relay_mux;
mod mux;
mod mux_attach_host;
mod mux_cancel;
mod mux_live;
mod mux_post;
mod mux_robust;
mod session;
mod timeouts;
