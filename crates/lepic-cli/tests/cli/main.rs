// SPDX-License-Identifier: Apache-2.0
//! The integration tests of `lepic-cli`, built as one test binary: every file below was once a
//! binary of its own, and each of those linked the whole wallet again. Run one former file by
//! its module name, `cargo nextest run -p lepic-cli -E 'test(/^api_tls::/)'`.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in the
// shared helpers that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;

mod api_contacts;
mod api_contract;
mod api_metrics;
mod api_network;
mod api_open;
mod api_payments;
mod api_service;
mod api_tls;
mod api_wallet;
mod api_webhook;
mod command_tree;
mod connection_mode;
mod contacts;
mod crypto_context;
mod encrypted_store;
mod end_to_end;
mod errors;
mod large_store;
mod mailbox;
mod owner_commands;
mod payments_paging;
mod send_epic1;
mod serve_push;
mod serve_tick;
mod service;
mod settings;
mod upgrade;
mod wallet_backup;
mod wallet_scan;
