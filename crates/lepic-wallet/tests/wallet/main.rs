// SPDX-License-Identifier: Apache-2.0
//! The wallet's integration tests, one module per former test file, in one binary so the wallet
//! and its dependencies link once. `vectors.rs` stays a separate binary for `cargo xtask vectors`.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in the
// shared helpers that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod adversarial_invoice_payer;
mod adversarial_races;
mod adversarial_replay;
mod app_data;
mod app_data_logs;
mod cancel;
mod coinbase;
mod completion_watch;
mod contact_check;
mod contact_domain;
mod contact_invoices;
mod contact_kind;
mod contact_lock_order;
mod contact_mailboxes;
mod contact_native;
mod contact_receive_race;
mod epic1;
mod epic1_installs;
mod epic1_outbox;
mod epic1_outbox_copies;
mod epicbox_invoices;
mod epicbox_send_logs;
#[path = "epicbox_invoices/world.rs"]
mod epicbox_world;
mod finalize;
mod finalize_cancel_race;
mod finalize_crash;
mod finalize_logs;
mod finalize_pool;
mod in_person;
mod inbox;
mod inbox_bounds;
mod inbox_logs;
mod inbox_pushed;
mod inbox_retention;
#[path = "inbox/world.rs"]
mod inbox_world;
mod invoice;
#[path = "invoice/harness.rs"]
mod invoice_harness;
mod invoice_payer;
mod kernel_lookup;
#[cfg(feature = "sqlite")]
mod legacy_history;
mod legacy_support;
#[cfg(feature = "sqlite")]
mod lifecycle;
mod lifecycle_logs;
mod listing;
mod lying_node;
mod messages;
mod min_confirmations;
mod no_probe;
mod offline_session;
mod pairing;
#[path = "pairing/helpers.rs"]
mod pairing_helpers;
mod pairing_v3;
mod post_retry;
mod read_api;
mod receive;
#[path = "receive/harness.rs"]
mod receive_harness;
mod receive_logs;
mod recover;
mod refresh;
mod refresh_node_data;
mod relay_cancel;
mod release;
mod restore_from_height;
mod scan;
mod scan_node_data;
mod scan_support;
mod sealed;
mod selection;
mod selection_properties;
mod self_send;
mod send;
mod send_cancelled;
mod send_declined;
mod send_logs;
mod send_posted;
mod send_support;
mod send_unanswered;
mod slate_reply_mutations;
mod spend_back;
mod state;
mod support;
mod twins;
mod unsolicited;
mod v2_local_ttl;
