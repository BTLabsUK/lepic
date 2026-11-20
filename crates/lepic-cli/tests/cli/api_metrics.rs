// SPDX-License-Identifier: Apache-2.0
//! `GET /api/v1/metrics` on the socket of `lepic serve`: off without `--metrics`, the Prometheus
//! text with it, and what its counters follow, in one process with a mock node and a mock relay.
//! The owner TLS side is in `api_tls`.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::json;
use support::{FUNDING, funded, http, problem, serving, serving_with};

const TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The families of the exposition and the type each says it has.
const FAMILIES: [(&str, &str); 14] = [
    ("lepic_balance", "gauge"),
    ("lepic_payments", "gauge"),
    ("lepic_payments_stuck", "gauge"),
    ("lepic_outbox_queue_depth", "gauge"),
    ("lepic_refresh_failures_total", "counter"),
    ("lepic_refresh_last_success_timestamp_seconds", "gauge"),
    ("lepic_wallet_height", "gauge"),
    ("lepic_node_height", "gauge"),
    ("lepic_mailbox_failures", "gauge"),
    ("lepic_mailbox_last_success_timestamp_seconds", "gauge"),
    ("lepic_mailbox_push_offered", "gauge"),
    ("lepic_mailbox_no_mux", "gauge"),
    ("lepic_payments_created_total", "counter"),
    ("lepic_payment_create_errors_total", "counter"),
];

fn scrape(socket: &Path) -> String {
    let reply = http(socket, "GET", "/api/v1/metrics", None);
    assert_eq!(reply.status, 200, "{reply:?}");
    assert_eq!(reply.header("content-type"), Some(TEXT), "{reply:?}");
    reply.body
}

/// The value of the sample `line_start` begins, e.g. `lepic_payments{state="posted"}`.
fn sample(text: &str, line_start: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(line_start)?.strip_prefix(' '))
        .map(|value| value.parse().unwrap())
}

#[test]
fn metrics_are_not_found_without_the_flag() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let reply = http(socket, "GET", "/api/v1/metrics", None);
        problem(&reply, 404, "not_found");
    });
}

#[test]
fn the_socket_answers_every_family_once_in_the_prometheus_format() {
    let (host, wallet) = funded();
    serving_with(host, &wallet, &["--metrics"], |socket, _| {
        let text = scrape(socket);
        let mut seen = BTreeSet::new();
        for (name, kind) in FAMILIES {
            assert_eq!(
                text.matches(&format!("# HELP {name} ")).count(),
                1,
                "{name} in {text}"
            );
            assert_eq!(
                text.matches(&format!("# TYPE {name} {kind}\n")).count(),
                1,
                "{name} in {text}"
            );
            seen.insert(name);
        }
        // Every sample belongs to a family named above.
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(seen.contains(name), "{line}");
        }
        assert!(text.ends_with('\n'), "{text}");

        let account = r#"{account="default",state="#;
        assert_eq!(
            sample(&text, &format!("lepic_balance{account}\"confirming\"}}")),
            Some(FUNDING),
            "{text}"
        );
        for state in ["spendable", "pending", "locked", "maturing"] {
            assert_eq!(
                sample(&text, &format!("lepic_balance{account}\"{state}\"}}")),
                Some(0),
                "{state} in {text}"
            );
        }
        for state in ["needs_approval", "awaiting_answer", "finalized", "posted"] {
            assert_eq!(
                sample(&text, &format!("lepic_payments{{state=\"{state}\"}}")),
                Some(0),
                "{state} in {text}"
            );
        }
        assert_eq!(sample(&text, "lepic_payments_stuck"), Some(0), "{text}");
        assert_eq!(sample(&text, "lepic_outbox_queue_depth"), Some(0), "{text}");
        assert!(sample(&text, "lepic_wallet_height").is_some(), "{text}");
        assert_eq!(
            sample(&text, "lepic_payments_created_total"),
            Some(0),
            "{text}"
        );
        // No error yet: the family has no sample.
        assert!(
            !text.contains("lepic_payment_create_errors_total{"),
            "{text}"
        );
        // Every mailbox of the list has its failures.
        assert!(text.contains("lepic_mailbox_failures{mailbox=\""), "{text}");
    });
}

#[test]
fn the_create_counters_follow_the_answers() {
    let (host, wallet) = funded();
    serving_with(host, &wallet, &["--metrics"], |socket, _| {
        let invoice = json!({ "kind": "invoice", "amount": "2", "via": "file" }).to_string();
        let made = http(socket, "POST", "/api/v1/payments", Some(&invoice));
        assert_eq!(made.status, 201, "{made:?}");
        let bad = json!({ "amount": "2", "to": "not an address" }).to_string();
        assert_eq!(
            http(socket, "POST", "/api/v1/payments", Some(&bad)).status,
            400
        );
        assert_eq!(
            http(socket, "POST", "/api/v1/payments", Some("{")).status,
            400
        );

        let text = scrape(socket);
        assert_eq!(
            sample(&text, "lepic_payments_created_total"),
            Some(1),
            "{text}"
        );
        assert_eq!(
            sample(
                &text,
                "lepic_payment_create_errors_total{category=\"usage\"}"
            ),
            Some(2),
            "{text}"
        );
    });
}
