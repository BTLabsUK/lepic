// SPDX-License-Identifier: Apache-2.0
//! `connection_mode` and the tor settings decide which connections a command makes. With a tor
//! named, a route that would connect directly to another computer is refused unless
//! `http_direct` says otherwise; offline, and tor-only without a tor, nothing connects while
//! the wallet's local work goes on.

// Tests may unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::support;

use serde_json::{Value, json};
use support::{Instance, TestHost, funded, http, new_wallet, problem, serving_with, text};

/// A tor the settings name; nothing listens on it, and nothing here reaches it.
const TOR: (&str, &str) = ("LEPIC_EPICBOX_TOR_SOCKS", "127.0.0.1:9050");

/// A payee on another computer; the tests never connect to it.
const PAYEE: &str = "https://payee.example.test";

fn env_with(wallet: &Instance, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = wallet.env();
    env.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    env
}

/// How many transactions `tx list` shows.
fn transactions(wallet: &Instance, host: &TestHost) -> usize {
    let listed = wallet.run(host, &["tx", "list"]).ok().json();
    listed["transactions"].as_array().unwrap().len()
}

/// The error's message and its causes, as one text.
fn message(outcome: &support::Outcome) -> String {
    outcome.json()["error"].to_string()
}

#[test]
fn with_a_tor_named_an_http_payee_elsewhere_is_refused_before_anything_is_stored() {
    let (host, wallet) = funded();
    let before = transactions(&wallet, &host);
    let refused = wallet.run_with(
        &host,
        &["tx", "send", "1", "--to", PAYEE],
        env_with(&wallet, &[TOR]),
        "",
    );
    assert_eq!(refused.code, 3, "{refused:?}");
    assert!(
        message(&refused).contains("the http payee would connect directly"),
        "{refused:?}"
    );
    assert_eq!(transactions(&wallet, &host), before);

    // ADR 0021: a payee on this computer is reached directly; nothing listens, so it fails
    // there and not on the tor settings.
    let here = wallet.run_with(
        &host,
        &["tx", "send", "1", "--to", "http://127.0.0.1:9"],
        env_with(&wallet, &[TOR]),
        "",
    );
    assert_ne!(here.code, 0, "{here:?}");
    assert!(!message(&here).contains("connect directly"), "{here:?}");
}

#[test]
fn with_a_tor_named_a_links_http_entry_is_not_posted_directly() {
    let (host, wallet) = funded();
    let payee = new_wallet(&host, "payee password");
    let made = payee
        .run(
            &host,
            &["epic1", "link", "2", "--http-host", "payee.example.test"],
        )
        .ok()
        .json();
    let link = text(&made, "link").to_owned();
    let refused = wallet.run_with(
        &host,
        &["epic1", "pay", &link],
        env_with(&wallet, &[TOR]),
        "",
    );
    assert_ne!(refused.code, 0, "{refused:?}");
    assert!(
        message(&refused).contains("http entry would connect directly"),
        "{refused:?}"
    );
    assert_eq!(host.relay.received("PostSlate"), 0);
}

#[test]
fn http_direct_is_refused_with_connection_mode_tor_only() {
    let (host, wallet) = funded();
    let refused = wallet.run_with(
        &host,
        &["wallet", "info"],
        env_with(
            &wallet,
            &[
                TOR,
                ("LEPIC_CONNECTION_MODE", "tor-only"),
                ("LEPIC_HTTP_DIRECT", "true"),
            ],
        ),
        "",
    );
    assert_eq!(refused.code, 3, "{refused:?}");
    assert!(message(&refused).contains("http_direct"), "{refused:?}");
}

/// In `mode`, a send to a payee is refused naming the mode, and the node's status and the
/// wallet's info, which refreshes, fail; a send to a file and the list still work. Offline, a
/// send builds on the tip refreshes confirmed, so the wallet refreshes online first.
fn networked_refused_and_local_kept(mode: &[&str], names: &str) {
    let (host, wallet) = funded();
    for _ in 0..2 {
        wallet.run(&host, &["wallet", "info"]).ok();
    }
    let connections = host.relay.connections_made();
    let mut args = vec!["tx", "send", "1", "--to", PAYEE];
    args.extend_from_slice(mode);
    let refused = wallet.run(&host, &args);
    assert_eq!(refused.code, 3, "{refused:?}");
    assert!(message(&refused).contains(names), "{refused:?}");

    // Both ask the node: the status, and the info's refresh.
    for asks in [["node", "status"], ["wallet", "info"]] {
        let mut args: Vec<&str> = asks.to_vec();
        args.extend_from_slice(mode);
        let node = wallet.run(&host, &args);
        assert_ne!(node.code, 0, "{node:?}");
    }

    let before = transactions(&wallet, &host);
    let file = wallet.path("offline.slate");
    let mut args = vec!["tx", "send", "1", "--to-file", file.to_str().unwrap()];
    args.extend_from_slice(mode);
    wallet.run(&host, &args).ok();
    assert!(file.exists());
    let mut args = vec!["tx", "list"];
    args.extend_from_slice(mode);
    let listed: Value = wallet.run(&host, &args).ok().json();
    assert_eq!(listed["transactions"].as_array().unwrap().len(), before + 1);
    assert_eq!(host.relay.connections_made(), connections);
}

#[test]
fn offline_refuses_networked_commands_and_keeps_local_ones() {
    networked_refused_and_local_kept(
        &["--connection-mode", "offline"],
        "connection_mode is offline",
    );
}

#[test]
fn offline_refuses_tor_listen_before_it_starts_tor() {
    let (host, wallet) = funded();
    let refused = wallet.run(
        &host,
        &[
            "--connection-mode",
            "offline",
            "tor",
            "listen",
            "--tor-binary",
            "/nonexistent/tor",
        ],
    );
    assert_eq!(refused.code, 3, "{refused:?}");
    assert!(
        message(&refused).contains("connection_mode is offline"),
        "{refused:?}"
    );
}

#[test]
fn offline_refuses_epicbox_listen_instead_of_retrying_the_relay() {
    let (host, wallet) = funded();
    let refused = wallet.run(
        &host,
        &["--connection-mode", "offline", "epicbox", "listen"],
    );
    assert_eq!(refused.code, 3, "{refused:?}");
    assert!(
        message(&refused).contains("connection_mode is offline"),
        "{refused:?}"
    );
}

#[test]
fn tor_only_without_a_tor_is_offline() {
    networked_refused_and_local_kept(
        &["--connection-mode", "tor-only"],
        "connection_mode is tor-only and no tor is named",
    );
}

#[test]
fn serve_in_offline_mode_makes_no_connection() {
    let (host, wallet) = funded();
    serving_with(
        host,
        &wallet,
        &["--connection-mode", "offline"],
        |socket, client| {
            let body = json!({
                "id": "5b0e2f6a-3c1d-4e8f-9a7b-2d4c6e8f0a1c",
                "amount": "1",
                "to": PAYEE,
            });
            let refused = http(socket, "POST", "/api/v1/payments", Some(&body.to_string()));
            let shown = problem(&refused, 409, "offline");
            assert!(
                text(&shown, "detail").contains("connection_mode is offline"),
                "{shown}"
            );
            assert_eq!(client.relay.connections_made(), 0);
        },
    );
}
