// SPDX-License-Identifier: Apache-2.0
//! The relay, peer and profile calls of the wallet API v1.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use serde_json::json;
use support::{TestHost, http, new_wallet, problem, serving, serving_with, text};

/// A relay the settings file offers, so a move to it is known.
const NEW_HOME: &str = "relay2.test";

#[test]
fn the_relay_is_read_and_its_moves_are_refused_when_wrong() {
    let host = TestHost::new();
    let wallet = new_wallet(&host, "wallet password");
    serving(host, &wallet, |socket, _| {
        let relay = http(socket, "GET", "/api/v1/relay", None).ok();
        assert!(relay["host"].is_string(), "{relay}");
        assert!(
            ["connected", "connecting", "disconnected"].contains(&text(&relay, "connection")),
            "{relay}"
        );
        assert!(!text(&relay, "address").is_empty(), "{relay}");
        assert_eq!(relay["waiting_deliveries"], 0, "{relay}");
        assert_eq!(relay["draining"], json!([]), "{relay}");

        let empty = http(socket, "POST", "/api/v1/relay/move", Some(r#"{"host":""}"#));
        let empty = problem(&empty, 400, "invalid_field");
        assert_eq!(empty["param"], "/host", "{empty}");
        let long = http(
            socket,
            "POST",
            "/api/v1/relay/move",
            Some(r#"{"host":"relay2.test","drain_days":9999}"#),
        );
        let long = problem(&long, 400, "invalid_field");
        assert_eq!(long["param"], "/drain_days", "{long}");
        let negative = http(
            socket,
            "POST",
            "/api/v1/relay/move",
            Some(r#"{"host":"relay2.test","drain_days":-1}"#),
        );
        let negative = problem(&negative, 400, "invalid_field");
        assert_eq!(negative["param"], "/drain_days", "{negative}");
        let missing = http(socket, "POST", "/api/v1/relay/move", Some("{}"));
        assert_eq!(missing.status, 400, "{missing:?}");
        // Nothing moved.
        let after = http(socket, "GET", "/api/v1/relay", None).ok();
        assert_eq!(after["host"], relay["host"], "{after}");
    });
}

#[test]
fn the_wallet_moves_its_home_relay() {
    let host = TestHost::new();
    let wallet = support::Instance::new("wallet password");
    let dir = wallet.home.path().join(".lepic");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("settings.toml"),
        format!("[epicbox]\nservers = [\"{NEW_HOME}\"]\n"),
    )
    .unwrap();
    wallet.run(&host, &["wallet", "init"]).ok();
    serving(host, &wallet, |socket, _| {
        let before = http(socket, "GET", "/api/v1/relay", None).ok();
        let moved = http(
            socket,
            "POST",
            "/api/v1/relay/move",
            Some(&json!({"host": NEW_HOME, "drain_days": 3}).to_string()),
        )
        .ok();
        assert_eq!(moved["host"], NEW_HOME, "{moved}");
        assert_ne!(before["host"], NEW_HOME, "{before}");
        assert_eq!(
            http(socket, "GET", "/api/v1/relay", None).ok()["host"],
            NEW_HOME
        );
    });
}

#[test]
fn peers_are_listed_and_unknown_ones_are_not_found() {
    let host = TestHost::new();
    let wallet = new_wallet(&host, "wallet password");
    serving(host, &wallet, |socket, _| {
        let peers = http(socket, "GET", "/api/v1/peers", None).ok();
        assert_eq!(peers["items"], json!([]), "{peers}");
        assert!(peers["next_cursor"].is_null(), "{peers}");
        problem(
            &http(
                socket,
                "DELETE",
                "/api/v1/peers/https%3A%2F%2Fpeer.example",
                None,
            ),
            404,
            "not_found",
        );
        problem(
            &http(socket, "DELETE", "/api/v1/peers/nonsense", None),
            404,
            "not_found",
        );
    });
}

#[test]
fn the_profile_is_read_and_updated() {
    let host = TestHost::new();
    let wallet = new_wallet(&host, "wallet password");
    serving(host, &wallet, |socket, _| {
        let profile = http(socket, "GET", "/api/v1/profile", None).ok();
        assert_eq!(profile["flags"], json!([]), "{profile}");
        assert!(profile.get("domain").is_none(), "{profile}");

        let updated = http(
            socket,
            "PATCH",
            "/api/v1/profile",
            Some(r#"{"name":"Riverside Shop","flags":["automated"]}"#),
        )
        .ok();
        assert_eq!(updated["name"], "Riverside Shop", "{updated}");
        assert_eq!(updated["flags"], json!(["automated"]), "{updated}");
        assert_eq!(http(socket, "GET", "/api/v1/profile", None).ok(), updated);

        let cleared = http(socket, "PATCH", "/api/v1/profile", Some(r#"{"flags":[]}"#)).ok();
        assert_eq!(cleared["flags"], json!([]), "{cleared}");
        assert_eq!(cleared["name"], "Riverside Shop", "{cleared}");

        let unknown = http(
            socket,
            "PATCH",
            "/api/v1/profile",
            Some(r#"{"flags":["shiny"]}"#),
        );
        let unknown = problem(&unknown, 400, "invalid_field");
        assert_eq!(unknown["param"], "/flags", "{unknown}");
        // The domain is the one the wallet runs with.
        problem(
            &http(
                socket,
                "PATCH",
                "/api/v1/profile",
                Some(r#"{"domain":"example.org"}"#),
            ),
            409,
            "domain_fixed",
        );
    });
}

#[test]
fn a_profile_update_with_a_bad_name_changes_nothing() {
    let host = TestHost::new();
    let wallet = new_wallet(&host, "wallet password");
    serving(host, &wallet, |socket, _| {
        let before = http(socket, "GET", "/api/v1/profile", None).ok();
        assert_eq!(before["flags"], json!([]), "{before}");

        for name in ["", "bad\\u0007name"] {
            let body = format!(r#"{{"name":"{name}","flags":["automated","no-payments"]}}"#);
            let refused = http(socket, "PATCH", "/api/v1/profile", Some(&body));
            let refused = problem(&refused, 400, "invalid_field");
            assert_eq!(refused["param"], "/name", "{refused}");
            // The flags given beside the bad name were not applied.
            assert_eq!(http(socket, "GET", "/api/v1/profile", None).ok(), before);
        }
    });
}

#[test]
fn the_domain_file_exists_when_a_domain_is_set() {
    let host = TestHost::new();
    let wallet = new_wallet(&host, "wallet password");
    // No domain: nothing to prove.
    let host = serving(host, &wallet, |socket, host| {
        problem(
            &http(socket, "GET", "/api/v1/profile/domain-file", None),
            404,
            "not_found",
        );
        host.without_interrupt()
    });
    serving_with(
        host,
        &wallet,
        &["--domain", "shop.example.org"],
        |socket, _| {
            let profile = http(socket, "GET", "/api/v1/profile", None).ok();
            assert_eq!(profile["domain"], "shop.example.org", "{profile}");
            let file = http(socket, "GET", "/api/v1/profile/domain-file", None);
            assert_eq!(file.status, 200, "{file:?}");
            assert!(
                file.header("content-type")
                    .unwrap()
                    .starts_with("text/plain"),
                "{file:?}"
            );
            assert!(!file.body.trim().is_empty(), "{file:?}");
            assert_eq!(profile["domain_proof"], file.body.as_str(), "{profile}");
            let blank = http(socket, "GET", "/api/v1/profile/domain-file?relay=", None);
            let blank = problem(&blank, 400, "invalid_field");
            assert_eq!(blank["param"], "/relay", "{blank}");
        },
    );
}
