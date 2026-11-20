// SPDX-License-Identifier: Apache-2.0
//! The relay, peer and profile calls of the wallet API v1.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

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
        format!(
            "[node]\nservers = [\"http://127.0.0.1:3413\"]\n[epicbox]\nservers = [\"{NEW_HOME}\"]\n"
        ),
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

/// The hosts of a `/mailboxes` answer with their origins.
fn mailbox_hosts(answer: &serde_json::Value) -> Vec<(String, String)> {
    answer["mailboxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                text(entry, "host").to_owned(),
                text(entry, "origin").to_owned(),
            )
        })
        .collect()
}

#[test]
fn the_mailbox_list_is_changed_through_the_api_and_kept_in_the_settings_file() {
    let host = TestHost::new();
    let wallet = new_wallet(&host, "wallet password");
    let settings = wallet.home.path().join(".lepic/settings.toml");
    serving(host, &wallet, |socket, _| {
        let shipped = |hosts: &[&str]| -> Vec<(String, String)> {
            hosts
                .iter()
                .map(|host| ((*host).to_owned(), "shipped".to_owned()))
                .collect()
        };
        let all = [
            "epicbox.btlabs.uk",
            "epicbox.epiccash.com",
            "epicbox.epicnet.us",
        ];
        let listed = http(socket, "GET", "/api/v1/mailboxes", None).ok();
        assert_eq!(mailbox_hosts(&listed), shipped(&all), "{listed}");

        let probe = Some(r#"{"host":"Mailbox.Example.Org"}"#);
        let probed = http(socket, "POST", "/api/v1/mailboxes/probe", probe).ok();
        assert_eq!(probed["host"], "mailbox.example.org", "{probed}");
        assert_eq!(probed["passed"], true, "{probed}");

        let add = Some(r#"{"host":"mailbox.example.org"}"#);
        let added = http(socket, "POST", "/api/v1/mailboxes", add);
        assert_eq!(added.status, 201, "{added:?}");
        let added = added.json();
        assert_eq!(added["added"], true, "{added}");
        assert_eq!(added["probe"]["passed"], true, "{added}");
        let again = http(socket, "POST", "/api/v1/mailboxes", add);
        assert_eq!(again.status, 200, "{again:?}");
        assert_eq!(again.json()["added"], false, "{again:?}");

        let removed = http(
            socket,
            "DELETE",
            "/api/v1/mailboxes/epicbox.epiccash.com",
            None,
        )
        .ok();
        let mut expected = shipped(&["epicbox.btlabs.uk", "epicbox.epicnet.us"]);
        expected.push(("mailbox.example.org".to_owned(), "added".to_owned()));
        assert_eq!(mailbox_hosts(&removed), expected, "{removed}");
        let file = std::fs::read_to_string(&settings).unwrap();
        assert!(
            file.contains(
                "added = [\"mailbox.example.org\"]\nremoved = [\"epicbox.epiccash.com\"]\n"
            ),
            "{file}"
        );

        let absent = http(socket, "DELETE", "/api/v1/mailboxes/gone.example.org", None);
        problem(&absent, 404, "not_found");
        let local = http(
            socket,
            "POST",
            "/api/v1/mailboxes",
            Some(r#"{"host":"localhost"}"#),
        );
        let local = problem(&local, 400, "mailbox_not_public");
        assert_eq!(local["param"], "/host", "{local}");
        let listed = http(socket, "GET", "/api/v1/mailboxes", None).ok();
        assert_eq!(mailbox_hosts(&listed), expected, "{listed}");
    });
}
