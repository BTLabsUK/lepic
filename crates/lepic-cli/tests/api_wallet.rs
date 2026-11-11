// SPDX-License-Identifier: Apache-2.0
//! The wallet, account, node, output, address and link calls of the wallet API v1.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use serde_json::{Value, json};
use support::{funded, http, problem, serving};

const API: &str = "/api/v1";

fn get(socket: &std::path::Path, path: &str) -> support::Reply {
    http(socket, "GET", &format!("{API}{path}"), None)
}

fn send(socket: &std::path::Path, method: &str, path: &str, body: &Value) -> support::Reply {
    http(
        socket,
        method,
        &format!("{API}{path}"),
        Some(&body.to_string()),
    )
}

#[test]
fn the_wallet_and_its_accounts_are_read() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let object = get(socket, "/wallet").ok();
        assert!(object["network"].is_string(), "{object}");
        assert!(object["height"].is_u64(), "{object}");
        assert_eq!(object["node_behind"], false);
        assert!(object["issues_addresses"].is_boolean());

        send(socket, "POST", "/sync", &json!({})).ok_status(200);
        let accounts = get(socket, "/accounts").ok();
        let first = &accounts["items"][0];
        assert_eq!(first["index"], 0);
        assert_eq!(first["balance"]["spendable"], "10.00000000");
        assert_eq!(first["balance"]["total"], "10.00000000");
    });
}

#[test]
fn an_account_is_created_once_per_label() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let made = send(socket, "POST", "/accounts", &json!({"label": "savings"}));
        assert_eq!(made.status, 201, "{made:?}");
        assert_eq!(made.json()["label"], "savings");
        assert_eq!(made.json()["balance"]["total"], "0.00000000");
        let listed = get(socket, "/accounts").ok();
        assert_eq!(listed["items"].as_array().unwrap().len(), 2);
        problem(
            &send(socket, "POST", "/accounts", &json!({"label": "savings"})),
            409,
            "account_exists",
        );
        problem(
            &send(socket, "POST", "/accounts", &json!({})),
            400,
            "invalid_body",
        );
    });
}

#[test]
fn outputs_page_and_filter() {
    let host = support::TestHost::new();
    host.fund(support::SENDER_MNEMONIC, 0, support::FUNDING, 1);
    host.fund(support::SENDER_MNEMONIC, 1, support::FUNDING, 2);
    let wallet = support::Instance::new("serving password");
    wallet.restore(&host, support::SENDER_MNEMONIC);
    serving(host, &wallet, |socket, _| {
        let all = get(socket, "/outputs").ok();
        let items = all["items"].as_array().unwrap();
        assert_eq!(items.len(), 2, "{all}");
        assert_eq!(items[0]["account"], "default");
        assert_eq!(items[0]["state"], "unspent");
        let first = get(socket, "/outputs?limit=1").ok();
        assert_eq!(first["items"].as_array().unwrap().len(), 1);
        let cursor = first["next_cursor"].as_str().unwrap();
        let second = get(socket, &format!("/outputs?limit=1&cursor={cursor}")).ok();
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert_ne!(
            second["items"][0]["commitment"],
            first["items"][0]["commitment"]
        );
        assert!(
            second.get("next_cursor").is_none_or(Value::is_null),
            "{second}"
        );
        let none = get(socket, "/outputs?state=spent").ok();
        assert!(none["items"].as_array().unwrap().is_empty());
        problem(
            &get(socket, "/outputs?state=nonsense"),
            400,
            "invalid_field",
        );
        problem(
            &get(socket, "/outputs?account=nobody"),
            400,
            "invalid_field",
        );
    });
}

#[test]
fn addresses_are_made_and_listed() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        issue(socket);
        let boxed = get(socket, "/addresses?type=epicbox").ok();
        assert_eq!(boxed["items"][0]["type"], "epicbox");

        let made = send(socket, "POST", "/addresses", &json!({"id": "addr-one"}));
        assert_eq!(made.status, 201, "{made:?}");
        let address = made.json();
        assert_eq!(address["type"], "epic1");
        let text = address["text"].as_str().unwrap().to_owned();
        let index = address["index"].as_u64().unwrap();

        let again = send(socket, "POST", "/addresses", &json!({"id": "addr-one"}));
        assert_eq!(again.status, 200, "{again:?}");
        assert_eq!(again.json()["text"], text.as_str());

        problem(
            &send(
                socket,
                "POST",
                "/addresses",
                &json!({"id": "addr-one", "account": "default"}),
            ),
            409,
            "idempotency_mismatch",
        );

        let listed = get(socket, &format!("/addresses?type=epic1&index={index}")).ok();
        assert_eq!(listed["items"][0]["text"], text.as_str());
        problem(&get(socket, "/addresses?type=bogus"), 400, "invalid_field");
        problem(
            &send(socket, "POST", "/addresses", &json!({"account": "nobody"})),
            400,
            "invalid_field",
        );
    });
}

/// `serving`, with a relay under a public name: the mock relay answers for any host, but
/// epic1 links are refused for a relay on this device, which the harness's default is.
fn serving_public<T: Send>(
    mut host: support::TestHost,
    wallet: &support::Instance,
    test: impl FnOnce(&std::path::Path) -> T + Send,
) -> T {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();
    let mut env = wallet.env();
    for (name, value) in &mut env {
        if name == "LEPIC_EPICBOX_RELAY" {
            "wss://relay.example.org".clone_into(value);
        }
    }
    std::thread::scope(|scope| {
        let server =
            scope.spawn(|| wallet.run_with(&host, &["serve", "--socket", socket_arg], env, ""));
        support::wait_for_socket(&socket);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&socket)));
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().ok();
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

#[test]
fn a_link_on_a_local_relay_is_refused() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        issue(socket);
        problem(&send(socket, "POST", "/links", &json!({})), 422, "rejected");
    });
}

#[test]
fn links_are_made_listed_and_retired() {
    let (host, wallet) = funded();
    serving_public(host, &wallet, |socket| {
        issue(socket);
        send(socket, "POST", "/addresses", &json!({})).ok_status(201);
        let made = send(
            socket,
            "POST",
            "/links",
            &json!({"id": "link-one", "kind": "printed", "amount": "1.5", "message": "rent"}),
        );
        assert_eq!(made.status, 201, "{made:?}");
        let link = made.json();
        assert_eq!(link["kind"], "printed");
        assert_eq!(link["amount"], "1.5");
        assert_eq!(link["message"], "rent");
        assert!(link["text"].as_str().unwrap().starts_with("epic"), "{link}");
        let id = link["id"].as_str().unwrap().to_owned();

        let again = send(
            socket,
            "POST",
            "/links",
            &json!({"id": "link-one", "kind": "printed", "amount": "1.5", "message": "rent"}),
        );
        assert_eq!(again.status, 200, "{again:?}");
        assert_eq!(again.json()["id"], id.as_str());

        let listed = get(socket, "/links").ok();
        assert_eq!(listed["items"].as_array().unwrap().len(), 1);
        assert_eq!(listed["items"][0]["id"], id.as_str());

        let retired = http(socket, "POST", &format!("{API}/links/{id}/retire"), None);
        assert_eq!(retired.status, 200, "{retired:?}");
        assert!(retired.json()["retired_at"].is_string());
        assert!(
            get(socket, "/links").ok()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        problem(
            &http(socket, "POST", &format!("{API}/links/{id}/retire"), None),
            404,
            "not_found",
        );
        problem(
            &http(socket, "POST", &format!("{API}/links/nope/retire"), None),
            404,
            "not_found",
        );

        problem(
            &send(socket, "POST", "/links", &json!({"kind": "poster"})),
            400,
            "invalid_field",
        );
        problem(
            &send(
                socket,
                "POST",
                "/links",
                &json!({"relays": ["a", "b", "c", "d"]}),
            ),
            400,
            "invalid_field",
        );
    });
}

fn issue(socket: &std::path::Path) {
    send(
        socket,
        "PATCH",
        "/wallet",
        &json!({"issues_addresses": true}),
    )
    .ok_status(200);
}

trait Status {
    fn ok_status(self, status: u16) -> Value;
}

impl Status for support::Reply {
    fn ok_status(self, status: u16) -> Value {
        assert_eq!(self.status, status, "{self:?}");
        self.json()
    }
}

#[test]
fn the_node_is_read() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let node = get(socket, "/node").ok();
        assert!(node["version"].is_string(), "{node}");
        assert!(node["tip_height"].is_u64(), "{node}");
        assert!(node["syncing"].is_boolean(), "{node}");
    });
}

#[test]
fn a_sync_refreshes_and_answers_the_wallet() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let object = send(socket, "POST", "/sync", &json!({})).ok_status(200);
        assert!(object["height"].is_u64(), "{object}");
        let relays_only = send(socket, "POST", "/sync", &json!({"node": false})).ok_status(200);
        assert!(relays_only["network"].is_string());
    });
}

#[test]
fn a_scan_runs_in_the_background() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let started = send(socket, "POST", "/wallet/scan", &json!({}));
        assert_eq!(started.status, 202, "{started:?}");
        assert_eq!(started.json()["scan"]["state"], "running");
        support::wait_until("the scan finishes", || {
            get(socket, "/wallet").json()["scan"]["state"] == "done"
        });
        problem(
            &send(
                socket,
                "POST",
                "/wallet/scan",
                &json!({"from_height": 5, "reset_chain": true}),
            ),
            400,
            "invalid_field",
        );
        problem(
            &send(
                socket,
                "POST",
                "/wallet/scan",
                &json!({"from_height": 99_999_999}),
            ),
            400,
            "invalid_field",
        );
    });
}

#[test]
fn the_address_flag_is_switched_on_only() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let on = send(
            socket,
            "PATCH",
            "/wallet",
            &json!({"issues_addresses": true}),
        )
        .ok_status(200);
        assert_eq!(on["issues_addresses"], true);
        problem(
            &send(
                socket,
                "PATCH",
                "/wallet",
                &json!({"issues_addresses": false}),
            ),
            400,
            "invalid_field",
        );
    });
}

#[test]
fn the_password_changes_over_the_socket() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        problem(
            &send(
                socket,
                "PUT",
                "/wallet/password",
                &json!({"current": "wrong password", "new": "another password"}),
            ),
            403,
            "wrong_password",
        );
        let changed = send(
            socket,
            "PUT",
            "/wallet/password",
            &json!({"current": "serving password", "new": "another password"}),
        );
        assert_eq!(changed.status, 204, "{changed:?}");
        problem(
            &send(
                socket,
                "PUT",
                "/wallet/password",
                &json!({"current": "another password", "new": ""}),
            ),
            400,
            "invalid_field",
        );
    });
}
