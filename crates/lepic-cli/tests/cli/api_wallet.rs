// SPDX-License-Identifier: Apache-2.0
//! The wallet, account, node, output, address and link calls of the wallet API v1.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;
use lepic_node::mock::MockFailure;

use serde_json::{Value, json};
use support::{SENDER_MNEMONIC, funded, http, problem, serving, with_settings};

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
fn each_account_lists_one_epic1_address() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        send(socket, "POST", "/accounts", &json!({"label": "savings"})).ok_status(201);
        let listed = get(socket, "/addresses").ok();
        let items = listed["items"].as_array().unwrap();
        let kinds: Vec<(&str, &str)> = items
            .iter()
            .map(|item| {
                (
                    item["type"].as_str().unwrap(),
                    item["account"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            kinds,
            [
                ("epicbox", "default"),
                ("epic1", "default"),
                ("epic1", "savings")
            ],
            "{listed}"
        );
        assert!(
            items.iter().all(|item| item.get("index").is_none()),
            "{listed}"
        );
        assert_ne!(items[1]["text"], items[2]["text"], "{listed}");

        let savings = get(socket, "/addresses?type=epic1&account=savings").ok();
        assert_eq!(savings["items"].as_array().unwrap().len(), 1, "{savings}");
        assert_eq!(savings["items"][0]["text"], items[2]["text"]);
        let none = get(socket, "/addresses?type=epicbox&account=savings").ok();
        assert!(none["items"].as_array().unwrap().is_empty(), "{none}");
        problem(&get(socket, "/addresses?type=bogus"), 400, "invalid_field");
        problem(
            &get(socket, "/addresses?account=nobody"),
            400,
            "invalid_field",
        );
        // No address is made: the route takes GET only.
        problem(
            &send(socket, "POST", "/addresses", &json!({})),
            405,
            "method_not_allowed",
        );
    });
}

/// `serving`, with a relay under a public name: the mock relay answers for any host, but
/// epic1 links are refused for a relay on this device, which the harness's default is.
pub(super) fn serving_public<T: Send>(
    host: support::TestHost,
    wallet: &support::Instance,
    test: impl FnOnce(&std::path::Path) -> T + Send,
) -> T {
    serving_public_with(host, wallet, &[], test)
}

/// [`serving_public`] with `extra` environment variables set for serve.
pub(super) fn serving_public_with<T: Send>(
    host: support::TestHost,
    wallet: &support::Instance,
    extra: &[(&str, &str)],
    test: impl FnOnce(&std::path::Path) -> T + Send,
) -> T {
    serving_public_args(host, wallet, &[], extra, test)
}

/// [`serving_public_with`] with `args` after `serve --socket PATH`.
pub(super) fn serving_public_args<T: Send>(
    mut host: support::TestHost,
    wallet: &support::Instance,
    args: &[&str],
    extra: &[(&str, &str)],
    test: impl FnOnce(&std::path::Path) -> T + Send,
) -> T {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let stop = Arc::new(AtomicBool::new(false));
    // Waits for the flag with no time limit, so a test may run longer than PATIENCE.
    host.stop_when_set = Some(Arc::clone(&stop));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();
    let mut env = wallet.env();
    for (name, value) in &mut env {
        if name == "LEPIC_EPICBOX_RELAY" {
            *value = format!("wss://{}", support::PUBLIC_MAILBOX);
        }
    }
    env.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    let mut serve = vec!["serve", "--socket", socket_arg];
    serve.extend_from_slice(args);
    std::thread::scope(|scope| {
        let server = support::serve_thread(scope, || wallet.run_with(&host, &serve, env, ""));
        support::wait_for_socket(&socket);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&socket)));
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().ok();
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Making a link posts nothing, so serve does not collect every few seconds for it.
#[test]
fn making_a_link_does_not_boost_the_relay_collect() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        send(socket, "POST", "/links", &json!({})).ok_status(200);
        let status = get(socket, "/status").ok_status(200);
        assert!(status["collect"].get("boost").is_none(), "{status}");
    });
}

/// A link names no relay, so a wallet whose own relay is on this device still makes one.
#[test]
fn a_link_on_a_local_relay_is_made_and_names_no_relay() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let made = send(socket, "POST", "/links", &json!({})).ok_status(200);
        let text = made["text"].as_str().unwrap();
        assert!(!text.contains('?'), "{made}");
        let address = get(socket, "/addresses?type=epic1").ok();
        assert_eq!(
            text,
            format!("epic:{}", address["items"][0]["text"].as_str().unwrap())
        );
    });
}

#[test]
fn an_epic1_link_is_read_by_inspect_and_paid_at_the_amount_given() {
    let (host, wallet) = funded();
    serving_public(host, &wallet, |socket| {
        let body = json!({"amount": "2", "message": "dues"});
        let made = send(socket, "POST", "/links", &body).json();
        let link = made["text"].as_str().unwrap();
        let read = send(socket, "POST", "/inspect", &json!({ "text": link })).ok();
        assert_eq!(read["type"], "link", "{read}");
        assert_eq!(read["next"], "pay", "{read}");
        assert_eq!(read["summary"]["amount"], "2.00000000", "{read}");
        assert_eq!(read["summary"]["message"], "dues", "{read}");
        // With no amount, the link's is taken.
        let fee = send(socket, "POST", "/payments/estimate", &json!({ "to": link })).ok();
        assert!(fee["fee"].is_string(), "{fee}");
        // The payer may pay another amount, with another message.
        let other = json!({ "to": link, "amount": "3", "message": "and a tip" });
        let paid = send(socket, "POST", "/payments", &other);
        assert_eq!(paid.status, 201, "{paid:?}");
        let paid = paid.json();
        assert_eq!(paid["amount"], "3.00000000", "{paid}");
        assert_eq!(paid["message"], "and a tip", "{paid}");
    });
}

/// A damaged epic1 address or link is refused by inspect and by an estimate with the refusal a
/// payment to it gets, and a sound one is read by all three.
#[test]
fn a_damaged_epic1_address_gets_the_same_refusal_everywhere() {
    let (host, wallet) = funded();
    serving_public(host, &wallet, |socket| {
        let listed = get(socket, "/addresses?type=epic1").ok();
        let sound = listed["items"][0]["text"].as_str().unwrap().to_owned();
        let mut chars: Vec<char> = sound.chars().collect();
        let at = chars.len() / 2;
        chars[at] = if chars[at] == 'q' { 'p' } else { 'q' };
        let damaged: String = chars.into_iter().collect();
        for to in [
            damaged.clone(),
            format!("epic:{damaged}"),
            "epic1notanaddress".to_owned(),
        ] {
            let paid = send(
                socket,
                "POST",
                "/payments",
                &json!({ "to": to, "amount": "1" }),
            );
            assert!(paid.status >= 400, "{to}: {paid:?}");
            let code = paid.json()["code"].clone();
            for (path, body) in [
                ("/inspect", json!({ "text": to })),
                ("/payments/estimate", json!({ "to": to, "amount": "1" })),
            ] {
                let refused = send(socket, "POST", path, &body);
                assert_eq!(refused.status, paid.status, "{path} {to}: {refused:?}");
                assert_eq!(refused.json()["code"], code, "{path} {to}: {refused:?}");
            }
        }
        // The sound address is read and estimated.
        let read = send(socket, "POST", "/inspect", &json!({ "text": sound })).ok();
        assert_eq!(read["type"], "epic1_address", "{read}");
        let fee = send(
            socket,
            "POST",
            "/payments/estimate",
            &json!({ "to": sound, "amount": "1" }),
        )
        .ok();
        assert!(fee["fee"].is_string(), "{fee}");
    });
}

#[test]
fn a_link_stores_nothing_and_the_same_body_gives_the_same_link() {
    let (host, wallet) = funded();
    serving_public(host, &wallet, |socket| {
        let body = json!({"amount": "1.5", "message": "rent"});
        let link = send(socket, "POST", "/links", &body).ok_status(200);
        let mut fields: Vec<&str> = link
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(fields, ["account", "amount", "message", "text"], "{link}");
        assert_eq!(link["account"], "default");
        assert_eq!(link["amount"], "1.5");
        assert_eq!(link["message"], "rent");
        assert!(
            link["text"].as_str().unwrap().starts_with("epic:"),
            "{link}"
        );
        assert_eq!(send(socket, "POST", "/links", &body).ok_status(200), link);

        send(socket, "POST", "/accounts", &json!({"label": "savings"})).ok_status(201);
        let savings = send(socket, "POST", "/links", &json!({"account": "savings"})).ok_status(200);
        let address = get(socket, "/addresses?type=epic1&account=savings").ok();
        assert_eq!(
            savings["text"],
            format!("epic:{}", address["items"][0]["text"].as_str().unwrap())
        );
        problem(
            &send(socket, "POST", "/links", &json!({"account": "nobody"})),
            400,
            "invalid_field",
        );
    });
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

/// Another install of the phrase receives while serve runs: the update scan after a sync's
/// refresh finds the output, which a refresh alone does not know of.
#[test]
fn a_sync_finds_what_another_install_received() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, host| {
        let outputs = |socket| {
            get(socket, "/outputs").ok()["items"]
                .as_array()
                .unwrap()
                .len()
        };
        assert_eq!(outputs(socket), 1);
        host.fund(SENDER_MNEMONIC, 1, support::FUNDING, 2);
        send(socket, "POST", "/sync", &json!({})).ok_status(200);
        assert_eq!(outputs(socket), 2);
    });
}

#[test]
fn a_boost_is_clamped_shown_in_the_status_and_ended() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let asked = json!({"poller": "node", "duration_seconds": 86_400, "interval_seconds": 1});
        let mut window = send(socket, "POST", "/sync/boost", &asked).ok_status(201);
        assert_eq!(window["poller"], "node", "{window}");
        assert_eq!(window["interval_seconds"], 5, "{window}");
        let id = window.as_object_mut().unwrap().remove("id").unwrap();
        let status = get(socket, "/status").ok_status(200);
        assert_eq!(status["refresh"]["boost"], window, "{status}");
        assert!(status["collect"].get("boost").is_none(), "{status}");

        let end = format!("{API}/sync/boost/{id}");
        assert_eq!(http(socket, "DELETE", &end, None).status, 204);
        let status = get(socket, "/status").ok_status(200);
        assert!(status["refresh"].get("boost").is_none(), "{status}");
        problem(&http(socket, "DELETE", &end, None), 404, "not_found");
        let mempool = json!({"poller": "mempool", "duration_seconds": 60, "interval_seconds": 5});
        problem(
            &send(socket, "POST", "/sync/boost", &mempool),
            400,
            "invalid_field",
        );
        let zero = json!({"poller": "relays", "duration_seconds": 60, "interval_seconds": 0});
        let raised = send(socket, "POST", "/sync/boost", &zero).ok_status(201);
        assert_eq!(raised["interval_seconds"], 5, "{raised}");
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

/// `POST /wallet/scan` with `body`, sent and not read.
fn scan_unread(socket: &std::path::Path, body: &Value) -> std::os::unix::net::UnixStream {
    use std::io::Write as _;
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    let body = body.to_string();
    write!(
        stream,
        "POST /api/v1/wallet/scan HTTP/1.1\r\nHost: lepic\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream
}

fn requests_in_flight(socket: &std::path::Path) -> u64 {
    get(socket, "/status").ok()["requests"]["in_flight"]
        .as_u64()
        .unwrap()
}

#[test]
fn a_caller_that_leaves_a_scan_request_does_not_leave_the_scan_running() {
    use std::io::Read as _;
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, client| {
        let body = json!({"from_height": 1});
        // The scan call waits for the node's tip, which the test holds back.
        client.tip_gate.close();
        let caller = scan_unread(socket, &body);
        support::wait_until("serve took the scan call", || {
            requests_in_flight(socket) == 2
        });
        // The call holds the scan while it waits for the tip: another is refused.
        let mut probe = scan_unread(socket, &body);
        probe.set_read_timeout(Some(support::PATIENCE)).unwrap();
        let mut answer = String::new();
        probe.read_to_string(&mut answer).unwrap();
        problem(&support::parse_reply(&answer), 409, "scan_running");
        drop(caller);
        support::wait_until("serve saw the caller leave", || {
            requests_in_flight(socket) == 1
        });
        client.tip_gate.open();
        // The scan the caller never saw does not block the next one.
        let again = send(socket, "POST", "/wallet/scan", &body);
        assert_eq!(again.status, 202, "{again:?}");
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

/// The wallet's environment with its relay under a public name, as `serving_public` has it.
fn public_env(wallet: &support::Instance) -> Vec<(String, String)> {
    let mut env = wallet.env();
    for (name, value) in &mut env {
        if name == "LEPIC_EPICBOX_RELAY" {
            *value = format!("wss://{}", support::PUBLIC_MAILBOX);
        }
    }
    env
}

#[test]
fn records_an_earlier_version_kept_for_addresses_and_links_are_no_obstacle() {
    use sha2::Digest as _;
    let (host, wallet) = funded();
    let cli = host.without_interrupt();
    // As an earlier version stored an address create and a link.
    let body = json!({"id": "addr-old", "account": null});
    with_settings(&wallet, SENDER_MNEMONIC, |repos| {
        repos.put_api_request(&lepic_store::ApiRequest {
            scope: "address".to_owned(),
            id: "addr-old".to_owned(),
            digest: sha2::Sha256::digest(serde_json::to_vec(&body).unwrap()).into(),
            created_at: jiff::Timestamp::now(),
        })?;
        repos.put_setting("api.created.address.addr-old", "1")?;
        repos.put_setting(
            "api.link.0.1",
            r#"{"id":"link-old","text":"","amount":"2","message":"dues"}"#,
        )
    });
    // The CLI's link, to compare with the API's from the same fields.
    let printed = wallet
        .run_with(
            &cli,
            &["epic1", "link", "3", "--message", "club fee"],
            public_env(&wallet),
            "",
        )
        .ok()
        .json();
    assert!(printed.get("index").is_none(), "{printed}");
    serving_public(host, &wallet, |socket| {
        let listed = get(socket, "/addresses?type=epic1").ok();
        assert_eq!(listed["items"].as_array().unwrap().len(), 1, "{listed}");
        let body = json!({"amount": "3", "message": "club fee"});
        let made = send(socket, "POST", "/links", &body).ok_status(200);
        assert_eq!(made["text"], printed["link"], "{made}");
    });
}

#[test]
fn outputs_are_consolidated_once_per_id_and_a_dry_run_stores_nothing() {
    let host = support::TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, support::FUNDING, 1);
    host.fund(SENDER_MNEMONIC, 1, support::FUNDING, 2);
    host.fund(SENDER_MNEMONIC, 2, support::FUNDING, 3);
    let wallet = support::Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    serving(host, &wallet, |socket, client| {
        let unspent = |socket| {
            get(socket, "/outputs?state=unspent").ok()["items"]
                .as_array()
                .unwrap()
                .len()
        };
        let payments = |socket| {
            get(socket, "/payments").ok()["items"]
                .as_array()
                .unwrap()
                .len()
        };
        let before = payments(socket);
        let dry_run = json!({
            "dry_run": true,
            "max_inputs": 2,
            "id": "1d8e2f30-5b6c-4d7e-9fa0-b1c2d3e4f5a6",
        });
        let estimate = send(socket, "POST", "/outputs/consolidate", &dry_run).ok();
        assert_eq!(
            estimate["outputs"].as_array().unwrap().len(),
            2,
            "{estimate}"
        );
        assert_eq!(unspent(socket), 3);
        assert_eq!(payments(socket), before, "a dry run stores no payment");
        problem(
            &get(socket, "/payments/1d8e2f30-5b6c-4d7e-9fa0-b1c2d3e4f5a6"),
            404,
            "not_found",
        );

        problem(
            &send(
                socket,
                "POST",
                "/outputs/consolidate",
                &json!({ "outputs": 11 }),
            ),
            400,
            "invalid_field",
        );
        problem(
            &send(
                socket,
                "POST",
                "/outputs/consolidate",
                &json!({ "max_inputs": 0 }),
            ),
            400,
            "invalid_body",
        );

        let id = "0c7d1e2f-4a5b-4c6d-8e9f-a0b1c2d3e4f5";
        let body = json!({ "id": id, "max_inputs": 2 });
        let created = send(socket, "POST", "/outputs/consolidate", &body);
        assert_eq!(created.status, 201, "{created:?}");
        let created = created.json();
        assert_eq!(created["id"], id, "{created}");
        assert_eq!(created["direction"], "self", "{created}");
        assert_eq!(created["fee"], estimate["fee"], "{created}");
        // The amount is all the outputs it makes (what it spends, less the fee), not one of them.
        let units = |value: &serde_json::Value| -> u64 {
            let (whole, fraction) = value
                .as_str()
                .unwrap_or_else(|| panic!("{value}"))
                .split_once('.')
                .unwrap();
            whole.parse::<u64>().unwrap() * 100_000_000
                + format!("{fraction:0<8}").parse::<u64>().unwrap()
        };
        let made: u64 = estimate["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|each| units(&each["amount"]))
            .sum();
        let fee = units(&created["fee"]);
        assert_eq!(units(&created["amount"]), made - fee, "{created}");
        assert_eq!(client.node.pushed_transactions().len(), 1);

        let repeated = send(socket, "POST", "/outputs/consolidate", &body);
        assert_eq!(repeated.status, 200, "{repeated:?}");
        assert_eq!(repeated.json()["id"], id, "{repeated:?}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
        problem(
            &send(
                socket,
                "POST",
                "/outputs/consolidate",
                &json!({ "id": id, "max_inputs": 3 }),
            ),
            409,
            "idempotency_mismatch",
        );
    });
}

#[test]
fn a_consolidation_whose_push_failed_answers_its_payment_and_its_repeat_too() {
    let host = support::TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, support::FUNDING, 1);
    host.fund(SENDER_MNEMONIC, 1, support::FUNDING, 2);
    let wallet = support::Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    serving(host, &wallet, |socket, client| {
        let payments = |socket| {
            get(socket, "/payments").ok()["items"]
                .as_array()
                .unwrap()
                .len()
        };
        let before = payments(socket);
        client
            .node
            .fail_every("push_transaction", MockFailure::Unreachable);
        let id = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b";
        let body = json!({ "id": id });
        let created = send(socket, "POST", "/outputs/consolidate", &body);
        assert_eq!(created.status, 201, "{created:?}");
        assert_eq!(created.json()["id"], id, "{created:?}");

        let repeated = send(socket, "POST", "/outputs/consolidate", &body);
        assert_eq!(repeated.status, 200, "{repeated:?}");
        assert_eq!(repeated.json()["id"], id, "{repeated:?}");
        assert_eq!(payments(socket), before + 1);
        assert!(client.node.pushed_transactions().is_empty());
    });
}
