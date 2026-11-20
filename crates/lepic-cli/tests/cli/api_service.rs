// SPDX-License-Identifier: Apache-2.0
//! How `lepic serve` answers the wallet API on its socket, whatever the call: problem documents,
//! the bounds on connections and bodies, and the event stream, in one process with a mock node
//! and a mock relay. Every `/api/v1` answer read through `support::http` is checked against
//! `docs/api/openapi.json`.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use lepic_cli::app_config::ApiLimits;
use lepic_node::mock::MockFailure;
use serde_json::{Value, json};
use support::{
    FUNDING, Instance, PATIENCE, SENDER_MNEMONIC, TestHost, http, http_typed, parse_reply, problem,
    serving, wait_until,
};

fn limits(max_connections: usize, header_timeout: Duration) -> ApiLimits {
    ApiLimits {
        max_connections,
        header_timeout,
        body_timeout: PATIENCE,
        max_body: 1024,
        tls_max_age: PATIENCE,
    }
}

fn read_until_closed(stream: &mut UnixStream) -> String {
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer
}

#[test]
fn errors_are_problem_documents() {
    let mut host = TestHost::new();
    host.api_limits = Some(limits(4, PATIENCE));
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    serving(host, &wallet, |socket, _| {
        let missing = "/api/v1/payments/0f8fad5b-d9cb-469f-a165-70867728950e";
        problem(&http(socket, "GET", missing, None), 404, "not_found");

        let garbled = http(socket, "POST", "/api/v1/payments", Some("{"));
        problem(&garbled, 400, "invalid_body");
        let extra = json!({"amount": "1", "to": "x", "fee": "1"}).to_string();
        let extra = http(socket, "POST", "/api/v1/payments", Some(&extra));
        let detail = problem(&extra, 400, "invalid_body")["detail"].to_string();
        assert!(detail.contains("fee"), "{detail}");

        problem(
            &http(socket, "GET", "/api/v1/nowhere", None),
            404,
            "no_route",
        );
        // The old owner API is gone.
        problem(&http(socket, "GET", "/v1/status", None), 404, "no_route");
        let method = http(socket, "DELETE", "/api/v1/payments", None);
        problem(&method, 405, "method_not_allowed");
        assert_eq!(method.header("allow"), Some("GET, POST"), "{method:?}");

        let large = json!({"text": "x".repeat(2048)}).to_string();
        let large = http(socket, "POST", "/api/v1/inspect", Some(&large));
        problem(&large, 413, "body_too_large");

        // A wrong password is refused without being repeated.
        let password = json!({"current": "wrong password", "new": "next password"}).to_string();
        let password = http(socket, "PUT", "/api/v1/wallet/password", Some(&password));
        let refused = problem(&password, 403, "wrong_password");
        let detail = refused["detail"].as_str().unwrap();
        assert!(!detail.contains("wrong password"), "{detail}");
    });
}

#[test]
fn a_body_needs_the_json_media_type_and_an_object() {
    let mut host = TestHost::new();
    host.api_limits = Some(limits(4, PATIENCE));
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    serving(host, &wallet, |socket, _| {
        let path = "/api/v1/links";
        let typed = |content_type: Option<&str>, body: &str| {
            http_typed(socket, "POST", path, content_type, Some(body))
        };
        for content_type in [None, Some("text/plain"), Some("application/jsonx")] {
            let refused = typed(content_type, "{}");
            problem(&refused, 415, "unsupported_media_type");
        }
        // The media type has any case and takes parameters.
        for content_type in ["Application/JSON", "application/json; charset=utf-8"] {
            assert_ne!(
                typed(Some(content_type), "{}").status,
                415,
                "{content_type}"
            );
        }
        // A body that is not an object, and no body where one is required.
        let array = problem(&typed(Some("application/json"), "[]"), 400, "invalid_body");
        assert!(
            array["detail"].as_str().unwrap().contains("object"),
            "{array}"
        );
        let empty = problem(&typed(Some("application/json"), ""), 400, "invalid_body");
        assert!(
            empty["detail"].as_str().unwrap().contains("object"),
            "{empty}"
        );
        // No body needs no media type: the answer is the body's own error.
        problem(&typed(None, ""), 400, "invalid_body");
    });
}

#[test]
fn connections_over_the_cap_are_answered_busy() {
    let mut host = TestHost::new();
    host.api_limits = Some(limits(2, PATIENCE));
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    serving(host, &wallet, |socket, _| {
        let first = UnixStream::connect(socket).unwrap();
        let second = UnixStream::connect(socket).unwrap();
        let busy = http(socket, "GET", "/api/v1/status", None);
        problem(&busy, 503, "busy");
        assert_eq!(busy.header("retry-after"), Some("5"), "{busy:?}");

        // As many again wait in the busy lane; past those a connection is closed unanswered.
        let third = UnixStream::connect(socket).unwrap();
        let fourth = UnixStream::connect(socket).unwrap();
        let mut over = UnixStream::connect(socket).unwrap();
        assert_eq!(read_until_closed(&mut over), "");

        drop((first, second, third, fourth));
        let mut answered = None;
        wait_until("serve answers again", || {
            let mut stream = UnixStream::connect(socket).unwrap();
            // A connection refused while the others close is closed before it is read, which
            // resets it.
            let _ = stream.write_all(
                b"GET /api/v1/status HTTP/1.1\r\nHost: lepic\r\nConnection: close\r\n\r\n",
            );
            stream.set_read_timeout(Some(PATIENCE)).unwrap();
            let mut answer = String::new();
            let read = stream.read_to_string(&mut answer);
            answered = (read.is_ok() && !answer.is_empty())
                .then(|| parse_reply(&answer))
                .filter(|reply| reply.status == 200);
            answered.is_some()
        });
        let status = answered.unwrap().ok();
        assert!(
            status["requests"]["refused"].as_u64() >= Some(2),
            "{status}"
        );
    });
}

#[test]
fn a_silent_connection_is_closed_at_the_header_deadline() {
    let deadline = Duration::from_millis(300);
    let mut host = TestHost::new();
    host.api_limits = Some(limits(4, deadline));
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    serving(host, &wallet, |socket, _| {
        let started = Instant::now();
        let mut silent = UnixStream::connect(socket).unwrap();
        let answer = read_until_closed(&mut silent);
        assert!(started.elapsed() >= deadline, "{:?}", started.elapsed());
        assert!(
            answer.is_empty() || answer.starts_with("HTTP/1.1 408"),
            "{answer}"
        );

        let mut partial = UnixStream::connect(socket).unwrap();
        partial
            .write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: lepic\r\n")
            .unwrap();
        let answer = read_until_closed(&mut partial);
        assert!(
            answer.is_empty() || answer.starts_with("HTTP/1.1 408"),
            "{answer}"
        );

        http(socket, "GET", "/api/v1/status", None).ok();
    });
}

/// The next event on a stream, skipping keep-alive comments: its `event:` name and its data.
fn next_event(events: &mut BufReader<UnixStream>) -> (String, Value) {
    let mut name = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(events.read_line(&mut line).unwrap(), 0, "the stream ended");
        if let Some(event) = line.strip_prefix("event: ") {
            event.trim().clone_into(&mut name);
        } else if let Some(data) = line.strip_prefix("data: ") {
            return (name, serde_json::from_str(data).unwrap());
        }
    }
}

#[test]
fn the_event_stream_yields_the_wallets_events() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let sender = Instance::new("sender password");
    sender.restore(&host, SENDER_MNEMONIC);
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let address = wallet.run(&host, &["wallet", "address"]).ok().json();
    let address = support::text(&address, "address").to_owned();

    serving(host, &wallet, |socket, client| {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        stream
            .write_all(
                b"GET /api/v1/events HTTP/1.1\r\nHost: lepic\r\nAccept: text/event-stream\r\n\r\n",
            )
            .unwrap();
        let mut events = BufReader::new(stream);
        let mut line = String::new();
        events.read_line(&mut line).unwrap();
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        let mut content_type = None;
        loop {
            line.clear();
            events.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.trim().to_owned());
            }
        }
        assert_eq!(content_type.as_deref(), Some("text/event-stream"));

        let status = http(socket, "GET", "/api/v1/status", None).ok();
        assert_eq!(status["requests"]["in_flight"], 2, "{status}");

        let sent = sender
            .run(client, &["tx", "send", "1", "--to", &address])
            .ok()
            .json();
        let started = Instant::now();
        let created = loop {
            assert!(started.elapsed() < PATIENCE, "no payment.created event");
            let (name, event) = next_event(&mut events);
            assert_eq!(event["type"], name.as_str(), "{event}");
            assert_eq!(
                support::contract::event_errors(&event),
                Vec::<String>::new(),
                "{event}"
            );
            if name == "payment.created" {
                break event;
            }
        };
        // The payment's id is the slate id the sender's wallet shows.
        let id = created["data"]["object"]["id"].as_str().unwrap();
        assert_eq!(id, sent["slate_id"], "{created}");
        let payment = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
        assert_eq!(payment["direction"], "in", "{payment}");
        assert_eq!(payment["amount"], "1.00000000", "{payment}");

        // The same events are listed, and a resumed stream starts after the last one read.
        let listed = http(socket, "GET", "/api/v1/events?types=payment.created", None).ok();
        let ids: Vec<&Value> = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| &event["id"])
            .collect();
        assert!(ids.contains(&&created["id"]), "{listed}");

        // Every event of a page keeps the contract, also its object.
        let page = http(socket, "GET", "/api/v1/events", None).ok();
        let items = page["items"].as_array().unwrap();
        assert!(!items.is_empty(), "{page}");
        for event in items {
            assert_eq!(
                support::contract::event_errors(event),
                Vec::<String>::new(),
                "{event}"
            );
        }
    });
}

#[test]
fn a_payment_is_logged_once_it_has_the_confirmations_asked() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    // The funding, at height 1, has 3 confirmations when serve starts.
    host.node
        .update_chain(|chain| chain.tip.height = lepic_primitives::amount::Height::new(3));
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let node = host.node.clone();
    serving(host, &wallet, |socket, _| {
        let path = "/api/v1/events?types=payment.confirmations_reached";
        let reached = || http(socket, "GET", path, None).ok()["items"].clone();
        let status = || http(socket, "GET", "/api/v1/status", None).ok();
        wait_until("a refresh", || {
            status()["refresh"]["last_success_at"].is_string()
        });
        assert_eq!(reached(), json!([]));
        let funding = || http(socket, "GET", "/api/v1/payments", None).ok()["items"][0].clone();
        let before = funding();
        assert_eq!(before["confirmations"], 3, "{before}");
        assert_eq!(before["final"], false, "{before}");
        node.update_chain(|chain| chain.tip.height = lepic_primitives::amount::Height::new(6));
        wait_until("payment.confirmations_reached", || {
            !reached().as_array().unwrap().is_empty()
        });
        let items = reached();
        assert_eq!(items.as_array().unwrap().len(), 1, "{items}");
        assert_eq!(items[0]["data"]["object"]["confirmations"], 6, "{items}");
        assert_eq!(items[0]["data"]["object"]["final"], true, "{items}");
        let after = funding();
        assert_eq!(after["final"], true, "{after}");
    });
}

#[test]
fn a_served_503_carries_retry_after() {
    let host = TestHost::new();
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let node = host.node.clone();
    serving(host, &wallet, |socket, _| {
        // The node cannot be reached: a scan from a height asks it for the tip first.
        for _ in 0..50 {
            node.fail_next("get_tip", MockFailure::Unreachable);
        }
        let body = json!({"from_height": 1}).to_string();
        let scan = http(socket, "POST", "/api/v1/wallet/scan", Some(&body));
        problem(&scan, 503, "node_unreachable");
        let wait = scan.header("retry-after").unwrap();
        assert!(wait.parse::<u64>().is_ok(), "{scan:?}");
    });
}

#[test]
fn status_shows_the_node_tip_as_the_last_refresh_saw_it() {
    let (host, wallet) = support::funded();
    let node = host.node.clone();
    node.fail_every("get_tip", MockFailure::Unreachable);
    serving(host, &wallet, |socket, _| {
        let status = || http(socket, "GET", "/api/v1/status", None).ok();
        wait_until("a failed refresh", || {
            status()["refresh"]["failures"].as_u64() > Some(0)
        });
        let before = status();
        assert_eq!(before["node"], json!({}), "{before}");

        node.stop_failing("get_tip");
        wait_until("the tip", || status()["node"]["tip_height"] == support::TIP);
        let seen = status()["node"]["tip_changed_at"].clone();
        assert!(seen.is_string(), "{seen}");
        // A later refresh at the same tip keeps the time it was first seen.
        let refreshed = status()["refresh"]["last_success_at"].clone();
        wait_until("another refresh", || {
            status()["refresh"]["last_success_at"] != refreshed
        });
        assert_eq!(status()["node"]["tip_changed_at"], seen);

        node.update_chain(|chain| {
            chain.tip.height = lepic_primitives::amount::Height::new(support::TIP + 1);
        });
        wait_until("the new tip", || {
            status()["node"]["tip_height"] == support::TIP + 1
        });
        assert_ne!(status()["node"]["tip_changed_at"], seen);
    });
}

#[test]
fn status_asks_the_node_nothing() {
    let (host, wallet) = support::funded();
    let node = host.node.clone();
    // Each refresh then stops at its first request, so the node sees one request per refresh.
    node.fail_every("get_tip", MockFailure::Unreachable);
    serving(host, &wallet, |socket, _| {
        let status = || http(socket, "GET", "/api/v1/status", None).ok();
        wait_until("a failed refresh", || {
            status()["refresh"]["failures"].as_u64() > Some(0)
        });
        let reads = 50;
        let before = node.calls().len();
        for _ in 0..reads {
            status();
        }
        let asked = node.calls().len() - before;
        assert!(
            asked < reads,
            "{asked} node requests for {reads} status reads"
        );
    });
}

/// A wallet served on a relay that speaks mux/1, whose periodic collect does not come round
/// again during a test.
fn served_on_mux() -> (TestHost, Instance) {
    let host = TestHost::with_mux(Duration::from_secs(3600));
    let wallet = Instance::new("serving password");
    // One relay: serve watches the public address on every mailbox of its list, and the mock
    // answers each host name, so the status would list one entry per mailbox.
    wallet.on_public_mailbox();
    wallet.restore(&host, SENDER_MNEMONIC);
    (host, wallet)
}

/// The one push session `GET /status` lists, once `ready` holds for it.
fn relay_status(socket: &std::path::Path, what: &str, ready: impl Fn(&Value) -> bool) -> Value {
    let relays = || {
        http(socket, "GET", "/api/v1/status", None).ok()["listeners"]["epicbox"]["relays"].clone()
    };
    wait_until(what, || {
        relays()
            .as_array()
            .is_some_and(|all| all.len() == 1 && ready(&all[0]))
    });
    relays()[0].clone()
}

#[test]
fn status_shows_an_attached_relay_and_its_last_mail() {
    let (host, wallet) = served_on_mux();
    serving(host, &wallet, |socket, host| {
        let relay = host.mux.as_ref().unwrap();
        let attached = relay_status(socket, "an attached session", |relay| {
            relay["state"] == "attached"
        });
        assert_eq!(attached["group"], "wallet", "{attached}");
        assert_eq!(attached["push"], true, "{attached}");
        assert!(
            attached["host"]
                .as_str()
                .and_then(|host| host.rsplit_once(':'))
                .is_some_and(|(domain, port)| !domain.is_empty() && port.parse::<u16>().is_ok()),
            "{attached}"
        );
        assert!(attached["connected_since"].is_string(), "{attached}");
        assert!(attached.get("last_error").is_none(), "{attached}");
        assert!(attached.get("last_mail_at").is_none(), "{attached}");

        wait_until("the payments address is attached", || {
            !relay.attached().is_empty()
        });
        let key = relay.attached().into_iter().next().unwrap();
        let to = lepic_epicbox::EpicboxAddress::parse(
            &format!("{key}@relay.test"),
            lepic_epicbox::Network::Floonet,
        )
        .unwrap();
        let keychain = lepic_keychain::Keychain::from_mnemonic(
            SENDER_MNEMONIC,
            lepic_primitives::params::Network::Floonet,
        )
        .unwrap();
        let secret = keychain
            .address_key(
                &lepic_keychain::Identifier::new(3, [0, 9, 9, 0]).unwrap(),
                0,
            )
            .unwrap();
        let sealed = lepic_epicbox::SignedMessage::seal(
            "not a payment",
            &to,
            &secret,
            lepic_epicbox::Salt::from([4; 8]),
            lepic_epicbox::Nonce::from([5; 12]),
        )
        .unwrap();
        relay.store(&to, &to, &sealed);
        let mailed = relay_status(socket, "the pushed mail", |relay| {
            relay["last_mail_at"].is_string()
        });
        // The session stayed attached, so the time it attached is the same.
        assert_eq!(mailed["connected_since"], attached["connected_since"]);
    });
}

#[test]
fn status_shows_why_a_relay_does_not_attach() {
    let (host, wallet) = served_on_mux();
    // Every attach is refused, with a retry far later than the test runs.
    host.mux
        .as_ref()
        .unwrap()
        .rate_limit_attaches(u32::MAX, 3600);
    serving(host, &wallet, |socket, _| {
        let refused = relay_status(socket, "a refused attach", |relay| {
            relay["last_error"].is_string()
        });
        assert_eq!(refused["state"], "waiting", "{refused}");
        assert_eq!(refused["push"], true, "{refused}");
        assert!(
            refused["last_error"]
                .as_str()
                .unwrap()
                .contains("rate limited"),
            "{refused}"
        );
        assert!(refused.get("connected_since").is_none(), "{refused}");
    });
}

#[test]
fn status_shows_a_relay_without_push() {
    let (host, wallet) = served_on_mux();
    host.mux.as_ref().unwrap().offer_mux(false);
    serving(host, &wallet, |socket, _| {
        let plain = relay_status(socket, "a relay without mux/1", |relay| {
            relay["state"] == "not_offered"
        });
        assert_eq!(plain["push"], false, "{plain}");
        assert!(plain.get("connected_since").is_none(), "{plain}");
        assert!(plain.get("last_error").is_none(), "{plain}");
    });
}

/// A decline mark as the wallet writes it: the time the decline came.
const DECLINED_AT: &str = "2026-11-18T00:00:00Z";

/// Runs `args` for `wallet` and gives the slate id its JSON names.
fn slate_of(wallet: &Instance, host: &TestHost, args: &[&str]) -> String {
    support::text(&wallet.run(host, args).ok().json(), "slate_id").to_owned()
}

/// The payments `GET /payments?state=<state>` lists, newest first.
fn listed(socket: &std::path::Path, state: &str) -> Vec<Value> {
    let path = format!("/api/v1/payments?state={state}&limit=500");
    let page = http(socket, "GET", &path, None).ok();
    assert!(page.get("next_cursor").is_none(), "{page}");
    page["items"].as_array().unwrap().clone()
}

#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn status_counts_the_open_payments_as_the_listing_shows_them() {
    let host = TestHost::new();
    for child in 0..5 {
        host.fund(SENDER_MNEMONIC, child, FUNDING, u64::from(child) + 1);
    }
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let receiver = support::new_wallet(&host, "receiver password");
    let issuer = support::new_wallet(&host, "issuer password");
    let file = |name: &str| wallet.path(name).to_str().unwrap().to_owned();
    let send = |name: &str| {
        slate_of(
            &wallet,
            &host,
            &["tx", "send", "1", "--to-file", &file(name)],
        )
    };
    let answer = |name: &str| {
        let received = receiver
            .run(&host, &["tx", "receive", &file(name)])
            .ok()
            .json();
        support::text(&received, "reply_file").to_owned()
    };

    // The oldest send is declined, so the oldest awaiting an answer is the next one.
    let declined = send("declined.slate");
    let awaiting = send("awaiting.slate");
    let posted = send("posted.slate");
    wallet
        .run(&host, &["tx", "finalize", &answer("posted.slate")])
        .ok();
    let finalized = send("finalized.slate");
    let reply = answer("finalized.slate");
    // The node stays out of reach, so no retry moves the send on while the test reads.
    host.node
        .fail_every("push_transaction", MockFailure::Unreachable);
    let failed = wallet.run(&host, &["tx", "finalize", &reply]);
    assert_eq!(failed.code, 11, "{failed:?}");
    let cancel = |name: &str| {
        let sent = wallet
            .run(&host, &["tx", "send", "1", "--to-file", &file(name)])
            .ok()
            .json();
        wallet
            .run(&host, &["tx", "cancel", &sent["tx_id"].to_string()])
            .ok();
        support::text(&sent, "slate_id").to_owned()
    };
    let cancelled = cancel("cancelled.slate");
    let marked = cancel("marked.slate");
    let invoice = slate_of(
        &wallet,
        &host,
        &["invoice", "issue", "2", "--to-file", &file("invoice.slate")],
    );
    let refused = slate_of(
        &wallet,
        &host,
        &["invoice", "issue", "2", "--to-file", &file("refused.slate")],
    );
    let held_file = issuer.path("held.slate");
    issuer
        .run(
            &host,
            &[
                "invoice",
                "issue",
                "3",
                "--to-file",
                held_file.to_str().unwrap(),
            ],
        )
        .ok();
    let held = std::fs::read_to_string(&held_file).unwrap();
    with_settings_marks(
        &wallet,
        &[
            // Declined but still open, so listed as `declined`.
            (format!("notice.send_declined.{declined}"), DECLINED_AT),
            (format!("notice.declined.{refused}"), DECLINED_AT),
            // A mark of an older version, which the listing does not read.
            (format!("notice.send_declined.{awaiting}"), "1"),
            // A mark on a payment that is over: listed as `declined`, open in no count.
            (format!("notice.send_declined.{marked}"), DECLINED_AT),
            // A mark of the wrong direction.
            (format!("notice.declined.{awaiting}"), DECLINED_AT),
        ],
    );

    serving(host, &wallet, |socket, _| {
        let opened = http(
            socket,
            "POST",
            "/api/v1/open",
            Some(&json!({ "text": held }).to_string()),
        )
        .ok();
        assert_eq!(opened["outcome"], "invoice_parked", "{opened}");

        let payments = http(socket, "GET", "/api/v1/status", None).ok()["payments"].clone();
        let ids = |state: &str| {
            let mut ids: Vec<String> = listed(socket, state)
                .iter()
                .map(|each| support::text(each, "id").to_owned())
                .collect();
            ids.sort();
            ids
        };
        let sorted = |mut ids: Vec<&String>| {
            ids.sort();
            ids.into_iter().cloned().collect::<Vec<_>>()
        };
        assert_eq!(ids("awaiting_answer"), sorted(vec![&invoice, &awaiting]));
        assert_eq!(ids("declined"), sorted(vec![&declined, &refused, &marked]));
        assert_eq!(ids("finalized"), vec![finalized.clone()]);
        assert_eq!(ids("posted"), vec![posted.clone()]);
        assert_eq!(ids("cancelled"), vec![cancelled.clone()]);
        assert_eq!(ids("needs_approval").len(), 1);
        for state in ["needs_approval", "awaiting_answer", "finalized", "posted"] {
            assert_eq!(
                payments["open"][state],
                listed(socket, state).len(),
                "{state}: {payments}"
            );
        }
        for (field, state) in [
            ("oldest_awaiting_answer", "awaiting_answer"),
            ("oldest_finalized", "finalized"),
        ] {
            let oldest = listed(socket, state).last().unwrap().clone();
            assert_eq!(
                payments[field],
                json!({ "id": oldest["id"], "since": oldest["created_at"] }),
                "{field}: {payments}"
            );
        }
    });
}

/// Writes `marks` into the settings of the stopped `wallet`.
fn with_settings_marks(wallet: &Instance, marks: &[(String, &str)]) {
    support::with_settings(wallet, SENDER_MNEMONIC, |repos| {
        for (key, value) in marks {
            repos.put_setting(key, value)?;
        }
        Ok(())
    });
}

#[test]
fn status_counts_a_parked_invoice_the_listing_cannot_read() {
    let (host, wallet) = support::funded();
    support::with_settings(&wallet, SENDER_MNEMONIC, |repos| {
        repos.park_invoice(&lepic_store::PendingInvoice {
            slate_id: "6d1b5cf4-9a3c-4c39-8a43-07a0a1b9f2c1".parse().unwrap(),
            sender_key: "02".repeat(33),
            sender_address: "nobody@example.invalid".to_owned(),
            // Serve's invoice sweep removes a parked invoice a day old, so it is received now.
            received_at: jiff::Timestamp::now(),
            status: lepic_store::PendingInvoiceStatus::Parked,
            codec: "json".to_owned(),
            bytes: b"not a slate".to_vec(),
        })
    });
    serving(host, &wallet, |socket, _| {
        let payments = http(socket, "GET", "/api/v1/status", None).ok()["payments"].clone();
        assert!(listed(socket, "needs_approval").is_empty());
        assert_eq!(
            payments,
            json!({
                "open": {
                    "needs_approval": 1,
                    "awaiting_answer": 0,
                    "finalized": 0,
                    "posted": 0,
                },
            }),
        );
    });
}

/// Runs serve with the host's drain set to `drain`, holds a connection that sent the head of a
/// request and no more, stops serve, lets `then` act while it drains, and returns once serve
/// ended. A serve that waited for the connection would wait for its body timeout, an hour.
fn serve_that_drains_a_stalled_connection(
    drain: Duration,
    then: impl FnOnce(&std::sync::atomic::AtomicBool),
) -> Duration {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (mut host, wallet) = support::funded();
    let hour = Duration::from_secs(3600);
    host.api_limits = Some(ApiLimits {
        max_connections: 8,
        header_timeout: hour,
        body_timeout: hour,
        max_body: 1024,
        tls_max_age: hour,
    });
    host.drain = Some(drain);
    let stop = Arc::new(AtomicBool::new(false));
    let hurry = Arc::new(AtomicBool::new(false));
    host.stop_when_set = Some(Arc::clone(&stop));
    host.hurry_when_set = Some(Arc::clone(&hurry));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let args = ["serve", "--socket", socket.to_str().unwrap()];
    std::thread::scope(|scope| {
        let server = support::serve_thread(scope, || wallet.run(&host, &args));
        support::wait_for_socket(&socket);
        let mut stalled = UnixStream::connect(&socket).unwrap();
        stalled
            .write_all(
                b"POST /api/v1/payments HTTP/1.1\r\nHost: lepic\r\nContent-Type: application/json\r\n\
                  Content-Length: 100\r\n\r\n{",
            )
            .unwrap();
        wait_until("serve saw the stalled request", || {
            http(&socket, "GET", "/api/v1/status", None).ok()["requests"]["in_flight"] == 2
        });
        let stopped = Instant::now();
        stop.store(true, Ordering::SeqCst);
        then(&hurry);
        // A panic here drops `stalled`, which lets serve end and the scope join.
        wait_until("serve ended without the stalled connection", || {
            server.is_finished()
        });
        let took = stopped.elapsed();
        server.join().unwrap().ok();
        drop(stalled);
        took
    })
}

#[test]
fn a_stopping_serve_stops_waiting_for_a_stalled_connection_after_its_drain_deadline() {
    serve_that_drains_a_stalled_connection(Duration::from_millis(300), |_| {});
}

#[test]
fn a_second_stop_signal_ends_the_drain_of_a_stopping_serve_at_once() {
    // A drain deadline that would not pass within the test, and a second signal that comes.
    serve_that_drains_a_stalled_connection(Duration::from_secs(3600), |hurry| {
        hurry.store(true, std::sync::atomic::Ordering::SeqCst);
    });
}
