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

mod support;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use lepic_cli::app_config::ApiLimits;
use lepic_node::mock::MockFailure;
use serde_json::{Value, json};
use support::{
    FUNDING, Instance, PATIENCE, SENDER_MNEMONIC, TestHost, http, parse_reply, problem, serving,
    wait_until,
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
fn connections_over_the_cap_are_closed_unanswered() {
    let mut host = TestHost::new();
    host.api_limits = Some(limits(2, PATIENCE));
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    serving(host, &wallet, |socket, _| {
        let first = UnixStream::connect(socket).unwrap();
        let second = UnixStream::connect(socket).unwrap();
        let mut over = UnixStream::connect(socket).unwrap();
        assert_eq!(read_until_closed(&mut over), "");

        drop((first, second));
        let mut answered = None;
        wait_until("serve answers again", || {
            let mut stream = UnixStream::connect(socket).unwrap();
            // A connection refused while the two close is closed before it is read, which
            // resets it.
            let _ = stream.write_all(
                b"GET /api/v1/status HTTP/1.1\r\nHost: lepic\r\nConnection: close\r\n\r\n",
            );
            stream.set_read_timeout(Some(PATIENCE)).unwrap();
            let mut answer = String::new();
            let read = stream.read_to_string(&mut answer);
            answered = (read.is_ok() && !answer.is_empty()).then(|| parse_reply(&answer));
            answered.is_some()
        });
        let status = answered.unwrap().ok();
        assert!(
            status["requests"]["refused"].as_u64() >= Some(1),
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
