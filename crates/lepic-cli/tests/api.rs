// SPDX-License-Identifier: Apache-2.0
//! The wallet API `lepic serve` answers on its socket: the routes, its problems and its
//! bounds, in one process with a mock node and a mock relay.

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
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use lepic_cli::app_config::ApiLimits;
use serde_json::Value;
use support::{
    FUNDING, Instance, PATIENCE, Reply, SENDER_MNEMONIC, TestHost, http, keys, parse_reply,
    wait_for_socket, wait_until,
};

/// Runs `test` against a `lepic serve` of `wallet` on a socket, then stops serve.
fn serving<T: Send>(
    mut host: TestHost,
    wallet: &Instance,
    test: impl FnOnce(&Path, &TestHost) -> T + Send,
) -> T {
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let client = host.without_interrupt();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();
    std::thread::scope(|scope| {
        let server = scope.spawn(|| wallet.run(&host, &["serve", "--socket", socket_arg]));
        // Stops serve when the test panics too, or the scope would wait for it forever.
        let stopping = Stop(&stop);
        wait_for_socket(&socket);
        let result = test(&socket, &client);
        drop(stopping);
        server.join().unwrap().ok();
        result
    })
}

struct Stop<'a>(&'a AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn limits(max_connections: usize, header_timeout: Duration) -> ApiLimits {
    ApiLimits {
        max_connections,
        header_timeout,
        body_timeout: PATIENCE,
        max_body: 1024,
    }
}

/// The problem a response carries, checked against the status and code it should have.
fn problem(reply: &Reply, status: u16, code: &str) -> Value {
    assert_eq!(reply.status, status, "{reply:?}");
    assert_eq!(
        reply.header("content-type"),
        Some("application/problem+json"),
        "{reply:?}"
    );
    let problem = reply.json();
    assert_eq!(problem["type"], "about:blank", "{problem}");
    assert_eq!(problem["status"], status, "{problem}");
    assert_eq!(problem["code"], code, "{problem}");
    assert!(problem["detail"].is_string(), "{problem}");
    problem
}

/// What a connection reads before serve closes it, waiting at most [`PATIENCE`].
fn read_until_closed(stream: &mut UnixStream) -> String {
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer
}

#[test]
fn status_wallet_and_outputs_answer_as_the_cli_does() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let info = wallet.run(&host, &["wallet", "info"]).ok().json();
    let outputs = wallet.run(&host, &["wallet", "outputs"]).ok().json();
    let address = wallet.run(&host, &["wallet", "address"]).ok().json();

    serving(host, &wallet, |socket, _| {
        let status = http(socket, "GET", "/v1/status", None).ok();
        assert_eq!(
            keys(&status),
            [
                "collect", "epicbox", "height", "node_tip", "refresh", "requests", "socket",
                "uptime_s"
            ]
        );
        assert_eq!(status["socket"], socket.to_str().unwrap(), "{status}");
        assert_eq!(status["requests"]["served"], 0, "{status}");
        assert_eq!(status["requests"]["in_flight"], 1, "{status}");
        assert_eq!(status["requests"]["refused"], 0, "{status}");

        assert_eq!(http(socket, "GET", "/v1/wallet", None).ok(), info);
        assert_eq!(
            http(socket, "GET", "/v1/wallet/address", None).ok(),
            address
        );
        assert_eq!(http(socket, "GET", "/v1/outputs", None).ok(), outputs);
        assert_eq!(
            http(socket, "GET", "/v1/outputs?account=default", None).ok(),
            outputs
        );

        let document = http(socket, "GET", "/v1/openapi.json", None).ok();
        assert_eq!(document["openapi"], "3.1.0");
        assert!(document["paths"]["/v1/status"].is_object(), "{document}");

        let status = http(socket, "GET", "/v1/status", None).ok();
        assert_eq!(status["requests"]["served"], 6, "{status}");
    });
}

#[test]
fn errors_are_problem_details() {
    let mut host = TestHost::new();
    host.api_limits = Some(limits(4, PATIENCE));
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    serving(host, &wallet, |socket, _| {
        let missing = http(socket, "GET", "/v1/transactions/99", None);
        problem(&missing, 404, "not_found");
        let account = http(socket, "GET", "/v1/outputs?account=nobody", None);
        problem(&account, 404, "not_found");

        let id = http(socket, "GET", "/v1/transactions/first", None);
        problem(&id, 400, "usage");
        let query = http(socket, "GET", "/v1/outputs?acount=default", None);
        problem(&query, 400, "usage");
        let garbled = http(socket, "POST", "/v1/transactions", Some("{"));
        problem(&garbled, 400, "usage");
        let extra = r#"{"amount":"1","to":"x","fee":"1"}"#;
        let extra = http(socket, "POST", "/v1/transactions", Some(extra));
        let detail = problem(&extra, 400, "usage")["detail"].to_string();
        assert!(detail.contains("fee"), "{detail}");

        let route = http(socket, "GET", "/v1/nowhere", None);
        problem(&route, 404, "not_found");
        let method = http(socket, "DELETE", "/v1/transactions", None);
        problem(&method, 405, "usage");
        assert_eq!(method.header("allow"), Some("GET, POST"), "{method:?}");

        let large = format!(r#"{{"slate":"{}"}}"#, "x".repeat(2048));
        let large = http(socket, "POST", "/v1/slates/receive", Some(&large));
        problem(&large, 413, "usage");

        let password = r#"{"current_password":"wrong password","new_password":"next"}"#;
        let password = http(socket, "PUT", "/v1/wallet/password", Some(password));
        let detail = problem(&password, 403, "wrong_password")["detail"].to_string();
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
            let _ = stream
                .write_all(b"GET /v1/status HTTP/1.1\r\nHost: lepic\r\nConnection: close\r\n\r\n");
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
            .write_all(b"GET /v1/status HTTP/1.1\r\nHost: lepic\r\n")
            .unwrap();
        let answer = read_until_closed(&mut partial);
        assert!(
            answer.is_empty() || answer.starts_with("HTTP/1.1 408"),
            "{answer}"
        );

        http(socket, "GET", "/v1/status", None).ok();
    });
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
            .write_all(b"GET /v1/events HTTP/1.1\r\nHost: lepic\r\n\r\n")
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

        let status = http(socket, "GET", "/v1/status", None).ok();
        assert_eq!(status["requests"]["in_flight"], 2, "{status}");

        sender
            .run(client, &["tx", "send", "1", "--to", &address])
            .ok();
        let started = Instant::now();
        let mut name = String::new();
        loop {
            assert!(started.elapsed() < PATIENCE, "no received event");
            line.clear();
            events.read_line(&mut line).unwrap();
            if let Some(event) = line.strip_prefix("event: ") {
                event.trim().clone_into(&mut name);
            } else if let Some(data) = line.strip_prefix("data: ") {
                let event: Value = serde_json::from_str(data).unwrap();
                assert_eq!(event["kind"], name.as_str(), "{event}");
                if name == "received" {
                    assert_eq!(event["amount"], "1.00000000", "{event}");
                    break;
                }
            }
        }
    });
}
