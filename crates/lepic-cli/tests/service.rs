// SPDX-License-Identifier: Apache-2.0
//! `lepic serve` holds the wallet and answers its API on a socket, in one process with a mock
//! node and a mock relay.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lepic_epicbox::mock_relay::Unanswered;
use lepic_node::RejectionKind;
use lepic_node::mock::MockFailure;
use support::{FUNDING, Instance, Outcome, SENDER_MNEMONIC, TestHost, http, keys, wait_for_socket};

#[test]
fn serve_answers_the_api_and_stops_on_interrupt() {
    let mut host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let info = wallet.run(&host, &["wallet", "info"]).ok().json();
    let listed = wallet.run(&host, &["tx", "list"]).ok().json();

    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();

    let served: Outcome = std::thread::scope(|scope| {
        let server = scope.spawn(|| wallet.run(&host, &["serve", "--socket", socket_arg]));
        wait_for_socket(&socket);

        assert_eq!(http(&socket, "GET", "/v1/wallet", None).ok(), info);
        assert_eq!(http(&socket, "GET", "/v1/transactions", None).ok(), listed);
        let garbled = http(&socket, "POST", "/v1/transactions", Some("not json"));
        assert_eq!(garbled.status, 400, "{garbled:?}");

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap()
    });

    let report = served.ok().json();
    assert_eq!(keys(&report), ["inbox", "requests", "socket"]);
    assert_eq!(report["requests"], 3, "{report}");
    assert!(!socket.exists());
    // The lock is released: a one-shot command opens the wallet again.
    host.interrupt_when = None;
    assert_eq!(wallet.run(&host, &["wallet", "info"]).ok().json(), info);
}

#[test]
fn serve_refuses_a_socket_path_it_cannot_use() {
    let host = TestHost::new();
    let wallet = Instance::new("path password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let dir = tempfile::tempdir().unwrap();

    let file = dir.path().join("taken");
    std::fs::write(&file, "not a socket").unwrap();
    let taken = wallet.run(&host, &["serve", "--socket", file.to_str().unwrap()]);
    assert_eq!(taken.code, 2, "{taken:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "not a socket");

    let long = dir.path().join("x".repeat(120));
    let mut human = wallet.env();
    human.retain(|(key, _)| key != "LEPIC_OUTPUT");
    let args = ["serve", "--socket", long.to_str().unwrap()];
    let too_long = wallet.run_with(&host, &args, human, "");
    assert_eq!(too_long.code, 2, "{too_long:?}");
    assert!(too_long.stderr.contains("--socket"), "{too_long:?}");
}

/// A stop while a request is in flight lets it end as Ctrl-C would and sends its reply before
/// serve exits: a send that could not post names the transaction it stored.
#[test]
fn serve_answers_a_request_in_flight_before_it_stops() {
    let mut host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let receiver = Instance::new("receiver password");
    receiver.run(&host, &["wallet", "init"]).ok();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let address = support::text(&address, "address").to_owned();
    host.relay.set_unanswered(Unanswered::PostSlate, true);

    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let client = host.without_interrupt();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();
    let send = format!(r#"{{"amount":"1","to":"{address}"}}"#);

    let (sent, served) = std::thread::scope(|scope| {
        let server = scope.spawn(|| wallet.run(&host, &["serve", "--socket", socket_arg]));
        wait_for_socket(&socket);
        let sending = scope.spawn(|| http(&socket, "POST", "/v1/transactions", Some(&send)));
        support::wait_until("the send posted", || {
            client.relay.received("PostSlate") >= 1
        });
        stop.store(true, Ordering::SeqCst);
        (sending.join().unwrap(), server.join().unwrap())
    });

    assert_eq!(sent.status, 503, "{sent:?}");
    let problem = sent.json();
    assert_eq!(problem["code"], "interrupted", "{problem}");
    let tx_id = problem["tx_id"].as_u64().unwrap().to_string();
    let report = served.ok().json();
    assert_eq!(report["requests"], 1, "{report}");
    let shown = wallet.run(&client, &["tx", "show", &tx_id]).ok().json();
    assert_eq!(shown["state"], "sent", "{shown}");
}

/// `GET /v1/status` counts refreshes that fail in a row with the latest error, and starts again
/// from zero at the next success while keeping that error.
#[test]
fn serve_status_reports_refreshes_failing_in_a_row() {
    let mut host = TestHost::new();
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let client = host.without_interrupt();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();
    let status = || http(&socket, "GET", "/v1/status", None).ok();

    let served = std::thread::scope(|scope| {
        let server = scope.spawn(|| wallet.run(&host, &["serve", "--socket", socket_arg]));
        wait_for_socket(&socket);
        support::wait_until("a first refresh", || {
            status()["refresh"]["last_success"].is_string()
        });
        // Enough failures for the count to be seen above one between two status requests.
        for _ in 0..20 {
            client
                .node
                .fail_next("get_tip", MockFailure::Rejected(RejectionKind::Internal));
        }
        support::wait_until("two refreshes failed in a row", || {
            let refresh = &status()["refresh"];
            refresh["consecutive_failures"].as_u64() >= Some(2) && refresh["last_error"].is_string()
        });
        support::wait_until("a refresh after the failures", || {
            let refresh = &status()["refresh"];
            refresh["consecutive_failures"] == 0 && refresh["last_error"].is_string()
        });
        assert_eq!(status()["collect"]["consecutive_failures"], 0);
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap()
    });
    served.ok();
}

/// `serve --http` answers the foreign API on a port the system picked, `GET /v1/status` shows the
/// listener, and serve's report ends with its counts.
#[test]
fn serve_with_http_answers_the_foreign_api() {
    let mut host = TestHost::new();
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();

    let served = std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            wallet.run(
                &host,
                &["serve", "--socket", socket_arg, "--http", "--port", "0"],
            )
        });
        wait_for_socket(&socket);
        let status = http(&socket, "GET", "/v1/status", None).ok();
        let listener = &status["http"];
        assert_eq!(listener["exposure"], "local", "{status}");
        assert_eq!(listener["coinbase"], "off", "{status}");
        assert_eq!(listener["received"], 0, "{status}");
        let port = listener["port"].as_u64().unwrap();
        assert_ne!(port, 0, "{status}");

        let body = r#"{"jsonrpc":"2.0","id":1,"method":"check_version","params":[]}"#;
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", u16::try_from(port).unwrap())).unwrap();
        write!(
            stream,
            "POST /v2/foreign HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut answer = String::new();
        std::io::Read::read_to_string(&mut stream, &mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        let json = answer.split("\r\n\r\n").nth(1).unwrap();
        let version: serde_json::Value = serde_json::from_str(json).unwrap();
        assert!(
            version["result"]["Ok"]["foreign_api_version"].is_number(),
            "{version}"
        );

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap()
    });
    let report = served.ok().json();
    assert_eq!(report["http"]["exposure"], "local", "{report}");
    assert_eq!(report["http"]["refused"], 0, "{report}");
    assert_eq!(keys(&report), ["http", "inbox", "requests", "socket"]);
}
