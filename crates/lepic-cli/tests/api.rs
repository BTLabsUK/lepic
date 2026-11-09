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
        tls_max_age: PATIENCE,
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

/// A funded, restored wallet served with its mock node and relay.
fn funded() -> (TestHost, Instance) {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    (host, wallet)
}

const NO_CONTACT: &str = "00000000000000000000000000000000";

#[test]
fn transaction_routes_refuse_what_the_cli_refuses() {
    let (host, wallet) = funded();

    serving(host, &wallet, |socket, _| {
        for action in ["cancel", "release"] {
            let path = format!("/v1/transactions/99/{action}");
            problem(&http(socket, "POST", &path, None), 404, "not_found");
            let path = format!("/v1/transactions/first/{action}");
            problem(&http(socket, "POST", &path, None), 400, "usage");
        }
        let post = "/v1/transactions/99/post";
        problem(&http(socket, "POST", post, Some("{}")), 404, "not_found");
        problem(&http(socket, "POST", post, Some("{")), 400, "usage");
        let fluff = http(socket, "POST", post, Some(r#"{"fluff":1}"#));
        problem(&fluff, 400, "usage");

        let both = r#"{"start_height":1,"reset_chain":true}"#;
        problem(
            &http(socket, "POST", "/v1/wallet/scan", Some(both)),
            400,
            "usage",
        );
        let scan = http(socket, "POST", "/v1/wallet/scan", Some("{}")).ok();
        assert!(scan.is_object(), "{scan}");
    });
}

#[test]
fn methods_are_listed_and_a_send_names_one() {
    let (host, wallet) = funded();

    serving(host, &wallet, |socket, _| {
        let listed = http(socket, "GET", "/v1/methods", None).ok();
        let methods = listed["methods"].as_array().unwrap();
        let ids: Vec<&str> = methods.iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert!(
            ids.contains(&"epicbox") && ids.contains(&"http"),
            "{listed}"
        );
        let epicbox = methods.iter().find(|m| m["id"] == "epicbox").unwrap();
        assert_eq!(epicbox["delivers"], true, "{listed}");
        assert_eq!(epicbox["notices"], true, "{listed}");
        let file = methods.iter().find(|m| m["id"] == "file").unwrap();
        assert_eq!(file["exchanges"], true, "{listed}");
        assert_eq!(file["carries"]["reply_key"], true, "{listed}");
        assert_eq!(ids, ["file", "epicbox", "http", "tor"], "{listed}");

        let send = |body: &str| http(socket, "POST", "/v1/transactions", Some(body));
        let unknown = send(r#"{"amount":"1","to":"x","method":"nope"}"#);
        let detail = problem(&unknown, 400, "usage")["detail"].to_string();
        assert!(detail.contains("unknown method nope"), "{detail}");
        for id in &ids {
            assert!(detail.contains(id), "{detail}");
        }
        let detail = detail.replace("\"", "");
        assert!(
            detail.ends_with(&format!("serve offers: {}", ids.join(", "))),
            "{detail}"
        );
        for id in ["tor", "file"] {
            if ids.contains(&id) {
                let parked = send(&format!(r#"{{"amount":"1","to":"x","method":"{id}"}}"#));
                let detail = problem(&parked, 400, "usage")["detail"].to_string();
                assert!(detail.contains("does not send over"), "{detail}");
            }
        }
        let http_to_address = send(r#"{"amount":"1","to":"x","method":"http"}"#);
        problem(&http_to_address, 400, "usage");
        let absent = send(r#"{"amount":"1","to":"http://a.b"}"#);
        let detail = problem(&absent, 400, "usage")["detail"].to_string();
        assert!(detail.contains("Epicbox only"), "{detail}");
    });
}

#[test]
fn epicbox_routes_answer_the_status_and_a_peer() {
    let (host, wallet) = funded();
    let status = wallet.run(&host, &["epicbox", "status"]).ok().json();

    serving(host, &wallet, |socket, _| {
        let answer = http(socket, "GET", "/v1/epicbox", None).ok();
        assert_eq!(keys(&answer), keys(&status), "{answer}");
        problem(
            &http(socket, "GET", "/v1/epicbox/peers/nobody", None),
            400,
            "usage",
        );
    });
}

#[test]
fn profile_routes_show_set_and_prove_the_domain() {
    let (host, wallet) = funded();
    let profile = wallet.run(&host, &["profile", "show"]).ok().json();

    serving(host, &wallet, |socket, _| {
        assert_eq!(http(socket, "GET", "/v1/profile", None).ok(), profile);
        let domain = http(socket, "GET", "/v1/profile/domain", None).ok();
        assert!(domain["domain_key"].is_string(), "{domain}");

        for body in ["{}", r#"{"names":"automated","bits":"1"}"#] {
            let both = http(socket, "PATCH", "/v1/profile", Some(body));
            problem(&both, 400, "usage");
        }
        let set = http(socket, "PATCH", "/v1/profile", Some(r#"{"bits":"1"}"#)).ok();
        assert_eq!(set["profile"], 1, "{set}");

        let file = http(socket, "POST", "/v1/profile/domain/file", Some("{}")).ok();
        assert!(
            file["document"]
                .as_str()
                .unwrap()
                .contains(domain["domain_key"].as_str().unwrap()),
            "{file}"
        );
        let attach = http(socket, "POST", "/v1/profile/domain/attach", None);
        problem(&attach, 400, "usage");
    });
}

#[test]
fn contact_routes_pair_back_up_and_refuse_bad_input() {
    let (host, wallet) = funded();

    serving(host, &wallet, |socket, _| {
        let list = http(socket, "GET", "/v1/contacts", None).ok();
        assert_eq!(list["contacts"], serde_json::json!([]), "{list}");
        let quarantine = http(socket, "GET", "/v1/contacts/quarantine", None).ok();
        assert_eq!(
            quarantine["messages"],
            serde_json::json!([]),
            "{quarantine}"
        );
        let invoices = http(socket, "GET", "/v1/contact-invoices", None).ok();
        assert_eq!(invoices["invoices"], serde_json::json!([]), "{invoices}");

        let invite = http(
            socket,
            "POST",
            "/v1/contacts/invites",
            Some(r#"{"expiry":"1h"}"#),
        )
        .ok();
        assert!(invite["link"].is_string(), "{invite}");
        assert!(invite["contact_id"].is_string(), "{invite}");

        let update = format!("/v1/contacts/{NO_CONTACT}");
        problem(
            &http(socket, "PATCH", &update, Some(r#"{"label":"Shop"}"#)),
            404,
            "not_found",
        );
        problem(&http(socket, "PATCH", &update, Some("{}")), 400, "usage");

        let backup = http(socket, "POST", "/v1/contacts/export", None).ok();
        let body = serde_json::json!({ "backup": backup["backup"] }).to_string();
        let import = http(socket, "POST", "/v1/contacts/import", Some(&body));
        assert_eq!(import.status, 200, "{import:?}");

        let removed = http(socket, "DELETE", &update, None).ok();
        assert_eq!(removed["removed"], false, "{removed}");

        problem(
            &http(socket, "DELETE", "/v1/contacts/ab12", None),
            400,
            "usage",
        );
        let sas = format!("/v1/contacts/{NO_CONTACT}/sas");
        problem(
            &http(socket, "POST", &sas, Some(r#"{"result":"maybe"}"#)),
            400,
            "usage",
        );
        let enter = r#"{"input":["a","b","c","d","e","f"]}"#;
        problem(
            &http(socket, "POST", "/v1/contacts/enter", Some(enter)),
            400,
            "usage",
        );
        let home = r#"{"host":"relay.example:443","drain_days":366}"#;
        problem(
            &http(socket, "POST", "/v1/contacts/move-home", Some(home)),
            400,
            "usage",
        );
        let extra = http(
            socket,
            "POST",
            "/v1/contacts/preview",
            Some(r#"{"link":"x","path":"y"}"#),
        );
        problem(&extra, 400, "usage");
    });
}

#[test]
fn in_person_routes_refuse_bad_input() {
    let (host, wallet) = funded();

    serving(host, &wallet, |socket, _| {
        let unknown = "/v1/in-person/2f4a6c1e-5b3d-4e8f-9a0b-1c2d3e4f5a6b";
        problem(
            &http(socket, "GET", &format!("{unknown}/answers"), None),
            404,
            "not_found",
        );
        problem(
            &http(
                socket,
                "POST",
                &format!("{unknown}/finalize"),
                Some(r#"{"answer":1}"#),
            ),
            404,
            "not_found",
        );
        problem(
            &http(
                socket,
                "POST",
                "/v1/in-person/read",
                Some(r#"{"code":"zz"}"#),
            ),
            400,
            "usage",
        );
        problem(
            &http(
                socket,
                "POST",
                "/v1/in-person/take",
                Some(r#"{"answer":[]}"#),
            ),
            400,
            "usage",
        );
        problem(
            &http(
                socket,
                "POST",
                "/v1/in-person/invoices",
                Some(r#"{"amount":"1","out":"code.bin"}"#),
            ),
            400,
            "usage",
        );
    });
}

#[test]
fn payload_routes_list_and_refuse_bad_input() {
    let (host, wallet) = funded();

    serving(host, &wallet, |socket, _| {
        let list = http(socket, "GET", "/v1/payloads", None).ok();
        assert_eq!(list["payloads"], serde_json::json!([]), "{list}");
        let ack = http(
            socket,
            "POST",
            &format!("/v1/payloads/{NO_CONTACT}/ack"),
            None,
        );
        assert_eq!(ack.status, 200, "{ack:?}");
        assert_eq!(ack.json()["acknowledged"], 0, "{ack:?}");

        let post = format!("/v1/contacts/{NO_CONTACT}/payloads");
        problem(
            &http(socket, "POST", &post, Some(r#"{"payload":"zz"}"#)),
            400,
            "usage",
        );
        problem(
            &http(
                socket,
                "POST",
                "/v1/contacts/ab12/payloads",
                Some(r#"{"payload":"00"}"#),
            ),
            400,
            "usage",
        );
    });
}

/// A wallet created from new entropy, and its Epicbox address.
fn receiver(host: &TestHost) -> (Instance, String) {
    let receiver = Instance::new("receiver password");
    receiver.run(host, &["wallet", "init"]).ok();
    let address = receiver.run(host, &["wallet", "address"]).ok().json();
    let address = support::text(&address, "address").to_owned();
    (receiver, address)
}

#[test]
fn sends_under_one_slate_id_make_one_transaction() {
    let (host, wallet) = funded();
    let (receiver, address) = receiver(&host);
    let slate_id = "3f0c9a52-7d1e-4b6a-8c2f-5e9d0b1a7c46";
    let body = format!(r#"{{"amount":"1","to":"{address}","slate_id":"{slate_id}"}}"#);

    serving(host, &wallet, |socket, client| {
        let send = || http(socket, "POST", "/v1/transactions", Some(&body)).ok();
        let concurrent: Vec<Value> = std::thread::scope(|scope| {
            let first = scope.spawn(send);
            let second = scope.spawn(send);
            vec![first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(
            concurrent[0]["tx_id"], concurrent[1]["tx_id"],
            "{concurrent:?}"
        );
        let fresh: Vec<&Value> = concurrent
            .iter()
            .filter(|sent| sent["repeated"] == false)
            .collect();
        assert_eq!(fresh.len(), 1, "{concurrent:?}");
        let sent = fresh[0].clone();
        assert_eq!(sent["slate_id"], slate_id, "{sent}");
        assert_eq!(sent["delivered"], true, "{sent}");

        let again = send();
        assert_eq!(again["repeated"], true, "{again}");
        assert_eq!(again["tx_id"], sent["tx_id"], "{again}");
        assert_eq!(again["amount"], sent["amount"], "{again}");

        let list = http(socket, "GET", "/v1/transactions", None).ok();
        let matching = list["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|tx| tx["slate_id"] == slate_id)
            .count();
        assert_eq!(matching, 1, "{list}");
        let drained = receiver.run(client, &["epicbox", "drain"]).ok().json();
        assert_eq!(drained["received"], 1, "{drained}");
    });
}

#[test]
fn a_received_slate_is_answered_and_the_sender_finalizes_the_reply() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let slate = payer.path("payment.slate");
    let sent = payer
        .run(
            &host,
            &["tx", "send", "1.5", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let body = serde_json::json!({ "slate": std::fs::read_to_string(&slate).unwrap() });

    serving(host, &wallet, |socket, client| {
        let received = http(
            socket,
            "POST",
            "/v1/slates/receive",
            Some(&body.to_string()),
        )
        .ok();
        assert_eq!(received["slate_id"], sent["slate_id"], "{received}");
        assert_eq!(received["amount"], "1.50000000", "{received}");
        assert_eq!(received["repeated"], false, "{received}");
        let reply = payer.path("payment.slate.response");
        std::fs::write(&reply, support::text(&received, "slate")).unwrap();

        let finalized = payer
            .run(client, &["tx", "finalize", reply.to_str().unwrap()])
            .ok()
            .json();
        assert_eq!(finalized["tx_id"], sent["tx_id"], "{finalized}");
        assert_eq!(finalized["state"], "posted", "{finalized}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

#[test]
fn the_finalize_route_posts_the_receivers_reply() {
    let (host, wallet) = funded();
    let (receiver, _) = receiver(&host);
    let slate = wallet.path("payment.slate");
    let sent = wallet
        .run(
            &host,
            &["tx", "send", "1.5", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    let reply = std::fs::read_to_string(support::text(&received, "reply_file")).unwrap();
    let body = serde_json::json!({ "slate": reply }).to_string();

    serving(host, &wallet, |socket, client| {
        let finalized = http(socket, "POST", "/v1/slates/finalize", Some(&body)).ok();
        assert_eq!(finalized["tx_id"], sent["tx_id"], "{finalized}");
        assert_eq!(finalized["slate_id"], sent["slate_id"], "{finalized}");
        assert_eq!(finalized["state"], "posted", "{finalized}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
        problem(
            &http(socket, "POST", "/v1/slates/finalize", Some("{")),
            400,
            "usage",
        );
    });
}

#[test]
fn a_send_over_http_is_received_finalized_and_posted() {
    let (host, wallet) = funded();
    let (receiver, _) = receiver(&host);

    serving(host, &wallet, |socket, client| {
        let mut payee = client.without_interrupt();
        let stop = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&stop);
        payee.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
        let dir = tempfile::tempdir().unwrap();
        let payee_socket = dir.path().join("payee.sock");
        let payee_arg = payee_socket.to_str().unwrap();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                receiver.run(
                    &payee,
                    &["serve", "--socket", payee_arg, "--http", "--port", "0"],
                )
            });
            let stopping = Stop(&stop);
            wait_for_socket(&payee_socket);
            let status = http(&payee_socket, "GET", "/v1/status", None).ok();
            let port = status["http"]["port"].as_u64().unwrap();
            let to = format!("http://127.0.0.1:{port}");
            let body = serde_json::json!({ "amount": "1", "to": to, "method": "http" });

            let sent = http(socket, "POST", "/v1/transactions", Some(&body.to_string())).ok();
            assert_eq!(sent["transport"], "http", "{sent}");
            assert_eq!(sent["destination"], format!("{to}/v2/foreign"), "{sent}");
            assert_eq!(sent["state"], "posted", "{sent}");
            assert_eq!(sent["delivered"], true, "{sent}");
            assert_eq!(client.node.pushed_transactions().len(), 1);
            let status = http(&payee_socket, "GET", "/v1/status", None).ok();
            assert_eq!(status["http"]["received"], 1, "{status}");

            drop(stopping);
            server.join().unwrap().ok();
        });
    });
}

#[test]
fn the_password_route_re_encrypts_the_vault() {
    let host = TestHost::new();
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();

    serving(host, &wallet, |socket, _| {
        let body = r#"{"current_password":"serving password","new_password":"changed password"}"#;
        let changed = http(socket, "PUT", "/v1/wallet/password", Some(body)).ok();
        assert_eq!(changed, serde_json::json!({ "changed": true }));
    });

    let host = TestHost::new();
    let old = wallet.run(&host, &["wallet", "address"]);
    assert_eq!(old.code, 4, "{old:?}");
    assert_eq!(old.json()["error"]["kind"], "wrong_password", "{old:?}");
    let mut env = wallet.env();
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    env.push(("LEPIC_PASSWORD".to_owned(), "changed password".to_owned()));
    let address = wallet.run_with(&host, &["wallet", "address"], env, "");
    assert_eq!(address.code, 0, "{address:?}");
}
