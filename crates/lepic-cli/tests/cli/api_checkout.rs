// SPDX-License-Identifier: Apache-2.0
//! In-person payment requests through the wallet API v1: a create with `via: in_person`, the
//! payer's answer by the shop's mailbox slot or its direct route, finalized by hand or by
//! serve itself, across restarts. Every answer is checked against `docs/api/openapi.json` by
//! `support::http`.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use lepic_node::mock::MockFailure;
use lepic_primitives::amount::Height;
use serde_json::{Value, json};
use support::{
    Instance, TestHost, funded, http, new_wallet, problem, serving, serving_with, text, wait_until,
};

/// The envelope media type the inbox route takes.
const ENVELOPE: &str = "application/vnd.lepic.epictx";

/// A public address for the shop's direct route; nothing is ever posted to it.
const PUBLIC_URL: &str = "https://shop.example.com";

fn post(socket: &Path, path: &str, body: &Value) -> support::Reply {
    http(socket, "POST", path, Some(&body.to_string()))
}

fn payment(socket: &Path, id: &str) -> Value {
    http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok()
}

/// Creates the request `body` asks for and checks what it hands off: the code as hex, its QR
/// frames and its link. Returns the payment.
fn request(socket: &Path, body: &Value) -> Value {
    let created = post(socket, "/api/v1/payments", body);
    assert_eq!(created.status, 201, "{created:?}");
    let made = created.json();
    assert_eq!(made["via"], "in_person", "{made}");
    let handoff = &made["handoff"];
    assert_eq!(handoff["format"], "in_person_code", "{made}");
    assert!(
        text(handoff, "text").chars().all(|c| c.is_ascii_hexdigit()),
        "{made}"
    );
    assert!(
        !handoff["qr_frames"].as_array().unwrap().is_empty(),
        "{made}"
    );
    assert!(
        text(handoff, "link").starts_with("epiccash://invoice/1/"),
        "{made}"
    );
    assert_eq!(made["request"]["state"], "open", "{made}");
    assert_eq!(made["request"]["answers_refused"], 0, "{made}");
    made
}

/// The payer `payer` pays the code `code` for `amount` and keeps the answer: its sealed answer,
/// as hex.
fn sealed(payer: &Instance, host: &TestHost, amount: &str, code: &str) -> Value {
    payer
        .run(host, &["in-person", "pay", amount, "--hex", code])
        .ok()
        .json()
}

/// The payer `payer` pays the code `code` for `amount` and posts the answer to the mailbox the
/// code names.
fn pay(payer: &Instance, host: &TestHost, amount: &str, code: &str) {
    let paid = sealed(payer, host, amount, code);
    let posted = payer
        .run(host, &["in-person", "post", text(&paid, "slate_id")])
        .ok()
        .json();
    assert_eq!(posted["posted"], true, "{posted}");
}

fn answers(socket: &Path, id: &str) -> usize {
    payment(socket, id)["answers"]
        .as_array()
        .map_or(0, Vec::len)
}

/// The `data` of each `kind` event listed so far for the payment `id`.
fn events_of(socket: &Path, kind: &str, id: &str) -> Vec<Value> {
    let listed = http(socket, "GET", &format!("/api/v1/events?types={kind}"), None).ok();
    listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["data"].clone())
        .filter(|data| data["object"]["id"] == id)
        .collect()
}

/// A manual request waits for the shop: the answer shows with its check code and a `post`
/// action, and the post finalizes it once.
#[test]
fn a_manual_request_is_paid_when_the_shop_posts_its_answer() {
    let (host, payer) = funded();
    let shop = new_wallet(&host, "shop password");
    let id = "4b1f6c2e-8a3d-4e5f-9a1b-2c3d4e5f6a7b";
    let body = json!({ "id": id, "kind": "invoice", "via": "in_person", "amount": "2" });
    serving(host, &shop, |socket, client| {
        let made = request(socket, &body);
        assert_eq!(made["request"]["finalize"], "manual", "{made}");
        assert!(!made["actions"].as_array().unwrap().contains(&json!("post")));
        let code = text(&made["handoff"], "text").to_owned();

        let repeated = post(socket, "/api/v1/payments", &body);
        assert_eq!(repeated.status, 200, "{repeated:?}");
        let repeated = repeated.json();
        assert_eq!(repeated["id"], made["id"]);
        assert_eq!(repeated["handoff"]["text"], code.as_str(), "{repeated}");
        let mut changed = body.clone();
        changed["amount"] = json!("3");
        problem(
            &post(socket, "/api/v1/payments", &changed),
            409,
            "idempotency_mismatch",
        );

        let slate = text(&made, "id").to_owned();
        problem(
            &post(
                socket,
                &format!("/api/v1/payments/{slate}/post"),
                &json!({}),
            ),
            409,
            "action_not_available",
        );

        pay(&payer, client, "2", &code);
        wait_until("the answer shows", || answers(socket, &slate) == 1);
        let waiting = payment(socket, &slate);
        assert!(
            waiting["actions"]
                .as_array()
                .unwrap()
                .contains(&json!("post")),
            "{waiting}"
        );
        assert_eq!(waiting["request"]["state"], "open", "{waiting}");
        let check_code = text(&waiting["answers"][0], "check_code").to_owned();
        assert!(client.node.pushed_transactions().is_empty());

        let posted = post(
            socket,
            &format!("/api/v1/payments/{slate}/post"),
            &json!({ "answer": check_code }),
        )
        .ok();
        assert_eq!(posted["request"]["state"], "paid", "{posted}");
        assert_eq!(
            posted["request"]["reference"],
            check_code.as_str(),
            "{posted}"
        );
        assert_eq!(posted["check_code"], check_code.as_str(), "{posted}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
        let changes = events_of(socket, "payment.state_changed", &slate);
        assert!(
            changes
                .iter()
                .any(|data| data["object"]["request"]["state"] == "paid"),
            "{changes:?}"
        );
    });
}

/// A `finalize: first` request answered while serve is down is finalized and posted once
/// serve is back, and once only across further restarts.
#[test]
fn a_first_request_is_finalized_once_across_restarts() {
    let (host, payer) = funded();
    let shop = new_wallet(&host, "shop password");
    let paying = host.without_interrupt();
    let again = host.without_interrupt();
    let third = host.without_interrupt();
    let node = host.node.clone();
    let body = json!({
        "id": "6d2a9b4c-1e3f-4a5b-8c7d-9e0f1a2b3c4d",
        "kind": "invoice",
        "via": "in_person",
        "amount": "2",
        "finalize": "first",
    });
    let made = serving(host, &shop, |socket, _| {
        let made = request(socket, &body);
        assert_eq!(made["request"]["finalize"], "first", "{made}");
        let slate = text(&made, "id").to_owned();
        problem(
            &post(
                socket,
                &format!("/api/v1/payments/{slate}/post"),
                &json!({}),
            ),
            409,
            "action_not_available",
        );
        made
    });
    let slate = text(&made, "id").to_owned();
    pay(&payer, &paying, "2", text(&made["handoff"], "text"));
    serving(again, &shop, |socket, _| {
        wait_until("serve finalizes the answer", || {
            payment(socket, &slate)["request"]["state"] == "paid"
        });
        let paid = payment(socket, &slate);
        assert!(paid["request"]["reference"].is_string(), "{paid}");
        assert_eq!(paid["request"]["reference"], paid["check_code"], "{paid}");
    });
    assert_eq!(node.pushed_transactions().len(), 1);
    serving(third, &shop, |socket, _| {
        let paid = payment(socket, &slate);
        assert_eq!(paid["request"]["state"], "paid", "{paid}");
        let repeated = post(socket, "/api/v1/payments", &body);
        assert_eq!(repeated.status, 200, "{repeated:?}");
    });
    assert_eq!(node.pushed_transactions().len(), 1);
}

/// A `finalize: first` request whose push the node did not take stops serve with its
/// transaction finalized but not posted. Once serve is back the wallet's retry pushes that same
/// transaction, once, and serve does not finalize the request again.
#[test]
fn a_first_request_stopped_between_finalize_and_post_is_pushed_once() {
    let (host, payer) = funded();
    let shop = new_wallet(&host, "shop password");
    let again = host.without_interrupt();
    let third = host.without_interrupt();
    let node = host.node.clone();
    let body = json!({
        "id": "8e3b0c5d-2f4a-4b6c-9d8e-0f1a2b3c4d5e",
        "kind": "invoice",
        "via": "in_person",
        "amount": "2",
        "finalize": "first",
    });
    node.fail_every("push_transaction", MockFailure::Unreachable);
    let (slate, kernel) = serving(host, &shop, |socket, client| {
        let made = request(socket, &body);
        let slate = text(&made, "id").to_owned();
        pay(&payer, client, "2", text(&made["handoff"], "text"));
        wait_until("serve finalizes the answer", || {
            payment(socket, &slate)["state"] == "finalized"
        });
        let finalized = payment(socket, &slate);
        assert_eq!(finalized["request"]["state"], "paid", "{finalized}");
        assert_eq!(
            finalized["request"]["reference"], finalized["check_code"],
            "{finalized}"
        );
        assert_eq!(
            finalized["post"]["last_outcome"], "unreachable",
            "{finalized}"
        );
        assert!(client.node.pushed_transactions().is_empty());
        (slate, text(&finalized, "kernel_excess").to_owned())
    });
    node.stop_failing("push_transaction");
    serving(again, &shop, |socket, client| {
        let stopped = payment(socket, &slate);
        assert_eq!(stopped["state"], "finalized", "{stopped}");
        assert_eq!(stopped["kernel_excess"], kernel.as_str(), "{stopped}");
        let next = stopped["post"]["next_attempt_height"].as_u64().unwrap();
        client
            .node
            .update_chain(|chain| chain.tip.height = Height::new(next));
        post(socket, "/api/v1/sync", &json!({})).ok();
        wait_until("the wallet pushes the transaction again", || {
            payment(socket, &slate)["state"] == "posted"
        });
        let posted = payment(socket, &slate);
        assert_eq!(posted["request"]["state"], "paid", "{posted}");
        assert_eq!(posted["post"]["last_outcome"], "accepted", "{posted}");
        assert_eq!(posted["kernel_excess"], kernel.as_str(), "{posted}");
    });
    let pushed = node.pushed_transactions();
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].kernels()[0].excess.to_hex(), kernel);
    serving(third, &shop, |socket, _| {
        let paid = payment(socket, &slate);
        assert_eq!(paid["request"]["state"], "paid", "{paid}");
        assert_eq!(paid["kernel_excess"], kernel.as_str(), "{paid}");
    });
    assert_eq!(node.pushed_transactions().len(), 1);
}

/// What an in-person request refuses: a TTL too short to pay in, a send, a recipient, the
/// request fields on another create, a direct route serve has no address for, and a node it
/// cannot reach. A cancel withdraws an open request.
#[test]
fn an_in_person_request_refuses_what_it_cannot_make() {
    let host = TestHost::new();
    let shop = new_wallet(&host, "shop password");
    serving(host, &shop, |socket, client| {
        let create = |body: Value| post(socket, "/api/v1/payments", &body);
        let invoice = |extra: Value| {
            let mut body = json!({ "kind": "invoice", "via": "in_person", "amount": "1" });
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            body
        };
        let refused = problem(
            &create(invoice(json!({ "ttl_blocks": 10 }))),
            400,
            "invalid_field",
        );
        assert_eq!(refused["param"], "/ttl_blocks", "{refused}");
        let refused = problem(
            &create(json!({ "via": "in_person", "amount": "1" })),
            400,
            "invalid_field",
        );
        assert_eq!(refused["param"], "/via", "{refused}");
        let refused = problem(
            &create(invoice(json!({ "to": "someone" }))),
            400,
            "invalid_field",
        );
        assert_eq!(refused["param"], "/to", "{refused}");
        let refused = problem(
            &create(invoice(json!({ "direct": true }))),
            400,
            "invalid_field",
        );
        assert_eq!(refused["param"], "/direct", "{refused}");
        let refused = problem(
            &create(invoice(json!({ "finalize": "later" }))),
            400,
            "invalid_field",
        );
        assert_eq!(refused["param"], "/finalize", "{refused}");
        for (field, value) in [("finalize", json!("first")), ("direct", json!(false))] {
            let mut body = json!({ "kind": "invoice", "via": "file", "amount": "1" });
            body[field] = value;
            let refused = problem(&create(body), 400, "invalid_field");
            assert_eq!(refused["param"], format!("/{field}"), "{refused}");
        }

        client.node.fail_every("get_tip", MockFailure::Unreachable);
        problem(&create(invoice(json!({}))), 503, "node_unreachable");
        client.node.stop_failing("get_tip");

        let made = request(socket, &invoice(json!({})));
        assert!(made["request"].get("link").is_some(), "{made}");
        let slate = text(&made, "id").to_owned();
        post(
            socket,
            &format!("/api/v1/payments/{slate}/cancel"),
            &json!({}),
        )
        .ok();
        let cancelled = payment(socket, &slate);
        assert_eq!(cancelled["request"]["state"], "refused", "{cancelled}");
        // No event of the cancel shows the request as expired.
        for kind in ["payment.state_changed", "payment.updated"] {
            for data in events_of(socket, kind, &slate) {
                assert_ne!(data["object"]["request"]["state"], "expired", "{data}");
            }
        }
        let changes = events_of(socket, "payment.state_changed", &slate);
        let last = changes.last().unwrap();
        assert_eq!(last["object"]["state"], "cancelled", "{last}");
        assert_eq!(last["object"]["request"]["state"], "refused", "{last}");
    });
}

/// A cancel that fails takes the shop's mark off the request again: a cancel made later
/// outside serve shows the request as expired, not refused by the shop.
#[test]
fn a_failed_cancel_leaves_the_request_unrefused() {
    let (host, payer) = funded();
    let shop = new_wallet(&host, "shop password");
    let later = host.without_interrupt();
    let node = host.node.clone();
    let body = json!({
        "kind": "invoice",
        "via": "in_person",
        "amount": "2",
        "finalize": "first",
    });
    node.fail_every("push_transaction", MockFailure::Unreachable);
    let slate = serving(host, &shop, |socket, client| {
        let made = request(socket, &body);
        let slate = text(&made, "id").to_owned();
        pay(&payer, client, "2", text(&made["handoff"], "text"));
        wait_until("serve finalizes the answer", || {
            payment(socket, &slate)["state"] == "finalized"
        });
        client
            .node
            .fail_every("get_unconfirmed_transactions", MockFailure::Unreachable);
        let failed = post(
            socket,
            &format!("/api/v1/payments/{slate}/cancel"),
            &json!({}),
        );
        assert_ne!(failed.status, 200, "{failed:?}");
        client.node.stop_failing("get_unconfirmed_transactions");
        let kept = payment(socket, &slate);
        assert_eq!(kept["state"], "finalized", "{kept}");
        assert_eq!(kept["request"]["state"], "paid", "{kept}");
        slate
    });
    let listed = shop.run(&later, &["tx", "list"]).ok().json();
    let tx_id = listed["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tx| tx["slate_id"] == slate.as_str())
        .map(|tx| tx["tx_id"].to_string())
        .unwrap();
    shop.run(&later, &["tx", "cancel", "--local-only", &tx_id])
        .ok();
    serving(later, &shop, |socket, _| {
        let ended = payment(socket, &slate);
        assert_eq!(ended["state"], "cancelled", "{ended}");
        assert_eq!(ended["request"]["state"], "expired", "{ended}");
    });
}

/// An answer posted to the direct route after the shop cancelled the request is refused with
/// the reason `cancelled`, and the request counts it.
#[test]
fn an_answer_to_a_cancelled_request_is_refused_as_cancelled() {
    let (host, payer) = funded();
    let shop = new_wallet(&host, "shop password");
    let extra = ["--http", "--port", "0", "--public-url", PUBLIC_URL];
    serving_with(host, &shop, &extra, |socket, client| {
        let status = http(socket, "GET", "/api/v1/status", None).ok();
        let port = u16::try_from(status["listeners"]["http"]["port"].as_u64().unwrap()).unwrap();
        let made = request(
            socket,
            &json!({ "kind": "invoice", "via": "in_person", "amount": "2" }),
        );
        let slate = text(&made, "id").to_owned();
        let paid = sealed(&payer, client, "2", text(&made["handoff"], "text"));
        let envelope = unhex(text(&paid, "envelope"));
        post(
            socket,
            &format!("/api/v1/payments/{slate}/cancel"),
            &json!({}),
        )
        .ok();
        // A sync runs the wallet's upkeep, which forgets the codes of ended requests.
        post(socket, "/api/v1/sync", &json!({})).ok();
        let status = to_inbox(port, &envelope);
        assert!(!status.starts_with("HTTP/1.1 200"), "{status}");
        wait_until("the request counts the refusal", || {
            payment(socket, &slate)["request"]["answers_refused"] == 1
        });
        let refused = payment(socket, &slate);
        assert_eq!(refused["request"]["state"], "refused", "{refused}");
        assert_eq!(refused["request"]["last_refusal"], "cancelled", "{refused}");
    });
}

/// The bytes the hex digits `hex` spell.
fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

/// Posts `body` to the inbox of the web listener at `port`: the status line.
fn to_inbox(port: u16, body: &[u8]) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "POST /api/v1/inbox HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {ENVELOPE}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut answer = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut answer).unwrap();
    String::from_utf8_lossy(&answer)
        .lines()
        .next()
        .unwrap()
        .to_owned()
}

/// With a public address, a request names serve's direct route and the web listener's inbox
/// takes the payer's answer; an answer taken before is taken again.
#[test]
fn the_web_listener_takes_an_answer_posted_to_the_direct_route() {
    let (host, payer) = funded();
    let shop = new_wallet(&host, "shop password");
    let extra = ["--http", "--port", "0", "--public-url", PUBLIC_URL];
    serving_with(host, &shop, &extra, |socket, client| {
        let status = http(socket, "GET", "/api/v1/status", None).ok();
        let port = u16::try_from(status["listeners"]["http"]["port"].as_u64().unwrap()).unwrap();
        let made = request(
            socket,
            &json!({ "kind": "invoice", "via": "in_person", "amount": "2" }),
        );
        let slate = text(&made, "id").to_owned();
        let paid = sealed(&payer, client, "2", text(&made["handoff"], "text"));
        let envelope = unhex(text(&paid, "envelope"));
        for _ in 0..2 {
            let status = to_inbox(port, &envelope);
            assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        }
        wait_until("the answer shows", || answers(socket, &slate) == 1);
        let status = to_inbox(port, b"not an envelope");
        assert!(!status.starts_with("HTTP/1.1 200"), "{status}");
        assert_eq!(answers(socket, &slate), 1);
    });
}

/// Serve refuses at startup a public address every payer refuses, from the option or from
/// `LEPIC_SERVE_PUBLIC_URL`.
#[test]
fn serve_refuses_a_public_address_payers_refuse() {
    let mut host = TestHost::new();
    let shop = new_wallet(&host, "shop password");
    // Should serve start after all, it stops at once.
    host.interrupt_when = Some(Arc::new(|| true));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket = socket.to_str().unwrap();
    let flag = shop.run(
        &host,
        &[
            "serve",
            "--socket",
            socket,
            "--public-url",
            "https://localhost",
        ],
    );
    assert_ne!(flag.code, 0, "{flag:?}");
    assert!(flag.stdout.contains("--public-url"), "{flag:?}");
    let mut env = shop.env();
    env.push((
        "LEPIC_SERVE_PUBLIC_URL".to_owned(),
        format!("{PUBLIC_URL},https://192.168.1.20"),
    ));
    let variable = shop.run_with(&host, &["serve", "--socket", socket], env, "");
    assert_ne!(variable.code, 0, "{variable:?}");
    assert!(variable.stdout.contains("192.168.1.20"), "{variable:?}");
}

/// A second payer on the funded phrase: two answers to one code.
fn second_payer(host: &TestHost) -> Instance {
    let payer = Instance::new("second payer password");
    payer.restore(host, support::SENDER_MNEMONIC);
    payer
}

/// The id and check code of each answer of the payment `id`, in the order they came.
fn answer_codes(socket: &Path, id: &str) -> Vec<(String, String)> {
    payment(socket, id)["answers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|answer| {
            (
                text(answer, "id").to_owned(),
                text(answer, "check_code").to_owned(),
            )
        })
        .collect()
}

/// The answer the wallet finalized is the request's answer. A post that failed before the
/// wallet finalized it names nothing; once another answer is finalized a post of the first is
/// refused and changes nothing, and a post of the finalized one is answered as it is.
#[test]
fn a_request_names_only_the_answer_the_wallet_finalized() {
    let (host, payer) = funded();
    let other = second_payer(&host);
    let shop = new_wallet(&host, "shop password");
    let body = json!({ "kind": "invoice", "via": "in_person", "amount": "2" });
    serving(host, &shop, |socket, client| {
        let made = request(socket, &body);
        let slate = text(&made, "id").to_owned();
        let code = text(&made["handoff"], "text").to_owned();
        let path = format!("/api/v1/payments/{slate}/post");
        pay(&payer, client, "2", &code);
        pay(&other, client, "2", &code);
        wait_until("both answers show", || answers(socket, &slate) == 2);
        let codes = answer_codes(socket, &slate);
        let ((first, first_code), (second, second_code)) = (&codes[0], &codes[1]);
        assert_ne!(first_code, second_code, "{codes:?}");

        client.node.fail_every("get_tip", MockFailure::Unreachable);
        let failed = post(socket, &path, &json!({ "answer": first }));
        assert_ne!(failed.status, 200, "{failed:?}");
        client.node.stop_failing("get_tip");
        let open = payment(socket, &slate);
        assert_eq!(open["request"]["state"], "open", "{open}");
        assert!(open["request"]["reference"].is_null(), "{open}");

        let paid = post(socket, &path, &json!({ "answer": second })).ok();
        assert_eq!(paid["request"]["state"], "paid", "{paid}");
        assert_eq!(paid["request"]["reference"], second_code.as_str(), "{paid}");
        assert_eq!(client.node.pushed_transactions().len(), 1);

        let refused = problem(
            &post(socket, &path, &json!({ "answer": first })),
            409,
            "invoice_already_paid",
        );
        assert_eq!(refused["payment_id"], slate.as_str(), "{refused}");
        let kept = payment(socket, &slate);
        assert_eq!(kept["request"]["reference"], second_code.as_str(), "{kept}");
        assert_eq!(kept["check_code"], second_code.as_str(), "{kept}");

        let repeated = post(socket, &path, &json!({ "answer": second })).ok();
        assert_eq!(
            repeated["request"]["reference"],
            second_code.as_str(),
            "{repeated}"
        );
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

/// Serve stopped after it noted the answer it was about to finalize and before the wallet
/// finalized it, as a kill at that point leaves the wallet: both answers taken, the attempt
/// noted, nothing finalized. Once serve is back it finalizes that answer, once, across
/// restarts.
#[test]
fn a_first_request_stopped_before_the_wallet_finalized_is_finalized_once() {
    let (host, payer) = funded();
    let other = second_payer(&host);
    let shop = Instance::new("shop password");
    let created = shop.run(&host, &["wallet", "init"]).ok().json();
    let phrase = text(&created, "recovery_phrase").to_owned();
    let paying = host.without_interrupt();
    let again = host.without_interrupt();
    let third = host.without_interrupt();
    let node = host.node.clone();
    let body = json!({
        "id": "9f4c1d6e-3a5b-4c7d-8e9f-1a2b3c4d5e6f",
        "kind": "invoice",
        "via": "in_person",
        "amount": "2",
        "finalize": "first",
    });
    let made = serving(host, &shop, |socket, _| request(socket, &body));
    let slate = text(&made, "id").to_owned();
    let code = text(&made["handoff"], "text");
    let taken: Vec<Value> = [&payer, &other]
        .into_iter()
        .map(|payer| {
            let paid = sealed(payer, &paying, "2", code);
            shop.run(&paying, &["in-person", "take", text(&paid, "envelope")])
                .ok()
                .json()
        })
        .collect();
    // The later answer: serve alone would pick the first.
    let attempt = taken[1]["answer"].as_u64().unwrap();
    let check_code = text(&taken[1], "check_code").to_owned();
    assert_ne!(taken[0]["answer"], taken[1]["answer"], "{taken:?}");
    support::with_settings(&shop, &phrase, |repos| {
        let key = format!("api.request.note.{slate}");
        let mut note: Value = serde_json::from_str(&repos.setting(&key)?.unwrap()).unwrap();
        note["attempt"] = json!(attempt);
        repos.put_setting(&key, &note.to_string())
    });
    assert!(node.pushed_transactions().is_empty());
    serving(again, &shop, |socket, _| {
        wait_until("serve finalizes the noted answer", || {
            payment(socket, &slate)["request"]["state"] == "paid"
        });
        let paid = payment(socket, &slate);
        assert_eq!(paid["request"]["reference"], check_code.as_str(), "{paid}");
    });
    assert_eq!(node.pushed_transactions().len(), 1);
    serving(third, &shop, |socket, _| {
        let paid = payment(socket, &slate);
        assert_eq!(paid["request"]["state"], "paid", "{paid}");
        assert_eq!(paid["request"]["reference"], check_code.as_str(), "{paid}");
    });
    assert_eq!(node.pushed_transactions().len(), 1);
}

/// One answer arriving by the mailbox slot and by the direct route at once is one answer,
/// finalized and pushed once.
#[test]
fn a_first_request_answered_by_both_routes_at_once_is_finalized_once() {
    let (host, payer) = funded();
    let shop = new_wallet(&host, "shop password");
    let extra = ["--http", "--port", "0", "--public-url", PUBLIC_URL];
    serving_with(host, &shop, &extra, |socket, client| {
        let status = http(socket, "GET", "/api/v1/status", None).ok();
        let port = u16::try_from(status["listeners"]["http"]["port"].as_u64().unwrap()).unwrap();
        let made = request(
            socket,
            &json!({ "kind": "invoice", "via": "in_person", "amount": "2", "finalize": "first" }),
        );
        let slate = text(&made, "id").to_owned();
        let paid = sealed(&payer, client, "2", text(&made["handoff"], "text"));
        let envelope = unhex(text(&paid, "envelope"));
        std::thread::scope(|scope| {
            let slot = scope.spawn(|| {
                payer
                    .run(client, &["in-person", "post", text(&paid, "slate_id")])
                    .ok()
                    .json()
            });
            let direct = scope.spawn(|| to_inbox(port, &envelope));
            let status = direct.join().unwrap();
            assert!(status.starts_with("HTTP/1.1 200"), "{status}");
            let posted = slot.join().unwrap();
            assert_eq!(posted["posted"], true, "{posted}");
        });
        wait_until("serve finalizes the answer", || {
            payment(socket, &slate)["state"] == "posted"
        });
        let done = payment(socket, &slate);
        assert_eq!(done["request"]["state"], "paid", "{done}");
        assert_eq!(done["answers"].as_array().unwrap().len(), 1, "{done}");
        assert_eq!(
            done["request"]["reference"], done["answers"][0]["check_code"],
            "{done}"
        );
        assert_eq!(done["post"]["attempts"], 1, "{done}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

/// A request whose TTL passes while its payment waits says so once, by `payment.state_changed`.
#[test]
fn a_request_past_its_ttl_says_so_once() {
    let host = TestHost::new();
    let shop = new_wallet(&host, "shop password");
    serving(host, &shop, |socket, client| {
        let made = request(
            socket,
            &json!({ "kind": "invoice", "via": "in_person", "amount": "1" }),
        );
        let slate = text(&made, "id").to_owned();
        let cutoff = made["expires_at_height"].as_u64().unwrap();
        let expired = |socket: &Path| {
            events_of(socket, "payment.state_changed", &slate)
                .into_iter()
                .filter(|data| data["object"]["request"]["state"] == "expired")
                .count()
        };
        // The first sync after a move holds the new tip, the next confirms it.
        let confirm = |height: u64| {
            client
                .node
                .update_chain(|chain| chain.tip.height = Height::new(height));
            post(socket, "/api/v1/sync", &json!({})).ok();
            let synced = post(socket, "/api/v1/sync", &json!({})).ok();
            assert_eq!(synced["height"], height, "{synced}");
        };
        confirm(cutoff - 1);
        assert_eq!(payment(socket, &slate)["request"]["state"], "open");
        confirm(cutoff);
        wait_until("the request says it expired", || expired(socket) == 1);
        assert_eq!(payment(socket, &slate)["request"]["state"], "expired");
        confirm(cutoff + 1);
        // The driver looks at the new tip on its own time: give it that time.
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(expired(socket), 1);
    });
}
