// SPDX-License-Identifier: Apache-2.0
//! The payment calls of the wallet API v1: create, read, list, approve, cancel, hand off,
//! inspect and open. Every answer is checked against `docs/api/openapi.json` by
//! `support::http`.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lepic_cli::app_config::ApiLimits;
use lepic_node::LocatedKernel;
use lepic_node::mock::{ChainOutput, MockFailure, MockNode};
use lepic_primitives::amount::Height;
use lepic_primitives::tx::Transaction;
use serde_json::{Value, json};
use support::{
    FUNDING, Instance, PATIENCE, SENDER_MNEMONIC, TestHost, funded, http, new_wallet, problem,
    serving, serving_with_env, text, wait_until, with_settings,
};

/// The amount a Decimal string names, in EPIC.
fn epic(decimal: &Value) -> f64 {
    decimal.as_str().unwrap().parse().unwrap()
}

fn post(socket: &Path, path: &str, body: &Value) -> support::Reply {
    http(socket, "POST", path, Some(&body.to_string()))
}

/// A wallet created from new entropy, and its Epicbox address.
fn receiver(host: &TestHost) -> (Instance, String) {
    let receiver = new_wallet(host, "receiver password");
    let address = receiver.run(host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();
    (receiver, address)
}

/// Every payment id `query` lists, read one page of one at a time.
fn page_through(socket: &Path, query: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(cursor) => format!("/api/v1/payments?{query}&limit=1&cursor={cursor}"),
            None => format!("/api/v1/payments?{query}&limit=1"),
        };
        let page = http(socket, "GET", &path, None).ok();
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 1, "{page}");
        ids.extend(items.iter().map(|item| text(item, "id").to_owned()));
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return ids,
        }
        assert!(ids.len() < 50, "the cursor never ends: {ids:?}");
    }
}

/// The payments listed with filters, newest first, and paged one at a time: `newest` is a send
/// by hand, `oldest` a send over epicbox that is posted.
fn check_listing(socket: &Path, newest: &str, oldest: &str) {
    let sends = http(
        socket,
        "GET",
        "/api/v1/payments?kind=send&direction=out",
        None,
    )
    .ok();
    let listed: Vec<&str> = sends["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| text(item, "id"))
        .collect();
    assert_eq!(listed, [newest, oldest], "{sends}");
    let posted = http(
        socket,
        "GET",
        "/api/v1/payments?state=posted&via=epicbox",
        None,
    )
    .ok();
    assert_eq!(posted["items"].as_array().unwrap().len(), 1, "{posted}");
    assert_eq!(posted["items"][0]["id"], oldest, "{posted}");
    let incoming = http(
        socket,
        "GET",
        "/api/v1/payments?direction=in&kind=send",
        None,
    )
    .ok();
    assert_eq!(incoming["items"], json!([]), "{incoming}");

    let everything = http(socket, "GET", "/api/v1/payments", None).ok();
    let mut all: Vec<String> = everything["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| text(item, "id").to_owned())
        .collect();
    assert_eq!(
        page_through(socket, "direction=out"),
        [newest.to_owned(), oldest.to_owned()]
    );
    let mut paged = page_through(socket, "kind=send");
    paged.extend(page_through(socket, "kind=invoice"));
    paged.extend(page_through(socket, "kind=coinbase"));
    paged.extend(page_through(socket, "kind=unknown"));
    paged.sort();
    all.sort();
    assert_eq!(paged, all, "{everything}");
}

#[test]
fn a_send_to_another_wallet_is_created_once_read_back_and_listed() {
    // Two coins: the first send locks one, the second send spends the other.
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    host.fund(SENDER_MNEMONIC, 1, FUNDING, 2);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let (receiver, address) = receiver(&host);
    let id = "5b0e2f6a-3c1d-4e8f-9a7b-2d4c6e8f0a1b";
    let body = json!({ "id": id, "amount": "1", "to": address, "message": "rent" });

    serving(host, &wallet, |socket, client| {
        let created = post(socket, "/api/v1/payments", &body);
        assert_eq!(created.status, 201, "{created:?}");
        let created = created.json();
        assert_eq!(created["id"], id, "{created}");
        assert_eq!(created["kind"], "send", "{created}");
        assert_eq!(created["direction"], "out", "{created}");
        assert_eq!(created["via"], "epicbox", "{created}");
        assert_eq!(epic(&created["amount"]), 1.0, "{created}");
        assert_eq!(created["state"], "awaiting_answer", "{created}");

        let repeated = post(socket, "/api/v1/payments", &body).ok();
        assert_eq!(repeated["id"], id, "{repeated}");
        let changed = json!({ "id": id, "amount": "2", "to": address, "message": "rent" });
        problem(
            &post(socket, "/api/v1/payments", &changed),
            409,
            "idempotency_mismatch",
        );

        let drained = receiver.run(client, &["epicbox", "drain"]).ok().json();
        assert_eq!(drained["received"], 1, "{drained}");
        let path = format!("/api/v1/payments/{id}");
        wait_until("the answer is collected and posted", || {
            http(socket, "GET", &path, None).ok()["state"] == "posted"
        });
        assert_eq!(client.node.pushed_transactions().len(), 1);
        let read = http(socket, "GET", &path, None).ok();
        assert_eq!(read["message"], "rent", "{read}");
        assert!(
            read["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|each| each == "post"),
            "{read}"
        );

        let patched = http(
            socket,
            "PATCH",
            &path,
            Some(&json!({ "metadata": { "order": "42" } }).to_string()),
        )
        .ok();
        assert_eq!(patched["metadata"]["order"], "42", "{patched}");

        let by_hand = json!({ "amount": "0.5", "via": "file" });
        let second = post(socket, "/api/v1/payments", &by_hand);
        assert_eq!(second.status, 201, "{second:?}");
        let second = text(&second.json(), "id").to_owned();

        check_listing(socket, &second, id);

        problem(
            &http(socket, "GET", "/api/v1/payments?state=lost", None),
            400,
            "invalid_field",
        );
    });
}

#[test]
fn an_invoice_opened_here_waits_for_approval_and_is_paid_on_the_retyped_amount() {
    let (host, wallet) = funded();
    let issuer = new_wallet(&host, "issuer password");
    let file = issuer.path("invoice.slate");
    let issued = issuer
        .run(
            &host,
            &["invoice", "issue", "3", "--to-file", file.to_str().unwrap()],
        )
        .ok()
        .json();
    let slate_id = text(&issued, "slate_id").to_owned();
    let invoice = std::fs::read_to_string(&file).unwrap();

    serving(host, &wallet, |socket, client| {
        let inspected = post(socket, "/api/v1/inspect", &json!({ "text": invoice })).ok();
        assert_eq!(inspected["type"], "slate_invoice", "{inspected}");
        assert_eq!(epic(&inspected["summary"]["amount"]), 3.0, "{inspected}");

        problem(
            &post(
                socket,
                "/api/v1/open",
                &json!({ "text": invoice, "expect": ["slate_send"] }),
            ),
            422,
            "unexpected_input",
        );
        let opened = post(socket, "/api/v1/open", &json!({ "text": invoice })).ok();
        assert_eq!(opened["outcome"], "invoice_parked", "{opened}");
        let parked = &opened["payment"];
        assert_eq!(parked["id"], slate_id.as_str(), "{opened}");
        assert_eq!(parked["state"], "needs_approval", "{opened}");
        assert_eq!(parked["actions"], json!(["approve", "decline"]), "{opened}");
        assert!(client.node.pushed_transactions().is_empty());
        let again = post(socket, "/api/v1/open", &json!({ "text": invoice })).ok();
        assert_eq!(again["outcome"], "already_done", "{again}");

        let held = http(socket, "GET", "/api/v1/payments?state=needs_approval", None).ok();
        assert_eq!(held["items"][0]["id"], slate_id.as_str(), "{held}");

        let approve = format!("/api/v1/payments/{slate_id}/approve");
        let wrong = problem(
            &post(socket, &approve, &json!({ "amount": "2" })),
            400,
            "invalid_field",
        );
        assert_eq!(wrong["param"], "/amount", "{wrong}");
        let paid = post(socket, &approve, &json!({ "amount": "3" })).ok();
        assert_eq!(paid["id"], slate_id.as_str(), "{paid}");
        assert_eq!(paid["direction"], "out", "{paid}");
        assert_ne!(paid["state"], "needs_approval", "{paid}");
        let answer = text(&paid["handoff"], "text").to_owned();

        problem(
            &post(
                socket,
                &format!("/api/v1/payments/{slate_id}/decline"),
                &json!({}),
            ),
            409,
            "action_not_available",
        );

        let reply = issuer.path("invoice.slate.response");
        std::fs::write(&reply, answer).unwrap();
        let finalized = issuer
            .run(client, &["tx", "finalize", reply.to_str().unwrap()])
            .ok()
            .json();
        assert_eq!(finalized["state"], "posted", "{finalized}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

#[test]
fn a_slate_handed_here_is_received_and_its_answer_handed_back() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let wallet = new_wallet(&host, "serving password");
    let slate = payer.path("payment.slate");
    let sent = payer
        .run(
            &host,
            &["tx", "send", "1.5", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let slate_text = std::fs::read_to_string(&slate).unwrap();

    serving(host, &wallet, |socket, client| {
        let inspected = post(socket, "/api/v1/inspect", &json!({ "text": slate_text })).ok();
        assert_eq!(inspected["type"], "slate_send", "{inspected}");
        assert_eq!(inspected["next"], "open", "{inspected}");
        assert!(inspected.get("payment_id").is_none(), "{inspected}");

        let opened = post(socket, "/api/v1/open", &json!({ "text": slate_text })).ok();
        assert_eq!(opened["outcome"], "received", "{opened}");
        assert_eq!(opened["payment"]["id"], sent["slate_id"], "{opened}");
        assert_eq!(opened["payment"]["direction"], "in", "{opened}");
        assert_eq!(epic(&opened["payment"]["amount"]), 1.5, "{opened}");
        assert_eq!(opened["handoff"]["format"], "slate", "{opened}");
        let answer = text(&opened["handoff"], "text").to_owned();
        assert!(
            serde_json::from_str::<serde_json::Value>(&answer).is_ok(),
            "the answer is a plain slate: {answer}"
        );

        let again = post(socket, "/api/v1/open", &json!({ "text": slate_text })).ok();
        assert_eq!(again["outcome"], "already_done", "{again}");
        let inspected = post(socket, "/api/v1/inspect", &json!({ "text": slate_text })).ok();
        assert_eq!(inspected["payment_id"], sent["slate_id"], "{inspected}");

        let reply = payer.path("payment.slate.response");
        std::fs::write(&reply, answer).unwrap();
        let finalized = payer
            .run(client, &["tx", "finalize", reply.to_str().unwrap()])
            .ok()
            .json();
        assert_eq!(finalized["state"], "posted", "{finalized}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

#[test]
fn a_cancelled_send_frees_its_coins_and_its_handoff_comes_in_each_form() {
    let (host, wallet) = funded();

    serving(host, &wallet, |socket, _| {
        let estimate = |amount: &str| {
            post(
                socket,
                "/api/v1/payments/estimate",
                &json!({ "amount": amount }),
            )
        };
        let before = estimate("max").ok();
        let max = epic(&before["max_amount"]);
        assert!(max > 9.0 && max < 10.0, "{before}");
        assert_eq!(before["outputs"].as_array().unwrap().len(), 1, "{before}");
        let max_send = problem(
            &post(
                socket,
                "/api/v1/payments",
                &json!({ "amount": "max", "via": "file" }),
            ),
            400,
            "invalid_field",
        );
        assert_eq!(max_send["param"], "/amount", "{max_send}");
        problem(
            &post(
                socket,
                "/api/v1/payments",
                &json!({ "amount": "100", "via": "file" }),
            ),
            422,
            "insufficient_funds",
        );

        let created = post(
            socket,
            "/api/v1/payments",
            &json!({ "amount": "1", "deliver": false }),
        );
        assert_eq!(created.status, 201, "{created:?}");
        let created = created.json();
        let id = text(&created, "id").to_owned();
        assert_eq!(created["state"], "awaiting_answer", "{created}");
        assert_eq!(created["handoff"]["format"], "slate", "{created}");
        assert_eq!(created["delivery"]["state"], "by_hand", "{created}");
        problem(&estimate("1"), 422, "insufficient_funds");

        let handoff = format!("/api/v1/payments/{id}/handoff");
        let plain = http(socket, "GET", &handoff, None).ok();
        assert_eq!(plain["format"], "slate", "{plain}");
        assert_eq!(plain["text"], created["handoff"]["text"], "{plain}");
        assert!(plain.get("qr_frames").is_none(), "{plain}");
        let qr = http(socket, "GET", &format!("{handoff}?qr=true"), None).ok();
        let frames = qr["qr_frames"].clone();
        assert!(!frames.as_array().unwrap().is_empty(), "{qr}");
        let other = problem(
            &http(socket, "GET", &format!("{handoff}?format=epictx"), None),
            409,
            "format_not_available",
        );
        assert_eq!(other["param"], "/format", "{other}");
        problem(
            &http(socket, "GET", &format!("{handoff}?format=card"), None),
            400,
            "invalid_field",
        );
        let scanned = post(socket, "/api/v1/inspect", &json!({ "qr_frames": frames })).ok();
        assert_eq!(scanned["type"], "slate_send", "{scanned}");
        assert_eq!(scanned["payment_id"], id.as_str(), "{scanned}");

        let cancel = format!("/api/v1/payments/{id}/cancel");
        let cancelled = http(socket, "POST", &cancel, None).ok();
        assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
        assert_eq!(cancelled["actions"], json!([]), "{cancelled}");
        let again = http(socket, "POST", &cancel, None).ok();
        assert_eq!(again, cancelled);
        problem(
            &post(socket, &format!("/api/v1/payments/{id}/post"), &json!({})),
            409,
            "action_not_available",
        );
        let after = estimate("max").ok();
        assert_eq!(after["max_amount"], before["max_amount"], "{after}");

        let unknown = "00000000-0000-4000-8000-000000000000";
        for (method, path) in [
            ("GET", format!("/api/v1/payments/{unknown}")),
            ("GET", format!("/api/v1/payments/{unknown}/handoff")),
            ("POST", format!("/api/v1/payments/{unknown}/cancel")),
        ] {
            problem(&http(socket, method, &path, None), 404, "not_found");
        }
    });
}

/// Sends 1 EPIC over the mock relay, at relay version `version`, to a new wallet that never
/// answers; cancels it through the API twice. Returns both answers and the cancels the relay
/// was sent.
fn cancel_a_sent_payment(version: &str) -> (Value, Value, usize) {
    let (host, wallet) = funded();
    host.relay.set_version(Some(version));
    let (_receiver, address) = receiver(&host);
    let body = json!({ "amount": "1", "to": address });
    serving(host, &wallet, |socket, client| {
        let created = post(socket, "/api/v1/payments", &body);
        assert_eq!(created.status, 201, "{created:?}");
        let created = created.json();
        assert_eq!(created["via"], "epicbox", "{created}");
        assert_eq!(created["state"], "awaiting_answer", "{created}");
        let cancel = format!("/api/v1/payments/{}/cancel", text(&created, "id"));
        let cancelled = http(socket, "POST", &cancel, None).ok();
        let again = http(socket, "POST", &cancel, None).ok();
        (cancelled, again, client.relay.received("CancelTx"))
    })
}

fn keys(answer: &Value) -> Vec<&String> {
    answer.as_object().unwrap().keys().collect()
}

#[test]
fn a_cancelled_send_is_cancelled_on_its_relay_once() {
    let (cancelled, again, cancels) = cancel_a_sent_payment("3.1.0");
    assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
    assert_eq!(cancelled["actions"], json!([]), "{cancelled}");
    assert_eq!(again, cancelled);
    assert_eq!(cancels, 1, "one cancel, none for the repeat");
}

#[test]
fn a_cancelled_send_on_a_relay_without_cancel_answers_the_same() {
    let (cancelled, again, cancels) = cancel_a_sent_payment("3.0.0");
    assert_eq!(cancels, 0);
    assert_eq!(again, cancelled);
    let (with_cancel, _, _) = cancel_a_sent_payment("3.1.0");
    assert_eq!(cancelled["state"], with_cancel["state"], "{cancelled}");
    assert_eq!(cancelled["actions"], with_cancel["actions"], "{cancelled}");
    assert_eq!(keys(&cancelled), keys(&with_cancel), "{cancelled}");
}

#[test]
fn inspect_names_each_kind_it_reads_and_changes_nothing() {
    let (host, wallet) = funded();
    let address = wallet.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();
    let onion = "http://pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

    serving(host, &wallet, |socket, _| {
        // Confirmations follow the refreshed tip, so the comparison leaves them out.
        let payments = || -> Vec<(String, String, String)> {
            let list = http(socket, "GET", "/api/v1/payments", None).ok();
            list["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    (
                        text(item, "id").to_owned(),
                        text(item, "state").to_owned(),
                        text(item, "updated_at").to_owned(),
                    )
                })
                .collect()
        };
        let before = payments();
        assert!(!before.is_empty());
        let key = address.split_once('@').map_or("", |(key, _)| key);
        let relay_address = format!("{key}@epicbox.example.org");
        let linked = format!("https://{relay_address}/");
        let cases = [
            (address.as_str(), "epicbox_address", "pay"),
            ("http://203.0.113.7:3415", "http_address", "pay"),
            (linked.as_str(), "epicbox_address", "pay"),
            (onion, "onion_address", "pay"),
            ("epic:pay?amount=1", "link", "pay"),
            ("hello there", "unknown", "none"),
            ("{\"not\":\"a slate\"}", "unknown", "none"),
        ];
        for (input, kind, next) in cases {
            let read = post(socket, "/api/v1/inspect", &json!({ "text": input })).ok();
            assert_eq!(read["type"], kind, "{input}: {read}");
            assert_eq!(read["next"], next, "{input}: {read}");
            if next == "pay" {
                let to = if input == linked {
                    relay_address.as_str()
                } else {
                    input
                };
                assert_eq!(read["summary"]["to"], to, "{read}");
            }
        }

        let terms = post(
            socket,
            "/api/v1/inspect",
            &json!({ "text": format!("epic:{address}?amount=1.5&message=for%20tea") }),
        )
        .ok();
        assert_eq!(terms["summary"]["amount"], "1.50000000", "{terms}");
        assert_eq!(terms["summary"]["message"], "for tea", "{terms}");

        let base64 = STANDARD.encode(&address);
        let file = post(socket, "/api/v1/inspect", &json!({ "file_base64": base64 })).ok();
        assert_eq!(file["type"], "epicbox_address", "{file}");

        let both = json!({ "text": address, "file_base64": base64 });
        problem(
            &post(socket, "/api/v1/inspect", &both),
            400,
            "invalid_request",
        );
        let bad = problem(
            &post(socket, "/api/v1/inspect", &json!({ "file_base64": "%%%" })),
            400,
            "invalid_field",
        );
        assert_eq!(bad["param"], "/file_base64", "{bad}");

        assert_eq!(payments(), before);
        problem(
            &post(socket, "/api/v1/open", &json!({ "text": address })),
            409,
            "nothing_to_open",
        );
    });
}

/// The `payment.created` events listed so far.
fn created_events(socket: &Path) -> usize {
    let listed = http(socket, "GET", "/api/v1/events?types=payment.created", None).ok();
    listed["items"].as_array().unwrap().len()
}

/// A send by hand, without an id: its id.
fn send_by_hand(socket: &Path) -> String {
    let sent = post(
        socket,
        "/api/v1/payments",
        &json!({ "amount": "1", "via": "file" }),
    );
    assert_eq!(sent.status, 201, "{sent:?}");
    text(&sent.json(), "id").to_owned()
}

#[test]
fn an_invoice_with_the_id_of_a_payment_is_refused_and_leaves_it_alone() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let id = send_by_hand(socket);
        let path = format!("/api/v1/payments/{id}");
        let max = |socket: &Path| {
            post(
                socket,
                "/api/v1/payments/estimate",
                &json!({ "amount": "max" }),
            )
            .json()
        };
        let before = max(socket);
        let body = json!({ "id": id, "kind": "invoice", "amount": "2", "via": "file" });
        let refused = problem(
            &post(socket, "/api/v1/payments", &body),
            409,
            "idempotency_mismatch",
        );
        assert_eq!(refused["param"], "/id", "{refused}");
        // No record was left: the refusal is the same again.
        problem(
            &post(socket, "/api/v1/payments", &body),
            409,
            "idempotency_mismatch",
        );

        let read = http(socket, "GET", &path, None).ok();
        assert_eq!(read["id"], id, "{read}");
        assert_eq!(read["kind"], "send", "{read}");
        let cancelled = post(socket, &format!("{path}/cancel"), &json!({})).ok();
        assert_eq!(cancelled["id"], id, "{cancelled}");
        assert_eq!(cancelled["kind"], "send", "{cancelled}");
        assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
        assert_ne!(max(socket), before, "the send's coins are free again");
    });
}

#[test]
fn a_send_with_the_id_of_a_payment_is_not_created_again() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let id = send_by_hand(socket);
        let events = created_events(socket);
        let body = json!({ "id": id, "amount": "100", "via": "file" });
        let reply = post(socket, "/api/v1/payments", &body);
        assert_eq!(reply.status, 409, "{reply:?}");
        assert_eq!(created_events(socket), events);
        let read = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
        assert_eq!(read["amount"], "1.00000000", "{read}");
    });
}

#[test]
fn an_invoice_with_a_caller_id_is_read_by_either_id() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let caller = "7c1e9a3b-2d4f-4a6b-8c0d-1e2f3a4b5c6d";
        let body = json!({ "id": caller, "kind": "invoice", "amount": "2", "via": "file" });
        let created = post(socket, "/api/v1/payments", &body);
        assert_eq!(created.status, 201, "{created:?}");
        let made = text(&created.json(), "id").to_owned();
        let repeated = post(socket, "/api/v1/payments", &body);
        assert_eq!(repeated.status, 200, "{repeated:?}");
        assert_eq!(repeated.json()["id"], made.as_str());
        for id in [caller, made.as_str()] {
            let path = format!("/api/v1/payments/{id}");
            let read = http(socket, "GET", &path, None).ok();
            assert_eq!(read["id"], made.as_str(), "{read}");
            let handoff = http(socket, "GET", &format!("{path}/handoff"), None);
            assert_eq!(handoff.status, 200, "{handoff:?}");
        }
        let cancelled = post(
            socket,
            &format!("/api/v1/payments/{caller}/cancel"),
            &json!({}),
        )
        .ok();
        assert_eq!(cancelled["id"], made.as_str(), "{cancelled}");
        assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
    });
}

#[test]
fn an_invoice_carries_its_ttl_and_message() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let body = json!({
            "kind": "invoice", "amount": "2", "via": "file",
            "ttl_blocks": 30, "message": "order 42",
        });
        let made = post(socket, "/api/v1/payments", &body);
        assert_eq!(made.status, 201, "{made:?}");
        let made = made.json();
        assert_eq!(made["message"], "order 42", "{made}");
        assert_eq!(made["expires_at_height"], support::TIP + 30, "{made}");
    });
}

/// A message over 256 bytes, or with a control, line-break or invisible formatting character, is
/// refused where it is taken, not cut or stripped.
#[test]
fn a_message_that_would_be_cut_is_refused() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let id = "6f1c1e0e-8f60-4d0c-9a53-0f4f1a1f6a10";
        let long = "x".repeat(257);
        let paths = [
            (
                "/api/v1/payments",
                json!({ "amount": "1", "to": "contact:1" }),
            ),
            (
                "/api/v1/payments/estimate",
                json!({ "amount": "1", "to": "a@b.example" }),
            ),
            (
                &format!("/api/v1/payments/{id}/approve"),
                json!({ "amount": "1" }),
            ),
            ("/api/v1/open", json!({ "text": "x" })),
        ];
        for (path, body) in paths {
            for bad in [
                long.as_str(),
                "two\nlines",
                "tab\there",
                "bell\u{7}",
                "flip\u{202E}ed",
                "zero\u{200B}width",
            ] {
                let mut body = body.clone();
                body["message"] = json!(bad);
                let reply = post(socket, path, &body);
                assert_eq!(reply.status, 400, "{path} {bad:?}: {reply:?}");
                let problem = reply.json();
                assert_eq!(problem["code"], "invalid_field", "{path}: {problem}");
                assert_eq!(problem["param"], "/message", "{path}: {problem}");
            }
        }
        // The longest text that fits, and plain text with a space, pass the check: the answer is
        // some other refusal, not one about the message.
        for fine in ["x".repeat(256), "a plain note, with é and 日本".to_owned()] {
            let body = json!({ "amount": "1", "to": "a@b.example", "message": fine });
            let reply = post(socket, "/api/v1/payments/estimate", &body);
            assert_ne!(reply.json()["param"], "/message", "{reply:?}");
        }
    });
}

#[test]
fn a_classic_epic_link_is_paid_to_its_address_at_the_amount_in_the_body_else_its_own() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let to = "epic:abc@epicbox.example?amount=1&message=tea";
        // The amount in the body wins over the link's; leaving it out takes the link's. Each
        // passes the amount check and goes on to the send, which refuses this made-up address.
        for body in [
            json!({ "to": to }),
            json!({ "to": to, "amount": "1.0" }),
            json!({ "to": to, "amount": "2" }),
        ] {
            let reply = post(socket, "/api/v1/payments", &body);
            assert_ne!(reply.json()["param"], "/amount", "{reply:?}");
        }
        let bare = json!({ "to": "epic:abc@epicbox.example" });
        let bad = problem(
            &post(socket, "/api/v1/payments", &bare),
            400,
            "invalid_field",
        );
        assert_eq!(bad["param"], "/amount", "{bad}");
        // An estimate takes the link's amount the same way.
        let fee = post(socket, "/api/v1/payments/estimate", &json!({ "to": to })).ok();
        assert!(fee["fee"].is_string(), "{fee}");
    });
}

/// A send to an Epicbox address that its mailbox refuses with a wait is a 502 `transport_failed`
/// whose `retry_after_secs` and `Retry-After` carry the mailbox's wait, not the fixed 5 s.
#[test]
fn a_send_a_mailbox_refuses_with_a_wait_answers_with_that_wait() {
    let (host, wallet) = funded();
    let (_receiver, address) = receiver(&host);
    host.relay.set_post_refusal(Some((
        "InvalidRequest",
        "Rate limit exceeded; retry in 12 s.",
    )));
    serving(host, &wallet, |socket, _| {
        let refused = post(
            socket,
            "/api/v1/payments",
            &json!({ "amount": "1", "to": address }),
        );
        let body = problem(&refused, 502, "transport_failed");
        assert_eq!(body["retry_after_secs"], 12, "{body}");
        assert_eq!(refused.header("retry-after"), Some("12"), "{refused:?}");
    });
}

#[test]
fn a_failed_create_leaves_its_id_free() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let id = "8d2f0b4c-3e5a-4b7c-9d1e-2f3a4b5c6d7e";
        let big = json!({ "id": id, "amount": "100000", "via": "file" });
        problem(
            &post(socket, "/api/v1/payments", &big),
            422,
            "insufficient_funds",
        );
        // The same body fails the same way; a smaller amount is a new create.
        problem(
            &post(socket, "/api/v1/payments", &big),
            422,
            "insufficient_funds",
        );
        let small = json!({ "id": id, "amount": "1", "via": "file" });
        let made = post(socket, "/api/v1/payments", &small);
        assert_eq!(made.status, 201, "{made:?}");
        // Once made, the id is kept: the repeat is 200, another body is a mismatch.
        assert_eq!(post(socket, "/api/v1/payments", &small).status, 200);
        problem(
            &post(socket, "/api/v1/payments", &big),
            409,
            "idempotency_mismatch",
        );
    });
}

#[test]
fn legacy_in_a_create_or_an_estimate_is_refused() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let body = json!({ "amount": "1", "via": "file", "legacy": true });
        for path in ["/api/v1/payments", "/api/v1/payments/estimate"] {
            let detail =
                problem(&post(socket, path, &body), 400, "invalid_body")["detail"].to_string();
            assert!(detail.contains("legacy"), "{path}: {detail}");
        }
        assert_eq!(count_of(socket, "send"), 0);
    });
}

#[test]
fn a_path_that_is_no_uuid_answers_404_without_a_payment_id() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let calls = [
            ("GET", "/api/v1/payments/not-a-uuid"),
            ("PATCH", "/api/v1/payments/not-a-uuid"),
            ("GET", "/api/v1/payments/not-a-uuid/handoff"),
            ("POST", "/api/v1/payments/not-a-uuid/approve"),
            ("POST", "/api/v1/payments/not-a-uuid/decline"),
            ("POST", "/api/v1/payments/not-a-uuid/deliver"),
            ("POST", "/api/v1/payments/not-a-uuid/post"),
            ("POST", "/api/v1/payments/not-a-uuid/cancel"),
            ("POST", "/api/v1/payments/not-a-uuid/recover"),
        ];
        for (method, path) in calls {
            // `approve` reads its body before it looks the payment up.
            let body = match (method, path.ends_with("/approve")) {
                ("GET", _) => None,
                (_, true) => Some(r#"{"amount":"1"}"#),
                _ => Some("{}"),
            };
            let answer = problem(&http(socket, method, path, body), 404, "not_found");
            assert!(
                answer.get("payment_id").is_none(),
                "{method} {path}: {answer}"
            );
        }
    });
}

#[test]
fn a_create_and_an_estimate_take_the_same_account_names() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        for account in ["default", "no such account"] {
            let body = json!({ "amount": "0.5", "via": "file", "account": account });
            let estimate = post(socket, "/api/v1/payments/estimate", &body);
            let create = post(socket, "/api/v1/payments", &body);
            if account == "default" {
                assert_eq!(estimate.status, 200, "{estimate:?}");
                assert_eq!(create.status, 201, "{create:?}");
            } else {
                assert_eq!(estimate.status, 404, "{estimate:?}");
                assert_eq!(create.status, 404, "{create:?}");
            }
        }
    });
}

#[test]
fn a_send_to_an_onion_runs_the_tor_binary_the_settings_name() {
    let onion = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    let body = json!({ "to": onion, "amount": "1" });

    // No tor binary: the send is refused as a request that cannot be made.
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let refused = problem(
            &post(socket, "/api/v1/payments", &body),
            400,
            "invalid_request",
        );
        assert!(
            refused["detail"].as_str().unwrap().contains("tor"),
            "{refused}"
        );
        assert_eq!(count_of(socket, "send"), 0);
    });

    // A tor binary in the settings: the send starts it. This one is missing, so the send stops
    // at the binary and stores nothing.
    let (host, wallet) = funded();
    let missing = wallet.path("no-tor-here");
    let missing = missing.to_str().unwrap();
    serving_with_env(
        host,
        &wallet,
        &[],
        &[("LEPIC_EPICBOX_TOR_BINARY", missing)],
        |socket, _| {
            let failed = problem(&post(socket, "/api/v1/payments", &body), 500, "config");
            assert!(
                failed["detail"].as_str().unwrap().contains("tor"),
                "{failed}"
            );
            assert_eq!(count_of(socket, "send"), 0);
        },
    );
}

#[test]
fn an_invoice_to_an_address_is_refused_and_nothing_is_stored() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        for to in [
            "esWr5yVhZ5WvR4Qb2MyXH2wqRK8FpjKpz9tJKhCwh1HHtGDF7eF4@epicbox.example",
            "https://host.example/path",
            "kvhbtumy6qbqikzkopp2tzkvgsxwuarkq5t5hfdu7uvfeyfbkgbsytid.onion",
            "epic:esWr5yVhZ5WvR4Qb2MyXH2wqRK8FpjKpz9tJKhCwh1HHtGDF7eF4@epicbox.example?amount=2",
        ] {
            let body = json!({ "kind": "invoice", "amount": "2", "to": to });
            let refused = problem(
                &post(socket, "/api/v1/payments", &body),
                400,
                "invoice_to_address",
            );
            assert_eq!(refused["param"], "/to", "{to}: {refused}");
        }
        assert_eq!(count_of(socket, "invoice"), 0);
    });
}

#[test]
fn a_create_is_remembered_across_a_restart() {
    let (host, wallet) = funded();
    let again = host.without_interrupt();
    let id = "9e3a1c5d-4f6b-4c8d-ae2f-3a4b5c6d7e8f";
    let body = json!({ "id": id, "amount": "1", "via": "file" });
    let made = serving(host, &wallet, |socket, _| {
        let created = post(socket, "/api/v1/payments", &body);
        assert_eq!(created.status, 201, "{created:?}");
        created.json()
    });
    serving(again, &wallet, |socket, _| {
        let repeated = post(socket, "/api/v1/payments", &body);
        assert_eq!(repeated.status, 200, "{repeated:?}");
        assert_eq!(repeated.json()["id"], made["id"]);
        let changed = json!({ "id": id, "amount": "2", "via": "file" });
        problem(
            &post(socket, "/api/v1/payments", &changed),
            409,
            "idempotency_mismatch",
        );
    });
}

/// The payments of `kind` the wallet lists.
fn count_of(socket: &Path, kind: &str) -> usize {
    let listed = http(socket, "GET", "/api/v1/payments?limit=100", None).ok();
    listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["kind"] == kind)
        .count()
}

/// Makes the payment `body` asks for, takes away what an earlier build wrote after the payment
/// (`keys`), as a crash between the two would, and repeats the call after a restart: the repeat
/// answers 200 with the same payment and makes none.
fn repeat_after_a_crash(body: &Value, kind: &str, keys: impl Fn(&str) -> Vec<String>) {
    let (host, wallet) = funded();
    let again = host.without_interrupt();
    let made = serving(host, &wallet, |socket, _| {
        let created = post(socket, "/api/v1/payments", body);
        assert_eq!(created.status, 201, "{created:?}");
        assert_eq!(count_of(socket, kind), 1);
        created.json()
    });
    let made_id = text(&made, "id").to_owned();
    with_settings(&wallet, SENDER_MNEMONIC, |repos| {
        for key in keys(&made_id) {
            repos.delete_setting(&key)?;
        }
        Ok(())
    });
    serving(again, &wallet, |socket, _| {
        let repeated = post(socket, "/api/v1/payments", body);
        assert_eq!(repeated.status, 200, "{repeated:?}");
        assert_eq!(repeated.json()["id"], made_id.as_str(), "{repeated:?}");
        assert_eq!(count_of(socket, kind), 1);
    });
}

#[test]
fn a_send_cut_short_after_it_was_made_is_answered_on_its_repeat() {
    let id = "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e";
    let body = json!({ "id": id, "amount": "1", "via": "file" });
    repeat_after_a_crash(&body, "send", |made| vec![format!("api.payment.{made}")]);
}

#[test]
fn an_invoice_cut_short_after_it_was_made_is_answered_on_its_repeat() {
    let id = "1c2d3e4f-5a6b-4c7d-9e8f-0a1b2c3d4e5f";
    let body = json!({ "id": id, "kind": "invoice", "amount": "2", "via": "file" });
    repeat_after_a_crash(&body, "invoice", |made| {
        // A random UUID is the invoice's slate id: nothing maps the caller's id to it.
        assert_eq!(made, id);
        vec![format!("api.payment.{made}")]
    });
}

#[test]
fn an_invoice_with_a_time_ordered_id_is_answered_on_its_repeat_after_a_crash() {
    // Not a random UUID: the wallet draws the slate id and stores it for the caller's id before
    // the invoice is made, so only the note can be missing after a crash.
    let id = "018f3a2b-4c5d-7e6f-8a9b-0c1d2e3f4a5b";
    let body = json!({ "id": id, "kind": "invoice", "amount": "2", "via": "file" });
    repeat_after_a_crash(&body, "invoice", |made| {
        assert_ne!(made, id);
        vec![format!("api.payment.{made}")]
    });
}

#[test]
fn an_expired_invoice_opened_here_is_refused_and_not_held() {
    let (host, wallet) = funded();
    let issuer = new_wallet(&host, "issuer password");
    let file = issuer.path("invoice.slate");
    issuer
        .run(
            &host,
            &["invoice", "issue", "3", "--to-file", file.to_str().unwrap()],
        )
        .ok();
    // The payer's TTL is not signed: a cutoff below the tip stands for an invoice that waited
    // too long.
    let mut slate: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert!(slate.get("ttl_cutoff_height").is_some(), "{slate}");
    slate["ttl_cutoff_height"] = json!(5);
    let invoice = slate.to_string();

    serving(host, &wallet, |socket, client| {
        // The wallet learns the tip, which is above the cutoff.
        let synced = post(socket, "/api/v1/sync", &json!({})).ok();
        assert!(synced["height"].as_u64().unwrap() > 5, "{synced}");
        for _ in 0..2 {
            problem(
                &post(socket, "/api/v1/open", &json!({ "text": invoice })),
                422,
                "payment_expired",
            );
        }
        let held = http(socket, "GET", "/api/v1/payments?state=needs_approval", None).ok();
        assert!(held["items"].as_array().unwrap().is_empty(), "{held}");
        assert!(client.node.pushed_transactions().is_empty());
    });
}

/// A send of the funded wallet to a new one with a cutoff 100 blocks ahead, answered and
/// finalized while the node fails every push with `failure`, so it stays `finalized`; then the
/// node's tip moves far past its cutoff.
/// The host and the sender, and the payment's id.
fn finalized_past_cutoff(failure: MockFailure) -> (TestHost, Instance, String) {
    let (host, wallet) = funded();
    let (receiver, _) = receiver(&host);
    let slate = wallet.path("payment.slate");
    let sent = wallet
        .run(
            &host,
            &[
                "tx",
                "send",
                "1",
                "--ttl-blocks",
                "100",
                "--to-file",
                slate.to_str().unwrap(),
            ],
        )
        .ok()
        .json();
    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    host.node.fail_every("push_transaction", failure);
    let finalized = wallet.run(&host, &["tx", "finalize", text(&received, "reply_file")]);
    assert_eq!(finalized.code, 11, "{finalized:?}");
    host.node
        .update_chain(|chain| chain.tip.height = Height::new(support::TIP + 10_000));
    (host, wallet, text(&sent, "slate_id").to_owned())
}

#[test]
fn a_send_the_node_refused_every_time_expires_with_its_reason_and_no_post() {
    let (host, wallet, id) = finalized_past_cutoff(MockFailure::PoolRefused);

    serving(host, &wallet, |socket, client| {
        let path = format!("/api/v1/payments/{id}");
        wait_until("the refused send expires", || {
            http(socket, "GET", &path, None).ok()["state"] == "expired"
        });
        let payment = http(socket, "GET", &path, None).ok();
        assert_eq!(
            payment["state_reason"], "expired_rejected_by_node",
            "{payment}"
        );
        // Its signed slate still spends coins the wallet holds, so it can be recovered.
        assert_eq!(payment["actions"], json!(["recover"]), "{payment}");
        assert!(client.node.pushed_transactions().is_empty());
    });
}

#[test]
fn a_send_past_its_cutoff_that_met_an_unreachable_node_stays_without_post() {
    let (host, wallet, id) = finalized_past_cutoff(MockFailure::Unreachable);

    serving(host, &wallet, |socket, _| {
        // The wallet has no confirmed tip yet, so the first refresh after the jump only holds
        // the new tip and the next one confirms it. Serve's own refresh at start may be either,
        // so two syncs in a row confirm it whichever runs first.
        post(socket, "/api/v1/sync", &json!({})).ok();
        let synced = post(socket, "/api/v1/sync", &json!({})).ok();
        assert_eq!(synced["height"], support::TIP + 10_000, "{synced}");
        let payment = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
        assert_eq!(payment["state"], "finalized", "{payment}");
        assert!(payment.get("state_reason").is_none(), "{payment}");
        assert_eq!(
            payment["actions"],
            json!(["cancel", "recover"]),
            "{payment}"
        );
    });
}

/// A send of 1 EPIC by file from the funded wallet, which holds a second coin, to a new wallet,
/// answered and finalized: the node took it, so it is `posted`, though no pool holds it.
/// The host and the sender, and the payment's id.
fn posted_by_file() -> (TestHost, Instance, String) {
    let (host, wallet) = funded();
    host.fund(SENDER_MNEMONIC, 1, FUNDING, 2);
    let (receiver, _) = receiver(&host);
    let slate = wallet.path("payment.slate");
    let sent = wallet
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    wallet
        .run(&host, &["tx", "finalize", text(&received, "reply_file")])
        .ok();
    (host, wallet, text(&sent, "slate_id").to_owned())
}

fn actions(payment: &Value) -> Vec<&str> {
    payment["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| action.as_str().unwrap())
        .collect()
}

#[test]
fn a_posted_send_the_node_no_longer_holds_is_recovered_once() {
    let (host, wallet, id) = posted_by_file();

    serving(host, &wallet, |socket, client| {
        let path = format!("/api/v1/payments/{id}");
        let recover = format!("{path}/recover");
        let before = http(socket, "GET", &path, None).ok();
        assert_eq!(before["state"], "posted", "{before}");
        assert!(before.get("recovery").is_none(), "{before}");
        assert!(actions(&before).contains(&"recover"), "{before}");

        // A pool that holds the payment refuses its recovery, and nothing is stored.
        let pushed = client.node.pushed_transactions();
        assert_eq!(pushed.len(), 1);
        client
            .node
            .update_chain(|chain| chain.pool.push(pushed[0].clone()));
        let in_pool = problem(&http(socket, "POST", &recover, None), 409, "in_pool");
        assert_eq!(in_pool["payment_id"], id.as_str(), "{in_pool}");
        let unchanged = http(socket, "GET", &path, None).ok();
        assert!(unchanged.get("recovery").is_none(), "{unchanged}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
        client.node.update_chain(|chain| chain.pool.clear());

        let answer = http(socket, "POST", &recover, None);
        assert_eq!(answer.status, 202, "{answer:?}");
        let recovering = answer.json();
        assert_eq!(recovering["id"], id.as_str(), "{recovering}");
        assert_eq!(recovering["state"], "posted", "{recovering}");
        let recovery = &recovering["recovery"];
        assert_eq!(recovery["state"], "posted", "{recovering}");
        assert_eq!(recovery["confirmations"], 0, "{recovering}");
        assert!(recovery["needed"].as_u64().unwrap() > 0, "{recovering}");
        // One input pays the fee of one input.
        assert!(
            (epic(&recovery["fee"]) - 0.004).abs() < 1e-9,
            "{recovering}"
        );
        assert!(recovery.get("error").is_none(), "{recovering}");
        assert_eq!(actions(&recovering), Vec::<&str>::new(), "{recovering}");
        // The recovery went to the node; the send itself was never pushed again. The
        // maintenance refresh may push the recovery again, so only the send is counted.
        let send = pushed[0].kernels()[0].excess;
        let pushes_of = |excess| {
            client
                .node
                .pushed_transactions()
                .iter()
                .filter(|tx| tx.kernels()[0].excess == excess)
                .count()
        };
        assert!(client.node.pushed_transactions().len() >= 2);
        assert_eq!(pushes_of(send), 1);

        // The recovery is a send to this wallet, listed as a payment of its own.
        let own = text(recovery, "tx_id");
        assert_ne!(own, id);
        let own = http(socket, "GET", &format!("/api/v1/payments/{own}"), None).ok();
        assert_eq!(own["direction"], "self", "{own}");
        assert_eq!(own["state"], "posted", "{own}");
        assert!(!actions(&own).contains(&"recover"), "{own}");
        // Only a send answers use_recover: the posted recovery falls to the actions rule.
        let own_cancel = format!("/api/v1/payments/{}/cancel", text(&own, "id"));
        problem(
            &http(socket, "POST", &own_cancel, None),
            409,
            "action_not_available",
        );

        problem(&http(socket, "POST", &recover, None), 409, "recovery_open");
        problem(
            &http(socket, "POST", &format!("{path}/post"), None),
            409,
            "action_not_available",
        );
        problem(
            &http(socket, "POST", &format!("{path}/cancel"), None),
            409,
            "use_recover",
        );
        assert_eq!(pushes_of(send), 1);

        let listed = http(
            socket,
            "GET",
            "/api/v1/events?types=payment.recovery_changed",
            None,
        )
        .ok();
        let items = listed["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{listed}");
        let object = &items[0]["data"]["object"];
        assert_eq!(object["id"], id.as_str(), "{listed}");
        assert_eq!(object["recovery"]["state"], "posted", "{listed}");
    });
}

#[test]
fn cancel_of_a_posted_send_answers_use_recover_and_changes_nothing() {
    let (host, wallet, id) = posted_by_file();

    serving(host, &wallet, |socket, client| {
        // The refresh serve starts with may still change the balance: let it end first.
        post(socket, "/api/v1/sync", &json!({})).ok();
        let path = format!("/api/v1/payments/{id}");
        let before = http(socket, "GET", &path, None).ok();
        assert_eq!(before["state"], "posted", "{before}");
        assert!(!actions(&before).contains(&"cancel"), "{before}");
        assert!(!actions(&before).contains(&"release"), "{before}");
        assert!(before.get("cancellable_from_height").is_none(), "{before}");
        let accounts = http(socket, "GET", "/api/v1/accounts", None).ok();
        let pushes = client.node.pushed_transactions().len();

        let refused = problem(
            &http(socket, "POST", &format!("{path}/cancel"), None),
            409,
            "use_recover",
        );

        assert_eq!(refused["payment_id"], id.as_str(), "{refused}");
        assert_eq!(http(socket, "GET", &path, None).ok(), before);
        assert_eq!(http(socket, "GET", "/api/v1/accounts", None).ok(), accounts);
        assert_eq!(client.node.pushed_transactions().len(), pushes);
    });
}

#[test]
fn a_send_that_holds_no_final_transaction_is_not_recovered() {
    let (host, wallet) = funded();

    serving(host, &wallet, |socket, client| {
        let id = send_by_hand(socket);
        let path = format!("/api/v1/payments/{id}");
        let payment = http(socket, "GET", &path, None).ok();
        assert_eq!(payment["state"], "awaiting_answer", "{payment}");
        assert!(!actions(&payment).contains(&"recover"), "{payment}");
        let refused = problem(
            &http(socket, "POST", &format!("{path}/recover"), None),
            409,
            "not_recoverable",
        );
        assert_eq!(refused["payment_id"], id.as_str(), "{refused}");
        assert_eq!(http(socket, "GET", &path, None).ok(), payment);
        assert!(client.node.pushed_transactions().is_empty());
    });
}

#[test]
fn a_send_the_chain_holds_is_not_recovered() {
    let (host, wallet, id) = posted_by_file();

    serving(host, &wallet, |socket, client| {
        let path = format!("/api/v1/payments/{id}");
        let pushed = client.node.pushed_transactions();
        assert_eq!(pushed.len(), 1);
        // The send's kernel in a block at the tip, which stays where it is.
        client.node.update_chain(|chain| {
            let mmr_index = u64::try_from(chain.kernels.len()).unwrap() + 1;
            chain.kernels.push(LocatedKernel {
                kernel: pushed[0].kernels()[0],
                height: chain.tip.height,
                mmr_index,
            });
        });

        let refused = problem(
            &http(socket, "POST", &format!("{path}/recover"), None),
            409,
            "on_chain",
        );

        assert_eq!(refused["payment_id"], id.as_str(), "{refused}");
        let after = http(socket, "GET", &path, None).ok();
        assert!(after.get("recovery").is_none(), "{after}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

#[test]
fn a_recovery_the_node_refuses_is_stored_failed_and_the_send_stays_posted() {
    let (host, wallet, id) = posted_by_file();

    serving(host, &wallet, |socket, client| {
        let path = format!("/api/v1/payments/{id}");
        let refusal = "Failed to update pool: InvalidTx(kernel sum mismatch)";
        client
            .node
            .fail_every("push_transaction", MockFailure::Internal(refusal));

        let answer = http(socket, "POST", &format!("{path}/recover"), None);

        assert_eq!(answer.status, 202, "{answer:?}");
        let payment = answer.json();
        assert_eq!(payment["state"], "posted", "{payment}");
        let recovery = &payment["recovery"];
        assert_eq!(recovery["state"], "failed", "{payment}");
        assert!(
            text(recovery, "error").contains("kernel sum mismatch"),
            "{payment}"
        );
        assert_eq!(http(socket, "GET", &path, None).ok()["state"], "posted");
    });
}

#[test]
fn a_recovery_that_meets_an_unreachable_node_is_uncertain() {
    let (host, wallet, id) = posted_by_file();

    serving(host, &wallet, |socket, client| {
        let path = format!("/api/v1/payments/{id}");
        client
            .node
            .fail_every("push_transaction", MockFailure::Unreachable);

        let answer = http(socket, "POST", &format!("{path}/recover"), None);

        assert_eq!(answer.status, 202, "{answer:?}");
        let payment = answer.json();
        assert_eq!(payment["state"], "posted", "{payment}");
        assert_eq!(payment["recovery"]["state"], "uncertain", "{payment}");
        assert!(payment["recovery"].get("error").is_none(), "{payment}");
        problem(
            &http(socket, "POST", &format!("{path}/recover"), None),
            409,
            "recovery_open",
        );
    });
}

/// A send of 1 EPIC by file from the funded wallet with a cutoff 100 blocks ahead, its slate
/// left with a new wallet that received it; then the node's tip moves far past the cutoff.
/// The host, the sender and the receiver, and the payment's id.
fn answered_past_cutoff(answer: bool) -> (TestHost, Instance, Instance, String) {
    let (host, wallet) = funded();
    let (receiver, _) = receiver(&host);
    let slate = wallet.path("payment.slate");
    let sent = wallet
        .run(
            &host,
            &[
                "tx",
                "send",
                "1",
                "--ttl-blocks",
                "100",
                "--to-file",
                slate.to_str().unwrap(),
            ],
        )
        .ok()
        .json();
    if answer {
        receiver
            .run(&host, &["tx", "receive", slate.to_str().unwrap()])
            .ok();
    }
    host.node
        .update_chain(|chain| chain.tip.height = Height::new(support::TIP + 10_000));
    (host, wallet, receiver, text(&sent, "slate_id").to_owned())
}

#[test]
fn a_send_nobody_answered_expires_with_no_answer() {
    let (host, wallet, _, id) = answered_past_cutoff(false);

    serving(host, &wallet, |socket, _| {
        let path = format!("/api/v1/payments/{id}");
        wait_until("the unanswered send expires", || {
            http(socket, "GET", &path, None).ok()["state"] == "expired"
        });
        let payment = http(socket, "GET", &path, None).ok();
        assert_eq!(payment["state_reason"], "expired_no_answer", "{payment}");
        // It never reached the node.
        assert!(payment.get("post").is_none(), "{payment}");
    });
}

#[test]
fn a_receive_never_mined_expires_with_not_mined() {
    let (host, _, receiver, id) = answered_past_cutoff(true);

    serving(host, &receiver, |socket, _| {
        let path = format!("/api/v1/payments/{id}");
        wait_until("the receive expires", || {
            http(socket, "GET", &path, None).ok()["state"] == "expired"
        });
        let payment = http(socket, "GET", &path, None).ok();
        assert_eq!(payment["direction"], "in", "{payment}");
        assert_eq!(payment["state_reason"], "expired_not_mined", "{payment}");
    });
}

/// Puts `transactions` into a block at `height`, the new tip: their inputs spent, their outputs
/// and kernels added.
fn mine(node: &MockNode, transactions: &[Transaction], height: u64) {
    node.update_chain(|chain| {
        let height = Height::new(height);
        for transaction in transactions {
            for input in transaction.inputs() {
                for output in &mut chain.outputs {
                    if output.commitment == input.commitment {
                        output.spent = true;
                    }
                }
            }
            for output in transaction.outputs() {
                let mmr_index = u64::try_from(chain.outputs.len()).unwrap() + 1;
                chain.outputs.push(ChainOutput {
                    commitment: output.commitment,
                    features: output.features,
                    proof: output.proof.clone(),
                    height,
                    mmr_index,
                    spent: false,
                });
            }
            for kernel in transaction.kernels() {
                let mmr_index = u64::try_from(chain.kernels.len()).unwrap() + 1;
                chain.kernels.push(LocatedKernel {
                    kernel: *kernel,
                    height,
                    mmr_index,
                });
            }
        }
        chain.tip.height = height;
    });
}

#[test]
fn a_send_whose_recovery_confirmed_is_cancelled_as_recovered() {
    let (host, wallet, id) = posted_by_file();

    serving(host, &wallet, |socket, client| {
        let path = format!("/api/v1/payments/{id}");
        let sent = client.node.pushed_transactions();
        let recovering = http(socket, "POST", &format!("{path}/recover"), None);
        assert_eq!(recovering.status, 202, "{recovering:?}");
        let needed = recovering.json()["recovery"]["needed"].as_u64().unwrap();
        // Only the recovery is mined; the send it spends back stays out of the chain.
        let recovery: Vec<Transaction> = client
            .node
            .pushed_transactions()
            .into_iter()
            .filter(|transaction| !sent.contains(transaction))
            .collect();
        assert!(!recovery.is_empty());
        mine(&client.node, &recovery, support::TIP + 1);
        client
            .node
            .update_chain(|chain| chain.tip.height = Height::new(support::TIP + needed));

        wait_until("the recovery reaches its confirmations", || {
            post(socket, "/api/v1/sync", &json!({})).ok();
            http(socket, "GET", &path, None).ok()["state"] == "cancelled"
        });
        let payment = http(socket, "GET", &path, None).ok();
        assert_eq!(payment["state_reason"], "recovered", "{payment}");
        assert_eq!(payment["recovery"]["state"], "done", "{payment}");
    });
}

/// The `data` of each event of `kind` listed so far for the payment `id`.
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

/// Moves the node's tip to the height the payment at `path` is pushed again, and syncs.
fn push_again(socket: &Path, node: &MockNode, path: &str) {
    let payment = http(socket, "GET", path, None).ok();
    let next = payment["post"]["next_attempt_height"].as_u64().unwrap();
    node.update_chain(|chain| chain.tip.height = Height::new(next));
    post(socket, "/api/v1/sync", &json!({})).ok();
}

#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_failed_push_is_shown_in_post_and_told_once_per_change() {
    let (host, wallet) = funded();
    let (receiver, _) = receiver(&host);
    let slate = wallet.path("payment.slate");
    let sent = wallet
        .run(
            &host,
            &[
                "tx",
                "send",
                "1",
                "--ttl-blocks",
                "1000",
                "--to-file",
                slate.to_str().unwrap(),
            ],
        )
        .ok()
        .json();
    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    host.node
        .fail_every("push_transaction", MockFailure::PoolRefused);
    let finalized = wallet.run(&host, &["tx", "finalize", text(&received, "reply_file")]);
    assert_eq!(finalized.code, 11, "{finalized:?}");
    let id = text(&sent, "slate_id").to_owned();
    // A node's text with terminal escapes, a bell, a line break, a right-to-left override, a
    // line separator and a zero-width space, far over the cap.
    let noisy: &'static str = Box::leak(
        format!(
            "Failed to update pool: \u{1b}[31mred\u{7}\nline\u{202E}gnol\u{2028}sep\u{200B}zw{}",
            "x".repeat(400)
        )
        .into_boxed_str(),
    );

    serving(host, &wallet, |socket, client| {
        let path = format!("/api/v1/payments/{id}");
        let refused = http(socket, "GET", &path, None).ok();
        assert_eq!(refused["state"], "finalized", "{refused}");
        let post_object = &refused["post"];
        assert_eq!(post_object["attempts"], 1, "{refused}");
        assert_eq!(post_object["last_outcome"], "refused", "{refused}");
        assert!(
            text(post_object, "last_error").contains("Failed to update pool"),
            "{refused}"
        );
        assert_eq!(post_object["accepted_once"], false, "{refused}");
        // The push made before serve started is not an event.
        assert!(events_of(socket, "payment.post_failed", &id).is_empty());

        // A new text is told once, capped and as plain text.
        client
            .node
            .fail_every("push_transaction", MockFailure::Internal(noisy));
        push_again(socket, &client.node, &path);
        wait_until("the new refusal is told", || {
            events_of(socket, "payment.post_failed", &id).len() == 1
        });
        let told = &events_of(socket, "payment.post_failed", &id)[0];
        let error = text(told, "error");
        assert_eq!(error.chars().count(), 256, "{error}");
        assert!(error.ends_with('…'), "{error}");
        assert!(!error.chars().any(char::is_control), "{error}");
        assert!(
            error.contains("\\u{1b}[31mred\\u{7}\\nline\\u{202e}gnol\\u{2028}sep\\u{200b}zw"),
            "{error}"
        );
        assert!(
            !error.contains(['\u{202E}', '\u{2028}', '\u{200B}']),
            "{error}"
        );
        let shown = http(socket, "GET", &path, None).ok();
        assert_eq!(shown["post"]["last_error"], error, "{shown}");
        assert_eq!(shown["post"]["attempts"], 2, "{shown}");

        // The same refusal again changes nothing a client is told.
        push_again(socket, &client.node, &path);
        wait_until("the same refusal is pushed", || {
            http(socket, "GET", &path, None).ok()["post"]["attempts"] == 3
        });
        assert_eq!(events_of(socket, "payment.post_failed", &id).len(), 1);

        // A node that cannot be reached is a new outcome.
        client
            .node
            .fail_every("push_transaction", MockFailure::Unreachable);
        push_again(socket, &client.node, &path);
        wait_until("the unreachable node is told", || {
            events_of(socket, "payment.post_failed", &id).len() == 2
        });
        let unreachable = http(socket, "GET", &path, None).ok();
        assert_eq!(unreachable["post"]["last_outcome"], "unreachable");
        assert_eq!(
            events_of(socket, "payment.post_failed", &id)[1]["error"],
            unreachable["post"]["last_error"]
        );

        // The node takes it: posted, and the last failure's text stays with accepted_once.
        client.node.stop_failing("push_transaction");
        push_again(socket, &client.node, &path);
        wait_until("the send is posted", || {
            http(socket, "GET", &path, None).ok()["state"] == "posted"
        });
        let posted = http(socket, "GET", &path, None).ok();
        let post_object = &posted["post"];
        assert_eq!(post_object["attempts"], 5, "{posted}");
        assert_eq!(post_object["last_outcome"], "accepted", "{posted}");
        assert_eq!(post_object["accepted_once"], true, "{posted}");
        assert_eq!(
            post_object["last_error"], unreachable["post"]["last_error"],
            "{posted}"
        );
        assert!(post_object["next_attempt_height"].is_u64(), "{posted}");
        assert_eq!(events_of(socket, "payment.post_failed", &id).len(), 2);
        // Only the move to posted is a state change.
        let changes = events_of(socket, "payment.state_changed", &id);
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0]["object"]["state"], "posted");
    });
}

/// The payer's own relay when it is served under a public name.
const PAYER_RELAY: &str = support::PUBLIC_MAILBOX;

/// The relay the payer lists after its own, so a payment to a link has a second route.
const SECOND_RELAY: &str = "relay2.test";

/// A link for 2 EPIC of a new wallet that is never served, so no payment to it is answered.
/// It has no entries: a payer posts it to the payee's mailbox on each relay of its own list.
fn stranger_link(host: &TestHost) -> String {
    let payee = new_wallet(host, "payee password");
    let made = payee.run(host, &["epic1", "link", "2"]).ok().json();
    text(&made, "link").to_owned()
}

/// The payee's delivery mailbox on `domain` of `link`.
fn mailbox_on(link: &str, domain: &str) -> lepic_epicbox::EpicboxAddress {
    lepic_wallet_contacts::epic1_testing::delivery_mailbox(link, domain).unwrap()
}

/// Makes [`PAYER_RELAY`] and [`SECOND_RELAY`] the stopped wallet's mailbox list, so a payment
/// to a link is posted on both.
fn offer_second_relay(wallet: &Instance) {
    wallet.with_mailboxes(&[PAYER_RELAY, SECOND_RELAY]);
}

/// Makes [`PAYER_RELAY`], the wallet's own relay, its only mailbox, so a payment to a link is
/// posted there alone.
fn offer_own_relay_only(wallet: &Instance) {
    wallet.with_mailboxes(&[PAYER_RELAY]);
}

/// Pays `link` with the payer's own relay silent for the rest of the test, so a post that goes
/// to that relay alone is uncertain and stays so: a retry of it goes unanswered too. The
/// payment's id.
fn pay_unanswered(
    socket: &Path,
    relay: &lepic_epicbox::mock_relay::MockRelay,
    link: &str,
) -> String {
    pay_unanswered_with(socket, relay, &json!({ "to": link }))
}

/// [`pay_unanswered`] with the whole request `body`.
fn pay_unanswered_with(
    socket: &Path,
    relay: &lepic_epicbox::mock_relay::MockRelay,
    body: &Value,
) -> String {
    relay.set_domain_unanswered(PAYER_RELAY);
    let paid = post(socket, "/api/v1/payments", body);
    assert_eq!(paid.status, 201, "{paid:?}");
    text(&paid.json(), "id").to_owned()
}

/// What a refused deliver must leave as it was: the whole payment but the delivery's
/// `updated_at`, `attempts` and `next_attempt_at`, which a retry of the uncertain post may
/// rewrite beside the call.
fn unchanged_part(payment: &Value) -> Value {
    let mut part = payment.clone();
    if let Some(delivery) = part["delivery"].as_object_mut() {
        delivery.remove("updated_at");
        delivery.remove("attempts");
        delivery.remove("next_attempt_at");
    }
    part
}

/// The states `payment.delivery_changed` told for the payment `id`, in order.
fn delivery_told(socket: &Path, id: &str) -> Vec<Value> {
    events_of(socket, "payment.delivery_changed", id)
        .iter()
        .map(|data| data["state"].clone())
        .collect()
}

/// An epic1 payment whose post may not have arrived shows its delivery as the outbox keeps it,
/// tells the change once, and offers `deliver`. The payer lists no relay past its own, so the
/// silent relay is the only one the payment is posted to.
#[test]
fn an_uncertain_epic1_payment_is_told_once_and_offers_deliver() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let relay = host.relay.clone();
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let id = pay_unanswered(socket, &relay, &link);

        let path = format!("/api/v1/payments/{id}");
        let payment = http(socket, "GET", &path, None).ok();
        assert_eq!(payment["delivery"]["state"], "uncertain", "{payment}");
        assert_eq!(payment["actions"][0], "deliver", "{payment}");
        assert_eq!(delivery_told(socket, &id), [json!("uncertain")]);
        // A later sync tells nothing new: its retry of the post goes unanswered as well.
        post(socket, "/api/v1/sync", &json!({})).ok();
        assert_eq!(delivery_told(socket, &id), [json!("uncertain")]);
    });
}

/// A payment whose delivery is uncertain counts as stuck in the metrics while it is open, and
/// stops counting once a cancel ends it: the rows of the outbox stay, the payment is over.
#[test]
fn a_cancelled_payment_with_a_failed_delivery_no_longer_counts_as_stuck() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let relay = host.relay.clone();
    let link = stranger_link(&host);
    super::api_wallet::serving_public_args(host, &wallet, &["--metrics"], &[], |socket| {
        let scrape = || http(socket, "GET", "/api/v1/metrics", None).body;
        let value = |text: &str, name: &str| -> String {
            text.lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
                .unwrap_or_else(|| panic!("no {name} in {text}"))
                .to_owned()
        };
        let id = pay_unanswered(socket, &relay, &link);
        let path = format!("/api/v1/payments/{id}");
        let payment = http(socket, "GET", &path, None).ok();
        assert_eq!(payment["delivery"]["state"], "uncertain", "{payment}");
        let open = scrape();
        assert_eq!(value(&open, "lepic_payments_stuck"), "1", "{open}");
        assert_eq!(value(&open, "lepic_outbox_queue_depth"), "0", "{open}");

        let cancelled = http(socket, "POST", &format!("{path}/cancel"), None).ok();
        assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
        let over = scrape();
        assert_eq!(value(&over, "lepic_payments_stuck"), "0", "{over}");
        assert_eq!(value(&over, "lepic_outbox_queue_depth"), "0", "{over}");
    });
}

/// A payment to a link without entries goes to every relay of the payer's list at once. The
/// payer's own relay stays silent and the second relay takes it, so the payment is `sent` from
/// the start: no `deliver` is offered and no delivery change is told, though one relay gave no
/// answer.
#[test]
fn a_payment_one_relay_of_two_takes_is_sent_and_tells_no_change() {
    let (host, wallet) = funded();
    offer_second_relay(&wallet);
    let relay = host.relay.clone();
    let link = stranger_link(&host);
    let second = mailbox_on(&link, SECOND_RELAY);
    relay.set_relays_apart(true);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let id = pay_unanswered(socket, &relay, &link);
        assert_eq!(
            relay.pending(&second),
            1,
            "the payment is posted on the second relay"
        );

        let payment = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
        assert_eq!(payment["delivery"]["state"], "sent", "{payment}");
        assert!(!actions(&payment).contains(&"deliver"), "{payment}");
        assert_eq!(delivery_told(socket, &id), Vec::<Value>::new());
        // A later read of the relays tells nothing and posts nothing again.
        post(socket, "/api/v1/sync", &json!({})).ok();
        assert_eq!(delivery_told(socket, &id), Vec::<Value>::new());
        assert_eq!(relay.pending(&second), 1);
    });
}

/// A deliver of a payment with no route left is refused and changes nothing: the payer lists
/// no relay past its own, so the link has one route. The relay stays silent, so the payment
/// stays uncertain; a retry of its post may still run beside the call, so the delivery's
/// `updated_at`, `attempts` and `next_attempt_at` are left out of the comparison, and the relay's count of posts
/// is not compared either: the retry posts on the one route there is.
#[test]
fn a_deliver_with_no_route_left_is_refused_and_changes_nothing() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let relay = host.relay.clone();
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let id = pay_unanswered(socket, &relay, &link);
        let path = format!("/api/v1/payments/{id}");
        let before = http(socket, "GET", &path, None).ok();
        assert!(actions(&before).contains(&"deliver"), "{before}");

        let refused = post(socket, &format!("{path}/deliver"), &json!({}));
        let refused = problem(&refused, 409, "no_more_routes");
        assert_eq!(refused["payment_id"], id.as_str(), "{refused}");

        let after = http(socket, "GET", &path, None).ok();
        assert_eq!(unchanged_part(&after), unchanged_part(&before), "{after}");
        assert_eq!(delivery_told(socket, &id), [json!("uncertain")]);
    });
}

/// Moves the node's tip to `height` and syncs until the wallet confirms it: the first sync
/// after a move holds the new tip, the next confirms it.
fn confirm_tip(socket: &Path, node: &MockNode, height: u64) {
    node.update_chain(|chain| chain.tip.height = Height::new(height));
    post(socket, "/api/v1/sync", &json!({})).ok();
    let synced = post(socket, "/api/v1/sync", &json!({})).ok();
    assert_eq!(synced["height"], height, "{synced}");
}

/// Moves the tip to `height` in steps of a thousand blocks: the node client refuses one report
/// more than a day of blocks above the tip it saw before.
fn confirm_tip_in_steps(socket: &Path, node: &MockNode, from: u64, height: u64) {
    let mut at = from;
    while at < height {
        at = height.min(at.saturating_add(1_000));
        confirm_tip(socket, node, at);
    }
}

/// Once the chain reaches an uncertain epic1 payment's cutoff, the payment has expired: it
/// offers no `deliver`, and a deliver is refused. The payer lists no relay past its own, and
/// that relay stays silent throughout, so the payment cannot go out before it expires.
#[test]
fn a_deliver_past_the_cutoff_is_refused_and_not_offered() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let relay = host.relay.clone();
    let node = host.node.clone();
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        // A short TTL keeps the cutoff within the tip the wallet believes.
        let ttl = 10;
        let id = pay_unanswered_with(socket, &relay, &json!({ "to": link, "ttl_blocks": ttl }));
        let path = format!("/api/v1/payments/{id}");
        let offered = http(socket, "GET", &path, None).ok();
        assert!(actions(&offered).contains(&"deliver"), "{offered}");
        confirm_tip(socket, &node, support::TIP + ttl);
        let before = http(socket, "GET", &path, None).ok();
        assert_eq!(before["state"], "expired", "{before}");
        assert_eq!(before["state_reason"], "expired_no_answer", "{before}");
        assert!(actions(&before).is_empty(), "{before}");

        let refused = post(socket, &format!("{path}/deliver"), &json!({}));
        let refused = problem(&refused, 409, "action_not_available");
        assert_eq!(refused["payment_id"], id.as_str(), "{refused}");

        let after = http(socket, "GET", &path, None).ok();
        assert_eq!(unchanged_part(&after), unchanged_part(&before), "{after}");
    });
}

/// A payment that names no `ttl_blocks` waits seven days of blocks, 10080, for an answer, and no
/// longer: the cutoff is the service's `send_ttl_blocks`.
#[test]
fn a_payment_with_no_ttl_expires_after_ten_thousand_and_eighty_blocks() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let relay = host.relay.clone();
    let node = host.node.clone();
    let clock = host.clock.clone();
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let id = pay_unanswered_with(socket, &relay, &json!({ "to": link }));
        let path = format!("/api/v1/payments/{id}");
        // The wallet believes a tip only as far above the first one as the clock allows.
        clock.advance(Duration::from_secs(8 * 24 * 3600));
        confirm_tip_in_steps(socket, &node, support::TIP, support::TIP + 10_079);
        let waiting = http(socket, "GET", &path, None).ok();
        assert_ne!(waiting["state"], "expired", "{waiting}");
        confirm_tip(socket, &node, support::TIP + 10_080);
        let expired = http(socket, "GET", &path, None).ok();
        assert_eq!(expired["state"], "expired", "{expired}");
        assert_eq!(expired["state_reason"], "expired_no_answer", "{expired}");
    });
}

/// One payment read alone is the same object as its item in the list, for each kind of payment
/// the list holds: a send, an invoice, an epic1 payment, an invoice waiting for approval and a
/// declined one.
#[test]
fn a_payment_read_alone_equals_its_item_in_the_list() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    host.fund(SENDER_MNEMONIC, 1, FUNDING, 2);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let issuer = new_wallet(&host, "issuer password");
    let invoices: Vec<(String, String)> = ["waiting.slate", "declined.slate"]
        .iter()
        .map(|name| {
            let file = issuer.path(name);
            let issued = issuer
                .run(
                    &host,
                    &["invoice", "issue", "3", "--to-file", file.to_str().unwrap()],
                )
                .ok()
                .json();
            (
                text(&issued, "slate_id").to_owned(),
                std::fs::read_to_string(&file).unwrap(),
            )
        })
        .collect();
    let relay = host.relay.clone();
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let mut ids = vec![send_by_hand(socket)];
        let invoice = post(
            socket,
            "/api/v1/payments",
            &json!({ "kind": "invoice", "amount": "2", "via": "file" }),
        );
        assert_eq!(invoice.status, 201, "{invoice:?}");
        ids.push(text(&invoice.json(), "id").to_owned());
        ids.push(pay_unanswered(socket, &relay, &link));
        for (id, text) in &invoices {
            let opened = post(socket, "/api/v1/open", &json!({ "text": text })).ok();
            assert_eq!(opened["outcome"], "invoice_parked", "{opened}");
            ids.push(id.clone());
        }
        let declined = &invoices[1].0;
        post(
            socket,
            &format!("/api/v1/payments/{declined}/decline"),
            &json!({}),
        )
        .ok();

        let listed = http(socket, "GET", "/api/v1/payments?limit=100", None).ok();
        let items = listed["items"].as_array().unwrap();
        for id in &ids {
            let alone = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
            let item = items
                .iter()
                .find(|item| item["id"] == id.as_str())
                .unwrap_or_else(|| panic!("{id} not in {listed}"));
            assert_eq!(&alone, item, "{id}");
        }
    });
}

#[test]
fn an_estimate_and_a_send_to_an_epicbox_address_name_the_slate_size() {
    let (host, wallet) = funded();
    let (_receiver, address) = receiver(&host);
    serving(host, &wallet, |socket, _| {
        let body = json!({ "amount": "1", "to": address });
        let estimate = post(socket, "/api/v1/payments/estimate", &body).ok();
        let bytes = estimate["slate_bytes"].as_u64().unwrap();
        assert_eq!(estimate["slate_limit"], 131_071, "{estimate}");
        assert!(bytes > 1_000 && bytes < 131_071, "{estimate}");
        // A slate handed back by file never goes through the relay.
        let by_hand = post(
            socket,
            "/api/v1/payments/estimate",
            &json!({ "amount": "1", "via": "file" }),
        )
        .ok();
        assert!(by_hand.get("slate_bytes").is_none(), "{by_hand}");

        let created = post(socket, "/api/v1/payments", &body);
        assert_eq!(created.status, 201, "{created:?}");
        let created = created.json();
        assert_eq!(created["slate_bytes"], bytes, "{created}");
        assert_eq!(created["slate_limit"], 131_071, "{created}");
    });
}

/// Sends `POST /payments` with `body` and leaves the answer unread; dropping the stream is a
/// client that gave up.
fn post_unread(socket: &Path, body: &Value) -> UnixStream {
    let mut stream = UnixStream::connect(socket).unwrap();
    let body = body.to_string();
    write!(
        stream,
        "POST /api/v1/payments HTTP/1.1\r\nHost: lepic\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream
}

/// `POST /payments` with `body`, answered within [`PATIENCE`]: a create that runs instead of
/// answering fails here rather than after the long patience of [`http`].
fn post_within(socket: &Path, body: &Value) -> support::Reply {
    let mut stream = post_unread(socket, body);
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .unwrap_or_else(|error| panic!("no answer within {PATIENCE:?}: {error}"));
    let reply = support::parse_reply(&answer);
    support::contract::check("POST", "/payments", &reply);
    reply
}

/// The requests serve is answering, the one that asks included.
fn in_flight(socket: &Path) -> u64 {
    http(socket, "GET", "/api/v1/status", None).ok()["requests"]["in_flight"]
        .as_u64()
        .unwrap()
}

/// Waits until serve has let go of every connection but the one that asks.
fn callers_gone(socket: &Path) {
    wait_until("serve saw the callers leave", || in_flight(socket) == 1);
}

#[test]
fn a_send_whose_caller_left_is_made_once_and_its_repeat_gets_the_handoff() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, client| {
        let id = "2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f6a";
        let body = json!({ "id": id, "amount": "1", "via": "file" });
        client.tip_gate.close();
        let caller = post_unread(socket, &body);
        wait_until("the create runs", || {
            post_within(socket, &body).status == 409
        });
        drop(caller);
        callers_gone(socket);
        let waiting = post_within(socket, &body);
        problem(&waiting, 409, "in_progress");
        assert!(waiting.header("retry-after").is_some(), "{waiting:?}");
        client.tip_gate.open();
        let mut repeated = None;
        wait_until("the create ends", || {
            let reply = post_within(socket, &body);
            let ended = reply.status != 409;
            repeated = Some(reply);
            ended
        });
        let repeated = repeated.unwrap().ok();
        let handoff = &repeated["handoff"];
        assert_eq!(handoff["format"], "slate", "{repeated}");
        assert!(text(handoff, "text").contains(id), "{repeated}");
        let path = format!("/api/v1/payments/{id}/handoff");
        let read = http(socket, "GET", &path, None).ok();
        assert_eq!(read["text"], handoff["text"], "{read}");
        assert_eq!(count_of(socket, "send"), 1);
    });
}

#[test]
fn a_create_running_when_serve_stops_is_made_by_its_repeat() {
    let (host, wallet) = funded();
    let again = host.without_interrupt();
    let id = "3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a7b";
    let body = json!({ "id": id, "amount": "1", "via": "file" });
    serving(host, &wallet, |socket, client| {
        client.tip_gate.close();
        let caller = post_unread(socket, &body);
        wait_until("the create runs", || {
            post_within(socket, &body).status == 409
        });
        drop(caller);
        callers_gone(socket);
    });
    again.tip_gate.open();
    serving(again, &wallet, |socket, _| {
        let made = post(socket, "/api/v1/payments", &body);
        assert_eq!(made.status, 201, "{made:?}");
        assert_eq!(made.json()["id"], id, "{made:?}");
        assert_eq!(count_of(socket, "send"), 1);
    });
}

/// Makes the payment `body` asks for by file, takes its handoff away from the note it is kept
/// in, and reads the handoff after a restart: the same text, rebuilt from the stored slate.
fn handoff_rebuilt(body: &Value) {
    let (host, wallet) = funded();
    let again = host.without_interrupt();
    let made = serving(host, &wallet, |socket, _| {
        let created = post(socket, "/api/v1/payments", body);
        assert_eq!(created.status, 201, "{created:?}");
        created.json()
    });
    let id = text(&made, "id").to_owned();
    with_settings(&wallet, SENDER_MNEMONIC, |repos| {
        repos.delete_setting(&format!("api.payment.{id}"))
    });
    serving(again, &wallet, |socket, _| {
        let path = format!("/api/v1/payments/{id}/handoff");
        let read = http(socket, "GET", &path, None).ok();
        assert_eq!(read["text"], made["handoff"]["text"], "{read}");
        assert_eq!(read["format"], "slate", "{read}");
    });
}

#[test]
fn the_handoff_of_a_send_by_hand_is_rebuilt_when_its_note_is_gone() {
    let id = "4f5a6b7c-8d9e-4f0a-9b1c-2d3e4f5a6b7c";
    handoff_rebuilt(&json!({ "id": id, "amount": "1", "via": "file" }));
}

#[test]
fn the_handoff_of_an_invoice_by_hand_is_rebuilt_when_its_note_is_gone() {
    let id = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
    handoff_rebuilt(&json!({ "id": id, "kind": "invoice", "amount": "2", "via": "file" }));
}

#[test]
fn a_send_by_hand_that_ended_with_its_note_gone_has_no_handoff() {
    let (host, wallet) = funded();
    let again = host.without_interrupt();
    let id = "9e0f1a2b-3c4d-4e5f-8a6b-7c8d9e0f1a2b";
    let body = json!({ "id": id, "amount": "1", "via": "file" });
    serving(host, &wallet, |socket, _| {
        assert_eq!(post(socket, "/api/v1/payments", &body).status, 201);
        let cancel = format!("/api/v1/payments/{id}/cancel");
        let cancelled = post(socket, &cancel, &json!({})).ok();
        assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
    });
    with_settings(&wallet, SENDER_MNEMONIC, |repos| {
        repos.delete_setting(&format!("api.payment.{id}"))
    });
    serving(again, &wallet, |socket, _| {
        let repeated = post(socket, "/api/v1/payments", &body).ok();
        assert_eq!(repeated["id"], id, "{repeated}");
        assert_eq!(repeated["delivery"]["state"], "by_hand", "{repeated}");
        assert!(repeated["handoff"].is_null(), "{repeated}");
        let path = format!("/api/v1/payments/{id}/handoff");
        problem(&http(socket, "GET", &path, None), 409, "no_handoff");
    });
}

#[test]
fn a_create_over_the_connection_bound_is_busy_and_keeps_nothing() {
    let mut host = TestHost::new();
    host.api_limits = Some(ApiLimits {
        max_connections: 2,
        header_timeout: PATIENCE,
        body_timeout: PATIENCE,
        max_body: 64 * 1024,
        tls_max_age: PATIENCE,
    });
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let invoice = |id: &str, amount: &str| {
        json!({
            "id": id, "kind": "invoice", "amount": amount, "via": "file"
        })
    };
    let finished = invoice("5f6a7b8c-9d0e-4f1a-8b2c-3d4e5f6a7b8c", "1");
    serving(host, &wallet, |socket, client| {
        assert_eq!(post(socket, "/api/v1/payments", &finished).status, 201);
        client.tip_gate.close();
        for id in [
            "6b7c8d9e-0f1a-4b2c-9d3e-4f5a6b7c8d9e",
            "7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f",
        ] {
            let caller = post_unread(socket, &invoice(id, "2"));
            wait_until("the create runs", || {
                post_within(socket, &invoice(id, "2")).status == 409
            });
            drop(caller);
            callers_gone(socket);
        }
        let refused_before =
            http(socket, "GET", "/api/v1/status", None).ok()["requests"]["refused"]
                .as_u64()
                .unwrap();
        let id = "8d9e0f1a-2b3c-4d4e-9f5a-6b7c8d9e0f1a";
        let busy = post_within(socket, &invoice(id, "3"));
        problem(&busy, 503, "busy");
        assert!(busy.header("retry-after").is_some(), "{busy:?}");
        let status = http(socket, "GET", "/api/v1/status", None).ok();
        assert_eq!(
            status["requests"]["refused"].as_u64(),
            Some(refused_before + 1),
            "{status}"
        );
        // The bound holds new creates only: a repeat of a made payment is answered.
        let repeated = post_within(socket, &finished).ok();
        assert_eq!(repeated["id"], finished["id"], "{repeated}");
        client.tip_gate.open();
        wait_until("the jobs end", || count_of(socket, "invoice") == 3);
        // Nothing was kept for the id: another body under it is a new create. A job frees its
        // place under the bound only after its payment is stored, so the create may still meet
        // `busy` (which keeps nothing) for a moment.
        let mut made = None;
        wait_until("the bound frees", || {
            let reply = post(socket, "/api/v1/payments", &invoice(id, "4"));
            let freed = reply.status != 503;
            made = Some(reply);
            freed
        });
        let made = made.unwrap();
        assert_eq!(made.status, 201, "{made:?}");
        assert_eq!(count_of(socket, "invoice"), 4);
    });
}

/// A payment to a link that asks a message carries it when the body names none, and none when
/// the body's message is empty.
#[test]
fn an_empty_message_pays_a_link_without_the_message_it_asks() {
    for (message, kept) in [(None, Some("for tea")), (Some(""), None)] {
        let (host, wallet) = funded();
        offer_own_relay_only(&wallet);
        let payee = new_wallet(&host, "payee password");
        let made = payee
            .run(&host, &["epic1", "link", "2", "-m", "for tea"])
            .ok()
            .json();
        let link = text(&made, "link").to_owned();
        super::api_wallet::serving_public(host, &wallet, |socket| {
            let mut body = json!({ "to": link });
            if let Some(message) = message {
                body["message"] = json!(message);
            }
            let paid = post(socket, "/api/v1/payments", &body);
            assert_eq!(paid.status, 201, "{paid:?}");
            let id = text(&paid.json(), "id").to_owned();
            let payment = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
            assert_eq!(payment["message"].as_str(), kept, "{message:?}: {payment}");
        });
    }
}

/// A payment made through an epic1 link or address reads as `via: "link"`, with the address it
/// went to as the counterparty, on its create answer, on GET and in the list.
#[test]
fn a_payment_to_an_epic1_address_is_shown_as_a_link_payment() {
    for by_address in [true, false] {
        // A wallet for each: the change of the first payment is locked until it confirms.
        let (host, wallet) = funded();
        offer_own_relay_only(&wallet);
        let payee = new_wallet(&host, "payee password");
        let body = if by_address {
            let made = payee.run(&host, &["epic1", "address"]).ok().json();
            json!({ "to": text(&made, "address"), "amount": "1" })
        } else {
            let made = payee.run(&host, &["epic1", "link", "2"]).ok().json();
            json!({ "to": text(&made, "link") })
        };
        super::api_wallet::serving_public(host, &wallet, |socket| {
            let paid = post(socket, "/api/v1/payments", &body);
            assert_eq!(paid.status, 201, "{paid:?}");
            let id = text(&paid.json(), "id").to_owned();
            assert_eq!(paid.json()["via"], "link", "{paid:?}");
            let shown = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
            assert_eq!(shown["via"], "link", "{shown}");
            let counterparty = shown["counterparty"]["address"].as_str().unwrap_or("");
            assert!(counterparty.contains("epic1"), "{shown}");
            let listed = http(socket, "GET", "/api/v1/payments", None).ok();
            let item = listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["id"] == id.as_str())
                .unwrap();
            assert_eq!(item["via"], "link", "{item}");
            assert_eq!(item["counterparty"], shown["counterparty"], "{item}");
        });
    }
}

/// A send cancelled before any relay took it reads as not delivered, and keeps the reason the
/// post failed for.
#[test]
fn a_cancelled_send_that_was_never_delivered_reads_as_not_delivered() {
    let (host, wallet) = funded();
    let (_receiver, address) = receiver(&host);
    host.relay.set_refusing(true);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        // The post is refused, so the answer is the failure; the id names the payment kept.
        let id = "5d1c1f5e-6b0a-4b7e-9a57-0c7f4f3b2a11";
        let made = post(
            socket,
            "/api/v1/payments",
            &json!({ "to": address, "amount": "1", "id": id }),
        );
        assert_eq!(made.status, 201, "{made:?}");
        let before = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
        let error = before["delivery"]["error"].clone();
        assert!(error.is_string(), "a read keeps the error: {before}");
        let cancelled = http(
            socket,
            "POST",
            &format!("/api/v1/payments/{id}/cancel"),
            None,
        )
        .ok();
        assert_eq!(cancelled["state"], "cancelled", "{cancelled}");
        let shown = http(socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
        let state = shown["delivery"]["state"].as_str().unwrap_or("");
        assert!(["uncertain", "failed"].contains(&state), "{shown}");
        assert_eq!(shown["delivery"]["undelivered"], true, "{shown}");
        assert_eq!(shown["delivery"]["error"], error, "{shown}");
    });
}

/// Mailboxes are refused at `/mailboxes` for a payment that does not go to an epic1 address,
/// and for a host that is not a public name, before anything is sent.
#[test]
fn mailboxes_are_refused_where_a_payment_cannot_use_them() {
    let (host, wallet) = funded();
    let (_receiver, address) = receiver(&host);
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let before = http(socket, "GET", "/api/v1/payments", None).ok();
        let to_address =
            json!({ "amount": "1", "to": address, "mailboxes": ["mailbox.example.org"] });
        let local = json!({ "to": link, "mailboxes": ["localhost"] });
        for body in [to_address, local] {
            let refused = problem(
                &post(socket, "/api/v1/payments", &body),
                400,
                "invalid_field",
            );
            assert_eq!(refused["param"], "/mailboxes", "{refused}");
        }
        // Nothing was sent: the same payments in the same states. Whole items are not compared,
        // as `confirmations` appears once the served wallet has read the node's height.
        let after = http(socket, "GET", "/api/v1/payments", None).ok();
        let listed = |page: &Value| -> Vec<(Value, Value)> {
            let items = page["items"].as_array().unwrap();
            items
                .iter()
                .map(|item| (item["id"].clone(), item["state"].clone()))
                .collect()
        };
        assert_eq!(listed(&after), listed(&before), "{before} then {after}");
    });
}

/// A bare epic1 address, as `GET /addresses` lists it, pays as its link does.
#[test]
fn a_bare_epic1_address_is_paid_as_its_link() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let payee = new_wallet(&host, "payee password");
    let made = payee.run(&host, &["epic1", "address"]).ok().json();
    let address = text(&made, "address").to_owned();
    assert!(
        address.starts_with("epic1") || address.starts_with("tepic1"),
        "{address}"
    );
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let paid = post(
            socket,
            "/api/v1/payments",
            &json!({ "to": address, "amount": "2" }),
        );
        assert_eq!(paid.status, 201, "{paid:?}");
        assert_eq!(paid.json()["amount"], "2.00000000", "{paid:?}");
    });
}

/// `via` is one of its values and the route `to` takes; it never changes the route. A mismatch
/// is 400 `via_mismatch` at `/via`, before anything is stored.
#[test]
fn a_via_that_does_not_match_the_destination_is_refused() {
    let (host, wallet) = funded();
    let (_receiver, address) = receiver(&host);
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let before = http(socket, "GET", "/api/v1/payments", None).ok();
        let nonsense = post(
            socket,
            "/api/v1/payments",
            &json!({ "to": address, "amount": "1", "via": "nonsense" }),
        );
        let refused = problem(&nonsense, 400, "invalid_field");
        assert_eq!(refused["param"], "/via", "{refused}");

        let mismatched = [
            json!({ "to": "http://127.0.0.1:8080/admin", "amount": "1", "via": "epicbox" }),
            json!({ "to": address, "amount": "1", "via": "http" }),
            json!({ "to": address, "amount": "1", "via": "tor" }),
            json!({ "to": link, "via": "epicbox" }),
            json!({ "to": "contact:7", "amount": "1", "via": "epicbox" }),
        ];
        for body in mismatched {
            let refused = problem(
                &post(socket, "/api/v1/payments", &body),
                400,
                "via_mismatch",
            );
            assert_eq!(refused["param"], "/via", "{body}: {refused}");
        }
        // Nothing was stored. Only the ids are compared: serve's first refresh may add the
        // tip's fields, such as `confirmations`, to a payment between the two listings.
        let after = http(socket, "GET", "/api/v1/payments", None).ok();
        let ids = |list: &Value| -> Vec<Value> {
            list["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["id"].clone())
                .collect()
        };
        assert_eq!(ids(&after), ids(&before), "{before} then {after}");
    });
}

/// A `via` that names the route `to` takes is accepted: `epicbox` for an address.
#[test]
fn a_via_epicbox_on_an_address_is_accepted() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let (_receiver, address) = receiver(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let body = json!({ "to": address, "amount": "0.1", "via": "epicbox" });
        let paid = post(socket, "/api/v1/payments", &body);
        assert_eq!(paid.status, 201, "{body}: {paid:?}");
    });
}

/// A `via` that names the route `to` takes is accepted: `link` for a payment link.
#[test]
fn a_via_link_on_a_payment_link_is_accepted() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let link = stranger_link(&host);
    super::api_wallet::serving_public(host, &wallet, |socket| {
        let body = json!({ "to": link, "via": "link" });
        let paid = post(socket, "/api/v1/payments", &body);
        assert_eq!(paid.status, 201, "{body}: {paid:?}");
    });
}
