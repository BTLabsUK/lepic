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

mod support;

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use support::{
    FUNDING, Instance, SENDER_MNEMONIC, TestHost, funded, http, new_wallet, problem, serving, text,
    wait_until,
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
        let cases = [
            (address.as_str(), "epicbox_address", "pay"),
            ("http://203.0.113.7:3415", "http_address", "pay"),
            (onion, "onion_address", "pay"),
            ("epic:pay?amount=1", "link", "open"),
            ("hello there", "unknown", "none"),
            ("{\"not\":\"a slate\"}", "unknown", "none"),
        ];
        for (input, kind, next) in cases {
            let read = post(socket, "/api/v1/inspect", &json!({ "text": input })).ok();
            assert_eq!(read["type"], kind, "{input}: {read}");
            assert_eq!(read["next"], next, "{input}: {read}");
            if next == "pay" {
                assert_eq!(read["summary"]["to"], input, "{read}");
            }
        }

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
