// SPDX-License-Identifier: Apache-2.0
//! Files opened by hand through the wallet API v1: sealed sends and invoices from a paired
//! contact, the cap and the expiry of the invoices held for approval, and the handoff of a
//! repeated open. Every answer is checked against `docs/api/openapi.json` by `support::http`.
//! The calls go over the socket; `tests/api_tls.rs` checks the roles over TLS.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;

use std::path::Path;

use lepic_primitives::amount::Height;
use lepic_wallet::slate::ur_slate::{MAX_FRAGMENT_LEN, encode_ur_slate};
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

/// The entry for `contact_id` in the instance's `contact list`.
fn listed(instance: &Instance, host: &TestHost, contact_id: &str) -> Value {
    let list = instance.run(host, &["contact", "list"]).ok().json();
    list["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|contact| contact["contact_id"] == contact_id)
        .cloned()
        .unwrap_or_else(|| panic!("{contact_id} not in {list}"))
}

/// Pairs the two by an invite link and returns the inviter's and the joiner's contact ids.
fn pair(host: &TestHost, inviter: &Instance, joiner: &Instance) -> (String, String) {
    let invite = inviter
        .run(host, &["contact", "invite", "--name", "Payer"])
        .ok()
        .json();
    let joined = joiner
        .run(
            host,
            &["contact", "accept", text(&invite, "link"), "--name", "Shop"],
        )
        .ok()
        .json();
    let ids = (
        text(&invite, "contact_id").to_owned(),
        text(&joined, "contact_id").to_owned(),
    );
    wait_until("both sides paired", || {
        inviter.run(host, &["contact", "collect"]).ok();
        joiner.run(host, &["contact", "collect"]).ok();
        listed(inviter, host, &ids.0)["state"] == "paired"
            && listed(joiner, host, &ids.1)["state"] == "paired"
    });
    // A seal needs each side to have heard the other since the pairing: the SAS verdicts
    // carry that both ways.
    inviter.run(host, &["contact", "sas", &ids.0, "match"]).ok();
    joiner.run(host, &["contact", "sas", &ids.1, "match"]).ok();
    wait_until("both sides verified", || {
        inviter.run(host, &["contact", "collect"]).ok();
        joiner.run(host, &["contact", "collect"]).ok();
        listed(inviter, host, &ids.0)["peer_verified_at"].is_string()
            && listed(joiner, host, &ids.1)["peer_verified_at"].is_string()
    });
    ids
}

/// A funded payer and a new shop, paired.
struct Paired {
    host: TestHost,
    payer: Instance,
    shop: Instance,
    /// The shop's contact id for the payer.
    shop_side: String,
    /// The payer's contact id for the shop.
    payer_side: String,
}

fn paired() -> Paired {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let shop = new_wallet(&host, "shop password");
    let (shop_side, payer_side) = pair(&host, &shop, &payer);
    Paired {
        host,
        payer,
        shop,
        shop_side,
        payer_side,
    }
}

/// `wallet`'s invoice for `amount` as a slate file, and its slate id and local tx id.
fn invoice(wallet: &Instance, host: &TestHost, amount: &str, name: &str) -> (String, String, u64) {
    let file = wallet.path(name);
    let issued = wallet
        .run(
            host,
            &[
                "invoice",
                "issue",
                amount,
                "--to-file",
                file.to_str().unwrap(),
            ],
        )
        .ok()
        .json();
    (
        std::fs::read_to_string(&file).unwrap(),
        text(&issued, "slate_id").to_owned(),
        issued["tx_id"].as_u64().unwrap(),
    )
}

/// Seals transaction `tx_id` of `wallet` to its contact `contact_id`.
fn seal(wallet: &Instance, host: &TestHost, contact_id: &str, tx_id: u64) -> String {
    let sealed = wallet
        .run(host, &["contact", "seal", contact_id, &tx_id.to_string()])
        .ok()
        .json();
    assert_eq!(sealed["action"], "sealed", "{sealed}");
    text(&sealed, "text").to_owned()
}

/// The balance of the default account.
/// The first account's total and locked amounts: what a payment changes. The rest moves as
/// serve sees the funding confirm.
fn balance(socket: &Path) -> (Value, Value) {
    let accounts = http(socket, "GET", "/api/v1/accounts", None).ok();
    let balance = &accounts["items"][0]["balance"];
    (balance["total"].clone(), balance["locked"].clone())
}

fn is_sealed_format(handoff: &Value) -> bool {
    handoff["format"] == "sealed" || handoff["format"] == "epictx"
}

#[test]
fn a_sealed_send_is_read_received_and_answered_sealed() {
    let Paired {
        host,
        payer,
        shop,
        shop_side,
        payer_side,
    } = paired();
    let file = payer.path("payment.slate");
    let sent = payer
        .run(
            &host,
            &["tx", "send", "2", "--to-file", file.to_str().unwrap()],
        )
        .ok()
        .json();
    let slate_id = text(&sent, "slate_id").to_owned();
    let sealed = seal(&payer, &host, &payer_side, sent["tx_id"].as_u64().unwrap());
    // Sealed by the shop for the payer: the shop's keys do not open it.
    let (_, _, invoice_tx) = invoice(&shop, &host, "1", "unrelated.slate");
    let not_ours = seal(&shop, &host, &shop_side, invoice_tx);

    serving(host, &shop, |socket, client| {
        let before = http(socket, "GET", "/api/v1/payments", None).ok();
        let inspected = post(socket, "/api/v1/inspect", &json!({ "text": sealed })).ok();
        assert_eq!(inspected["type"], "sealed", "{inspected}");
        assert_eq!(inspected["next"], "open", "{inspected}");
        assert_eq!(epic(&inspected["summary"]["amount"]), 2.0, "{inspected}");
        assert_eq!(
            inspected["summary"]["contact_id"],
            shop_side.as_str(),
            "{inspected}"
        );
        let after = http(socket, "GET", "/api/v1/payments", None).ok();
        assert_eq!(before, after, "inspect changed the payments");

        let closed = post(socket, "/api/v1/inspect", &json!({ "text": not_ours })).ok();
        assert_eq!(closed["type"], "sealed", "{closed}");
        assert_eq!(closed["next"], "none", "{closed}");
        let refused = problem(
            &post(socket, "/api/v1/open", &json!({ "text": not_ours })),
            409,
            "nothing_to_open",
        );
        assert!(
            refused["detail"]
                .as_str()
                .unwrap()
                .contains("does not open with this wallet's keys"),
            "{refused}"
        );

        let opened = post(socket, "/api/v1/open", &json!({ "text": sealed })).ok();
        assert_eq!(opened["outcome"], "received", "{opened}");
        assert_eq!(opened["payment"]["id"], slate_id.as_str(), "{opened}");
        assert_eq!(opened["payment"]["direction"], "in", "{opened}");
        assert!(is_sealed_format(&opened["handoff"]), "{opened}");
        let answer = text(&opened["handoff"], "text").to_owned();

        let again = post(socket, "/api/v1/open", &json!({ "text": sealed })).ok();
        assert_eq!(again["outcome"], "already_done", "{again}");
        assert_eq!(again["handoff"]["text"], answer.as_str(), "{again}");

        let reply = payer.path("payment.epicsealed.response");
        std::fs::write(&reply, &answer).unwrap();
        let finalized = payer
            .run(client, &["contact", "open-sealed", reply.to_str().unwrap()])
            .ok()
            .json();
        assert_eq!(finalized["action"], "finalized", "{finalized}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

#[test]
fn a_sealed_invoice_waits_for_approval_and_is_paid_sealed() {
    let Paired {
        host,
        payer,
        shop,
        shop_side,
        payer_side,
    } = paired();
    let (_, slate_id, tx_id) = invoice(&shop, &host, "1.5", "invoice.slate");
    let sealed = seal(&shop, &host, &shop_side, tx_id);

    serving(host, &payer, |socket, client| {
        let inspected = post(socket, "/api/v1/inspect", &json!({ "text": sealed })).ok();
        assert_eq!(inspected["type"], "sealed", "{inspected}");
        assert_eq!(inspected["next"], "pay", "{inspected}");
        assert_eq!(epic(&inspected["summary"]["amount"]), 1.5, "{inspected}");
        assert_eq!(
            inspected["summary"]["contact_id"],
            payer_side.as_str(),
            "{inspected}"
        );

        let funds = balance(socket);
        let opened = post(socket, "/api/v1/open", &json!({ "text": sealed })).ok();
        assert_eq!(opened["outcome"], "invoice_parked", "{opened}");
        let parked = &opened["payment"];
        assert_eq!(parked["id"], slate_id.as_str(), "{opened}");
        assert_eq!(parked["state"], "needs_approval", "{opened}");
        assert_eq!(
            parked["counterparty"]["contact_id"],
            payer_side.as_str(),
            "{opened}"
        );
        assert_eq!(balance(socket), funds);
        assert!(client.node.pushed_transactions().is_empty());
        let held = http(socket, "GET", "/api/v1/payments?state=needs_approval", None).ok();
        assert_eq!(held["items"][0]["id"], slate_id.as_str(), "{held}");

        let approve = format!("/api/v1/payments/{slate_id}/approve");
        let kept = problem(
            &post(
                socket,
                &approve,
                &json!({ "amount": "1.5", "deliver": false }),
            ),
            400,
            "invalid_field",
        );
        assert_eq!(kept["param"], "/deliver", "{kept}");
        assert_eq!(balance(socket), funds);
        let paid = post(socket, &approve, &json!({ "amount": "1.5" })).ok();
        assert_eq!(paid["id"], slate_id.as_str(), "{paid}");
        assert_eq!(paid["direction"], "out", "{paid}");
        assert_ne!(paid["state"], "needs_approval", "{paid}");
        assert!(is_sealed_format(&paid["handoff"]), "{paid}");
        let answer = text(&paid["handoff"], "text").to_owned();

        let reply = shop.path("invoice.epicsealed.response");
        std::fs::write(&reply, answer).unwrap();
        let finalized = shop
            .run(client, &["contact", "open-sealed", reply.to_str().unwrap()])
            .ok()
            .json();
        assert_eq!(finalized["action"], "finalized", "{finalized}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

#[test]
fn a_contact_invoice_shows_its_message_on_both_sides() {
    let Paired {
        host,
        payer,
        shop,
        shop_side,
        payer_side,
    } = paired();
    payer
        .run(&host, &["contact", "allow-invoices", &payer_side, "on"])
        .ok();
    shop.run(&host, &["contact", "collect"]).ok();
    serving(host, &shop, |socket, client| {
        let body = json!({
            "kind": "invoice", "amount": "1.5", "to": format!("contact:{shop_side}"),
            "message": "order 42", "ttl_blocks": 30,
        });
        let made = post(socket, "/api/v1/payments", &body);
        assert_eq!(made.status, 201, "{made:?}");
        let made = made.json();
        assert_eq!(made["message"], "order 42", "{made}");
        assert_eq!(made["expires_at_height"], support::TIP + 30, "{made}");
        payer.run(client, &["contact", "collect"]).ok();
        let held = payer.run(client, &["contact", "invoices"]).ok().json();
        assert_eq!(held["invoices"][0]["message"], "order 42", "{held}");
    });
}

/// `slate` with its TTL cutoff set to `height`.
fn with_cutoff(slate: &str, height: u64) -> String {
    let mut value: Value = serde_json::from_str(slate).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("ttl_cutoff_height".to_owned(), json!(height));
    value.to_string()
}

#[test]
fn held_invoices_have_a_cap_and_drop_out_once_expired() {
    let (mut host, wallet) = funded();
    host.max_held = Some(1);
    let issuer = new_wallet(&host, "issuer password");
    let (first, first_id, _) = invoice(&issuer, &host, "1", "first.slate");
    let first = with_cutoff(&first, support::TIP + 10);
    let (second, second_id, _) = invoice(&issuer, &host, "2", "second.slate");

    serving(host, &wallet, |socket, client| {
        let held = |socket: &Path| -> Vec<String> {
            let list = http(socket, "GET", "/api/v1/payments?state=needs_approval", None).ok();
            list["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| text(item, "id").to_owned())
                .collect()
        };
        let opened = post(socket, "/api/v1/open", &json!({ "text": first })).ok();
        assert_eq!(opened["outcome"], "invoice_parked", "{opened}");
        let full = problem(
            &post(socket, "/api/v1/open", &json!({ "text": second })),
            409,
            "too_many_held",
        );
        assert!(
            full["detail"]
                .as_str()
                .unwrap()
                .contains("approve or decline one first"),
            "{full}"
        );
        // A repeat of the invoice already held is not one more.
        let again = post(socket, "/api/v1/open", &json!({ "text": first })).ok();
        assert_eq!(again["outcome"], "already_done", "{again}");
        assert_eq!(held(socket), std::slice::from_ref(&first_id));

        client
            .node
            .update_chain(|chain| chain.tip.height = Height::new(support::TIP + 30));
        wait_until("the expired invoice is dropped", || held(socket).is_empty());
        let opened = post(socket, "/api/v1/open", &json!({ "text": second })).ok();
        assert_eq!(opened["outcome"], "invoice_parked", "{opened}");
        assert_eq!(held(socket), std::slice::from_ref(&second_id));
    });
}

/// A funded payer's send of 1 as a slate file, its path, and the wallet that will serve.
fn plain_send() -> (TestHost, Instance, Instance, String) {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let wallet = new_wallet(&host, "serving password");
    let slate = payer.path("payment.slate");
    payer
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok();
    let text = std::fs::read_to_string(&slate).unwrap();
    (host, payer, wallet, text)
}

#[test]
fn a_plain_send_with_the_lepic_marker_is_answered_sealed_to_its_reply_key() {
    let (host, payer, wallet, slate_text) = plain_send();
    serving(host, &wallet, |socket, client| {
        let opened = post(socket, "/api/v1/open", &json!({ "text": slate_text })).ok();
        assert_eq!(opened["outcome"], "received", "{opened}");
        let handoff = &opened["handoff"];
        assert_eq!(handoff["format"], "sealed", "{opened}");
        let id = text(&opened["payment"], "id");
        assert_eq!(
            handoff["file_name"],
            format!("{id}.epicsealed.response"),
            "{opened}"
        );
        // Sealed text is no slate JSON, so it has no QR frames, even when asked.
        let qr = format!("/api/v1/payments/{id}/handoff?qr=true");
        problem(&http(socket, "GET", &qr, None), 409, "format_not_available");

        let reply = payer.path("payment.epicsealed.response");
        std::fs::write(&reply, text(handoff, "text")).unwrap();
        let finalized = payer
            .run(client, &["contact", "open-sealed", reply.to_str().unwrap()])
            .ok()
            .json();
        assert_eq!(finalized["action"], "finalized", "{finalized}");
        assert_eq!(client.node.pushed_transactions().len(), 1);
    });
}

#[test]
fn a_repeated_open_hands_back_the_stored_answer_with_frames_when_asked() {
    let (host, _payer, wallet, slate_text) = plain_send();
    // Without the LEPIC marker, as a legacy wallet sends it: the answer goes plain, as JSON
    // that fits QR frames.
    let mut legacy: Value = serde_json::from_str(&slate_text).unwrap();
    legacy.as_object_mut().unwrap().remove("lepic").unwrap();
    let legacy = legacy.to_string();
    let frames = encode_ur_slate(&legacy, MAX_FRAGMENT_LEN).unwrap();

    serving(host, &wallet, |socket, _| {
        let opened = post(socket, "/api/v1/open", &json!({ "text": legacy })).ok();
        assert_eq!(opened["outcome"], "received", "{opened}");
        assert_eq!(opened["handoff"]["format"], "slate", "{opened}");
        assert!(opened["handoff"].get("qr_frames").is_none(), "{opened}");
        let answer = text(&opened["handoff"], "text").to_owned();

        let again = post(socket, "/api/v1/open", &json!({ "qr_frames": frames })).ok();
        assert_eq!(again["outcome"], "already_done", "{again}");
        assert_eq!(again["handoff"]["text"], answer.as_str(), "{again}");
        assert!(
            !again["handoff"]["qr_frames"]
                .as_array()
                .unwrap_or_else(|| panic!("no frames: {again}"))
                .is_empty(),
            "{again}"
        );
        // The frames belong to that answer only: the stored handoff is unchanged.
        let id = text(&opened["payment"], "id");
        let path = format!("/api/v1/payments/{id}/handoff");
        let stored = http(socket, "GET", &path, None).ok();
        assert_eq!(stored["text"], answer.as_str(), "{stored}");
        assert!(stored.get("qr_frames").is_none(), "{stored}");
    });
}
