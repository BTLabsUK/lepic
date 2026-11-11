// SPDX-License-Identifier: Apache-2.0
//! Paired contacts between CLI instances on the mock relay: the contact check answered by a
//! serving wallet, the move of a wallet's own home relay (ADR 0040), and the host app's
//! payloads.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use support::{
    FUNDING, Instance, SENDER_MNEMONIC, TestHost, http, text, wait_for_socket, wait_until,
};

/// The relay the mover moves to. The settings file offers it, so the CLI knows its endpoint.
const NEW_HOME: &str = "relay2.test";

/// A new wallet whose settings file lists [`NEW_HOME`] among its Epicbox servers.
fn wallet_offering_new_home(host: &TestHost, password: &str) -> Instance {
    let wallet = Instance::new(password);
    let dir = wallet.home.path().join(".lepic");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("settings.toml"),
        format!("[epicbox]\nservers = [\"{NEW_HOME}\"]\n"),
    )
    .unwrap();
    wallet.run(host, &["wallet", "init"]).ok();
    wallet
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

fn collect(instance: &Instance, host: &TestHost) -> Value {
    instance.run(host, &["contact", "collect"]).ok().json()
}

/// Pairs the two by an invite link and returns the inviter's and the joiner's contact ids.
fn pair(host: &TestHost, inviter: &Instance, joiner: &Instance) -> (String, String) {
    let invite = inviter
        .run(host, &["contact", "invite", "--name", "Shop"])
        .ok()
        .json();
    let joined = joiner
        .run(
            host,
            &[
                "contact",
                "accept",
                text(&invite, "link"),
                "--name",
                "Buyer",
            ],
        )
        .ok()
        .json();
    let ids = (
        text(&invite, "contact_id").to_owned(),
        text(&joined, "contact_id").to_owned(),
    );
    wait_until("both sides paired", || {
        collect(inviter, host);
        collect(joiner, host);
        listed(inviter, host, &ids.0)["state"] == "paired"
            && listed(joiner, host, &ids.1)["state"] == "paired"
    });
    ids
}

/// After both sides answer `match`, `contact list` carries the SAS indexes and when the contact's
/// verdict was accepted.
#[test]
fn a_verified_contact_lists_its_sas_indexes_and_verdict_time() {
    let host = TestHost::new();
    let shop = Instance::new("shop password");
    shop.run(&host, &["wallet", "init"]).ok();
    let buyer = Instance::new("buyer password");
    buyer.run(&host, &["wallet", "init"]).ok();
    let (shop_side, buyer_side) = pair(&host, &shop, &buyer);
    shop.run(&host, &["contact", "sas", &shop_side, "match"])
        .ok();
    buyer
        .run(&host, &["contact", "sas", &buyer_side, "match"])
        .ok();
    wait_until("the verdicts accepted", || {
        collect(&shop, &host);
        collect(&buyer, &host);
        listed(&shop, &host, &shop_side)["peer_verified_at"].is_string()
            && listed(&buyer, &host, &buyer_side)["peer_verified_at"].is_string()
    });
    let contact = listed(&shop, &host, &shop_side);
    assert_eq!(
        contact["sas_indexes"].as_array().unwrap().len(),
        4,
        "{contact}"
    );
    assert_eq!(contact["status"], "verified", "{contact}");
    assert!(contact["peer_heard_at"].is_string(), "{contact}");
    assert_eq!(contact["ended_reason"], Value::Null, "{contact}");
}

/// `lepic serve` answers a check by itself; the asking wallet's next collect takes the answer
/// and `contact list` shows the contact heard again.
/// A wallet that paid a LEPIC peer over Epicbox asks it to pair at its payments address. The
/// request goes out over Epicbox, so the command attaches the wallet's identity first.
#[test]
fn a_pairing_request_to_a_paid_peer_is_posted() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let shop = Instance::new("shop password");
    shop.run(&host, &["wallet", "init"]).ok();
    let address = shop.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();
    payer
        .run(&host, &["tx", "send", "2", "--to", &address])
        .ok();
    shop.run(&host, &["epicbox", "drain"]).ok();
    let drained = payer.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(drained["finalized"], 1, "{drained}");

    let request = payer
        .run(&host, &["contact", "request", &address, "--name", "Payer"])
        .ok()
        .json();
    assert!(request["contact_id"].is_string(), "{request}");
    assert!(
        text(&request, "link").starts_with("epiccash://pair/"),
        "{request}"
    );
}

/// A wallet that paid a LEPIC peer and asked it to pair: the request is listed as sent until it
/// is withdrawn, the peer lists it as received, and a withdrawn request lets a new one go out.
#[test]
fn a_pairing_request_is_listed_on_both_sides_and_can_be_withdrawn_or_dismissed() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let shop = Instance::new("shop password");
    shop.run(&host, &["wallet", "init"]).ok();
    let address = shop.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();
    payer
        .run(&host, &["tx", "send", "2", "--to", &address])
        .ok();
    shop.run(&host, &["epicbox", "drain"]).ok();
    payer.run(&host, &["epicbox", "drain"]).ok();

    let request = payer
        .run(&host, &["contact", "request", &address, "--name", "Payer"])
        .ok()
        .json();
    let contact_id = text(&request, "contact_id").to_owned();

    let sent = payer.run(&host, &["contact", "list"]).ok().json();
    let sent = sent["sent_requests"].as_array().unwrap().clone();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["contact_id"], contact_id.as_str());
    assert_eq!(sent[0]["to_address"], address.as_str());
    // A second request to the same address is refused while the first stands.
    let again = payer.run(&host, &["contact", "request", &address]);
    assert_ne!(again.code, 0, "{again:?}");
    assert_eq!(again.json()["error"]["kind"], "rejected");

    let seen = shop.run(&host, &["epicbox", "drain"]).ok().json();
    drop(seen);
    let received = shop.run(&host, &["contact", "requests"]).ok().json();
    let received = received["requests"].as_array().unwrap().clone();
    assert_eq!(received.len(), 1, "{received:?}");
    assert!(
        text(&received[0], "invite_link").starts_with("epiccash://pair/"),
        "{received:?}"
    );
    let request_id = text(&received[0], "request_id").to_owned();
    let dismissed = shop
        .run(&host, &["contact", "request-dismiss", &request_id])
        .ok()
        .json();
    assert_eq!(dismissed["dismissed"], true, "{dismissed}");
    let received = shop.run(&host, &["contact", "requests"]).ok().json();
    assert!(received["requests"].as_array().unwrap().is_empty());
    let unknown = shop.run(&host, &["contact", "request-dismiss", &request_id]);
    assert_eq!(unknown.code, 6, "{unknown:?}");
    assert_eq!(unknown.json()["error"]["kind"], "not_found");

    let cancelled = payer
        .run(&host, &["contact", "request-cancel", &contact_id])
        .ok()
        .json();
    assert_eq!(cancelled["cancelled"], true, "{cancelled}");
    let sent = payer.run(&host, &["contact", "list"]).ok().json();
    assert!(sent["sent_requests"].as_array().unwrap().is_empty());
    payer
        .run(&host, &["contact", "request", &address, "--name", "Payer"])
        .ok();
}

#[test]
fn removing_an_unknown_contact_is_not_found() {
    let host = TestHost::new();
    let wallet = Instance::new("wallet password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let failed = wallet.run(
        &host,
        &["contact", "remove", "0123456789abcdef0123456789abcdef"],
    );
    assert_eq!(failed.code, 6, "{failed:?}");
    assert_eq!(failed.json()["error"]["kind"], "not_found");
}

#[test]
fn an_empty_profile_value_clears_it_and_no_value_is_a_usage_error() {
    let host = TestHost::new();
    let wallet = Instance::new("wallet password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let set = wallet
        .run(&host, &["profile", "set", "no-payments"])
        .ok()
        .json();
    assert_ne!(set["profile"], 0, "{set}");
    let cleared = wallet.run(&host, &["profile", "set", ""]).ok().json();
    assert_eq!(cleared["profile"], 0, "{cleared}");
    assert_eq!(wallet.run(&host, &["profile", "set"]).code, 2);
}

#[test]
fn a_contact_check_is_answered_by_a_serving_wallet() {
    let mut host = TestHost::new();
    let shop = Instance::new("shop password");
    shop.run(&host, &["wallet", "init"]).ok();
    let buyer = Instance::new("buyer password");
    buyer.run(&host, &["wallet", "init"]).ok();
    let (_, shop_id) = pair(&host, &shop, &buyer);
    // The joiner may not have heard the shop since the pairing; the answer sets it either way.
    let heard = listed(&buyer, &host, &shop_id)["last_heard"].clone();

    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let client = host.without_interrupt();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();

    let served = std::thread::scope(|scope| {
        let server = support::serve_thread(scope, || {
            shop.run(&host, &["serve", "--socket", socket_arg])
        });
        wait_for_socket(&socket);
        // The check leaves after the pairing's last message, so its answer is heard later.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let checked = buyer
            .run(&client, &["contact", "check", &shop_id])
            .ok()
            .json();
        assert_eq!(checked["contact_id"], shop_id.as_str());
        wait_until("the answer heard", || {
            collect(&buyer, &client);
            let now = &listed(&buyer, &client, &shop_id)["last_heard"];
            now.is_string() && *now != heard
        });
        let status = http(&socket, "GET", "/api/v1/status", None).ok();
        assert_eq!(status["collect"]["failures"], 0, "{status}");
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap()
    });
    served.ok();
    let contact = listed(&buyer, &client, &shop_id);
    assert_eq!(contact["state"], "paired", "{contact}");
    assert_eq!(contact["requested_relay"], Value::Null, "{contact}");
}

/// The mover tells each contact once and reads only its new mailboxes. A contact that takes the
/// update is asked to follow, follows with `contact move --apply`, and pays the mover on the new
/// relay. A contact whose update expired unread keeps writing to the old mailbox: its check gets
/// no answer and it never hears the mover again.
#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_contact_follows_a_moved_home_and_one_that_missed_the_move_goes_unanswered() {
    let host = TestHost::new();
    // The CLI's relay and the new home are separate relays.
    host.relay.set_relays_apart(true);
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let shop = wallet_offering_new_home(&host, "shop password");
    let buyer = Instance::new("buyer password");
    buyer.restore(&host, SENDER_MNEMONIC);
    let late = Instance::new("late password");
    late.run(&host, &["wallet", "init"]).ok();
    let (buyer_at_shop, shop_at_buyer) = pair(&host, &shop, &buyer);
    let (_, shop_at_late) = pair(&host, &shop, &late);
    let old_home = listed(&buyer, &host, &shop_at_buyer)["home_relay"].clone();

    let moved = shop
        .run(&host, &["contact", "move-home", NEW_HOME])
        .ok()
        .json();
    assert_eq!(moved["moved"], 2, "{moved}");
    // Moved once, a second move to the same relay tells nobody.
    let again = shop
        .run(&host, &["contact", "move-home", NEW_HOME])
        .ok()
        .json();
    assert_eq!(again["moved"], 0, "{again}");

    // The buyer takes the update and is asked to follow; the late contact's update expires.
    collect(&buyer, &host);
    let asked = listed(&buyer, &host, &shop_at_buyer);
    let new_home = text(&asked, "requested_relay").to_owned();
    assert!(new_home.starts_with(NEW_HOME), "{asked}");
    assert_eq!(
        listed(&shop, &host, &buyer_at_shop)["home_relay"],
        new_home.as_str()
    );
    host.relay.expire_all();

    let followed = buyer
        .run(
            &host,
            &["contact", "move", &shop_at_buyer, "--apply", &new_home],
        )
        .ok()
        .json();
    assert_eq!(followed["home_relay"], new_home.as_str(), "{followed}");
    assert_eq!(followed["requested_relay"], Value::Null, "{followed}");
    collect(&buyer, &host);
    let heard_buyer = listed(&shop, &host, &buyer_at_shop)["last_heard"].clone();
    wait_until("the shop hears the buyer on the new relay", || {
        collect(&shop, &host);
        listed(&shop, &host, &buyer_at_shop)["last_heard"] != heard_buyer
    });

    // A payment to the moved shop goes through its new mailbox and back.
    let sent = buyer
        .run(&host, &["tx", "send", "2", "--to-contact", &shop_at_buyer])
        .ok()
        .json();
    wait_until("the buyer posts the payment", || {
        collect(&shop, &host);
        collect(&buyer, &host);
        !host.node.pushed_transactions().is_empty()
    });
    let list = buyer.run(&host, &["tx", "list"]).ok().json();
    let tx = list["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tx| tx["slate_id"] == sent["slate_id"])
        .cloned()
        .unwrap();
    assert_eq!(tx["state"], "posted", "{tx}");

    // The late contact never heard of the move: its check goes to the old mailbox.
    let before = listed(&late, &host, &shop_at_late);
    assert_eq!(before["requested_relay"], Value::Null, "{before}");
    assert_eq!(before["home_relay"], old_home, "{before}");
    late.run(&host, &["contact", "check", &shop_at_late]).ok();
    collect(&shop, &host);
    collect(&late, &host);
    let after = listed(&late, &host, &shop_at_late);
    assert_eq!(after["last_heard"], before["last_heard"], "{after}");
    assert_eq!(after["requested_relay"], Value::Null, "{after}");
    assert_eq!(after["state"], "paired", "{after}");
}

fn payloads(instance: &Instance, host: &TestHost) -> Vec<Value> {
    let list = instance
        .run(host, &["contact", "payload", "list"])
        .ok()
        .json();
    list["payloads"].as_array().unwrap().clone()
}

/// A posts bytes given as hex and as a file; B's collect takes both, the list shows them as
/// sent, and once acknowledged they are gone.
#[test]
fn a_payload_posted_to_a_contact_is_listed_until_acknowledged() {
    let host = TestHost::new();
    let shop = Instance::new("shop password");
    shop.run(&host, &["wallet", "init"]).ok();
    let buyer = Instance::new("buyer password");
    buyer.run(&host, &["wallet", "init"]).ok();
    let (buyer_at_shop, shop_at_buyer) = pair(&host, &shop, &buyer);

    let posted = shop
        .run(
            &host,
            &[
                "contact",
                "payload",
                "post",
                &buyer_at_shop,
                "--hex",
                "00ff10",
            ],
        )
        .ok()
        .json();
    assert_eq!(posted["contact_id"], buyer_at_shop.as_str(), "{posted}");
    assert_eq!(posted["peer_lacks_app_payloads"], false, "{posted}");
    let by_hex = text(&posted, "payload_id").to_owned();
    let file = shop.home.path().join("payload.bin");
    std::fs::write(&file, b"from a file").unwrap();
    let by_file = shop
        .run(
            &host,
            &[
                "contact",
                "payload",
                "post",
                &buyer_at_shop,
                "--file",
                file.to_str().unwrap(),
            ],
        )
        .ok()
        .json();
    let by_file = text(&by_file, "payload_id").to_owned();

    collect(&buyer, &host);
    let kept = payloads(&buyer, &host);
    assert_eq!(kept.len(), 2, "{kept:?}");
    let entry = |id: &str| kept.iter().find(|kept| kept["id"] == id).unwrap().clone();
    assert_eq!(entry(&by_hex)["payload"], "00ff10");
    assert_eq!(entry(&by_file)["payload"], "66726f6d20612066696c65");
    for kept in &kept {
        assert_eq!(kept["contact_id"], shop_at_buyer.as_str(), "{kept}");
        assert!(kept["received_at"].is_string(), "{kept}");
    }

    let acked = buyer
        .run(&host, &["contact", "payload", "ack", &by_hex, &by_file])
        .ok()
        .json();
    assert_eq!(acked["acknowledged"], 2, "{acked}");
    assert!(payloads(&buyer, &host).is_empty());
}
