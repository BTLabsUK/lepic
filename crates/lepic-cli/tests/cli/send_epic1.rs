// SPDX-License-Identifier: Apache-2.0
//! `lepic tx send --to` an epic1 address or link: the address decides the protocol, so the send
//! is the payment `lepic epic1 pay` makes, with its checks and its report. A flag that has no
//! meaning for that payment is refused before anything is stored.

// Tests may unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::support;

use serde_json::Value;
use support::{Instance, SHIPPED_MAILBOXES, TestHost, funded, new_wallet, text};

/// The payer's own relay, under a public name: an epic1 payment is not posted through a relay
/// on this device, and the mock relay answers for any host.
const PUBLIC_RELAY: &str = support::PUBLIC_MAILBOX;

/// `wallet` runs `args` with its own relay at [`PUBLIC_RELAY`].
fn run_public(wallet: &Instance, host: &TestHost, args: &[&str]) -> support::Outcome {
    let mut env = wallet.env();
    for (name, value) in &mut env {
        if name == "LEPIC_EPICBOX_RELAY" {
            *value = format!("wss://{PUBLIC_RELAY}");
        }
    }
    wallet.run_with(host, args, env, "")
}

/// Makes [`PUBLIC_RELAY`] the stopped wallet's only mailbox, so a payment it makes to an epic1
/// address is posted once, on its own relay.
fn offer_own_relay_only(wallet: &Instance) {
    wallet.with_mailboxes(&[PUBLIC_RELAY]);
}

/// The first epic1 address of a new wallet that is never served.
fn stranger_address(host: &TestHost) -> String {
    let payee = new_wallet(host, "payee password");
    let made = payee.run(host, &["epic1", "address"]).ok().json();
    text(&made, "address").to_owned()
}

/// A link for 2 EPIC of a new wallet that is never served, without entries.
fn stranger_link(host: &TestHost) -> String {
    let payee = new_wallet(host, "payee password");
    let made = payee.run(host, &["epic1", "link", "2"]).ok().json();
    text(&made, "link").to_owned()
}

/// How many envelopes wait in the delivery mailbox of `to`, a link or a bare address, on the
/// payer's relay.
fn pending(host: &TestHost, to: &str) -> usize {
    let mailbox = lepic_wallet_contacts::epic1_testing::delivery_mailbox(to, PUBLIC_RELAY).unwrap();
    host.relay.pending(&mailbox)
}

/// The wallet's transactions, as `tx list` shows them.
fn transactions(wallet: &Instance, host: &TestHost) -> Value {
    wallet.run(host, &["tx", "list"]).ok().json()["transactions"].clone()
}

/// What the transaction `tx_id` sent, fee left out, in the smallest unit.
fn sent(wallet: &Instance, host: &TestHost, tx_id: &Value) -> u64 {
    let shown = wallet
        .run(host, &["tx", "show", &tx_id.to_string()])
        .ok()
        .json();
    let units = |field: &str| text(&shown, field).replace('.', "").parse::<u64>().unwrap();
    units("amount_debited") - units("amount_credited") - units("fee")
}

/// Asserts `paid` is the report `epic1 pay` gives for a payment posted to the mailbox of
/// `address`.
fn assert_paid_to_mailbox(paid: &Value, address: &str) {
    assert_eq!(paid["address"], address, "{paid}");
    assert_eq!(paid["posted_ok"], true, "{paid}");
    assert_eq!(paid["repeated"], false, "{paid}");
    assert!(paid["tx_id"].is_u64(), "{paid}");
    assert!(paid["attempts"].is_array(), "{paid}");
    // The same fields a send to any other address reports.
    assert_eq!(paid["transport"], "epic1", "{paid}");
    assert_eq!(paid["destination"], address, "{paid}");
    for field in ["amount", "fee", "state"] {
        assert!(paid[field].is_string(), "{field}: {paid}");
    }
}

#[test]
fn a_send_to_a_bare_epic1_address_is_paid_as_epic1_pay_pays_it() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let address = stranger_address(&host);

    let paid = run_public(&wallet, &host, &["tx", "send", "1.5", "--to", &address])
        .ok()
        .json();
    assert_paid_to_mailbox(&paid, &address);
    assert_eq!(paid["amount"], "1.50000000", "{paid}");
    assert_eq!(pending(&host, &address), 1);
    assert_eq!(sent(&wallet, &host, &paid["tx_id"]), 150_000_000);
}

#[test]
fn a_send_to_a_link_pays_the_amount_it_asks() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let link = stranger_link(&host);

    let paid = run_public(&wallet, &host, &["tx", "send", "--to", &link])
        .ok()
        .json();
    let address = text(&paid, "address").to_owned();
    assert!(link.contains(&address), "{paid}");
    assert_paid_to_mailbox(&paid, &address);
    assert_eq!(pending(&host, &link), 1);
    assert_eq!(sent(&wallet, &host, &paid["tx_id"]), 200_000_000);
}

#[test]
fn a_send_to_a_link_with_another_amount_pays_that_amount() {
    // The link only fills in the payment: the payer may pay another amount.
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let link = stranger_link(&host);

    let paid = run_public(&wallet, &host, &["tx", "send", "3", "--to", &link])
        .ok()
        .json();
    let address = text(&paid, "address").to_owned();
    assert!(link.contains(&address), "{paid}");
    assert_paid_to_mailbox(&paid, &address);
    assert_eq!(pending(&host, &link), 1);
    assert_eq!(sent(&wallet, &host, &paid["tx_id"]), 300_000_000);
}

#[test]
fn a_flag_an_epic1_payment_has_no_use_for_is_refused_before_anything_is_stored() {
    let (host, wallet) = funded();
    let address = stranger_address(&host);
    let before = transactions(&wallet, &host);

    let refused = run_public(
        &wallet,
        &host,
        &["tx", "send", "1", "--to", &address, "--fluff"],
    );
    assert_eq!(refused.code, 2, "{refused:?}");
    let error = &refused.json()["error"];
    assert_eq!(error["kind"], "usage", "{error}");
    assert!(text(error, "message").contains("--fluff"), "{error}");
    assert_eq!(pending(&host, &address), 0);
    assert_eq!(transactions(&wallet, &host), before);
}

#[test]
fn epic1_pay_takes_a_bare_address_as_the_link_that_pays_it() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let address = stranger_address(&host);

    let paid = run_public(&wallet, &host, &["epic1", "pay", &address, "1.5"])
        .ok()
        .json();
    assert_paid_to_mailbox(&paid, &address);
    assert_eq!(pending(&host, &address), 1);
    assert_eq!(sent(&wallet, &host, &paid["tx_id"]), 150_000_000);
}

#[test]
fn a_send_to_an_epicbox_address_without_an_amount_is_a_usage_error() {
    let (host, wallet) = funded();
    let payee = new_wallet(&host, "payee password");
    let address = payee.run(&host, &["wallet", "address"]).ok().json();
    let before = transactions(&wallet, &host);

    let refused = wallet.run(&host, &["tx", "send", "--to", text(&address, "address")]);
    assert_eq!(refused.code, 2, "{refused:?}");
    let error = &refused.json()["error"];
    assert_eq!(error["kind"], "usage", "{error}");
    assert!(text(error, "message").contains("AMOUNT"), "{error}");
    assert_eq!(transactions(&wallet, &host), before);
}

/// The messages of the transaction `tx_id`, as `tx show` shows them.
fn messages(wallet: &Instance, host: &TestHost, tx_id: &Value) -> Value {
    let shown = wallet
        .run(host, &["tx", "show", &tx_id.to_string()])
        .ok()
        .json();
    shown["messages"].clone()
}

#[test]
fn an_empty_message_pays_a_link_without_the_message_it_asks() {
    let link_with_message = |host: &TestHost| {
        let payee = new_wallet(host, "payee password");
        let made = payee
            .run(host, &["epic1", "link", "2", "-m", "for tea"])
            .ok()
            .json();
        text(&made, "link").to_owned()
    };

    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let link = link_with_message(&host);
    let paid = run_public(&wallet, &host, &["epic1", "pay", &link])
        .ok()
        .json();
    let kept = messages(&wallet, &host, &paid["tx_id"]);
    assert!(kept.to_string().contains("for tea"), "{kept}");

    for empty in ["", "   "] {
        let (host, wallet) = funded();
        offer_own_relay_only(&wallet);
        let link = link_with_message(&host);
        let paid = run_public(&wallet, &host, &["epic1", "pay", &link, "-m", empty])
            .ok()
            .json();
        assert_paid_to_mailbox(&paid, text(&paid, "address"));
        let kept = messages(&wallet, &host, &paid["tx_id"]);
        assert!(!kept.to_string().contains("for tea"), "{empty:?}: {kept}");
    }
}

/// A payer whose list keeps no shipped mailbox is refused with exit code 14 before anything is
/// stored; the same payment with `--mailbox` goes through the mailbox given alone.
#[test]
fn a_payer_sharing_no_mailbox_pays_only_through_a_mailbox_it_gives() {
    let (host, wallet) = funded();
    wallet.with_mailboxes(&["mine.example.org"]);
    host.relay.set_relays_apart(true);
    let link = stranger_link(&host);
    let before = transactions(&wallet, &host);

    let refused = run_public(&wallet, &host, &["epic1", "pay", &link]);
    assert_eq!(refused.code, 14, "{refused:?}");
    let error = refused.json()["error"].clone();
    assert_eq!(error["kind"], "no_shared_mailbox", "{error}");
    assert_eq!(transactions(&wallet, &host), before);

    let paid = run_public(
        &wallet,
        &host,
        &["epic1", "pay", &link, "--mailbox", "Given.Example.Org"],
    )
    .ok()
    .json();
    assert_paid_to_mailbox(&paid, text(&paid, "address"));
    let on = |domain: &str| {
        let mailbox =
            lepic_wallet_contacts::epic1_testing::delivery_mailbox(&link, domain).unwrap();
        host.relay.pending(&mailbox)
    };
    assert_eq!(on("given.example.org"), 1);
    for other in SHIPPED_MAILBOXES.into_iter().chain(["mine.example.org"]) {
        assert_eq!(on(other), 0, "{other}");
    }
}

/// A mailbox that refuses the post says so in the attempt: its words, the wait it asked for in
/// seconds and that the post may go again.
#[test]
fn an_epic1_post_a_mailbox_refuses_reports_its_reason_and_retry_seconds() {
    let (host, wallet) = funded();
    offer_own_relay_only(&wallet);
    let address = stranger_address(&host);
    host.relay.set_post_refusal(Some((
        "InvalidRequest",
        "Rate limit exceeded; retry in 12 s.",
    )));

    let paid = run_public(&wallet, &host, &["tx", "send", "1", "--to", &address])
        .ok()
        .json();
    assert_eq!(paid["posted_ok"], false, "{paid}");
    let refusal = &paid["attempts"][0]["refusal"];
    assert_eq!(refusal["retry_after_secs"], 12, "{paid}");
    assert!(
        text(refusal, "reason").contains("Rate limit exceeded"),
        "{paid}"
    );
    assert_eq!(refusal["retryable"], true, "{paid}");
    assert!(text(refusal, "text").contains("retry in 12 s"), "{paid}");
}

/// The epic1 address of a 0.5.x wallet (65 data bytes, no version byte).
const EARLIER_ADDRESS: &str = "epic1qxzjpuqf3yc2w4r53d7aedp77adqm0e6p5nrsxh5awj2nr42nd8x5qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhxjd58y";

#[test]
fn a_send_to_an_address_of_an_earlier_wallet_has_its_own_exit_code() {
    let (host, wallet) = funded();
    let before = transactions(&wallet, &host);

    let refused = run_public(
        &wallet,
        &host,
        &["tx", "send", "1", "--to", EARLIER_ADDRESS],
    );
    assert_eq!(refused.code, 16, "{refused:?}");
    let error = &refused.json()["error"];
    assert_eq!(error["kind"], "earlier_address", "{error}");
    assert_eq!(error["exit_code"], 16, "{error}");
    assert!(
        error["causes"].to_string().contains("older wallet version"),
        "{error}"
    );
    assert_eq!(transactions(&wallet, &host), before);
}
