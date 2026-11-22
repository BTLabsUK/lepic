// SPDX-License-Identifier: Apache-2.0
//! `lepic serve`'s timed tick of the delivery layer. Each tick of the timer asks the push
//! sessions what waits and posts the outbox rows that fell due, and a boost of the relays brings
//! the next tick forward. A `tor` entry of a link is reached only through tor.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};
use support::{
    FUNDING, Instance, SENDER_MNEMONIC, TestHost, funded, http, new_wallet, problem, serving, text,
    wait_until, wait_until_within,
};

use super::api_wallet::{serving_public, serving_public_with};

/// How often serve ticks here when no test says otherwise: several ticks a second.
const TICK: Duration = Duration::from_millis(200);

/// Far longer than any test runs: no timed tick comes after the first.
const NO_TICK: Duration = Duration::from_secs(3600);

/// The payer's own relay here, under a public name: the mock relays answer for any host.
const PUBLIC_RELAY: &str = support::PUBLIC_MAILBOX;

/// A v3 onion a `tor` entry names; nothing serves it.
const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

/// When serve's last tick that worked ended, as `GET /status` tells it.
fn last_tick(socket: &Path) -> Value {
    http(socket, "GET", "/api/v1/status", None).ok()["collect"]["last_success_at"].clone()
}

/// Waits for `count` more ticks to end.
fn wait_ticks(socket: &Path, count: usize) {
    for _ in 0..count {
        let before = last_tick(socket);
        wait_until("a tick ends", || last_tick(socket) != before);
    }
}

/// A link for 2 EPIC of a new wallet that is never served, with the CLI flags `entries`.
fn stranger_link(host: &TestHost, entries: &[&str]) -> String {
    let payee = new_wallet(host, "payee password");
    let mut args = vec!["epic1", "link", "2"];
    args.extend_from_slice(entries);
    let made = payee.run(host, &args).ok().json();
    text(&made, "link").to_owned()
}

#[test]
fn each_tick_of_the_timer_asks_the_sessions_what_waits() {
    let host = TestHost::with_mux(TICK);
    let wallet = Instance::new("serving password");
    wallet.on_public_mailbox();
    wallet.restore(&host, SENDER_MNEMONIC);
    serving(host, &wallet, |socket, host| {
        let relay = host.mux.as_ref().unwrap();
        let invited = http(
            socket,
            "POST",
            "/api/v1/contacts",
            Some(r#"{"method":"invite","label":"Buyer"}"#),
        );
        assert_eq!(invited.status, 201, "{invited:?}");
        // The payments address, the mailbox of the public epic1 address and the invite's inbox.
        wait_until("the three mailboxes are attached", || {
            relay.attached().len() == 3
        });
        wait_ticks(socket, 1);
        let asked = relay.received("Waiting");
        // Nothing is pushed here: the ticks that follow are the timer's.
        wait_until("three more ticks ask what waits", || {
            relay.received("Waiting") >= asked + 3
        });
    });
}

#[test]
fn an_epic1_payment_between_two_serves_completes_by_push_alone() {
    // The relay pushes native mail to mux/1 sessions and takes the outbox's posts on short
    // connections, as an Epicbox relay that offers mux/1 does.
    let mut host = TestHost::new();
    host.collect = Some(NO_TICK);
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("serving password");
    payer.restore(&host, SENDER_MNEMONIC);
    let payee = new_wallet(&host, "payee password");
    let node = host.node.clone();
    let payee_host = host.without_interrupt();
    serving_public(host, &payer, |payer_socket| {
        serving_public(payee_host, &payee, |payee_socket| {
            let link = http(
                payee_socket,
                "POST",
                "/api/v1/links",
                Some(r#"{"amount":"2"}"#),
            );
            assert_eq!(link.status, 200, "{link:?}");
            let link = text(&link.json(), "text").to_owned();
            let paid = http(
                payer_socket,
                "POST",
                "/api/v1/payments",
                Some(&json!({ "to": link }).to_string()),
            );
            assert_eq!(paid.status, 201, "{paid:?}");
            // Both serves tick an hour apart: only pushed mail brings the payee's answer.
            wait_until_within(
                "the payer posts the transaction",
                Duration::from_secs(60),
                || !node.pushed_transactions().is_empty(),
            );
            assert_eq!(node.pushed_transactions().len(), 1);

            // The payee lists the payment it took, with no link named in it. It came to the
            // payee's epic1 address, so it reads as a link payment from a payer with no
            // address, in the list, on GET and under the `via` filter.
            let listed = http(payee_socket, "GET", "/api/v1/payments?direction=in", None).ok();
            let item = &listed["items"][0];
            assert_eq!(item["amount"], "2.00000000", "{listed}");
            assert!(item.get("link_id").is_none(), "{listed}");
            assert_eq!(item["via"], "link", "{listed}");
            assert_eq!(item["our_address"]["type"], "epic1", "{listed}");
            assert!(item["counterparty"].is_null(), "{listed}");
            let id = text(item, "id");
            let shown = http(payee_socket, "GET", &format!("/api/v1/payments/{id}"), None).ok();
            assert_eq!(shown["via"], "link", "{shown}");
            let by_link = http(payee_socket, "GET", "/api/v1/payments?via=link", None).ok();
            assert_eq!(by_link["items"][0]["id"], item["id"], "{by_link}");
        });
    });
}

#[test]
fn a_tick_posts_again_an_unanswered_payment_once_it_falls_due() {
    let mut host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.with_mailboxes(&[PUBLIC_RELAY]);
    wallet.restore(&host, SENDER_MNEMONIC);
    host.collect = Some(TICK);
    let link = stranger_link(&host, &[]);
    let (relay, clock) = (host.relay.clone(), std::sync::Arc::clone(&host.clock));
    serving_public(host, &wallet, |socket| {
        // The first tick, at start, posts every queued row: wait until later ticks post only
        // the due ones.
        wait_until("the first tick ends", || last_tick(socket).is_string());
        wait_ticks(socket, 1);
        relay.set_domain_unanswered(PUBLIC_RELAY);
        let before = relay.received("PostSlate");
        let paid = http(
            socket,
            "POST",
            "/api/v1/payments",
            Some(&json!({ "to": link }).to_string()),
        );
        assert_eq!(paid.status, 201, "{paid:?}");
        // The call that made the row posts it once.
        assert_eq!(relay.received("PostSlate"), before + 1);
        let posts = relay.received("PostSlate");
        // The first retry falls due 30 s after the post went unanswered.
        wait_ticks(socket, 3);
        assert_eq!(relay.received("PostSlate"), posts);
        clock.advance(Duration::from_secs(31));
        wait_until("a tick posts the payment again", || {
            relay.received("PostSlate") > posts
        });
    });
}

/// A classic send whose post failed stays in the outbox. Serve's tick posts it again once the
/// back-off of its one failed attempt (60 s) has passed, as a call of `deliver` does by hand.
#[test]
fn a_tick_posts_again_an_undelivered_classic_send_once_it_falls_due() {
    let mut host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let receiver = new_wallet(&host, "payee password");
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();
    host.relay.set_refusing(true);
    let sent = wallet.run(&host, &["tx", "send", "1", "--to", &address]);
    assert_eq!(sent.code, 11, "{sent:?}");
    host.relay.set_refusing(false);
    host.collect = Some(TICK);
    let (relay, clock) = (host.relay.clone(), std::sync::Arc::clone(&host.clock));
    serving(host, &wallet, |socket, _| {
        wait_until("the first tick ends", || last_tick(socket).is_string());
        let attempts = |socket| {
            let listed = http(socket, "GET", "/api/v1/payments", None).ok();
            listed["items"][0]["delivery"]["attempts"].clone()
        };
        assert_eq!(attempts(socket), 1, "the refused first post counts once");
        // The send failed 0 s ago on the clock: its first repost is not due.
        wait_ticks(socket, 3);
        assert_eq!(relay.received("PostSlate"), 0);
        clock.advance(Duration::from_secs(61));
        wait_until("a tick posts the send again", || {
            relay.received("PostSlate") == 1
        });
        // Delivered, the row is done: later ticks post nothing more.
        wait_ticks(socket, 3);
        assert_eq!(relay.received("PostSlate"), 1);
        assert_eq!(attempts(socket), 2, "the repost counts as a second attempt");
    });
}

#[test]
fn a_relays_boost_brings_the_next_tick_forward() {
    let (mut host, wallet) = funded();
    host.collect = Some(NO_TICK);
    serving(host, &wallet, |socket, _| {
        wait_until("the first tick ends", || last_tick(socket).is_string());
        let boost = http(
            socket,
            "POST",
            "/api/v1/sync/boost",
            Some(r#"{"poller":"relays","duration_seconds":60,"interval_seconds":5}"#),
        );
        assert_eq!(boost.status, 201, "{boost:?}");
        // A session that attaches starts one tick at most; only the boost brings three.
        wait_ticks(socket, 3);
    });
}

#[test]
fn a_tor_entry_is_posted_through_tor_or_not_at_all() {
    // Two coins: each payment locks one.
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    host.fund(SENDER_MNEMONIC, 1, FUNDING, 2);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let pay = |link: &str, tor: bool| {
        let mut env = wallet.env();
        // The relay the payer's own entry names must be one other devices reach.
        for (name, value) in &mut env {
            if name == "LEPIC_EPICBOX_RELAY" {
                *value = format!("wss://{PUBLIC_RELAY}");
            }
        }
        if tor {
            env.push((
                "LEPIC_EPICBOX_TOR_SOCKS".to_owned(),
                "127.0.0.1:9050".to_owned(),
            ));
        }
        let paid = wallet
            .run_with(&host, &["epic1", "pay", link], env, "")
            .ok()
            .json();
        assert_eq!(paid["posted_ok"], false, "{paid}");
        assert_eq!(paid["attempts"][0]["host"], ONION, "{paid}");
        paid
    };

    let off = pay(&stranger_link(&host, &["--tor", ONION]), false);
    assert_eq!(off["attempts"][0]["error"], "Tor is not available", "{off}");
    assert!(host.dialer.dialed().is_empty());
    assert_eq!(host.relay.received("PostSlate"), 0);

    let before = host.relay.received("PostSlate");
    pay(&stranger_link(&host, &["--tor", ONION]), true);
    let dialed = host.dialer.dialed();
    assert_eq!(dialed.len(), 1, "{dialed:?}");
    assert_eq!(dialed[0].0, ONION);
    assert_eq!(host.relay.received("PostSlate"), before);
}

#[test]
fn a_send_the_payee_declines_is_answered_as_declined_and_never_as_unknown() {
    let mut host = TestHost::new();
    host.collect = Some(NO_TICK);
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("serving password");
    payer.restore(&host, SENDER_MNEMONIC);
    let payee = new_wallet(&host, "payee password");
    let payee_host = host.without_interrupt();
    serving_public(host, &payer, |payer_socket| {
        serving_public_with(
            payee_host,
            &payee,
            &[("LEPIC_REFUSE_UNSOLICITED_PAYMENTS", "true")],
            |payee_socket| {
                let link = http(
                    payee_socket,
                    "POST",
                    "/api/v1/links",
                    Some(r#"{"amount":"2"}"#),
                );
                assert_eq!(link.status, 200, "{link:?}");
                let link = text(&link.json(), "text").to_owned();
                let id = "6f1d1a43-5a41-4f0d-9b52-3b1f0a9a7c11";
                let create = json!({ "to": link, "id": id }).to_string();
                let paid = http(payer_socket, "POST", "/api/v1/payments", Some(&create));
                assert_eq!(paid.status, 201, "{paid:?}");
                assert_eq!(text(&paid.json(), "id"), id);
                let path = format!("/api/v1/payments/{id}");
                wait_until_within(
                    "the payment reads as declined",
                    Duration::from_secs(60),
                    || http(payer_socket, "GET", &path, None).status == 404,
                );
                let gone = http(payer_socket, "GET", &path, None);
                let body = problem(&gone, 404, "payment_declined");
                assert_eq!(body["payment_id"], id, "{body}");
                assert!(body["declined_at"].is_string(), "{body}");
                // A repeat of the create with the same id and body finds the same answer, not
                // a store error.
                let again = http(payer_socket, "POST", "/api/v1/payments", Some(&create));
                let repeat = problem(&again, 404, "payment_declined");
                assert_eq!(repeat["payment_id"], id, "{repeat}");
                assert_eq!(repeat["declined_at"], body["declined_at"], "{repeat}");
                // Nothing else to do with it: a cancel finds the same answer.
                let cancelled = http(payer_socket, "POST", &format!("{path}/cancel"), Some("{}"));
                problem(&cancelled, 404, "payment_declined");
                // The log tells it once.
                let events = http(payer_socket, "GET", "/api/v1/events?limit=200", None).ok();
                let told: Vec<&Value> = events["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|event| event["type"] == "payment.declined")
                    .collect();
                assert_eq!(told.len(), 1, "{events}");
                assert_eq!(told[0]["data"]["payment_id"], id, "{events}");
                assert_eq!(
                    told[0]["data"]["declined_at"], body["declined_at"],
                    "{events}"
                );
            },
        );
    });
}
