//! Send, receive and finalize between two CLI instances, through slate files and through the
//! mock relay, against one mock node.

// Tests may unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod support;

use std::sync::Arc;

use lepic_epicbox::EpicboxAddress;

use support::{FUNDING, Instance, SENDER_MNEMONIC, TIP, TestHost, keys, text};

/// A funded sender restored from its phrase and a receiver created from new entropy.
fn two_wallets() -> (TestHost, Instance, Instance) {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let sender = Instance::new("sender password");
    let restored = sender.restore(&host, SENDER_MNEMONIC);
    assert_eq!(restored["scan"]["found"], 1);
    assert_eq!(restored["scan"]["restored"], 1);
    let receiver = Instance::new("receiver password");
    let created = receiver.run(&host, &["wallet", "init"]).ok().json();
    assert_eq!(text(&created, "recovery_phrase").split(' ').count(), 24);
    (host, sender, receiver)
}

/// The one transaction of `slate_id` in the instance's default account.
fn transaction(
    instance: &Instance,
    host: &TestHost,
    slate_id: &serde_json::Value,
) -> serde_json::Value {
    let list = instance.run(host, &["tx", "list"]).ok().json();
    let matching: Vec<_> = list["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|tx| tx["slate_id"] == *slate_id)
        .cloned()
        .collect();
    assert_eq!(matching.len(), 1, "{list}");
    matching[0].clone()
}

#[test]
fn send_receive_and_finalize_through_files() {
    let (host, sender, receiver) = two_wallets();
    let info = sender.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000");

    let slate = sender.path("payment.slate");
    let sent = sender
        .run(
            &host,
            &[
                "tx",
                "send",
                "1.5",
                "--to-file",
                slate.to_str().unwrap(),
                "-m",
                "thanks",
            ],
        )
        .ok()
        .json();
    assert_eq!(
        keys(&sent),
        [
            "amount",
            "destination",
            "fee",
            "slate_id",
            "transport",
            "tx_id"
        ]
    );
    assert_eq!(sent["amount"], "1.50000000");
    assert_eq!(sent["transport"], "file");
    assert!(slate.is_file());

    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    assert_eq!(
        keys(&received),
        ["amount", "reply_file", "slate_id", "tx_id"]
    );
    assert_eq!(received["slate_id"], sent["slate_id"]);
    assert_eq!(received["amount"], "1.50000000");
    let reply = text(&received, "reply_file").to_owned();
    assert_eq!(reply, format!("{}.response", slate.display()));

    let finalized = sender.run(&host, &["tx", "finalize", &reply]).ok().json();
    assert_eq!(keys(&finalized), ["slate_id", "state", "tx_id"]);
    assert_eq!(finalized["tx_id"], sent["tx_id"]);
    assert_eq!(finalized["state"], "posted");
    assert_eq!(host.node.pushed_transactions().len(), 1);

    let outgoing = transaction(&sender, &host, &sent["slate_id"]);
    assert_eq!(
        keys(&outgoing),
        [
            "amount_credited",
            "amount_debited",
            "created_at",
            "direction",
            "fee",
            "slate_id",
            "state",
            "transport",
            "tx_id",
            "updated_at"
        ]
    );
    assert_eq!(outgoing["direction"], "outgoing");
    assert_eq!(outgoing["state"], "posted");
    assert_eq!(outgoing["fee"], sent["fee"]);
    let incoming = transaction(&receiver, &host, &sent["slate_id"]);
    assert_eq!(incoming["state"], "received");
    assert_eq!(incoming["direction"], "incoming");
    assert_eq!(incoming["amount_credited"], "1.50000000");

    let tx_id = sent["tx_id"].to_string();
    let shown = sender.run(&host, &["tx", "show", &tx_id]).ok().json();
    let stages: Vec<&str> = shown["stages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|stage| stage.as_str().unwrap())
        .collect();
    assert!(
        stages.contains(&"S1") && stages.contains(&"S3"),
        "{stages:?}"
    );

    // Posting again sends the stored transaction again.
    sender.run(&host, &["tx", "post", &tx_id]).ok();
    assert_eq!(host.node.pushed_transactions().len(), 2);
    assert!(
        host.node.violations().is_empty(),
        "{:?}",
        host.node.violations()
    );
}

#[test]
fn send_receive_and_finalize_through_the_relay() {
    let (host, sender, receiver) = two_wallets();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();

    let sent = sender
        .run(&host, &["tx", "send", "2", "--to", &address])
        .ok()
        .json();
    assert_eq!(sent["transport"], "epicbox");
    assert_eq!(sent["destination"], address.as_str());

    let receiver_drain = receiver.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(receiver_drain["received"], 1, "{receiver_drain}");

    let sender_drain = sender.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(sender_drain["finalized"], 1, "{sender_drain}");
    assert_eq!(host.node.pushed_transactions().len(), 1);
    assert_eq!(
        transaction(&sender, &host, &sent["slate_id"])["state"],
        "posted"
    );

    let status = sender.run(&host, &["epicbox", "status"]).ok().json();
    assert_eq!(status["pending_deliveries"], 0);
    assert_eq!(status["relay"], "ws://127.0.0.1:80");
}

#[test]
fn a_cancelled_send_releases_its_inputs() {
    let (host, sender, _) = two_wallets();
    let slate = sender.path("cancelled.slate");
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let tx_id = sent["tx_id"].to_string();
    let cancelled = sender.run(&host, &["tx", "cancel", &tx_id]).ok().json();
    assert_eq!(cancelled["state"], "cancelled");
    let info = sender.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000");
    assert_eq!(info["accounts"][0]["locked"], "0.00000000");
}

#[test]
fn listen_handles_a_waiting_slate_and_stops_when_interrupted() {
    let (mut host, sender, receiver) = two_wallets();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    sender
        .run(
            &host,
            &["tx", "send", "1", "--to", text(&address, "address")],
        )
        .ok();
    let relay = host.relay.clone();
    let inbox =
        EpicboxAddress::parse(text(&address, "address"), lepic_epicbox::Network::Floonet).unwrap();
    assert_eq!(relay.pending(&inbox), 1);
    host.interrupt_when = Some(Arc::new(move || relay.pending(&inbox) == 0));
    let listened = receiver.run(&host, &["epicbox", "listen"]).ok().json();
    assert_eq!(
        keys(&listened),
        ["finalized", "held", "received", "rejected", "repeated"]
    );
    assert_eq!(listened["received"], 1, "{listened}");
}

#[test]
fn issue_pay_and_finalize_an_invoice_through_files() {
    let (host, payer, issuer) = two_wallets();
    let invoice = issuer.path("invoice.slate");
    let issued = issuer
        .run(
            &host,
            &[
                "invoice",
                "issue",
                "3",
                "--to-file",
                invoice.to_str().unwrap(),
                "-m",
                "for the bike",
            ],
        )
        .ok()
        .json();
    assert_eq!(keys(&issued), ["amount", "file", "slate_id", "tx_id"]);
    assert_eq!(issued["amount"], "3.00000000");
    assert!(invoice.is_file());

    let paid = payer
        .run(&host, &["invoice", "pay", invoice.to_str().unwrap(), "3"])
        .ok()
        .json();
    assert_eq!(
        keys(&paid),
        ["amount", "fee", "reply_file", "slate_id", "tx_id"]
    );
    assert_eq!(paid["slate_id"], issued["slate_id"]);
    let reply = text(&paid, "reply_file").to_owned();
    assert_eq!(reply, format!("{}.response", invoice.display()));

    let finalized = issuer.run(&host, &["tx", "finalize", &reply]).ok().json();
    assert_eq!(finalized["tx_id"], issued["tx_id"]);
    assert_eq!(finalized["state"], "posted");
    assert_eq!(host.node.pushed_transactions().len(), 1);

    let incoming = transaction(&issuer, &host, &issued["slate_id"]);
    assert_eq!(incoming["direction"], "incoming");
    assert_eq!(incoming["state"], "posted");
    assert_eq!(incoming["amount_credited"], "3.00000000");
    let outgoing = transaction(&payer, &host, &issued["slate_id"]);
    assert_eq!(outgoing["direction"], "outgoing");
    assert_eq!(outgoing["fee"], paid["fee"]);

    // A standard reply finalized as an invoice, or the reverse, is not mistaken for the other.
    let again = issuer.run(&host, &["tx", "finalize", invoice.to_str().unwrap()]);
    assert_eq!(again.code, 7, "{again:?}");
    assert!(
        host.node.violations().is_empty(),
        "{:?}",
        host.node.violations()
    );
}

#[test]
fn a_send_to_an_invalid_address_stores_nothing() {
    let (host, sender, receiver) = two_wallets();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address");
    let (key, relay) = address.split_once('@').unwrap();
    let truncated = format!("{}@{relay}", &key[1..]);
    for bad in ["bogus", truncated.as_str()] {
        let outcome = sender.run(&host, &["tx", "send", "1", "--to", bad]);
        assert_eq!(outcome.code, 2, "{bad}: {outcome:?}");
        assert_eq!(outcome.json()["error"]["kind"], "usage");
    }
    let list = sender.run(&host, &["tx", "list"]).ok().json();
    let restored_only = list["transactions"].as_array().unwrap();
    assert!(
        restored_only.iter().all(|tx| tx["direction"] == "incoming"),
        "{list}"
    );
    let info = sender.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["accounts"][0]["locked"], "0.00000000");
}

#[test]
fn resend_delivers_the_first_slate_again_until_it_is_answered() {
    let (host, sender, receiver) = two_wallets();
    let first = sender.path("first.slate");
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", first.to_str().unwrap()],
        )
        .ok()
        .json();
    let tx_id = sent["tx_id"].to_string();

    let again = sender.path("again.slate");
    let resent = sender
        .run(
            &host,
            &["tx", "resend", &tx_id, "--to-file", again.to_str().unwrap()],
        )
        .ok()
        .json();
    assert_eq!(keys(&resent), ["destination", "transport", "tx_id"]);
    assert_eq!(resent["tx_id"], sent["tx_id"]);
    assert_eq!(resent["transport"], "file");

    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    sender
        .run(
            &host,
            &["tx", "resend", &tx_id, "--to", text(&address, "address")],
        )
        .ok();
    let drained = receiver.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(drained["received"], 1, "{drained}");
    let finalized = sender.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(finalized["finalized"], 1, "{finalized}");

    let outcome = sender.run(
        &host,
        &["tx", "resend", &tx_id, "--to-file", again.to_str().unwrap()],
    );
    assert_eq!(outcome.code, 7, "{outcome:?}");
}

#[test]
fn restore_and_listen_report_progress_on_stderr_for_people() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let sender = Instance::new("sender password");
    let mut human = sender.env();
    human.retain(|(key, _)| key != "LEPIC_OUTPUT");
    let restored = sender.run_with(
        &host,
        &["wallet", "restore"],
        human.clone(),
        &format!("{SENDER_MNEMONIC}\n"),
    );
    let restored = restored.ok();
    let last = restored.stderr.lines().last().unwrap_or_default();
    assert_eq!(
        last,
        format!("scanned to height {TIP} of {TIP}"),
        "{restored:?}"
    );

    let receiver = Instance::new("receiver password");
    receiver.run(&host, &["wallet", "init"]).ok();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1", "--to", text(&address, "address")],
        )
        .ok()
        .json();
    receiver.run(&host, &["epicbox", "drain"]).ok();
    let reply_sent = host.relay.clone();
    let inbox = EpicboxAddress::parse(
        text(
            &sender.run(&host, &["wallet", "address"]).ok().json(),
            "address",
        ),
        lepic_epicbox::Network::Floonet,
    )
    .unwrap();
    assert_eq!(reply_sent.pending(&inbox), 1);
    let mut host = host;
    host.interrupt_when = Some(Arc::new(move || reply_sent.pending(&inbox) == 0));
    let listened = sender
        .run_with(&host, &["epicbox", "listen"], human, "")
        .ok();
    assert!(
        listened
            .stderr
            .contains("connected to the relay; waiting for slates"),
        "{listened:?}"
    );
    let tx_id = &sent["tx_id"];
    for state in ["finalized", "posted"] {
        let line = format!("transaction {tx_id} {state}");
        assert!(listened.stderr.contains(&line), "{listened:?}");
    }
    assert!(
        listened.stdout.starts_with("Received 0, finalized 1"),
        "{listened:?}"
    );
    // JSON output keeps stderr for logs.
    host.interrupt_when = None;
    let quiet = sender.run(&host, &["epicbox", "drain"]).ok();
    assert!(quiet.stderr.is_empty(), "{quiet:?}");
}
