//! Send, receive and finalize between two CLI instances, through slate files and through the
//! mock relay, against one mock node.

// Tests may unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod support;

use std::sync::Arc;

use lepic_epicbox::EpicboxAddress;

use support::{FUNDING, Instance, SENDER_MNEMONIC, TestHost, keys, text};

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
    assert_eq!(status["relay"], "ws://relay.test:80");
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
