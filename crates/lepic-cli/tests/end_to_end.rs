// SPDX-License-Identifier: Apache-2.0
//! Send, receive and finalize between two CLI instances, through slate files and through the
//! mock relay, against one mock node.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::sync::Arc;

use lepic_epicbox::EpicboxAddress;
use lepic_epicbox::mock_relay::Unanswered;
use lepic_node::LocatedKernel;
use lepic_node::mock::ChainOutput;
use lepic_primitives::amount::Height;
use lepic_wallet::chain::TIP_STEP_BLOCKS;

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
    let send = ["tx", "send", "1.5", "--to-file", slate.to_str().unwrap()];
    let sent = sender
        .run(&host, &[send.as_slice(), &["-m", "thanks"]].concat())
        .ok()
        .json();
    assert_eq!(
        keys(&sent),
        [
            "amount",
            "delivered",
            "destination",
            "fee",
            "repeated",
            "slate_id",
            "state",
            "transport",
            "tx_id"
        ]
    );
    assert_eq!(sent["amount"], "1.50000000");
    assert_eq!(sent["transport"], "file");
    assert_eq!(sent["state"], "sent");
    assert!(slate.is_file());

    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    assert_eq!(
        keys(&received),
        ["amount", "repeated", "reply_file", "slate_id", "tx_id"]
    );
    assert_eq!(received["repeated"], false);
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
    let kernel = text(&shown, "kernel_excess");
    assert_eq!(kernel.len(), 66, "{shown}");
    assert!(kernel.bytes().all(|b| b.is_ascii_hexdigit()), "{shown}");
    assert!(shown.get("confirmed_height").is_none(), "{shown}");

    // Posting again sends the stored transaction again.
    sender.run(&host, &["tx", "post", &tx_id]).ok();
    assert_eq!(host.node.pushed_transactions().len(), 2);
    assert!(
        host.node.violations().is_empty(),
        "{:?}",
        host.node.violations()
    );
}

/// A reply file lost after the receive stored it is written again by receiving the same slate,
/// and the sender finalizes that copy. Another slate under the same id is refused.
#[test]
fn receiving_the_same_slate_again_writes_the_same_reply() {
    let (host, sender, receiver) = two_wallets();
    let slate = sender.path("payment.slate");
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1.5", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let receive = ["tx", "receive", slate.to_str().unwrap()];
    let first = receiver.run(&host, &receive).ok().json();
    let reply = text(&first, "reply_file").to_owned();
    let first_bytes = std::fs::read(&reply).unwrap();
    std::fs::remove_file(&reply).unwrap();

    let again = receiver.run(&host, &receive).ok().json();

    assert_eq!(again["repeated"], true, "{again}");
    assert_eq!(again["tx_id"], first["tx_id"]);
    assert_eq!(again["slate_id"], first["slate_id"]);
    assert_eq!(again["reply_file"], first["reply_file"]);
    assert_eq!(std::fs::read(&reply).unwrap(), first_bytes);
    let finalized = sender.run(&host, &["tx", "finalize", &reply]).ok().json();
    assert_eq!(finalized["tx_id"], sent["tx_id"]);
    assert_eq!(finalized["state"], "posted");
    assert_eq!(host.node.pushed_transactions().len(), 1);
    let list = receiver.run(&host, &["tx", "list"]).ok().json();
    assert_eq!(list["transactions"].as_array().unwrap().len(), 1, "{list}");

    let mut changed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&slate).unwrap()).unwrap();
    changed["amount"] = serde_json::Value::String("1".to_owned());
    let changed_path = sender.path("changed.slate");
    std::fs::write(&changed_path, changed.to_string()).unwrap();
    let refused = receiver.run(&host, &["tx", "receive", changed_path.to_str().unwrap()]);
    assert_eq!(refused.code, 7, "{refused:?}");
    let error = &refused.json()["error"];
    assert_eq!(error["kind"], "rejected");
    assert!(
        error["causes"][0]
            .as_str()
            .unwrap()
            .contains("was already received as transaction"),
        "{error}"
    );
    assert!(!sender.path("changed.slate.response").exists());
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

/// Puts every transaction pushed so far into a block at `height`, the new tip: its inputs spent,
/// its outputs and kernels added.
fn mine_pushed(host: &TestHost, height: u64) {
    let pushed = host.node.pushed_transactions();
    host.node.update_chain(|chain| {
        let height = Height::new(height);
        for transaction in &pushed {
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
fn tx_show_gives_the_kernel_and_the_confirmation_height() {
    let (host, sender, receiver) = two_wallets();
    let funding = sender.run(&host, &["tx", "list"]).ok().json()["transactions"][0].clone();
    let restored = sender
        .run(&host, &["tx", "show", &funding["tx_id"].to_string()])
        .ok()
        .json();
    assert_eq!(restored["state"], "confirmed");
    assert_eq!(restored["confirmed_height"], 1, "{restored}");
    assert!(restored.get("kernel_excess").is_none(), "{restored}");

    let slate = sender.path("confirmed.slate");
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let tx_id = sent["tx_id"].to_string();
    let unsent = sender.run(&host, &["tx", "show", &tx_id]).ok().json();
    assert!(unsent.get("kernel_excess").is_none(), "{unsent}");
    assert!(unsent.get("confirmed_height").is_none(), "{unsent}");

    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    sender
        .run(&host, &["tx", "finalize", text(&received, "reply_file")])
        .ok();
    mine_pushed(&host, TIP + 1);
    sender.run(&host, &["wallet", "info"]).ok();

    let confirmed = sender.run(&host, &["tx", "show", &tx_id]).ok().json();
    assert_eq!(confirmed["state"], "confirmed", "{confirmed}");
    assert_eq!(confirmed["confirmed_height"], TIP + 1, "{confirmed}");
    let kernel = host.node.pushed_transactions()[0].kernels()[0].excess;
    assert_eq!(text(&confirmed, "kernel_excess"), kernel.to_hex());

    let mut env = sender.env();
    env.retain(|(name, _)| name != "LEPIC_OUTPUT");
    env.push(("LEPIC_OUTPUT".to_owned(), "human".to_owned()));
    let human = sender
        .run_with(&host, &["tx", "show", &tx_id], env, "")
        .ok()
        .stdout;
    assert!(
        human.contains(&format!("Kernel       {}\n", kernel.to_hex())),
        "{human}"
    );
    assert!(
        human.contains(&format!("Confirmed at {}\n", TIP + 1)),
        "{human}"
    );
}

/// A wallet whose last refresh is more than [`TIP_STEP_BLOCKS`] behind the node holds the
/// node's tip after one answer. `wallet info` catches up rather than printing the balance at the
/// old height next to the new one.
#[test]
fn info_far_behind_the_node_shows_the_balance_at_the_tip_it_reports() {
    let (host, sender, receiver) = two_wallets();
    let slate = sender.path("far.slate");
    sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok();
    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    sender
        .run(&host, &["tx", "finalize", text(&received, "reply_file")])
        .ok();
    let before = receiver.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(before["height"], TIP, "{before}");

    mine_pushed(&host, TIP + 2);
    let ahead = TIP + TIP_STEP_BLOCKS + 2;
    host.node
        .update_chain(|chain| chain.tip.height = Height::new(ahead));
    let info = receiver.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["height"], ahead, "{info}");
    assert_eq!(info["accounts"][0]["spendable"], "1.00000000", "{info}");
    assert_eq!(
        info["accounts"][0]["awaiting_confirmation"], "0.00000000",
        "{info}"
    );
    assert_eq!(info["catching_up"], false, "{info}");
}

#[test]
fn tx_release_refuses_a_send_until_it_is_releasable() {
    let (host, sender, receiver) = two_wallets();
    let slate = sender.path("release.slate");
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let tx_id = sent["tx_id"].to_string();
    let unsent = sender.run(&host, &["tx", "show", &tx_id]).ok().json();
    assert!(unsent.get("releasable_from").is_none(), "{unsent}");
    let refused = sender.run(&host, &["tx", "release", &tx_id]);
    assert_ne!(refused.code, 0);
    assert_eq!(refused.json()["error"]["kind"], "rejected", "{refused:?}");

    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    sender
        .run(&host, &["tx", "finalize", text(&received, "reply_file")])
        .ok();
    let posted = sender.run(&host, &["tx", "show", &tx_id]).ok().json();
    assert_eq!(posted["state"], "posted", "{posted}");
    assert_eq!(posted["releasable_from"], TIP + 1_440, "{posted}");
    assert_eq!(posted["releasable"], false, "{posted}");

    let early = sender.run(&host, &["tx", "release", &tx_id]);
    assert_eq!(early.json()["error"]["kind"], "rejected", "{early:?}");
    let shown = sender.run(&host, &["tx", "show", &tx_id]).ok().json();
    assert_eq!(shown["state"], "posted", "{shown}");
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
        [
            "bounced",
            "dropped",
            "expired",
            "finalized",
            "held",
            "notices",
            "parked",
            "received",
            "rejected",
            "repeated"
        ]
    );
    assert_eq!(listened["received"], 1, "{listened}");
}

#[test]
fn an_interrupted_listen_settles_the_slate_in_hand_first() {
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
    let watched = relay.clone();
    let watched_inbox = inbox.clone();
    host.interrupt_when = Some(Arc::new(move || watched.in_hand(&watched_inbox) == 1));
    let listened = receiver.run(&host, &["epicbox", "listen"]).ok().json();
    assert_eq!(listened["received"], 1, "{listened}");
    assert_eq!(relay.pending(&inbox), 0);
}

#[test]
fn an_interrupted_send_names_the_transaction_it_stored() {
    let (mut host, sender, receiver) = two_wallets();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let relay = host.relay.clone();
    relay.set_unanswered(Unanswered::PostSlate, true);
    let watched = relay.clone();
    host.interrupt_when = Some(Arc::new(move || watched.received("PostSlate") >= 1));
    let interrupted = sender.run(
        &host,
        &["tx", "send", "1", "--to", text(&address, "address")],
    );
    assert_eq!(interrupted.code, 12, "{interrupted:?}");
    let error = interrupted.json();
    let tx_id = error["error"]["tx_id"].as_u64().unwrap().to_string();

    host.interrupt_when = None;
    let shown = sender.run(&host, &["tx", "show", &tx_id]).ok().json();
    assert_eq!(shown["state"], "sent", "{shown}");
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
    assert_eq!(
        keys(&issued),
        [
            "amount",
            "destination",
            "file",
            "slate_id",
            "transport",
            "tx_id"
        ]
    );
    assert_eq!(issued["transport"], "file");
    assert_eq!(issued["amount"], "3.00000000");
    assert!(invoice.is_file());

    let paid = payer
        .run(&host, &["invoice", "pay", invoice.to_str().unwrap(), "3"])
        .ok()
        .json();
    assert_eq!(
        keys(&paid),
        [
            "amount",
            "destination",
            "fee",
            "reply_file",
            "slate_id",
            "transport",
            "tx_id"
        ]
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
fn a_send_made_again_under_its_slate_id_sends_nothing() {
    let (host, sender, receiver) = two_wallets();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();
    let slate_id = "8a6e2f0c-4b1d-4c3e-9f2a-7d5b6c8e9f01";
    let send = |amount: &str, to: &str| {
        sender.run(
            &host,
            &["tx", "send", amount, "--to", to, "--slate-id", slate_id],
        )
    };

    let sent = send("2", &address).ok().json();
    assert_eq!(sent["slate_id"], slate_id);
    assert_eq!(sent["repeated"], false);
    assert_eq!(sent["delivered"], true);

    let again = send("2", &address).ok().json();
    assert_eq!(again["repeated"], true, "{again}");
    assert_eq!(again["delivered"], true);
    assert_eq!(again["tx_id"], sent["tx_id"]);
    assert_eq!(again["amount"], sent["amount"]);
    assert_eq!(again["fee"], sent["fee"]);
    assert_eq!(again["state"], "sent");

    let other_amount = send("3", &address);
    assert_eq!(other_amount.code, 7, "{other_amount:?}");
    let drained = receiver.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(drained["received"], 1, "{drained}");

    let shown = sender
        .run(&host, &["tx", "show", "--slate-id", slate_id])
        .ok()
        .json();
    assert_eq!(shown["tx_id"], sent["tx_id"], "{shown}");
    let unknown = sender.run(
        &host,
        &[
            "tx",
            "show",
            "--slate-id",
            "0b6e2f0c-4b1d-4c3e-9f2a-7d5b6c8e9f01",
        ],
    );
    assert_eq!(unknown.code, 6, "{unknown:?}");

    // Version 1, not random: it would carry whatever the caller derived it from.
    let not_random = sender.run(
        &host,
        &[
            "tx",
            "send",
            "1",
            "--to",
            &address,
            "--slate-id",
            "8a6e2f0c-4b1d-1c3e-9f2a-7d5b6c8e9f01",
        ],
    );
    assert_eq!(not_random.code, 2, "{not_random:?}");
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
    assert_eq!(
        keys(&resent),
        ["destination", "state", "transport", "tx_id"]
    );
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

#[test]
fn listen_shows_each_slate_it_receives() {
    let (mut host, sender, receiver) = two_wallets();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let address = text(&address, "address").to_owned();
    sender
        .run(&host, &["tx", "send", "1", "--to", &address])
        .ok();
    let relay = host.relay.clone();
    let inbox = EpicboxAddress::parse(&address, lepic_epicbox::Network::Floonet).unwrap();
    host.interrupt_when = Some(Arc::new(move || relay.pending(&inbox) == 0));
    let mut human = receiver.env();
    human.retain(|(key, _)| key != "LEPIC_OUTPUT");
    let listened = receiver
        .run_with(&host, &["epicbox", "listen"], human, "")
        .ok();
    assert!(
        listened
            .stderr
            .contains("transaction 1 received 1.00000000 EPIC"),
        "{listened:?}"
    );
}

/// The CLI keeps no policy of its own: a short password and an invoice expiry beyond 48 hours
/// are taken as given. Only what cannot work is refused: an empty password for a new wallet and
/// an expiry of no hours.
#[test]
fn the_cli_takes_short_passwords_and_long_expiries_and_refuses_an_empty_password() {
    let host = TestHost::new();
    let short = Instance::new("a b");
    short.run(&host, &["wallet", "init"]).ok();
    short.run(&host, &["wallet", "info"]).ok();

    let mut env = short.env();
    env.push(("LEPIC_INVOICE_EXPIRY_HOURS".to_owned(), "72".to_owned()));
    let drained = short
        .run_with(&host, &["epicbox", "drain"], env.clone(), "")
        .ok()
        .json();
    assert!(drained["expired"].is_object(), "{drained}");
    env.retain(|(name, _)| name != "LEPIC_INVOICE_EXPIRY_HOURS");
    env.push(("LEPIC_INVOICE_EXPIRY_HOURS".to_owned(), "0".to_owned()));
    let none = short.run_with(&host, &["epicbox", "drain"], env, "");
    assert_eq!(none.code, 3, "{none:?}");
    assert_eq!(none.json()["error"]["kind"], "config", "{none:?}");

    // An empty LEPIC_PASSWORD counts as unset, so the empty line on standard input is read.
    let empty = Instance::new("not used");
    let mut env = empty.env();
    env.retain(|(name, _)| name != "LEPIC_PASSWORD");
    for (env, stdin) in [
        (
            [
                env.clone(),
                vec![("LEPIC_PASSWORD".to_owned(), String::new())],
            ]
            .concat(),
            "\n",
        ),
        (env.clone(), "\n"),
    ] {
        let refused = support::run_in(&host, &["wallet", "init"], env, stdin);
        assert_eq!(refused.code, 7, "{refused:?}");
        assert_eq!(refused.json()["error"]["kind"], "rejected", "{refused:?}");
    }
    // Nothing was created.
    assert_ne!(empty.run(&host, &["wallet", "info"]).code, 0);
}
