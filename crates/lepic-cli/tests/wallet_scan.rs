//! `lepic wallet scan` against the mock node: the pending restore scan, an update from the last
//! scan, a start height, the `--delete-unconfirmed` repair and the chain reset.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use lepic_primitives::amount::Height;
use support::{FUNDING, Instance, SENDER_MNEMONIC, TIP, TestHost, keys, text};

const SCAN_FIELDS: [&str; 8] = [
    "deleted",
    "end_height",
    "found",
    "restored",
    "resumed",
    "revived",
    "start_height",
    "unlocked",
];

fn human_env(instance: &Instance) -> Vec<(String, String)> {
    let mut env = instance.env();
    env.retain(|(key, _)| key != "LEPIC_OUTPUT");
    env
}

fn scan(instance: &Instance, host: &TestHost, options: &[&str]) -> serde_json::Value {
    let mut args = vec!["wallet", "scan"];
    args.extend_from_slice(options);
    let report = instance.run(host, &args).ok().json();
    assert_eq!(keys(&report), SCAN_FIELDS, "{report}");
    report
}

fn total(instance: &Instance, host: &TestHost) -> String {
    let info = instance.run(host, &["wallet", "info"]).ok().json();
    text(&info["accounts"][0], "total").to_owned()
}

fn funded_sender(host: &TestHost) -> Instance {
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let sender = Instance::new("sender password");
    sender.restore(host, SENDER_MNEMONIC);
    sender
}

/// A wallet restored with `--no-scan` refuses to receive until `wallet scan` runs the scan from
/// genesis it is missing; afterwards it has its funds and receives.
#[test]
fn a_wallet_restored_without_a_scan_receives_after_wallet_scan() {
    let host = TestHost::new();
    let sender = funded_sender(&host);
    let receiver = restored_without_scan(&host, FUNDING / 2);

    let slate = sender.path("payment.slate");
    sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok();
    let receive = ["tx", "receive", slate.to_str().unwrap()];
    let refused = receiver.run(&host, &receive);
    assert_eq!(refused.code, 5, "{refused:?}");
    assert_eq!(refused.json()["error"]["kind"], "wallet_state");
    let human = receiver.run_with(&host, &receive, human_env(&receiver), "");
    assert!(
        human.stderr.contains("hint: ") && human.stderr.contains("`lepic wallet scan`"),
        "{human:?}"
    );
    assert!(!sender.path("payment.slate.response").exists());
    assert_eq!(total(&receiver, &host), "0.00000000");

    let scanned = scan(&receiver, &host, &[]);
    assert_eq!(scanned["start_height"], 0, "{scanned}");
    assert_eq!(scanned["end_height"], TIP, "{scanned}");
    assert_eq!(scanned["found"], 1, "{scanned}");
    assert_eq!(scanned["restored"], 1, "{scanned}");
    assert_eq!(scanned["resumed"], false, "{scanned}");
    assert_eq!(total(&receiver, &host), "5.00000000");

    let received = receiver.run(&host, &receive).ok().json();
    assert_eq!(received["amount"], "1.00000000");
    assert_eq!(received["repeated"], false);
}

/// A scan from above genesis completes without ending the wait after a `--no-scan` restore, so
/// the next plain scan starts at genesis instead of before that scan's end.
#[test]
fn a_pending_restore_scan_starts_at_genesis_after_a_partial_scan() {
    let host = TestHost::new();
    let sender = funded_sender(&host);
    let receiver = restored_without_scan(&host, FUNDING / 2);
    let slate = sender.path("payment.slate");
    sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok();
    host.node
        .update_chain(|chain| chain.tip.height = Height::new(300));

    let partial = scan(&receiver, &host, &["--start-height", "250"]);
    assert_eq!(partial["start_height"], 250, "{partial}");
    assert_eq!(partial["end_height"], 300, "{partial}");
    assert_eq!(partial["found"], 0, "{partial}");
    let receive = ["tx", "receive", slate.to_str().unwrap()];
    let refused = receiver.run(&host, &receive);
    assert_eq!(refused.code, 5, "{refused:?}");

    let full = scan(&receiver, &host, &[]);
    assert_eq!(full["start_height"], 0, "{full}");
    assert_eq!(full["restored"], 1, "{full}");
    let received = receiver.run(&host, &receive).ok().json();
    assert_eq!(received["amount"], "1.00000000");
}

/// A wallet restored with `--no-scan` from a new phrase that owns one output of `amount` on
/// chain.
fn restored_without_scan(host: &TestHost, amount: u64) -> Instance {
    let phrase = {
        let created = Instance::new("throwaway password");
        let report = created.run(host, &["wallet", "init"]).ok().json();
        text(&report, "recovery_phrase").to_owned()
    };
    host.fund(&phrase, 0, amount, 2);
    let receiver = Instance::new("receiver password");
    let restored = receiver
        .run_with(
            host,
            &["wallet", "restore", "--no-scan"],
            receiver.env(),
            &format!("{phrase}\n"),
        )
        .ok()
        .json();
    assert!(restored["scan"].is_null(), "{restored}");
    receiver
}

/// Without options a scan reaches back 100 blocks from the last completed one; a start height
/// overrides that, and 0 scans the whole chain.
#[test]
fn a_scan_starts_before_the_last_scan_or_at_the_height_given() {
    let host = TestHost::new();
    let sender = funded_sender(&host);
    host.node
        .update_chain(|chain| chain.tip.height = Height::new(200));

    let given = scan(&sender, &host, &["--start-height", "150"]);
    assert_eq!(given["start_height"], 150, "{given}");
    assert_eq!(given["end_height"], 200, "{given}");
    assert_eq!(given["found"], 0, "{given}");

    let above = sender.run(&host, &["wallet", "scan", "--start-height", "201"]);
    assert_eq!(above.code, 2, "{above:?}");
    let error = &above.json()["error"];
    assert_eq!(error["kind"], "usage", "{error}");
    assert_eq!(
        error["message"], "start height 201 is above the node's tip 200",
        "{error}"
    );

    host.node
        .update_chain(|chain| chain.tip.height = Height::new(260));
    let update = scan(&sender, &host, &[]);
    assert_eq!(update["start_height"], 100, "{update}");
    assert_eq!(update["end_height"], 260, "{update}");

    let whole = scan(&sender, &host, &["--start-height", "0"]);
    assert_eq!(whole["start_height"], 0, "{whole}");
    assert_eq!(whole["found"], 1, "{whole}");
    assert_eq!(whole["restored"], 0, "{whole}");

    let mut env = human_env(&sender);
    env.push(("LEPIC_LOG_LEVEL".to_owned(), "off".to_owned()));
    let human = sender.run_with(&host, &["wallet", "scan"], env, "").ok();
    assert_eq!(
        human.stdout,
        "Scanned heights 160 to 260: 0 outputs found, 0 restored, 0 revived.\n"
    );
    assert_eq!(
        human.stderr.lines().last(),
        Some("scanned to height 260 of 260"),
        "{human:?}"
    );
}

/// A send that was never finalized leaves its input locked and its change unconfirmed. A plain
/// scan leaves both; the repair unlocks the input, deletes the change and cancels the send.
#[test]
fn delete_unconfirmed_releases_what_an_unfinished_send_held() {
    let host = TestHost::new();
    let sender = funded_sender(&host);
    let slate = sender.path("abandoned.slate");
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    let locked = |instance: &Instance| {
        let info = instance.run(&host, &["wallet", "info"]).ok().json();
        text(&info["accounts"][0], "locked").to_owned()
    };
    assert_eq!(locked(&sender), "10.00000000");

    let plain = scan(&sender, &host, &[]);
    assert_eq!(
        (plain["unlocked"].clone(), plain["deleted"].clone()),
        (0.into(), 0.into())
    );
    assert_eq!(locked(&sender), "10.00000000");

    let repaired = scan(&sender, &host, &["--delete-unconfirmed"]);
    assert_eq!(repaired["unlocked"], 1, "{repaired}");
    assert_eq!(repaired["deleted"], 1, "{repaired}");
    assert_eq!(repaired["found"], 1, "{repaired}");
    assert_eq!(locked(&sender), "0.00000000");
    let info = sender.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000");
    let shown = sender
        .run(&host, &["tx", "show", &sent["tx_id"].to_string()])
        .ok()
        .json();
    assert_eq!(shown["state"], "cancelled", "{shown}");

    let human = sender
        .run_with(
            &host,
            &["wallet", "scan", "--delete-unconfirmed"],
            human_env(&sender),
            "",
        )
        .ok();
    assert!(
        human
            .stdout
            .ends_with("0 revived, 0 unlocked, 0 deleted.\n"),
        "{human:?}"
    );
}

/// A wallet that stored a height its node's chain does not have stays behind it: an ordinary
/// scan keeps the stored height, and `--reset-chain` forgets it and scans from genesis. With
/// `--delete-unconfirmed` the reset also releases what an unfinished send held.
#[test]
fn reset_chain_recovers_a_wallet_ahead_of_its_node() {
    let host = TestHost::new();
    let sender = funded_sender(&host);
    let slate = sender.path("abandoned.slate");
    let sent = sender
        .run(
            &host,
            &["tx", "send", "1", "--to-file", slate.to_str().unwrap()],
        )
        .ok()
        .json();
    sender.run(&host, &["wallet", "info"]).ok();
    host.node
        .update_chain(|chain| chain.tip.height = Height::new(TIP - 10));

    let behind = sender.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(behind["node_behind"], true, "{behind}");
    let human = sender
        .run_with(&host, &["wallet", "info"], human_env(&sender), "")
        .ok();
    assert!(
        human
            .stdout
            .contains("`lepic wallet scan --reset-chain` recovers"),
        "{human:?}"
    );

    scan(&sender, &host, &[]);
    let still = sender.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(still["node_behind"], true, "{still}");

    let reset = scan(&sender, &host, &["--reset-chain", "--delete-unconfirmed"]);
    assert_eq!(reset["start_height"], 0, "{reset}");
    assert_eq!(reset["end_height"], TIP - 10, "{reset}");
    assert_eq!(reset["found"], 1, "{reset}");
    assert_eq!(reset["unlocked"], 1, "{reset}");
    assert_eq!(reset["deleted"], 1, "{reset}");
    let info = sender.run(&host, &["wallet", "info"]).ok().json();
    assert_eq!(info["node_behind"], false, "{info}");
    assert_eq!(info["height"], TIP - 10, "{info}");
    assert_eq!(info["accounts"][0]["total"], "10.00000000");
    assert_eq!(info["accounts"][0]["locked"], "0.00000000");
    let shown = sender
        .run(&host, &["tx", "show", &sent["tx_id"].to_string()])
        .ok()
        .json();
    assert_eq!(shown["state"], "cancelled", "{shown}");

    let conflict = sender.run(
        &host,
        &["wallet", "scan", "--reset-chain", "--start-height", "5"],
    );
    assert_eq!(conflict.code, 2, "{conflict:?}");
}
