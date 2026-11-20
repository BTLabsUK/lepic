// SPDX-License-Identifier: Apache-2.0
//! `lepic mailbox`: the mailbox list kept in the settings file, and a test of one mailbox on the
//! mock relay.

// Tests may unwrap, index and panic (docs/rules.md).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::support;

use serde_json::{Value, json};
use support::{Instance, SHIPPED_MAILBOXES, TestHost, funded, new_wallet, text};

/// The hosts of `mailbox list` with their origins.
fn listed(wallet: &Instance, host: &TestHost) -> Vec<(String, String)> {
    let list = wallet.run(host, &["mailbox", "list"]).ok().json();
    list["mailboxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["host"].as_str().unwrap().to_owned(),
                entry["origin"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn shipped(hosts: &[&str]) -> Vec<(String, String)> {
    hosts
        .iter()
        .map(|host| ((*host).to_owned(), "shipped".to_owned()))
        .collect()
}

fn settings_file(wallet: &Instance) -> String {
    std::fs::read_to_string(wallet.home.path().join(".lepic/settings.toml")).unwrap()
}

#[test]
fn the_mailbox_commands_keep_the_list_in_the_settings_file() {
    let host = TestHost::new();
    let wallet = Instance::new("mailbox password");

    let list = wallet.run(&host, &["mailbox", "list"]).ok().json();
    assert_eq!(
        list["mailboxes"][0],
        json!({"host": "epicbox.btlabs.uk", "origin": "shipped", "push": null,
               "no_mux": false, "last_success": null, "failures": 0, "last_error": null}),
        "a command on its own saw no session"
    );
    assert_eq!(listed(&wallet, &host), shipped(&SHIPPED_MAILBOXES));

    let probe = wallet
        .run(&host, &["mailbox", "probe", "Mailbox.Example.Org:443"])
        .ok()
        .json();
    let passed = json!({"result": "passed", "error": null});
    assert_eq!(
        probe,
        json!({"host": "mailbox.example.org", "tls": passed, "greeting": passed,
               "push": passed, "passed": true})
    );
    assert_eq!(
        listed(&wallet, &host),
        shipped(&SHIPPED_MAILBOXES),
        "a test changes nothing"
    );

    let added = wallet
        .run(&host, &["mailbox", "add", "mailbox.example.org"])
        .ok()
        .json();
    assert_eq!(added["added"], true, "{added}");
    assert_eq!(added["probe"]["passed"], true, "{added}");
    let again = wallet
        .run(&host, &["mailbox", "add", "mailbox.example.org:443"])
        .ok()
        .json();
    assert_eq!(again["added"], false, "{again}");
    let removed = wallet
        .run(&host, &["mailbox", "remove", "epicbox.epiccash.com"])
        .ok()
        .json();
    assert_eq!(
        removed,
        json!({"host": "epicbox.epiccash.com", "removed": true})
    );
    let absent = wallet
        .run(&host, &["mailbox", "remove", "gone.example.org"])
        .ok()
        .json();
    assert_eq!(absent["removed"], false, "{absent}");

    let mut expected = shipped(&["epicbox.btlabs.uk", "epicbox.epicnet.us"]);
    expected.push(("mailbox.example.org".to_owned(), "added".to_owned()));
    assert_eq!(listed(&wallet, &host), expected);
    let file = settings_file(&wallet);
    assert!(
        file.contains("added = [\"mailbox.example.org\"]\nremoved = [\"epicbox.epiccash.com\"]\n"),
        "{file}"
    );

    let mut env = wallet.env();
    for (key, value) in &mut env {
        if key == "LEPIC_OUTPUT" {
            "human".clone_into(value);
        }
    }
    let shown = wallet.run_with(&host, &["mailbox", "list"], env, "").ok();
    assert_eq!(
        shown.stdout,
        "epicbox.btlabs.uk  shipped  push: not known  last success: not tried  failures: 0\n\
         epicbox.epicnet.us  shipped  push: not known  last success: not tried  failures: 0\n\
         mailbox.example.org  added  push: not known  last success: not tried  failures: 0\n"
    );
}

#[test]
fn a_mailbox_that_fails_its_test_is_added_only_anyway() {
    let host = TestHost::new();
    host.relay.offer_mux(false);
    let wallet = Instance::new("mailbox password");
    let before = listed(&wallet, &host);

    let refused = wallet.run(&host, &["mailbox", "add", "plain.example.org"]);
    assert_eq!(refused.code, 10, "{refused:?}");
    assert_eq!(refused.json()["error"]["kind"], "transport", "{refused:?}");
    assert_eq!(listed(&wallet, &host), before);
    assert!(!settings_file(&wallet).contains("plain.example.org"));

    // A failed probe still prints its report, and the exit code says it failed.
    let probed = wallet.run(&host, &["mailbox", "probe", "plain.example.org"]);
    assert_eq!(probed.code, 10, "{probed:?}");
    let probe = probed.json();
    assert_eq!(probe["push"]["result"], "failed", "{probe}");
    assert_eq!(probe["passed"], false, "{probe}");

    let added = wallet
        .run(&host, &["mailbox", "add", "plain.example.org", "--anyway"])
        .ok()
        .json();
    assert_eq!(added["added"], true, "{added}");
    assert_eq!(added["probe"]["passed"], false, "{added}");
    assert_eq!(
        listed(&wallet, &host).last(),
        Some(&("plain.example.org".to_owned(), "added".to_owned()))
    );
}

#[test]
fn a_host_that_is_not_a_public_name_is_refused() {
    let host = TestHost::new();
    let wallet = Instance::new("mailbox password");
    for bad in [
        "localhost",
        "127.0.0.1:8443",
        "relay.lan",
        "bad host!",
        "my-box.example.org",
    ] {
        for command in ["add", "probe", "remove"] {
            let refused = wallet.run(&host, &["mailbox", command, bad]);
            assert_eq!(refused.code, 2, "{command} {bad}: {refused:?}");
            let error: Value = refused.json()["error"].clone();
            assert_eq!(error["kind"], "usage", "{command} {bad}: {error}");
        }
    }
    assert!(!settings_file(&wallet).contains("\nadded = "));
}

/// The wallet's environment with `local_mailbox` on, its relay the mock relay's loopback name.
fn local_env(wallet: &Instance) -> Vec<(String, String)> {
    let mut env = wallet.env();
    env.push(("LEPIC_LOCAL_MAILBOX".to_owned(), "true".to_owned()));
    env
}

fn run_local(wallet: &Instance, host: &TestHost, args: &[&str]) -> support::Outcome {
    wallet.run_with(host, args, local_env(wallet), "")
}

#[test]
fn local_mailbox_makes_the_loopback_relay_the_one_mailbox_a_payment_goes_through() {
    let (host, payer) = funded();
    host.relay.set_relays_apart(true);
    let payee = new_wallet(&host, "payee password");

    let list = run_local(&payer, &host, &["mailbox", "list"]).ok().json();
    let hosts = list["mailboxes"].as_array().unwrap();
    assert_eq!(hosts.len(), 1, "{list}");
    assert_eq!(hosts[0]["host"], "127.0.0.1:80", "{list}");
    assert_eq!(hosts[0]["origin"], "shipped", "{list}");

    let made = run_local(&payee, &host, &["epic1", "address"]).ok().json();
    let address = text(&made, "address").to_owned();
    let paid = run_local(&payer, &host, &["epic1", "pay", &address, "2"])
        .ok()
        .json();
    assert_eq!(paid["posted_ok"], true, "{paid}");
    let on = |domain: &str| {
        let mailbox =
            lepic_wallet_contacts::epic1_testing::delivery_mailbox(&address, domain).unwrap();
        host.relay.pending(&mailbox)
    };
    assert_eq!(on("127.0.0.1"), 1);
    for shipped in SHIPPED_MAILBOXES {
        assert_eq!(on(shipped), 0, "{shipped}");
    }

    let taken = run_local(&payee, &host, &["contact", "collect"])
        .ok()
        .json();
    assert_eq!(taken["epic1"], 1, "{taken}");
    let finalized = run_local(&payer, &host, &["contact", "collect"])
        .ok()
        .json();
    assert_eq!(finalized["epic1"], 1, "{finalized}");
    let shown = payer
        .run(&host, &["tx", "show", &paid["tx_id"].to_string()])
        .ok()
        .json();
    assert_ne!(shown["state"], "sent", "{shown}");
    assert!(
        !host.node.pushed_transactions().is_empty(),
        "the payer posted the finalized transaction"
    );
}

#[test]
fn local_mailbox_is_refused_with_a_relay_off_this_device_or_a_changed_list() {
    let host = TestHost::new();
    let wallet = Instance::new("mailbox password");

    let mut env = local_env(&wallet);
    for (key, value) in &mut env {
        if key == "LEPIC_EPICBOX_RELAY" {
            "wss://relay.example.org".clone_into(value);
        }
    }
    let public = wallet.run_with(&host, &["mailbox", "list"], env, "");
    assert_eq!(public.code, 3, "{public:?}");
    let error = public.json()["error"].clone();
    assert_eq!(error["kind"], "config", "{error}");
    assert!(
        error["causes"].to_string().contains("local_mailbox"),
        "{error}"
    );

    wallet.with_mailboxes(&["mailbox.example.org"]);
    let changed = run_local(&wallet, &host, &["mailbox", "list"]);
    assert_eq!(changed.code, 3, "{changed:?}");
    let error = changed.json()["error"].clone();
    assert!(
        error["causes"].to_string().contains("mailboxes.added"),
        "{error}"
    );
}

#[test]
fn local_mailbox_refuses_a_change_to_the_list() {
    let host = TestHost::new();
    let wallet = Instance::new("mailbox password");
    for (command, mailbox) in [
        ("add", "mailbox.example.org"),
        ("remove", "epicbox.btlabs.uk"),
    ] {
        let refused = run_local(&wallet, &host, &["mailbox", command, mailbox]);
        assert_eq!(refused.code, 2, "{command}: {refused:?}");
        let error = refused.json()["error"].clone();
        assert_eq!(error["kind"], "usage", "{command}: {error}");
        assert!(
            error["message"].as_str().unwrap().contains("local_mailbox"),
            "{command}: {error}"
        );
    }
    assert_eq!(
        run_local(&wallet, &host, &["mailbox", "list"]).ok().json()["mailboxes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!settings_file(&wallet).contains("\nadded = "));
}

#[test]
fn mailboxes_past_the_limit_of_sixteen_are_reported_as_left_out() {
    let host = TestHost::new();
    let wallet = Instance::new("mailbox password");
    wallet
        .run(&host, &["mailbox", "add", "mailbox.example.org"])
        .ok();
    let path = wallet.home.path().join(".lepic/settings.toml");
    let hosts: Vec<String> = (1..=15).map(|n| format!("\"m{n}.example.org\"")).collect();
    let file = std::fs::read_to_string(&path).unwrap().replace(
        "added = [\"mailbox.example.org\"]",
        &format!("added = [{}]", hosts.join(", ")),
    );
    std::fs::write(&path, file).unwrap();

    let list = wallet.run(&host, &["mailbox", "list"]).ok().json();
    // Three shipped and thirteen added fill the list; the last two named are not used.
    assert_eq!(list["mailboxes"].as_array().unwrap().len(), 16, "{list}");
    assert_eq!(
        list["left_out"],
        json!(["m14.example.org", "m15.example.org"]),
        "{list}"
    );

    let mut env = wallet.env();
    for (key, value) in &mut env {
        if key == "LEPIC_OUTPUT" {
            "human".clone_into(value);
        }
    }
    let shown = wallet.run_with(&host, &["mailbox", "list"], env, "").ok();
    assert!(
        shown.stdout.contains(
            "Not used, the list holds at most 16 mailboxes: m14.example.org, m15.example.org"
        ),
        "{shown:?}"
    );
}

#[test]
fn a_list_within_the_limit_reports_nothing_left_out() {
    let host = TestHost::new();
    let wallet = Instance::new("mailbox password");
    let list = wallet.run(&host, &["mailbox", "list"]).ok().json();
    assert!(list.get("left_out").is_none(), "{list}");
}
