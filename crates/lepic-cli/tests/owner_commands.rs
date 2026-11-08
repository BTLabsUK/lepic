// SPDX-License-Identifier: Apache-2.0
//! `wallet outputs` lists the stored outputs and `wallet password` re-encrypts the vault.

// Tests may unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod support;

use support::{FUNDING, Instance, Outcome, SENDER_MNEMONIC, TestHost, keys, text};

fn with_env(wallet: &Instance, name: &str, value: &str) -> Vec<(String, String)> {
    let mut env = wallet.env();
    env.push((name.to_owned(), value.to_owned()));
    env
}

fn error_kind(outcome: &Outcome) -> String {
    text(&outcome.json()["error"], "kind").to_owned()
}

#[test]
fn outputs_lists_what_the_wallet_holds_without_key_material() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");

    let empty = wallet.run(&host, &["wallet", "init"]);
    assert_eq!(empty.code, 0, "{empty:?}");
    let none = wallet.run(&host, &["wallet", "outputs"]).ok().json();
    assert_eq!(none["account"], "default");
    assert!(none["outputs"].as_array().unwrap().is_empty(), "{none}");

    let funded = Instance::new("right password");
    funded.restore(&host, SENDER_MNEMONIC);
    // `outputs` reads the store as the last refresh left it.
    funded.run(&host, &["wallet", "info"]).ok();
    let listed = funded.run(&host, &["wallet", "outputs"]).ok().json();
    assert_eq!(keys(&listed), ["account", "outputs"]);
    let outputs = listed["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 1, "{listed}");
    let output = &outputs[0];
    assert_eq!(
        keys(output),
        [
            "category",
            "commitment",
            "confirmations",
            "height",
            "is_coinbase",
            "lock_height",
            "status",
            "tx_id",
            "value"
        ]
    );
    assert_eq!(output["value"], "10.00000000", "{listed}");
    assert_eq!(output["status"], "unspent");
    assert_eq!(output["category"], "spendable");
    assert_eq!(text(output, "commitment").len(), 66);

    let unknown = funded.run(&host, &["wallet", "outputs", "--account", "nope"]);
    assert_ne!(unknown.code, 0, "{unknown:?}");

    let human = funded.run_with(
        &host,
        &["wallet", "outputs", "--output", "human"],
        funded.env(),
        "",
    );
    assert_eq!(human.code, 0, "{human:?}");
    assert!(human.stdout.contains("10.00000000"), "{human:?}");
}

#[test]
fn a_changed_password_unlocks_the_wallet_and_the_old_one_no_longer_does() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("old password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let changed = wallet.run_with(
        &host,
        &["wallet", "password"],
        with_env(&wallet, "LEPIC_NEW_PASSWORD", "new password"),
        "",
    );
    assert_eq!(changed.json(), serde_json::json!({ "changed": true }));
    assert_eq!(changed.code, 0, "{changed:?}");
    assert!(!changed.stdout.contains("new password"), "{changed:?}");
    assert!(!changed.stderr.contains("new password"), "{changed:?}");

    let old = wallet.run(&host, &["wallet", "info"]);
    assert_eq!(
        (old.code, error_kind(&old).as_str()),
        (4, "wrong_password"),
        "{old:?}"
    );
    let mut env = wallet.env();
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    env.push(("LEPIC_PASSWORD".to_owned(), "new password".to_owned()));
    let info = wallet
        .run_with(&host, &["wallet", "info"], env, "")
        .ok()
        .json();
    assert_eq!(info["accounts"][0]["spendable"], "10.00000000", "{info}");
}

#[test]
fn a_wrong_current_password_changes_nothing() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("old password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let mut env = with_env(&wallet, "LEPIC_NEW_PASSWORD", "new password");
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    env.push(("LEPIC_PASSWORD".to_owned(), "wrong".to_owned()));
    let refused = wallet.run_with(&host, &["wallet", "password"], env, "");
    assert_eq!(
        (refused.code, error_kind(&refused).as_str()),
        (4, "wrong_password"),
        "{refused:?}"
    );
    wallet.run(&host, &["wallet", "info"]).ok();
}

#[test]
fn an_empty_new_password_is_refused() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("old password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let refused = wallet.run_with(&host, &["wallet", "password"], wallet.env(), "\n");
    assert_eq!(
        (refused.code, error_kind(&refused).as_str()),
        (7, "rejected"),
        "{refused:?}"
    );
    wallet.run(&host, &["wallet", "info"]).ok();
}

#[cfg(unix)]
#[test]
fn the_new_password_can_come_from_an_owner_only_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let host = TestHost::new();
    let wallet = Instance::new("old password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let file = wallet.path("new-password");
    let change = |path: &std::path::Path| {
        let env = with_env(&wallet, "LEPIC_NEW_PASSWORD_FILE", path.to_str().unwrap());
        wallet.run_with(&host, &["wallet", "password"], env, "")
    };

    let absent = change(&file);
    assert_eq!(
        (absent.code, error_kind(&absent).as_str()),
        (3, "config"),
        "{absent:?}"
    );

    std::fs::write(&file, "file password\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let open = change(&file);
    assert_eq!(
        (open.code, error_kind(&open).as_str()),
        (3, "config"),
        "{open:?}"
    );
    wallet.run(&host, &["wallet", "address"]).ok();

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let changed = change(&file);
    assert_eq!(changed.json(), serde_json::json!({ "changed": true }));
    assert!(!changed.stdout.contains("file password"), "{changed:?}");
    assert!(!changed.stderr.contains("file password"), "{changed:?}");
    let mut env = wallet.env();
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    env.push(("LEPIC_PASSWORD".to_owned(), "file password".to_owned()));
    wallet.run_with(&host, &["wallet", "address"], env, "").ok();
    let old = wallet.run(&host, &["wallet", "address"]);
    assert_eq!(old.code, 4, "{old:?}");
}
