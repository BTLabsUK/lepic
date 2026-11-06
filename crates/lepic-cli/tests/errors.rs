// SPDX-License-Identifier: Apache-2.0
//! Failures reach the user as typed exit codes and, with `--output json`, as one JSON document.

// Tests may unwrap and index (docs/rules.md).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod support;

use std::sync::Arc;

use support::{
    FUNDING, Instance, SENDER_MNEMONIC, SilentInput, TestHost, run_in, run_reading, text,
};

fn error_kind(outcome: &support::Outcome) -> String {
    let document = outcome.json();
    assert_eq!(
        document["error"]["exit_code"],
        u64::from(outcome.code),
        "{document}"
    );
    text(&document["error"], "kind").to_owned()
}

#[test]
fn engine_failures_map_to_exit_codes_and_json_errors() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let mut wrong = wallet.env();
    wrong.retain(|(key, _)| key != "LEPIC_PASSWORD");
    wrong.push(("LEPIC_PASSWORD".to_owned(), "wrong".to_owned()));
    let outcome = wallet.run_with(&host, &["wallet", "info"], wrong, "");
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (4, "wrong_password")
    );

    let outcome = wallet.run(
        &host,
        &[
            "tx",
            "send",
            "500",
            "--to-file",
            wallet.path("x").to_str().unwrap(),
        ],
    );
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (8, "insufficient_funds")
    );
    assert!(!wallet.path("x").exists());

    let outcome = wallet.run(&host, &["tx", "show", "99"]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (6, "not_found")
    );

    let outcome = wallet.run(&host, &["tx", "list", "--account", "savings"]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (6, "not_found")
    );

    let outcome = wallet.run(&host, &["wallet", "init"]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (5, "wallet_state")
    );

    let outcome = wallet.run(&host, &["tx", "send", "1.000000001", "--to-file", "y"]);
    assert_eq!((outcome.code, error_kind(&outcome).as_str()), (2, "usage"));

    let outcome = wallet.run(
        &host,
        &["tx", "receive", wallet.path("missing").to_str().unwrap()],
    );
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (10, "transport")
    );
}

#[test]
fn an_http_address_is_refused_before_the_wallet_stores_anything() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);

    for args in [
        ["tx", "send", "1", "--to", "http://203.0.113.7:3415"],
        ["tx", "send", "1", "--to", "ftp://host.example"],
        ["invoice", "issue", "1", "--to", "http://127.0.0.1:3415"],
    ] {
        let outcome = wallet.run(&host, &args);
        assert_eq!(
            (outcome.code, error_kind(&outcome).as_str()),
            (2, "usage"),
            "{args:?}"
        );
    }
    let listed = wallet.run(&host, &["tx", "list"]).json();
    assert_eq!(listed["transactions"].as_array().unwrap().len(), 1);
}

#[test]
fn a_send_to_a_contact_this_wallet_does_not_hold_stores_nothing() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let unknown = "0".repeat(32);
    let outcome = wallet.run(
        &host,
        &["tx", "send", "1", "--to-contact", unknown.as_str()],
    );
    assert_eq!(error_kind(&outcome), "not_found");
    let outcome = wallet.run(
        &host,
        &["tx", "send", "1", "--to-contact", "not-a-contact-id"],
    );
    assert_eq!((outcome.code, error_kind(&outcome).as_str()), (2, "usage"));
    let slate_file = wallet.path("x.slate");
    let outcome = wallet.run(
        &host,
        &[
            "tx",
            "send",
            "1",
            "--to-file",
            slate_file.to_str().unwrap(),
            "--purpose",
            "withdrawal",
        ],
    );
    assert_eq!(outcome.code, 2);
    assert!(outcome.stderr.contains("--purpose"), "{}", outcome.stderr);
    let listed = wallet.run(&host, &["tx", "list"]).json();
    assert_eq!(listed["transactions"].as_array().unwrap().len(), 1);
    let leftovers: Vec<_> = std::fs::read_dir(wallet.data_dir())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".slate"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// The onion of the payment-proof key of account `m/0/0`, as `epic-wallet address` derives it.
fn onion_of(mnemonic: &str) -> String {
    let keychain = lepic_keychain::Keychain::from_mnemonic(
        mnemonic,
        lepic_primitives::params::Network::Floonet,
    )
    .unwrap();
    let parent = lepic_keychain::Identifier::new(2, [0, 0, 0, 0]).unwrap();
    let key = keychain.payment_proof_key(&parent, 0).unwrap();
    lepic_tor::onion_address(&key.public_key())
}

#[test]
fn tor_address_prints_an_onion_of_its_own_and_previous_prints_the_payment_proof_one() {
    let host = TestHost::new();
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let again = Instance::new("other password");
    again.restore(&host, SENDER_MNEMONIC);

    let onion = wallet.run(&host, &["tor", "address"]);
    let previous = wallet.run(&host, &["tor", "address", "--previous"]);
    let restored = again.run(&host, &["tor", "address"]);

    assert_eq!(onion.code, 0);
    assert_eq!(previous.code, 0);
    let onion = text(&onion.json(), "onion").to_owned();
    assert_eq!(text(&previous.json(), "onion"), onion_of(SENDER_MNEMONIC));
    assert_ne!(onion, onion_of(SENDER_MNEMONIC));
    assert_eq!(onion.len(), 62, "{onion}");
    assert!(onion.ends_with(".onion"), "{onion}");
    assert_eq!(
        text(&restored.json(), "onion"),
        onion,
        "a restore gives the same onion"
    );
}

#[test]
fn a_send_to_an_onion_needs_a_tor_binary_and_stores_nothing_without_one() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let onion = onion_of(SENDER_MNEMONIC);
    let mut typo = onion.clone();
    typo.replace_range(..1, if typo.starts_with('a') { "b" } else { "a" });
    let missing = wallet.path("no-tor-here");
    let missing = missing.to_str().unwrap();

    for (args, expected) in [
        (
            vec!["tx", "send", "1", "--to", onion.as_str()],
            (2, "usage"),
        ),
        (
            vec!["tx", "send", "1", "--to", &format!("http://{onion}/")],
            (2, "usage"),
        ),
        (
            vec![
                "tx",
                "send",
                "1",
                "--to",
                typo.as_str(),
                "--tor-binary",
                missing,
            ],
            (2, "usage"),
        ),
        (
            vec![
                "tx",
                "send",
                "1",
                "--to",
                "wallet.onion",
                "--tor-binary",
                missing,
            ],
            (2, "usage"),
        ),
        (
            vec![
                "tx",
                "send",
                "1",
                "--to",
                onion.as_str(),
                "--tor-binary",
                missing,
            ],
            (3, "config"),
        ),
        // Funds are checked before tor is started.
        (
            vec![
                "tx",
                "send",
                "1000",
                "--to",
                onion.as_str(),
                "--tor-binary",
                missing,
            ],
            (8, "insufficient_funds"),
        ),
        (vec!["tor", "listen"], (2, "usage")),
        (
            vec!["tor", "listen", "--tor-binary", missing],
            (3, "config"),
        ),
    ] {
        let outcome = wallet.run(&host, &args);
        assert_eq!(
            (outcome.code, error_kind(&outcome).as_str()),
            expected,
            "{args:?}"
        );
    }
    let listed = wallet.run(&host, &["tx", "list"]).json();
    assert_eq!(listed["transactions"].as_array().unwrap().len(), 1);
}

#[test]
fn an_invoice_to_any_address_with_a_scheme_is_refused_as_an_invoice_over_http() {
    let host = TestHost::new();
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);

    for to in [
        "http://127.0.0.1:3415",
        "http://203.0.113.7:3415",
        "https://host.example/path?query",
        "ftp://host.example",
    ] {
        let outcome = wallet.run(&host, &["invoice", "issue", "1", "--to", to]);
        assert_eq!(error_kind(&outcome), "usage", "{to}");
        let document = outcome.json();
        assert_eq!(
            text(&document["error"], "message"),
            "invoices go over epicbox or through a slate file, not over http",
            "{to}"
        );
    }
}

#[test]
fn a_data_directory_without_a_wallet_is_reported_as_such() {
    let host = TestHost::new();
    let empty = Instance::new("test password");
    let outcome = empty.run(&host, &["wallet", "info"]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (5, "wallet_state")
    );
}

#[test]
fn a_data_directory_another_process_holds_is_refused_until_released() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let holder = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(wallet.data_dir().join(".lepic.lock"))
        .unwrap();
    holder.try_lock().unwrap();
    for args in [
        &["wallet", "info"][..],
        &["tx", "list"],
        &["wallet", "address"],
    ] {
        let outcome = wallet.run(&host, args);
        assert_eq!(
            (outcome.code, error_kind(&outcome).as_str()),
            (5, "wallet_state"),
            "{args:?}"
        );
    }
    drop(holder);
    wallet.run(&host, &["wallet", "info"]).ok();
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_in_place_of_the_lock_file_is_not_followed() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("created-through-the-link");
    let lock = wallet.data_dir().join(".lepic.lock");
    std::fs::remove_file(&lock).unwrap();
    std::os::unix::fs::symlink(&target, &lock).unwrap();

    let outcome = wallet.run(&host, &["wallet", "info"]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (1, "internal")
    );
    assert!(!target.exists(), "the lock followed the link");
}

#[test]
fn init_on_a_locked_data_directory_creates_nothing() {
    let host = TestHost::new();
    let wallet = Instance::new("test password");
    let dir = wallet.data_dir();
    std::fs::create_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let holder = std::fs::File::create(dir.join(".lepic.lock")).unwrap();
    holder.try_lock().unwrap();
    let outcome = wallet.run(&host, &["wallet", "init"]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (5, "wallet_state")
    );
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, [".lepic.lock"]);
}

#[test]
fn the_first_tip_of_a_command_is_bounded_by_the_tip_the_wallet_confirmed() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);
    wallet.run(&host, &["wallet", "info"]).ok();

    // More than a day of blocks above the confirmed tip, moments after it was seen.
    host.node.update_chain(|chain| {
        chain.tip.height = lepic_primitives::amount::Height::new(support::TIP + 10_000);
    });
    let outcome = wallet.run(&host, &["wallet", "info"]);
    assert_eq!((outcome.code, error_kind(&outcome).as_str()), (9, "node"));
    // The engine refuses such a tip with the same exit code, so the cause shows that the node
    // client refused it first, from the tip the wallet stored.
    let refused_by_client = lepic_node::NodeError::ImplausibleTip {
        previous: lepic_primitives::amount::Height::new(support::TIP),
        reported: lepic_primitives::amount::Height::new(support::TIP + 10_000),
    }
    .to_string();
    let document = outcome.json();
    let causes = document["error"]["causes"].as_array().unwrap();
    assert!(
        causes
            .iter()
            .any(|cause| cause == refused_by_client.as_str()),
        "{document}"
    );
}

#[test]
fn human_errors_go_to_stderr_and_json_errors_to_stdout() {
    let host = TestHost::new();
    let empty = Instance::new("test password");
    let mut human = empty.env();
    human.retain(|(key, _)| key != "LEPIC_OUTPUT");
    let outcome = run_in(&host, &["wallet", "info"], human, "");
    assert_eq!(outcome.code, 5);
    assert!(outcome.stdout.is_empty());
    assert!(outcome.stderr.starts_with("error: "), "{}", outcome.stderr);

    let outcome = empty.run(&host, &["wallet", "info"]);
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    assert_eq!(outcome.stdout.lines().count(), 1);
}

#[test]
fn a_missing_password_on_standard_input_is_a_usage_error() {
    let host = TestHost::new();
    let wallet = Instance::new("test password");
    let mut env = wallet.env();
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    let outcome = wallet.run_with(&host, &["wallet", "init"], env.clone(), "");
    assert_eq!((outcome.code, error_kind(&outcome).as_str()), (2, "usage"));

    let created = wallet.run_with(&host, &["wallet", "init"], env.clone(), "from stdin\n");
    created.ok();
    let opened = wallet.run_with(&host, &["wallet", "address"], env, "from stdin\n");
    opened.ok();
}

#[test]
fn usage_errors_exit_with_code_two_and_help_with_zero() {
    let host = TestHost::new();
    let wallet = Instance::new("test password");
    let outcome = wallet.run(&host, &["tx", "send", "1"]);
    assert_eq!(outcome.code, 2);
    assert!(outcome.stderr.contains("--to"), "{}", outcome.stderr);
    let outcome = wallet.run(&host, &["--network", "testnet", "node", "status"]);
    assert_eq!(outcome.code, 2);
    let outcome = wallet.run(&host, &["--help"]);
    assert_eq!(outcome.code, 0);
    assert!(outcome.stdout.contains("Exit codes:"));
}

#[test]
fn node_status_reports_the_tip() {
    let host = TestHost::new();
    let outcome = Instance::new("test password")
        .run(&host, &["node", "status"])
        .ok()
        .json();
    assert_eq!(outcome["height"], support::TIP);
    assert_eq!(outcome["node_version"], "4.0.4");
    assert_eq!(outcome["node"], "127.0.0.1");
}

#[test]
fn an_interrupt_at_a_password_prompt_ends_the_command() {
    let mut host = TestHost::new();
    host.interrupt_when = Some(Arc::new(|| true));
    let wallet = Instance::new("test password");
    let mut env = wallet.env();
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    let (done, finished) = std::sync::mpsc::channel();
    // On its own thread, so a prompt the interrupt cannot end fails the test instead of
    // hanging it.
    std::thread::spawn(move || {
        let (_keep_open, never) = std::sync::mpsc::channel();
        let outcome = run_reading(
            &host,
            &["wallet", "init"],
            env,
            Box::new(std::io::BufReader::new(SilentInput(never))),
        );
        let _ = done.send(outcome);
    });
    let outcome = finished
        .recv_timeout(support::PATIENCE)
        .expect("the interrupt did not end the prompt");
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (12, "interrupted")
    );
}

#[test]
fn an_invoice_for_another_amount_is_refused_and_writes_no_reply() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let issuer = Instance::new("issuer password");
    issuer.run(&host, &["wallet", "init"]).ok();
    let invoice = issuer.path("invoice.slate");
    issuer
        .run(
            &host,
            &[
                "invoice",
                "issue",
                "3",
                "--to-file",
                invoice.to_str().unwrap(),
            ],
        )
        .ok();
    let outcome = payer.run(&host, &["invoice", "pay", invoice.to_str().unwrap(), "2.5"]);
    assert_eq!(
        (outcome.code, error_kind(&outcome).as_str()),
        (7, "rejected")
    );
    assert!(!issuer.path("invoice.slate.response").exists());
}

#[cfg(unix)]
#[test]
fn a_data_directory_other_users_can_access_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let host = TestHost::new();
    let wallet = Instance::new("right password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let set_mode = |mode| {
        std::fs::set_permissions(wallet.data_dir(), std::fs::Permissions::from_mode(mode)).unwrap();
    };

    set_mode(0o755);
    let outcome = wallet.run(&host, &["wallet", "info"]);
    assert_eq!((outcome.code, error_kind(&outcome).as_str()), (3, "config"));

    set_mode(0o700);
    wallet.run(&host, &["wallet", "info"]).ok();
}

/// The instance's environment with human output.
fn human_env(instance: &Instance) -> Vec<(String, String)> {
    let mut env = instance.env();
    env.retain(|(key, _)| key != "LEPIC_OUTPUT");
    env
}

#[test]
fn a_missing_wallet_is_reported_before_the_password_is_asked_for() {
    let host = TestHost::new();
    let empty = Instance::new("test password");
    let mut env = human_env(&empty);
    env.retain(|(key, _)| key != "LEPIC_PASSWORD");
    let outcome = empty.run_with(&host, &["wallet", "info"], env, "");
    assert_eq!(outcome.code, 5, "{outcome:?}");
    let hint = format!("hint: no floonet wallet in {}", empty.data_dir().display());
    assert!(outcome.stderr.contains(&hint), "{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("lepic wallet init"),
        "{}",
        outcome.stderr
    );
}

#[test]
fn human_errors_end_with_a_hint_and_json_errors_carry_none() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("test password");
    wallet.restore(&host, SENDER_MNEMONIC);

    let send = ["tx", "send", "500", "--to-file", "unused.slate"];
    let outcome = wallet.run_with(&host, &send, human_env(&wallet), "");
    assert_eq!(outcome.code, 8);
    assert!(
        outcome
            .stderr
            .contains("hint: 10.00000000 EPIC is spendable and 500."),
        "{}",
        outcome.stderr
    );
    let json = wallet.run(&host, &send);
    assert!(!json.stdout.contains("hint"), "{}", json.stdout);

    // A slate file in a directory that does not exist cannot be written: the transaction is
    // stored and the hint says how to deliver it again or give it up.
    let unwritable = wallet.path("missing/payment.slate");
    let outcome = wallet.run_with(
        &host,
        &["tx", "send", "1", "--to-file", unwritable.to_str().unwrap()],
        human_env(&wallet),
        "",
    );
    assert_eq!(outcome.code, 11, "{outcome:?}");
    for expected in [
        "hint: the inputs stay locked",
        "lepic tx resend ",
        "lepic tx cancel ",
    ] {
        assert!(outcome.stderr.contains(expected), "{}", outcome.stderr);
    }
    assert!(
        !outcome.stderr.contains("must name its port"),
        "{}",
        outcome.stderr
    );
    // Over the relay the hint adds that a non-default relay port belongs in the address.
    let receiver = Instance::new("receiver password");
    receiver.run(&host, &["wallet", "init"]).ok();
    let address = receiver.run(&host, &["wallet", "address"]).ok().json();
    let tx_id = wallet.run(&host, &["tx", "list"]).ok().json()["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tx| tx["state"] == "sent")
        .unwrap()["tx_id"]
        .to_string();
    host.relay.set_refusing(true);
    let outcome = wallet.run_with(
        &host,
        &["tx", "resend", &tx_id, "--to", text(&address, "address")],
        human_env(&wallet),
        "",
    );
    assert_eq!(outcome.code, 11, "{outcome:?}");
    for expected in ["hint: the inputs stay locked", "<key>@127.0.0.1:80"] {
        assert!(outcome.stderr.contains(expected), "{}", outcome.stderr);
    }
}

#[test]
fn a_slate_file_error_names_the_file() {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("test password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let missing = wallet.path("missing.slate");
    for args in [
        vec!["tx", "receive", missing.to_str().unwrap()],
        vec!["tx", "finalize", missing.to_str().unwrap()],
        vec!["invoice", "pay", missing.to_str().unwrap(), "1"],
    ] {
        let outcome = wallet.run(&host, &args);
        assert_eq!(
            (outcome.code, error_kind(&outcome).as_str()),
            (10, "transport"),
            "{args:?}"
        );
        let message = format!("slate file {}", missing.display());
        assert_eq!(outcome.json()["error"]["message"], message, "{args:?}");
    }
}
