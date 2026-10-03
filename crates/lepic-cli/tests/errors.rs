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
            &["wallet", "info"],
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
