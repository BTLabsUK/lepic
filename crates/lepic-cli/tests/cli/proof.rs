// SPDX-License-Identifier: Apache-2.0
//! `lepic proof`: the payment proof a paid epic1 address leaves the payer, exported and
//! verified, and `--require-proof` refused where no proof can come.

// Tests may unwrap, index and panic (docs/rules.md).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::support;

use lepic_node::LocatedKernel;
use serde_json::Value;
use support::{Instance, TestHost, funded, http, new_wallet, problem, serving, text};

/// The wallet's environment with `local_mailbox` on, its relay the mock relay's loopback name.
fn local_env(wallet: &Instance) -> Vec<(String, String)> {
    let mut env = wallet.env();
    env.push(("LEPIC_LOCAL_MAILBOX".to_owned(), "true".to_owned()));
    env
}

fn run_local(wallet: &Instance, host: &TestHost, args: &[&str]) -> support::Outcome {
    wallet.run_with(host, args, local_env(wallet), "")
}

/// A payer that paid 2 EPIC to a fresh epic1 address, requiring a proof, and took the payee's
/// answer; with the payment's transaction id and slate id.
fn paid_and_answered() -> (TestHost, Instance, String, String) {
    let (host, payer) = funded();
    host.relay.set_relays_apart(true);
    let payee = new_wallet(&host, "payee password");
    let made = run_local(&payee, &host, &["epic1", "address"]).ok().json();
    let address = text(&made, "address").to_owned();
    let paid = run_local(
        &payer,
        &host,
        &["epic1", "pay", &address, "2", "--require-proof"],
    )
    .ok()
    .json();
    let taken = run_local(&payee, &host, &["contact", "collect"])
        .ok()
        .json();
    assert_eq!(taken["epic1"], 1, "{taken}");
    let finalized = run_local(&payer, &host, &["contact", "collect"])
        .ok()
        .json();
    assert_eq!(finalized["epic1"], 1, "{finalized}");
    assert_eq!(host.node.pushed_transactions().len(), 1);
    let slate_id = text(&paid, "slate_id").to_owned();
    (host, payer, paid["tx_id"].to_string(), slate_id)
}

/// The error of a refused run, after checking its exit code and kind.
fn refused(outcome: &support::Outcome, code: u8, kind: &str) -> Value {
    assert_eq!(outcome.code, code, "{outcome:?}");
    let error = outcome.json()["error"].clone();
    assert_eq!(error["kind"], kind, "{error}");
    error
}

#[test]
fn a_paid_epic1_address_leaves_a_proof_that_verifies_and_one_changed_fact_fails() {
    let (mut host, payer, tx_id, slate_id) = paid_and_answered();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("proof.json");
    let path = file.to_str().unwrap();

    let shown = payer.run(&host, &["proof", "export", &tx_id]).ok().json();
    assert_eq!(shown["proof"]["type"], "lepic-epic1-receipt", "{shown}");
    let saved = payer
        .run(&host, &["proof", "export", &tx_id, "--out", path])
        .ok()
        .json();
    assert_eq!(saved["path"], path, "{saved}");
    assert_eq!(saved["proof"], shown["proof"], "{saved}");
    let again = payer.run(&host, &["proof", "export", &tx_id, "--out", path]);
    assert_ne!(again.code, 0, "{again:?}");
    assert!(text(&again.json()["error"], "message").contains("--force"));
    payer
        .run(
            &host,
            &["proof", "export", &tx_id, "--out", path, "--force"],
        )
        .ok();

    let verified = payer.run(&host, &["proof", "verify", path]).ok().json();
    assert_eq!(verified["valid"], true, "{verified}");
    assert_eq!(verified["amount"], 200_000_000, "{verified}");
    assert_eq!(verified["address"], shown["proof"]["address"], "{verified}");
    assert!(verified.get("height").is_none(), "{verified}");

    // The node holds no kernel yet; once a block holds it, the proof says where.
    let missing = payer.run(&host, &["proof", "verify", path, "--on-chain"]);
    let error = refused(&missing, 7, "rejected");
    assert!(text(&error, "message").contains("no kernel"), "{error}");
    let pushed = host.node.pushed_transactions();
    host.node.update_chain(|chain| {
        let mmr_index = u64::try_from(chain.kernels.len()).unwrap() + 1;
        chain.kernels.push(LocatedKernel {
            kernel: pushed[0].kernels()[0],
            height: chain.tip.height,
            mmr_index,
        });
    });
    let on_chain = payer
        .run(&host, &["proof", "verify", path, "--on-chain"])
        .ok()
        .json();
    assert_eq!(on_chain["on_chain"], true, "{on_chain}");
    assert_eq!(on_chain["height"], support::TIP, "{on_chain}");

    // Another network's flag reads it as a proof for another chain. The test host forces
    // floonet; the shipped binary leaves the network to the flag.
    let forced = host.network.take();
    let elsewhere = payer.run(&host, &["proof", "verify", path, "--network", "mainnet"]);
    host.network = forced;
    let error = refused(&elsewhere, 7, "rejected");
    assert!(
        text(&error, "message").contains("--network floonet"),
        "{error}"
    );

    let changed = dir.path().join("changed.json");
    let mut proof = shown["proof"].clone();
    proof["amount"] = Value::from(300_000_000_u64);
    std::fs::write(&changed, proof.to_string()).unwrap();
    let error = refused(
        &payer.run(&host, &["proof", "verify", changed.to_str().unwrap()]),
        7,
        "rejected",
    );
    assert!(text(&error, "message").contains("signature"), "{error}");

    std::fs::write(&changed, "not a proof").unwrap();
    refused(
        &payer.run(&host, &["proof", "verify", changed.to_str().unwrap()]),
        7,
        "rejected",
    );

    // Serve hands out the same proof, and none for a payment that has none.
    serving(host, &payer, |socket, _| {
        let served = http(
            socket,
            "GET",
            &format!("/api/v1/payments/{slate_id}/proof"),
            None,
        )
        .ok();
        assert_eq!(served, shown["proof"]);
        let list = http(socket, "GET", "/api/v1/payments", None).ok();
        let other = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|payment| text(payment, "id"))
            .find(|id| *id != slate_id)
            .unwrap();
        problem(
            &http(
                socket,
                "GET",
                &format!("/api/v1/payments/{other}/proof"),
                None,
            ),
            409,
            "no_payment_proof",
        );
    });
}

#[test]
fn a_transaction_without_a_proof_has_none_to_export() {
    let (host, wallet) = funded();
    let list = wallet.run(&host, &["tx", "list"]).ok().json();
    let tx_id = list["transactions"][0]["tx_id"].to_string();
    let error = refused(
        &wallet.run(&host, &["proof", "export", &tx_id]),
        6,
        "not_found",
    );
    assert!(
        text(&error, "message").contains("no payment proof"),
        "{error}"
    );
}

#[test]
fn require_proof_is_refused_for_a_payment_to_an_epicbox_address() {
    let (host, wallet) = funded();
    let payee = new_wallet(&host, "payee password");
    let address = payee.run(&host, &["wallet", "address"]).ok().json();
    let error = refused(
        &wallet.run(
            &host,
            &[
                "tx",
                "send",
                "1",
                "--to",
                text(&address, "address"),
                "--require-proof",
            ],
        ),
        2,
        "usage",
    );
    assert!(
        text(&error, "message").contains("--require-proof"),
        "{error}"
    );
}
