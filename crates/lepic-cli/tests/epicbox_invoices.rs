//! Invoices over Epicbox between two CLI instances, through the mock relay, against one mock
//! node: the payer's invoice address and allowlist, parking, paying and declining, and the
//! issuer's listen finalizing the payment.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::sync::Arc;

use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork};

use support::{FUNDING, Instance, SENDER_MNEMONIC, TestHost, keys, text};

/// A funded payer restored from its phrase and an issuer created from new entropy, with the
/// payer's invoice address and the issuer's payments address.
struct Parties {
    host: TestHost,
    payer: Instance,
    issuer: Instance,
    invoice_address: String,
    issuer_address: String,
}

fn parties() -> Parties {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let payer = Instance::new("payer password");
    payer.restore(&host, SENDER_MNEMONIC);
    let issuer = Instance::new("issuer password");
    issuer.run(&host, &["wallet", "init"]).ok();
    let shown = payer
        .run(&host, &["epicbox", "invoice-address"])
        .ok()
        .json();
    let invoice_address = text(&shown, "address").to_owned();
    let issuer_address = text(
        &issuer.run(&host, &["wallet", "address"]).ok().json(),
        "address",
    )
    .to_owned();
    Parties {
        host,
        payer,
        issuer,
        invoice_address,
        issuer_address,
    }
}

impl Parties {
    fn allow_issuer(&self) {
        self.payer
            .run(
                &self.host,
                &["epicbox", "allow", "add", &self.issuer_address],
            )
            .ok();
    }

    /// Issues an invoice for `amount` to the payer's invoice address and returns its slate id.
    fn issue(&self, amount: &str) -> String {
        let issued = self
            .issuer
            .run(
                &self.host,
                &["invoice", "issue", amount, "--to", &self.invoice_address],
            )
            .ok()
            .json();
        text(&issued, "slate_id").to_owned()
    }

    fn drain_invoices(&self) -> serde_json::Value {
        self.payer
            .run(&self.host, &["epicbox", "drain", "--invoices"])
            .ok()
            .json()
    }

    fn parked(&self) -> Vec<serde_json::Value> {
        let list = self.payer.run(&self.host, &["invoice", "list"]).ok().json();
        assert_eq!(keys(&list), ["invoices"]);
        list["invoices"].as_array().unwrap().clone()
    }
}

fn address(text: &str) -> EpicboxAddress {
    EpicboxAddress::parse(text, RelayNetwork::Floonet).unwrap()
}

#[test]
fn an_invoice_is_parked_paid_and_finalized_by_the_issuers_listen() {
    let mut parties = parties();
    let shown = parties
        .payer
        .run(&parties.host, &["epicbox", "invoice-address"])
        .ok()
        .json();
    assert_eq!(keys(&shown), ["address", "index", "rotated"]);
    assert_eq!(shown["index"], 1);
    let payments = parties
        .payer
        .run(&parties.host, &["wallet", "address"])
        .ok()
        .json();
    assert_ne!(text(&payments, "address"), parties.invoice_address);

    let allowed = parties
        .payer
        .run(
            &parties.host,
            &[
                "epicbox",
                "allow",
                "add",
                &parties.issuer_address,
                "--label",
                "bike shop",
            ],
        )
        .ok()
        .json();
    assert_eq!(keys(&allowed), ["added_at", "address", "label"]);
    assert_eq!(allowed["address"], parties.issuer_address.as_str());
    let listed = parties
        .payer
        .run(&parties.host, &["epicbox", "allow", "list"])
        .ok()
        .json();
    assert_eq!(listed["senders"].as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(listed["senders"][0]["label"], "bike shop");

    let issued = parties
        .issuer
        .run(
            &parties.host,
            &[
                "invoice",
                "issue",
                "3",
                "--to",
                &parties.invoice_address,
                "-m",
                "order 42",
            ],
        )
        .ok()
        .json();
    assert_eq!(
        keys(&issued),
        ["amount", "destination", "slate_id", "transport", "tx_id"]
    );
    assert_eq!(issued["transport"], "epicbox");
    assert_eq!(issued["destination"], parties.invoice_address.as_str());
    assert_eq!(
        parties
            .host
            .relay
            .pending(&address(&parties.invoice_address)),
        1
    );

    let drained = parties.drain_invoices();
    assert_eq!(drained["parked"], 1, "{drained}");
    assert_eq!(drained["dropped"], 0, "{drained}");
    assert_eq!(
        drained["expired"],
        serde_json::json!({"deleted": [], "cancelled": [], "cancellable": []})
    );
    assert_eq!(
        parties
            .host
            .relay
            .pending(&address(&parties.invoice_address)),
        0
    );

    let parked = parties.parked();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0]["slate_id"], issued["slate_id"]);
    assert_eq!(parked[0]["sender"], parties.issuer_address.as_str());
    assert_eq!(parked[0]["amount"], "3.00000000");
    assert_eq!(parked[0]["message"], "order 42");
    let slate_id = text(&issued, "slate_id").to_owned();

    let wrong = parties
        .payer
        .run(&parties.host, &["invoice", "pay", &slate_id, "2"]);
    assert_eq!(wrong.code, 7, "{wrong:?}");
    assert_eq!(parties.parked().len(), 1);

    let paid = parties
        .payer
        .run(&parties.host, &["invoice", "pay", &slate_id, "3"])
        .ok()
        .json();
    assert_eq!(
        keys(&paid),
        [
            "amount",
            "destination",
            "fee",
            "slate_id",
            "transport",
            "tx_id"
        ]
    );
    assert_eq!(paid["transport"], "epicbox");
    assert_eq!(paid["destination"], parties.issuer_address.as_str());
    assert!(parties.parked().is_empty());

    let relay = parties.host.relay.clone();
    let inbox = address(&parties.issuer_address);
    assert_eq!(relay.pending(&inbox), 1);
    parties.host.interrupt_when = Some(Arc::new(move || relay.pending(&inbox) == 0));
    let listened = parties
        .issuer
        .run(&parties.host, &["epicbox", "listen"])
        .ok()
        .json();
    parties.host.interrupt_when = None;
    assert_eq!(listened["finalized"], 1, "{listened}");
    assert_eq!(parties.host.node.pushed_transactions().len(), 1);
    let list = parties
        .issuer
        .run(&parties.host, &["tx", "list"])
        .ok()
        .json();
    let tx = &list["transactions"][0];
    assert_eq!(tx["tx_id"], issued["tx_id"]);
    assert_eq!(tx["state"], "posted");
    assert_eq!(tx["amount_credited"], "3.00000000");
    assert!(
        parties.host.node.violations().is_empty(),
        "{:?}",
        parties.host.node.violations()
    );
}

#[test]
fn the_invoice_address_drops_invoices_from_senders_not_allowed() {
    let parties = parties();
    parties.issue("1");
    let drained = parties.drain_invoices();
    assert_eq!(drained["parked"], 0, "{drained}");
    assert_eq!(drained["dropped"], 1, "{drained}");
    assert!(parties.parked().is_empty());
    assert_eq!(
        parties
            .host
            .relay
            .pending(&address(&parties.invoice_address)),
        0
    );

    parties.allow_issuer();
    let slate_id = parties.issue("1");
    assert_eq!(parties.drain_invoices()["parked"], 1);
    assert_eq!(parties.parked()[0]["slate_id"], slate_id.as_str());

    // The payments address does not park invoices; only the invoice address does.
    let plain = parties
        .payer
        .run(&parties.host, &["epicbox", "drain"])
        .ok()
        .json();
    assert_eq!(plain["parked"], 0, "{plain}");
}

#[test]
fn a_declined_invoice_is_never_paid() {
    let parties = parties();
    parties.allow_issuer();
    let slate_id = parties.issue("2");
    parties.drain_invoices();

    let declined = parties
        .payer
        .run(&parties.host, &["invoice", "decline", &slate_id])
        .ok()
        .json();
    assert_eq!(keys(&declined), ["slate_id", "state"]);
    assert_eq!(declined["state"], "declined");
    assert!(parties.parked().is_empty());

    for args in [
        vec!["invoice", "pay", slate_id.as_str(), "2"],
        vec!["invoice", "decline", slate_id.as_str()],
    ] {
        let refused = parties.payer.run(&parties.host, &args);
        assert_eq!(refused.code, 6, "{args:?}: {refused:?}");
        assert_eq!(refused.json()["error"]["kind"], "not_found");
    }
    let bad = parties
        .payer
        .run(&parties.host, &["invoice", "decline", "not-a-slate-id"]);
    assert_eq!(bad.code, 2, "{bad:?}");
    assert!(parties.host.node.pushed_transactions().is_empty());
}

#[test]
fn a_parked_invoice_is_paid_over_epicbox_only() {
    let parties = parties();
    parties.allow_issuer();
    let slate_id = parties.issue("2");
    parties.drain_invoices();
    let refused = parties.payer.run(
        &parties.host,
        &[
            "invoice",
            "pay",
            &slate_id,
            "2",
            "--reply-file",
            parties.payer.path("reply").to_str().unwrap(),
        ],
    );
    assert_eq!(refused.code, 2, "{refused:?}");
    assert_eq!(parties.parked().len(), 1);
    assert!(!parties.payer.path("reply").exists());
}

#[test]
fn a_payment_the_relay_did_not_take_is_resent_to_the_allowed_address() {
    let parties = parties();
    parties.allow_issuer();
    let slate_id = parties.issue("2");
    parties.drain_invoices();

    parties.host.relay.set_refusing(true);
    let failed = parties
        .payer
        .run(&parties.host, &["invoice", "pay", &slate_id, "2"]);
    assert_eq!(failed.code, 11, "{failed:?}");
    assert_eq!(failed.json()["error"]["kind"], "incomplete");
    parties.host.relay.set_refusing(false);
    let list = parties
        .payer
        .run(&parties.host, &["tx", "list"])
        .ok()
        .json();
    let payment = list["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tx| tx["slate_id"] == slate_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(payment["state"], "sent");
    let tx_id = payment["tx_id"].to_string();

    let elsewhere = parties.payer.run(
        &parties.host,
        &["tx", "resend", &tx_id, "--to", &parties.invoice_address],
    );
    assert_eq!(elsewhere.code, 7, "{elsewhere:?}");

    parties
        .payer
        .run(
            &parties.host,
            &["tx", "resend", &tx_id, "--to", &parties.issuer_address],
        )
        .ok();
    let finalized = parties
        .issuer
        .run(&parties.host, &["epicbox", "drain"])
        .ok()
        .json();
    assert_eq!(finalized["finalized"], 1, "{finalized}");
    assert_eq!(parties.host.node.pushed_transactions().len(), 1);
}

#[test]
fn the_invoice_address_rotates_to_the_next_index() {
    let parties = parties();
    let rotated = parties
        .payer
        .run(&parties.host, &["epicbox", "invoice-address", "--rotate"])
        .ok()
        .json();
    assert_eq!(rotated["index"], 2);
    assert_eq!(rotated["rotated"], true);
    assert_ne!(rotated["address"], parties.invoice_address.as_str());
    let shown = parties
        .payer
        .run(&parties.host, &["epicbox", "invoice-address"])
        .ok()
        .json();
    assert_eq!(shown["address"], rotated["address"]);
    assert_eq!(shown["rotated"], false);

    // An invoice to the abandoned address is not read.
    parties.allow_issuer();
    parties.issue("1");
    assert_eq!(parties.drain_invoices()["parked"], 0);
    assert_eq!(
        parties
            .host
            .relay
            .pending(&address(&parties.invoice_address)),
        1
    );
}

#[test]
fn the_allowlist_takes_valid_addresses_and_removes_them() {
    let parties = parties();
    for (args, code) in [
        (vec!["epicbox", "allow", "add", "bogus"], 2),
        (
            vec![
                "epicbox",
                "allow",
                "add",
                parties.issuer_address.as_str(),
                "--label",
                "a\u{7}b",
            ],
            2,
        ),
    ] {
        let refused = parties.payer.run(&parties.host, &args);
        assert_eq!(refused.code, code, "{args:?}: {refused:?}");
    }
    let empty = parties
        .payer
        .run(&parties.host, &["epicbox", "allow", "list"])
        .ok()
        .json();
    assert_eq!(empty["senders"], serde_json::json!([]));

    parties.allow_issuer();
    let remove = [
        "epicbox",
        "allow",
        "remove",
        parties.issuer_address.as_str(),
    ];
    let removed = parties.payer.run(&parties.host, &remove).ok().json();
    assert_eq!(keys(&removed), ["address", "removed"]);
    assert_eq!(removed["removed"], true);
    let again = parties.payer.run(&parties.host, &remove).ok().json();
    assert_eq!(again["removed"], false);

    parties.issue("1");
    assert_eq!(parties.drain_invoices()["dropped"], 1);
}

#[test]
fn the_invoice_expiry_setting_sets_when_a_parked_invoice_expires() {
    let parties = parties();
    parties.allow_issuer();
    parties.issue("1");
    let mut env = parties.payer.env();
    env.push(("LEPIC_INVOICE_EXPIRY_HOURS".to_owned(), "2".to_owned()));
    parties
        .payer
        .run_with(
            &parties.host,
            &["epicbox", "drain", "--invoices"],
            env.clone(),
            "",
        )
        .ok();
    let list = parties
        .payer
        .run_with(&parties.host, &["invoice", "list"], env, "")
        .ok()
        .json();
    let invoice = &list["invoices"][0];
    let received: jiff::Timestamp = text(invoice, "received_at").parse().unwrap();
    let expires: jiff::Timestamp = text(invoice, "expires_at").parse().unwrap();
    assert_eq!(
        expires.duration_since(received),
        jiff::SignedDuration::from_hours(2)
    );

    for bad in ["0", "49", "two"] {
        let mut env = parties.payer.env();
        env.push(("LEPIC_INVOICE_EXPIRY_HOURS".to_owned(), bad.to_owned()));
        let refused = parties
            .payer
            .run_with(&parties.host, &["invoice", "list"], env, "");
        assert_eq!(refused.code, 3, "{bad}: {refused:?}");
    }
}

#[test]
fn a_drain_shows_each_parked_invoice_for_people() {
    let parties = parties();
    parties.allow_issuer();
    let slate_id = parties.issue("1.5");
    let mut human = parties.payer.env();
    human.retain(|(key, _)| key != "LEPIC_OUTPUT");
    let drained = parties
        .payer
        .run_with(
            &parties.host,
            &["epicbox", "drain", "--invoices"],
            human.clone(),
            "",
        )
        .ok();
    assert!(
        drained.stderr.contains(&format!(
            "invoice {slate_id} for 1.50000000 EPIC parked; `lepic invoice pay {slate_id} \
             1.50000000` pays it"
        )),
        "{drained:?}"
    );
    assert!(drained.stdout.contains("parked 1"), "{drained:?}");
    let listed = parties
        .payer
        .run_with(&parties.host, &["invoice", "list"], human, "")
        .ok();
    assert!(
        listed.stdout.starts_with(&format!(
            "{slate_id}  1.50000000 EPIC from {}\n",
            parties.issuer_address
        )),
        "{listed:?}"
    );
}
