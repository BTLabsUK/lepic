// SPDX-License-Identifier: Apache-2.0
//! The contact, pairing, payload and quarantine calls of the wallet API v1: two wallets on one
//! mock relay pair through the API and the CLI, and the calls refuse what they should.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::path::Path;

use lepic_keychain::Seed;
use lepic_store::{CONTACT_EXTRA_PREFIX, WalletStore as _};
use lepic_wallet::{EncryptedSqliteStores, StoreOpener as _};
use serde_json::json;
use support::{
    Instance, SENDER_MNEMONIC, TestHost, funded, http, new_wallet, problem, serving, text,
    wait_until,
};

/// The id a CLI `contact` command prints is the id the API uses.
fn path(id: &str) -> String {
    format!("/api/v1/contacts/{id}")
}

fn contact_state(socket: &Path, id: &str) -> String {
    let reply = http(socket, "GET", &path(id), None);
    assert_eq!(reply.status, 200, "{reply:?}");
    text(&reply.json(), "state").to_owned()
}

/// A (served) invites; B (not served) accepts. Returns the ids at A and at B once both sides are
/// paired.
fn pair(socket: &Path, host: &TestHost, buyer: &Instance) -> (String, String) {
    let created = http(
        socket,
        "POST",
        "/api/v1/contacts",
        Some(r#"{"method":"invite","label":"Buyer"}"#),
    );
    assert_eq!(created.status, 201, "{created:?}");
    let invite = created.json();
    assert_eq!(invite["state"], "waiting", "{invite}");
    assert_eq!(invite["label"], "Buyer", "{invite}");
    assert_eq!(invite["pairing"]["method"], "invite", "{invite}");
    let link = text(&invite["pairing"], "invite_link").to_owned();
    assert!(link.starts_with("epiccash://pair/"), "{invite}");
    let at_shop = text(&invite, "id").to_owned();

    let joined = buyer
        .run(host, &["contact", "accept", &link, "--name", "Shop"])
        .ok()
        .json();
    let at_buyer = text(&joined, "contact_id").to_owned();
    wait_until("both sides paired", || {
        buyer.run(host, &["contact", "collect"]).ok();
        contact_state(socket, &at_shop) == "paired"
    });
    (at_shop, at_buyer)
}

#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_contact_pairs_is_managed_and_deleted_through_the_api() {
    let host = TestHost::new();
    let shop = new_wallet(&host, "shop password");
    let buyer = new_wallet(&host, "buyer password");
    serving(host, &shop, |socket, host| {
        let (id, at_buyer) = pair(socket, host, &buyer);

        // It is listed, with the filters.
        let listed = http(socket, "GET", "/api/v1/contacts", None).ok();
        let items = listed["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{listed}");
        assert_eq!(items[0]["id"], id.as_str());
        let by_state = http(socket, "GET", "/api/v1/contacts?state=paired", None).ok();
        assert_eq!(by_state["items"].as_array().unwrap().len(), 1);
        let none = http(socket, "GET", "/api/v1/contacts?state=ended", None).ok();
        assert!(none["items"].as_array().unwrap().is_empty());
        problem(
            &http(socket, "GET", "/api/v1/contacts?state=unheard-of", None),
            400,
            "invalid_field",
        );

        // Its fields while unverified.
        let contact = http(socket, "GET", &path(&id), None).ok();
        assert_eq!(contact["class"], "standard", "{contact}");
        assert_eq!(contact["verify_words"].as_array().unwrap().len(), 4);
        assert_eq!(contact["allow_invoices"], false);
        assert!(contact["home_relay"].is_string(), "{contact}");
        assert!(contact.get("verified_at").is_none(), "{contact}");

        // Invoices wait for the verification.
        let early = http(
            socket,
            "PATCH",
            &path(&id),
            Some(r#"{"allow_invoices":true}"#),
        );
        problem(&early, 409, "contact_not_verified");

        // Rename.
        let renamed = http(
            socket,
            "PATCH",
            &path(&id),
            Some(r#"{"label":"Best buyer"}"#),
        )
        .ok();
        assert_eq!(renamed["label"], "Best buyer", "{renamed}");
        assert_eq!(
            http(socket, "GET", &path(&id), None).ok()["label"],
            "Best buyer"
        );

        // Verify: both sides answer `match`.
        let bad = http(
            socket,
            "POST",
            &format!("{}/verify", path(&id)),
            Some(r#"{"result":"maybe"}"#),
        );
        let bad = problem(&bad, 400, "invalid_field");
        assert_eq!(bad["param"], "/result", "{bad}");
        buyer
            .run(host, &["contact", "sas", &at_buyer, "match"])
            .ok();
        let verified = http(
            socket,
            "POST",
            &format!("{}/verify", path(&id)),
            Some(r#"{"result":"match"}"#),
        )
        .ok();
        assert!(verified["verified_at"].is_string(), "{verified}");
        assert!(verified.get("verify_words").is_none(), "{verified}");
        let allowed = http(
            socket,
            "PATCH",
            &path(&id),
            Some(r#"{"allow_invoices":true}"#),
        )
        .ok();
        assert_eq!(allowed["allow_invoices"], true, "{allowed}");

        // A payload goes to the contact; the contact reads it.
        let sent = http(
            socket,
            "POST",
            &format!("{}/payloads", path(&id)),
            Some(r#"{"data_base64":"aGVsbG8="}"#),
        );
        assert_eq!(sent.status, 204, "{sent:?}");
        wait_until("the buyer holds the payload", || {
            buyer.run(host, &["contact", "collect"]).ok();
            !buyer.run(host, &["contact", "payload", "list"]).ok().json()["payloads"]
                .as_array()
                .unwrap()
                .is_empty()
        });
        let toolarge = format!(r#"{{"data_base64":"{}"}}"#, "A".repeat(100_000));
        let big = http(
            socket,
            "POST",
            &format!("{}/payloads", path(&id)),
            Some(&toolarge),
        );
        assert_eq!(big.status, 400, "{big:?}");
        // One limit, checked once: a body of 65,535 bytes goes, one byte more is refused here.
        let limit = |len: usize| {
            use base64::Engine as _;
            let data = base64::engine::general_purpose::STANDARD.encode(vec![7_u8; len]);
            http(
                socket,
                "POST",
                &format!("{}/payloads", path(&id)),
                Some(&format!(r#"{{"data_base64":"{data}"}}"#)),
            )
        };
        let over = problem(&limit(65_536), 400, "invalid_field");
        assert_eq!(over["param"], "/data_base64", "{over}");
        assert_eq!(limit(65_535).status, 204);
        let bad = http(
            socket,
            "POST",
            &format!("{}/payloads", path(&id)),
            Some(r#"{"data_base64":"***"}"#),
        );
        let bad = problem(&bad, 400, "invalid_field");
        assert_eq!(bad["param"], "/data_base64", "{bad}");

        // A payload from the contact is listed until it is deleted.
        buyer
            .run(
                host,
                &["contact", "payload", "post", &at_buyer, "--hex", "6869"],
            )
            .ok();
        wait_until("the shop holds the payload", || {
            !http(socket, "GET", "/api/v1/payloads", None).ok()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        });
        let payloads = http(socket, "GET", "/api/v1/payloads", None).ok();
        let payload = payloads["items"][0].clone();
        assert_eq!(payload["contact_id"], id.as_str(), "{payload}");
        assert_eq!(payload["data_base64"], "aGk=", "{payload}");
        assert_eq!(payload["size"], 2, "{payload}");
        let payload_id = text(&payload, "id").to_owned();
        let gone = http(
            socket,
            "DELETE",
            &format!("/api/v1/payloads/{payload_id}"),
            None,
        );
        assert_eq!(gone.status, 204, "{gone:?}");
        problem(
            &http(
                socket,
                "DELETE",
                &format!("/api/v1/payloads/{payload_id}"),
                None,
            ),
            404,
            "not_found",
        );
        assert!(
            http(socket, "GET", "/api/v1/payloads", None).ok()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        // Nothing is quarantined, and nothing unknown can be retried or deleted.
        let quarantine = http(socket, "GET", "/api/v1/quarantine", None).ok();
        assert!(
            quarantine["items"].as_array().unwrap().is_empty(),
            "{quarantine}"
        );
        let unknown = "0123456789abcdef0123456789abcdef";
        problem(
            &http(
                socket,
                "POST",
                &format!("/api/v1/quarantine/{unknown}/retry"),
                Some("{}"),
            ),
            404,
            "not_found",
        );
        problem(
            &http(
                socket,
                "DELETE",
                &format!("/api/v1/quarantine/{unknown}"),
                None,
            ),
            404,
            "not_found",
        );

        // Nothing is announced to move.
        let moved = http(
            socket,
            "POST",
            &format!("{}/move", path(&id)),
            Some(r#"{"host":"relay.test"}"#),
        );
        problem(&moved, 409, "relay_changed");

        // Delete.
        let removed = http(
            socket,
            "DELETE",
            &format!("{}?notify=false", path(&id)),
            None,
        );
        assert_eq!(removed.status, 204, "{removed:?}");
        problem(&http(socket, "GET", &path(&id), None), 404, "not_found");
        problem(&http(socket, "DELETE", &path(&id), None), 404, "not_found");
    });
}

/// The settings kept beside contact `id` in `wallet`, a wallet of [`SENDER_MNEMONIC`], read
/// from its store while nothing else has it open.
fn kept_beside(wallet: &Instance, id: &str) -> Vec<String> {
    let seed = Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
    let store = EncryptedSqliteStores
        .open(
            &wallet.data_dir(),
            lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
            &lepic_wallet::store_key(&seed).unwrap(),
        )
        .unwrap();
    store
        .read(|repos| repos.settings_with_prefix(&format!("{CONTACT_EXTRA_PREFIX}{id}.")))
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

#[test]
fn what_serve_keeps_beside_a_contact_goes_with_a_cli_remove() {
    let (host, shop) = funded();
    let buyer = new_wallet(&host, "buyer password");
    let (id, host) = serving(host, &shop, |socket, host| {
        let (id, _) = pair(socket, host, &buyer);
        (id, host.without_interrupt())
    });
    // The invite's link and the label given while it waited.
    assert_eq!(kept_beside(&shop, &id).len(), 2, "{id}");

    shop.run(&host, &["contact", "remove", &id]).ok();
    assert_eq!(kept_beside(&shop, &id), Vec::<String>::new());
}

#[test]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn a_contact_is_created_once_and_refused_when_the_body_is_wrong() {
    let host = TestHost::new();
    let shop = new_wallet(&host, "shop password");
    serving(host, &shop, |socket, _| {
        let body =
            r#"{"id":"11111111-1111-4111-8111-111111111111","method":"invite","label":"Once"}"#;
        let first = http(socket, "POST", "/api/v1/contacts", Some(body));
        assert_eq!(first.status, 201, "{first:?}");
        let first = first.json();
        let again = http(socket, "POST", "/api/v1/contacts", Some(body));
        assert_eq!(again.status, 200, "{again:?}");
        assert_eq!(again.json()["id"], first["id"]);
        let other =
            r#"{"id":"11111111-1111-4111-8111-111111111111","method":"invite","label":"Other"}"#;
        problem(
            &http(socket, "POST", "/api/v1/contacts", Some(other)),
            409,
            "idempotency_mismatch",
        );
        assert_eq!(
            http(socket, "GET", "/api/v1/contacts", None).ok()["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        // The invite is listed while it waits.
        let waiting = http(socket, "GET", "/api/v1/contacts?state=waiting", None).ok();
        assert_eq!(waiting["items"].as_array().unwrap().len(), 1, "{waiting}");

        // 400 with the field that is wrong.
        let accept = http(
            socket,
            "POST",
            "/api/v1/contacts",
            Some(r#"{"method":"accept","label":"x"}"#),
        );
        let accept = problem(&accept, 400, "invalid_field");
        assert_eq!(accept["param"], "/invite", "{accept}");
        let long = json!({"method": "invite", "label": "L".repeat(200)}).to_string();
        let long = problem(
            &http(socket, "POST", "/api/v1/contacts", Some(&long)),
            400,
            "invalid_field",
        );
        assert_eq!(long["param"], "/label", "{long}");
        let unknown = http(
            socket,
            "POST",
            "/api/v1/contacts",
            Some(r#"{"method":"invite","colour":"red"}"#),
        );
        assert_eq!(unknown.status, 400, "{unknown:?}");
        let garbled = http(
            socket,
            "POST",
            "/api/v1/contacts",
            Some(r#"{"method":"accept","invite":"not a link"}"#),
        );
        assert_eq!(garbled.status, 400, "{garbled:?}");

        // 404 for what is not there, whatever the id looks like.
        for id in ["0123456789abcdef0123456789abcdef", "nonsense"] {
            problem(&http(socket, "GET", &path(id), None), 404, "not_found");
            problem(
                &http(socket, "PATCH", &path(id), Some(r#"{"label":"x"}"#)),
                404,
                "not_found",
            );
            problem(
                &http(
                    socket,
                    "POST",
                    &format!("{}/verify", path(id)),
                    Some(r#"{"result":"match"}"#),
                ),
                404,
                "not_found",
            );
            problem(
                &http(
                    socket,
                    "POST",
                    &format!("{}/move", path(id)),
                    Some(r#"{"host":"relay.test"}"#),
                ),
                404,
                "not_found",
            );
        }
        problem(
            &http(
                socket,
                "DELETE",
                "/api/v1/pair-requests/0123456789abcdef0123456789abcdef",
                None,
            ),
            404,
            "no_route",
        );
        problem(
            &http(
                socket,
                "POST",
                "/api/v1/pair-requests/0123456789abcdef0123456789abcdef/accept",
                Some("{}"),
            ),
            404,
            "no_route",
        );
    });
}

#[test]
fn the_contacts_are_exported_and_imported_on_the_socket() {
    let host = TestHost::new();
    let shop = new_wallet(&host, "shop password");
    let buyer = new_wallet(&host, "buyer password");
    serving(host, &shop, |socket, host| {
        let (id, _) = pair(socket, host, &buyer);
        let backup = http(socket, "POST", "/api/v1/contacts/export", Some("{}")).ok();
        let document = text(&backup, "document").to_owned();
        assert!(!document.is_empty());

        let deleted = http(
            socket,
            "DELETE",
            &format!("{}?notify=false", path(&id)),
            None,
        );
        assert_eq!(deleted.status, 204, "{deleted:?}");
        let body = json!({ "document": document }).to_string();
        let restored = http(socket, "POST", "/api/v1/contacts/import", Some(&body)).ok();
        assert_eq!(restored["imported"], 1, "{restored}");
        assert_eq!(contact_state(socket, &id), "paired");

        let bad = http(
            socket,
            "POST",
            "/api/v1/contacts/import",
            Some(r#"{"document":"not a backup"}"#),
        );
        let bad = problem(&bad, 400, "invalid_field");
        assert_eq!(bad["param"], "/document", "{bad}");
    });
}

#[test]
fn a_contact_is_checked_and_its_keys_resolved() {
    let host = TestHost::new();
    let shop = new_wallet(&host, "shop password");
    let buyer = new_wallet(&host, "buyer password");
    serving(host, &shop, |socket, host| {
        let (id, _) = pair(socket, host, &buyer);
        // Keys have not changed.
        let keys = http(
            socket,
            "POST",
            &format!("{}/keys", path(&id)),
            Some(r#"{"use":"new"}"#),
        );
        problem(&keys, 409, "keys_not_changed");
        let bad = http(
            socket,
            "POST",
            &format!("{}/keys", path(&id)),
            Some(r#"{"use":"both"}"#),
        );
        let bad = problem(&bad, 400, "invalid_field");
        assert_eq!(bad["param"], "/use", "{bad}");
        // The buyer is not served, so the check is not answered.
        let checked = http(socket, "POST", &format!("{}/check", path(&id)), Some("{}"));
        assert_eq!(checked.status, 200, "{checked:?}");
    });
}
