// SPDX-License-Identifier: Apache-2.0
//! The wallet API keeps the contract of `docs/api/openapi.json`. Every answer a test reads
//! through `support::http` from `/api/v1` is checked against it (`support::contract`); this
//! file checks the checker, and walks every operation of the document once.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use serde_json::{Value, json};
use support::contract::{self, is_date_time, is_decimal, is_uuid};
use support::{Reply, funded, http, problem, serving};

fn reply(status: u16, content_type: &str, body: &Value) -> Reply {
    Reply {
        status,
        headers: vec![("content-type".to_owned(), content_type.to_owned())],
        body: body.to_string(),
    }
}

#[test]
fn the_checker_knows_the_formats_the_document_uses() {
    assert!(is_date_time("2026-11-11T01:02:03Z"));
    assert!(is_date_time("2026-11-11T01:02:03.123456Z"));
    assert!(is_date_time("2026-11-11T01:02:03+00:00"));
    assert!(!is_date_time("2026-11-11 01:02:03Z"));
    assert!(is_decimal("1.5") && is_decimal("-0.00000001") && is_decimal("10"));
    assert!(!is_decimal("1.") && !is_decimal(".5") && !is_decimal("1.123456789"));
    assert!(is_uuid("0f8fad5b-d9cb-469f-a165-70867728950e"));
    assert!(!is_uuid("0f8fad5b"));
}

#[test]
fn the_checker_finds_drift() {
    let good = json!({
        "type": "about:blank",
        "title": "Not Found",
        "status": 404,
        "detail": "no such payment",
        "code": "not_found",
        "category": "not_found",
    });
    let problem_json = "application/problem+json";
    assert_eq!(
        contract::errors("GET", "/payments/x", &reply(404, problem_json, &good)),
        Vec::<String>::new()
    );
    // A status the operation does not document.
    assert!(!contract::errors("GET", "/payments/x", &reply(418, problem_json, &good)).is_empty());
    // A field the schema does not name.
    let mut extra = good.clone();
    extra["hint"] = json!("run lepic tx list");
    let errors = contract::errors("GET", "/payments/x", &reply(404, problem_json, &extra));
    assert!(errors.iter().any(|e| e.contains("/hint")), "{errors:?}");
    // A required field missing.
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("code");
    let errors = contract::errors("GET", "/payments/x", &reply(404, problem_json, &missing));
    assert!(errors.iter().any(|e| e.contains("code")), "{errors:?}");
    // The wrong media type.
    assert!(!contract::errors("GET", "/payments/x", &reply(404, "text/plain", &good)).is_empty());
    // A problem any call may answer, though the operation does not list its status.
    let mut large = good.clone();
    large["status"] = json!(413);
    large["code"] = json!("body_too_large");
    large["title"] = json!("Payload Too Large");
    let errors = contract::errors("GET", "/status", &reply(413, problem_json, &large));
    assert_eq!(errors, Vec::<String>::new());
    // Not with another code.
    large["code"] = json!("not_found");
    assert!(!contract::errors("GET", "/status", &reply(413, problem_json, &large)).is_empty());
    // A wrong type deep inside.
    let status = json!({"version": 1});
    let errors = contract::errors("GET", "/status", &reply(200, "application/json", &status));
    assert!(errors.iter().any(|e| e.contains("/version")), "{errors:?}");
}

#[test]
fn the_service_calls_keep_the_contract() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        let status = http(socket, "GET", "/api/v1/status", None).ok();
        assert!(status["version"].is_string(), "{status}");
        let document = http(socket, "GET", "/api/v1/openapi.json", None).ok();
        assert_eq!(document["openapi"], "3.1.0");
        let events = http(socket, "GET", "/api/v1/events?limit=5", None).ok();
        assert!(events["items"].is_array(), "{events}");
        problem(
            &http(socket, "GET", "/api/v1/no-such-thing", None),
            404,
            "no_route",
        );
        let wrong = http(socket, "DELETE", "/api/v1/status", None);
        problem(&wrong, 405, "method_not_allowed");
    });
}

/// Calls `method` on `path` below `/api/v1` and notes the operation it reaches; the answer is
/// checked against the document by `support::http`.
struct Walk<'a> {
    socket: &'a std::path::Path,
    reached: std::collections::BTreeSet<String>,
}

impl Walk<'_> {
    fn call(&mut self, method: &str, path: &str, body: Option<&Value>) -> support::Reply {
        let id = contract::operation_id(method, path);
        assert!(id.is_some(), "{method} {path} is not in the document");
        let id = id.unwrap();
        let body = body.map(Value::to_string);
        let reply = http(
            self.socket,
            method,
            &format!("/api/v1{path}"),
            body.as_deref(),
        );
        assert_ne!(reply.status, 501, "{id} is not implemented: {reply:?}");
        self.reached.insert(id);
        reply
    }
}

/// Every operation of the document answers once as the document says, on a funded wallet with
/// a second wallet to pay. Most calls on unknown ids only reach their refusals; the other api
/// tests cover the paths that succeed.
#[test]
#[allow(clippy::too_many_lines)] // One walk through the whole document.
fn every_operation_keeps_the_contract() {
    let (host, wallet) = funded();
    let other = support::new_wallet(&host, "other password");
    let address = other.run(&host, &["wallet", "address"]).ok().json();
    let address = support::text(&address, "address").to_owned();

    serving(host, &wallet, |socket, _| {
        let mut walk = Walk {
            socket,
            reached: std::collections::BTreeSet::new(),
        };
        // The service and the wallet.
        walk.call("GET", "/status", None).ok();
        walk.call("GET", "/openapi.json", None).ok();
        walk.call("GET", "/wallet", None).ok();
        walk.call("PATCH", "/wallet", Some(&json!({"issues_addresses": true})))
            .ok();
        walk.call("POST", "/sync", Some(&json!({})));
        walk.call("GET", "/accounts", None).ok();
        let account = walk.call("POST", "/accounts", Some(&json!({"label": "walk"})));
        assert_eq!(account.status, 201, "{account:?}");
        walk.call("GET", "/node", None).ok();

        // Coins and being paid.
        walk.call("GET", "/outputs", None).ok();
        walk.call("GET", "/addresses", None).ok();
        let issued = json!({"id": "a1b2c3d4-0000-4000-8000-000000000001"});
        let first = walk.call("POST", "/addresses", Some(&issued));
        assert_eq!(first.status, 201, "{first:?}");
        let again = walk.call("POST", "/addresses", Some(&issued));
        assert_eq!(again.status, 200, "{again:?}");
        assert_eq!(again.json(), first.json());
        walk.call("GET", "/links", None).ok();
        walk.call("POST", "/links", Some(&json!({"kind": "printed"})));
        walk.call("POST", "/links/0.printed.999/retire", None);

        // Payments: a send that waits for its answer, an invoice by file, and the actions a
        // send does not offer.
        let send = json!({
            "id": "a1b2c3d4-0000-4000-8000-000000000002",
            "amount": "1",
            "to": address,
        });
        walk.call("POST", "/payments/estimate", Some(&send)).ok();
        let sent = walk.call("POST", "/payments", Some(&send));
        assert_eq!(sent.status, 201, "{sent:?}");
        let id = sent.json()["id"].as_str().unwrap().to_owned();
        let repeat = walk.call("POST", "/payments", Some(&send));
        assert_eq!(repeat.status, 200, "{repeat:?}");
        let invoice = json!({
            "id": "a1b2c3d4-0000-4000-8000-000000000003",
            "kind": "invoice",
            "amount": "1",
            "via": "file",
        });
        let invoice = walk.call("POST", "/payments", Some(&invoice));
        assert_eq!(invoice.status, 201, "{invoice:?}");
        let invoice_id = invoice.json()["id"].as_str().unwrap().to_owned();
        walk.call("GET", "/payments", None).ok();
        walk.call("GET", &format!("/payments/{id}"), None).ok();
        let note = json!({"metadata": {"order": "walk"}});
        walk.call("PATCH", &format!("/payments/{id}"), Some(&note))
            .ok();
        walk.call("GET", &format!("/payments/{invoice_id}/handoff"), None)
            .ok();
        walk.call("GET", &format!("/payments/{id}/handoff"), None);
        let approve = json!({"amount": "1"});
        walk.call("POST", &format!("/payments/{id}/approve"), Some(&approve));
        walk.call("POST", &format!("/payments/{id}/decline"), None);
        let answer = json!({"answer_id": "a1b2c3d4-0000-4000-8000-000000000004"});
        walk.call("POST", &format!("/payments/{id}/finalize"), Some(&answer));
        walk.call("POST", &format!("/payments/{id}/deliver"), Some(&json!({})));
        walk.call("POST", &format!("/payments/{id}/post"), Some(&json!({})));
        walk.call("POST", &format!("/payments/{id}/cancel"), None)
            .ok();

        // Things handed to the wallet.
        let nonsense = json!({"text": "not a slate"});
        walk.call("POST", "/inspect", Some(&nonsense));
        walk.call("POST", "/open", Some(&nonsense));

        // Contacts, on an id nobody has.
        let nobody = "/contacts/00000000000000000000000000000000";
        walk.call("GET", "/contacts", None).ok();
        walk.call("POST", "/contacts", Some(&json!({"method": "invite"})));
        walk.call("GET", nobody, None);
        walk.call("PATCH", nobody, Some(&json!({"label": "x"})));
        walk.call("DELETE", &format!("{nobody}?notify=false"), None);
        let verify = json!({"result": "skip"});
        walk.call("POST", &format!("{nobody}/verify"), Some(&verify));
        walk.call("POST", &format!("{nobody}/check"), Some(&json!({})));
        walk.call(
            "POST",
            &format!("{nobody}/keys"),
            Some(&json!({"use": "new"})),
        );
        let move_to = json!({"host": "relay.example"});
        walk.call("POST", &format!("{nobody}/move"), Some(&move_to));
        let payload = json!({"data_base64": "aGk="});
        walk.call("POST", &format!("{nobody}/payloads"), Some(&payload));
        let backup = walk.call("POST", "/contacts/export", None).ok();
        let document = json!({"document": backup["document"]});
        walk.call("POST", "/contacts/import", Some(&document));
        walk.call("GET", "/pair-requests", None).ok();
        walk.call("POST", "/pair-requests/nobody/accept", Some(&json!({})));
        walk.call("DELETE", "/pair-requests/nobody", None);
        walk.call("GET", "/payloads", None).ok();
        walk.call("DELETE", "/payloads/nobody", None);
        walk.call("GET", "/quarantine", None).ok();
        walk.call("POST", "/quarantine/nobody/retry", None);
        walk.call("DELETE", "/quarantine/nobody", None);

        // The network and the owner's profile.
        walk.call("GET", "/relay", None).ok();
        walk.call("POST", "/relay/move", Some(&json!({"host": "not a host"})));
        walk.call("GET", "/peers", None).ok();
        walk.call("DELETE", "/peers/nobody", None);
        walk.call("GET", "/profile", None).ok();
        walk.call("PATCH", "/profile", Some(&json!({"name": "walk"})));
        walk.call("GET", "/profile/domain-file", None);

        // The log, a scan, and the password last.
        walk.call("GET", "/events", None).ok();
        // No webhook is set here; its delivery has its own tests.
        walk.call("GET", "/webhook", None);
        walk.call("POST", "/webhook/resume", None);
        let scan = walk.call("POST", "/wallet/scan", Some(&json!({})));
        assert_eq!(scan.status, 202, "{scan:?}");
        let password = json!({"current": "serving password", "new": "walked password"});
        let changed = walk.call("PUT", "/wallet/password", Some(&password));
        assert!([204, 409].contains(&changed.status), "{changed:?}");

        let missing: Vec<String> = contract::operation_ids()
            .into_iter()
            .filter(|id| !walk.reached.contains(id))
            .collect();
        assert_eq!(
            missing,
            Vec::<String>::new(),
            "operations the walk did not reach"
        );
    });
}
