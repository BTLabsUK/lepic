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
        problem(&http(socket, "GET", "/api/v1/no-such-thing", None), 404, "no_route");
        let wrong = http(socket, "DELETE", "/api/v1/status", None);
        problem(&wrong, 405, "method_not_allowed");
    });
}
