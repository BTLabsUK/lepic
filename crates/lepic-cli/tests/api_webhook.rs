// SPDX-License-Identifier: Apache-2.0
//! The webhook calls of `lepic serve`, answered per `docs/api/openapi.json` (the delivery is
//! tested in the webhook module, where time can be shortened), and a bad webhook setting
//! stopping serve at start.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::os::unix::fs::PermissionsExt as _;

use serde_json::json;
use support::{Instance, TestHost, funded, http, problem, serving, serving_with};

#[test]
fn without_a_webhook_both_calls_answer_not_found() {
    let (host, wallet) = funded();
    serving(host, &wallet, |socket, _| {
        problem(
            &http(socket, "GET", "/api/v1/webhook", None),
            404,
            "not_found",
        );
        let resume = http(socket, "POST", "/api/v1/webhook/resume", Some("{}"));
        problem(&resume, 404, "not_found");
    });
}

#[test]
fn a_webhook_is_shown_and_resumed() {
    let (host, wallet) = funded();
    let secrets = wallet.path("webhook-secrets");
    std::fs::write(&secrets, "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw\n").unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = wallet.path("webhook-config.toml");
    std::fs::write(
        &config,
        format!(
            "webhook_url = \"http://127.0.0.1:9/hook\"\nwebhook_allow_private = true\n\
             webhook_types = \"payment.*\"\nwebhook_secret_file = \"{}\"\n",
            secrets.display()
        ),
    )
    .unwrap();
    serving_with(
        host,
        &wallet,
        &["--config", config.to_str().unwrap()],
        |socket, _| {
            // The cursor moves past the events `payment.*` leaves out, which serve may add at
            // any time, so only its type is checked here; the webhook module tests the moves.
            let without_cursor = |mut view: serde_json::Value| {
                assert!(view["cursor"].is_u64(), "{view}");
                view.as_object_mut().unwrap().remove("cursor");
                view
            };
            let shown = without_cursor(http(socket, "GET", "/api/v1/webhook", None).ok());
            assert_eq!(
                shown,
                json!({
                    "url": "http://127.0.0.1:9/hook", "types": ["payment.*"],
                    "state": "active", "attempts": 0
                })
            );
            // Nothing fails, so a resume without `after` changes nothing.
            let same = http(socket, "POST", "/api/v1/webhook/resume", None).ok();
            assert_eq!(without_cursor(same), shown);
            let moved = http(
                socket,
                "POST",
                "/api/v1/webhook/resume",
                Some(r#"{"after":0}"#),
            )
            .ok();
            assert_eq!(moved["cursor"], 0);
            let beyond = http(
                socket,
                "POST",
                "/api/v1/webhook/resume",
                Some(r#"{"after":99}"#),
            );
            problem(&beyond, 400, "invalid_field");
            let extra = http(
                socket,
                "POST",
                "/api/v1/webhook/resume",
                Some(r#"{"before":1}"#),
            );
            problem(&extra, 400, "invalid_body");
        },
    );
}

#[test]
fn a_bad_webhook_setting_stops_serve_at_start() {
    let host = TestHost::new();
    let wallet = Instance::new("serving password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let socket = wallet.path("never.sock");
    let mut env = wallet.env();
    env.push((
        "LEPIC_WEBHOOK_URL".to_owned(),
        "http://hooks.example/in".to_owned(),
    ));
    env.push(("LEPIC_WEBHOOK_SECRET_FILE".to_owned(), "/none".to_owned()));
    let outcome = wallet.run_with(
        &host,
        &["serve", "--socket", socket.to_str().unwrap()],
        env,
        "",
    );
    assert_eq!(outcome.code, 3, "{outcome:?}");
    assert!(outcome.stdout.contains("webhook_url"), "{outcome:?}");
    assert!(!socket.exists());
}
