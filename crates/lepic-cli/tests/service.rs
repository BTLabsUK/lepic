// SPDX-License-Identifier: Apache-2.0
//! `lepic serve` holds the wallet and answers `lepic --service` commands on a socket, in one
//! process with a mock node and a mock relay.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use support::{FUNDING, Instance, Outcome, SENDER_MNEMONIC, TestHost, keys};

fn wait_for_socket(socket: &Path) {
    let started = Instant::now();
    while !socket.exists() {
        assert!(
            started.elapsed() < support::PATIENCE,
            "serve never bound {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The reply to one raw request line.
fn raw_request(socket: &Path, line: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(line.as_bytes()).unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    serde_json::from_str(&reply).unwrap()
}

#[test]
fn serve_answers_commands_and_stops_on_interrupt() {
    let mut host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    let info = wallet.run(&host, &["wallet", "info"]).ok().json();
    let listed = wallet.run(&host, &["tx", "list"]).ok().json();

    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    host.interrupt_when = Some(Arc::new(move || signal.load(Ordering::SeqCst)));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let service = format!("--service={}", socket.display());
    let socket_arg = socket.to_str().unwrap();

    let served: Outcome = std::thread::scope(|scope| {
        let server = scope.spawn(|| wallet.run(&host, &["serve", "--socket", socket_arg]));
        wait_for_socket(&socket);

        let through = wallet.run(&host, &[&service, "wallet", "info"]).ok().json();
        assert_eq!(through, info);
        let through = wallet.run(&host, &[&service, "tx", "list"]).ok().json();
        assert_eq!(through, listed);

        let mut human_env = wallet.env();
        human_env.retain(|(key, _)| key != "LEPIC_OUTPUT");
        let human = wallet.run_with(&host, &[&service, "wallet", "info"], human_env, "");
        assert_eq!(human.code, 0, "{human:?}");
        assert!(serde_json::from_str::<serde_json::Value>(&human.stdout).is_err());

        for refused in [
            vec!["wallet", "init"],
            vec!["serve"],
            vec!["epicbox", "listen"],
            vec!["--data-dir", "elsewhere", "wallet", "info"],
        ] {
            let mut args = vec![service.as_str()];
            args.extend(refused);
            let outcome = wallet.run(&host, &args);
            assert_eq!(outcome.code, 2, "{outcome:?}");
            assert_eq!(outcome.json()["error"]["kind"], "usage", "{outcome:?}");
        }

        let garbled = raw_request(&socket, "not json\n");
        assert_eq!(garbled["code"], 2, "{garbled}");

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap()
    });

    let report = served.ok().json();
    assert_eq!(keys(&report), ["inbox", "requests", "socket"]);
    assert_eq!(report["requests"], 8, "{report}");
    assert!(!socket.exists());
    // The lock is released: a one-shot command opens the wallet again.
    host.interrupt_when = None;
    assert_eq!(wallet.run(&host, &["wallet", "info"]).ok().json(), info);
}

#[test]
fn a_service_nobody_listens_at_is_exit_5() {
    let host = TestHost::new();
    let wallet = Instance::new("quiet password");
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("none.sock");
    let service = format!("--service={}", socket.display());

    let missing = wallet.run(&host, &[&service, "wallet", "info"]);
    assert_eq!(missing.code, 5, "{missing:?}");
    assert_eq!(missing.json()["error"]["kind"], "service_unavailable");

    // A socket file nobody serves refuses the connection.
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    let stale = wallet.run(&host, &[&service, "wallet", "info"]);
    assert_eq!(stale.code, 5, "{stale:?}");

    let mut human = wallet.env();
    human.retain(|(key, _)| key != "LEPIC_OUTPUT");
    let default_socket = wallet.run_with(&host, &["--service", "wallet", "info"], human, "");
    assert_eq!(default_socket.code, 5, "{default_socket:?}");
    assert!(
        default_socket.stderr.contains("hint: "),
        "{default_socket:?}"
    );
}

#[test]
fn serve_refuses_a_socket_path_it_cannot_use() {
    let host = TestHost::new();
    let wallet = Instance::new("path password");
    wallet.run(&host, &["wallet", "init"]).ok();
    let dir = tempfile::tempdir().unwrap();

    let file = dir.path().join("taken");
    std::fs::write(&file, "not a socket").unwrap();
    let taken = wallet.run(&host, &["serve", "--socket", file.to_str().unwrap()]);
    assert_eq!(taken.code, 2, "{taken:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "not a socket");

    let long = dir.path().join("x".repeat(120));
    let mut human = wallet.env();
    human.retain(|(key, _)| key != "LEPIC_OUTPUT");
    let args = ["serve", "--socket", long.to_str().unwrap()];
    let too_long = wallet.run_with(&host, &args, human, "");
    assert_eq!(too_long.code, 2, "{too_long:?}");
    assert!(too_long.stderr.contains("--socket"), "{too_long:?}");
}
