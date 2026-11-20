// SPDX-License-Identifier: Apache-2.0
//! `lepic serve` on a relay that speaks mux/1: it holds the relay's sockets with the payments
//! address and every live contact inbox attached, attaches an invite's inbox as soon as the
//! invite is made, and reads what the relay pushes without waiting for the periodic collect.
//! The periodic collect runs an hour apart here, so only a push can explain mail being read.
//! The tick of the delivery layer in between is covered by `serve_tick.rs`.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::support;

use std::collections::HashSet;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork, Nonce, Salt, SignedMessage};
use lepic_keychain::{Identifier, Keychain};
use lepic_primitives::params::Network;
use support::{
    Instance, SENDER_MNEMONIC, TestHost, http, serving, text, wait_until, wait_until_within,
};

/// Far longer than any test runs: serve's periodic collect does not come round again.
const NO_POLL: Duration = Duration::from_secs(3600);

/// How long a test here may take, serve's stop included.
const DEADLINE: Duration = Duration::from_secs(90);

/// Runs `test` and ends the whole test binary when it is still running after [`DEADLINE`]. A
/// serve that does not stop would otherwise keep the binary waiting for its thread for ever.
fn within_deadline(name: &str, test: impl FnOnce()) {
    let (done, finished) = mpsc::channel::<()>();
    let name = name.to_owned();
    let watchdog = std::thread::spawn(move || {
        // A test that ended, passed or panicked, drops `done`.
        if finished.recv_timeout(DEADLINE) == Err(mpsc::RecvTimeoutError::Timeout) {
            eprintln!("{name} still running after {DEADLINE:?}: serve did not stop");
            std::process::exit(101);
        }
    });
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
    drop(done);
    watchdog.join().unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// A wallet served on a mux/1 relay whose own relay is its one mailbox, with `config` as its
/// config file when given.
fn wallet_on_mux(config: Option<&str>) -> (TestHost, Instance) {
    let host = TestHost::with_mux(NO_POLL);
    let wallet = Instance::new("serving password");
    wallet.on_public_mailbox();
    wallet.restore(&host, SENDER_MNEMONIC);
    if let Some(config) = config {
        let dir = wallet.home.path().join(".lepic");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), config).unwrap();
    }
    (host, wallet)
}

fn relay(host: &TestHost) -> &MuxMockRelay {
    host.mux.as_ref().unwrap()
}

/// Makes an invite through the API and returns its contact id.
fn invite(socket: &Path) -> String {
    let created = http(
        socket,
        "POST",
        "/api/v1/contacts",
        Some(r#"{"method":"invite","label":"Buyer"}"#),
    );
    assert_eq!(created.status, 201, "{created:?}");
    text(&created.json(), "id").to_owned()
}

/// Waits for one mailbox to be attached beside `before`, and returns it.
fn newly_attached(relay: &MuxMockRelay, before: &HashSet<String>) -> String {
    wait_until("the invite's inbox is attached", || {
        relay.attached().len() > before.len()
    });
    let mut added: Vec<String> = relay.attached().difference(before).cloned().collect();
    assert_eq!(added.len(), 1, "{added:?}");
    added.remove(0)
}

/// Waits until serve's payments address and the delivery mailbox of the wallet's public epic1
/// address are attached, and returns what is attached then.
fn payments_attached(relay: &MuxMockRelay) -> HashSet<String> {
    wait_until(
        "the payments address and the epic1 mailbox are attached",
        || relay.attached().len() == 2,
    );
    relay.attached()
}

/// Stores mail for mailbox `key` that no contact of the wallet can open, as a stranger would
/// post it, and returns its id. serve's collect reads and drops it, which acknowledges it.
fn stranger_mail(relay: &MuxMockRelay, key: &str) -> String {
    let to = EpicboxAddress::parse(&format!("{key}@relay.test"), RelayNetwork::Floonet).unwrap();
    let keychain = Keychain::from_mnemonic(SENDER_MNEMONIC, Network::Floonet).unwrap();
    let secret = keychain
        .address_key(&Identifier::new(3, [0, 9, 9, 0]).unwrap(), 0)
        .unwrap();
    let sealed = SignedMessage::seal(
        "not a contact message",
        &to,
        &secret,
        Salt::from([4; 8]),
        Nonce::from([5; 12]),
    )
    .unwrap();
    relay.store(&to, &to, &sealed)
}

#[test]
fn payments_and_contacts_share_one_socket_by_default() {
    within_deadline("payments_and_contacts_share_one_socket_by_default", || {
        // The shipped settings: the own relay and three shipped mailboxes, which the mock answers.
        let host = TestHost::with_mux(NO_POLL);
        let wallet = Instance::new("serving password");
        wallet.restore(&host, SENDER_MNEMONIC);
        serving(host, &wallet, |socket, host| {
            let relay = relay(host);
            let before = payments_attached(relay);
            invite(socket);
            newly_attached(relay, &before);
            // One socket on the own relay holds both, and one on each shipped mailbox holds the
            // slots read there; split, the own relay would hold two.
            wait_until("one socket per relay", || relay.sockets_open() == 4);
        });
    });
}

#[test]
fn split_reads_payments_and_contacts_on_separate_sockets() {
    within_deadline(
        "split_reads_payments_and_contacts_on_separate_sockets",
        || {
            let (host, wallet) = wallet_on_mux(Some("relay_sockets = \"split\"\n"));
            serving(host, &wallet, |socket, host| {
                let relay = relay(host);
                let before = payments_attached(relay);
                // The payments address and the mailbox of the public epic1 address.
                assert_eq!(before.len(), 2, "{before:?}");
                invite(socket);
                newly_attached(relay, &before);
                wait_until("a socket each", || relay.sockets_open() == 2);
            });
        },
    );
}

#[test]
fn with_tor_on_payments_and_contacts_read_on_separate_sockets() {
    within_deadline(
        "with_tor_on_payments_and_contacts_read_on_separate_sockets",
        || {
            let (host, wallet) = wallet_on_mux(Some("epicbox_tor_socks = \"127.0.0.1:9050\"\n"));
            serving(host, &wallet, |socket, host| {
                let relay = relay(host);
                let before = payments_attached(relay);
                invite(socket);
                newly_attached(relay, &before);
                wait_until("a socket each", || relay.sockets_open() == 2);
            });
        },
    );
}

#[test]
fn mail_pushed_to_an_invite_is_read_without_the_periodic_collect() {
    within_deadline(
        "mail_pushed_to_an_invite_is_read_without_the_periodic_collect",
        || {
            let (host, wallet) = wallet_on_mux(None);
            serving(host, &wallet, |socket, host| {
                let relay = relay(host);
                let before = payments_attached(relay);
                invite(socket);
                let inbox = newly_attached(relay, &before);
                let mail = stranger_mail(relay, &inbox);
                wait_until("the pushed mail is read", || relay.is_acked(&mail));
            });
        },
    );
}

#[test]
fn serve_attaches_again_and_reads_what_came_while_the_relay_was_gone() {
    within_deadline(
        "serve_attaches_again_and_reads_what_came_while_the_relay_was_gone",
        || {
            let (host, wallet) = wallet_on_mux(None);
            serving(host, &wallet, |socket, host| {
                let relay = relay(host);
                let before = payments_attached(relay);
                invite(socket);
                let inbox = newly_attached(relay, &before);
                let made = relay.sockets_made();
                relay.drop_sockets();
                let mail = stranger_mail(relay, &inbox);
                wait_until("serve dials again", || relay.sockets_made() > made);
                wait_until("the inbox is attached again", || {
                    relay.attached().contains(&inbox)
                });
                // A collect that began while the socket was down reports the relay unreachable
                // and reads nothing; the session reads the mail once it is attached again.
                wait_until_within(
                    "the mail stored meanwhile is read",
                    Duration::from_secs(40),
                    || relay.is_acked(&mail),
                );
            });
        },
    );
}

#[test]
fn a_sync_while_the_session_dials_again_does_not_hold_back_pushed_mail() {
    within_deadline(
        "a_sync_while_the_session_dials_again_does_not_hold_back_pushed_mail",
        || {
            let (host, wallet) = wallet_on_mux(None);
            serving(host, &wallet, |socket, host| {
                let relay = relay(host);
                let before = payments_attached(relay);
                invite(socket);
                let inbox = newly_attached(relay, &before);
                relay.drop_sockets();
                let mail = stranger_mail(relay, &inbox);
                // The session waits to dial again, so this collect finds the relay unreachable.
                // Nothing backs the relay off: the session reads the mail once attached again.
                let synced = http(
                    socket,
                    "POST",
                    "/api/v1/sync",
                    Some(r#"{"node":false,"relays":true}"#),
                );
                assert_eq!(synced.status, 200, "{synced:?}");
                wait_until("the mail stored meanwhile is read", || {
                    relay.is_acked(&mail)
                });
            });
        },
    );
}

#[test]
fn a_deleted_invite_stays_attached_to_refuse_a_late_answer() {
    within_deadline(
        "a_deleted_invite_stays_attached_to_refuse_a_late_answer",
        || {
            let (host, wallet) = wallet_on_mux(None);
            serving(host, &wallet, |socket, host| {
                let relay = relay(host);
                let before = payments_attached(relay);
                let id = invite(socket);
                let inbox = newly_attached(relay, &before);
                let deleted = http(socket, "DELETE", &format!("/api/v1/contacts/{id}"), None);
                assert!(deleted.status < 300, "{deleted:?}");
                // The sync returns once its collect has ended. A cancelled invite is kept until
                // its deadline so that a late answer is read and refused: the relay is still a
                // home of the contacts, and the collect lets go of none of its mailboxes.
                let synced = http(
                    socket,
                    "POST",
                    "/api/v1/sync",
                    Some(r#"{"node":false,"relays":true}"#),
                );
                assert_eq!(synced.status, 200, "{synced:?}");
                assert!(relay.attached().contains(&inbox));
                assert_eq!(relay.received("Detach"), 0);
                assert_eq!(relay.sockets_open(), 1);
            });
        },
    );
}

#[test]
fn serve_opens_another_socket_when_the_relay_caps_the_mailboxes_of_one() {
    within_deadline(
        "serve_opens_another_socket_when_the_relay_caps_the_mailboxes_of_one",
        || {
            let (host, wallet) = wallet_on_mux(None);
            relay(&host).set_mailboxes_per_socket(3);
            serving(host, &wallet, |socket, host| {
                let relay = relay(host);
                payments_attached(relay);
                for _ in 0..4 {
                    invite(socket);
                }
                // The payments address, the mailbox of the public epic1 address and four
                // inboxes, three to a socket.
                wait_until("every inbox is attached", || relay.attached().len() == 6);
                assert_eq!(relay.sockets_open(), 2);
                let before = relay.attached();
                invite(socket);
                let inbox = newly_attached(relay, &before);
                let mail = stranger_mail(relay, &inbox);
                wait_until("the mail on the new socket is read", || {
                    relay.is_acked(&mail)
                });
                assert_eq!(relay.sockets_open(), 3);
            });
        },
    );
}
