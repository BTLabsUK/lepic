// SPDX-License-Identifier: Apache-2.0
//! The mux/1 client against a real relay that offers it.
//!
//! Every test is `#[ignore]` and returns early unless `LEPIC_MUX_RELAY` names a relay, for
//! example `ws://127.0.0.1:3426` or `wss://relay.example:443`. Each case prints one line
//! `MUX_LIVE {json}` with its figures. Run with:
//!
//! ```text
//! LEPIC_MUX_RELAY=ws://127.0.0.1:3426 cargo test -p lepic-epicbox --test mux_live \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Optional settings:
//! - `LEPIC_MUX_RESTART_CMD`: a shell command that restarts the relay (case 5).
//! - `LEPIC_MUX_STALL_URL`: the relay's test endpoint, `http://host:port/test/stall` (case 6). A
//!   POST of `{"address": <key>, "seconds": N}` makes the relay stop pushing to that address.
//! - `LEPIC_MUX_STALL_S`: how long the stall lasts, default 14.
//! - `LEPIC_MUX_ATTACH_LIMIT`: the relay's attach frames per minute and socket, default 30.
//! - `LEPIC_MUX_IDLE_S`: seconds an idle session sits in case 7; 0, the default, skips it.
//! - `LEPIC_MUX_PEER`: another relay, `wss://host:port`. Case 8 posts on `LEPIC_MUX_RELAY` to a
//!   mailbox of the peer and reads it there, so the relay must forward to it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::testing::client_settings;
use lepic_epicbox::{
    ClientSettings, Connector, Domain, EpicboxAddress, Handled, Identity, MailboxClient,
    MailboxContent, MailboxHandler, MailboxMessage, MuxCounters, MuxEvent, MuxOptions, MuxSession,
    MuxState, Network, RelayEndpoint, Security, TcpConnector,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, watch};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const SHORT: Duration = Duration::from_secs(30);

struct Live {
    settings: ClientSettings,
    connector: Arc<dyn Connector>,
    host: String,
    port: Option<u16>,
}

impl Live {
    fn client(&self) -> MailboxClient {
        MailboxClient::new(self.settings.clone(), Arc::clone(&self.connector))
    }

    fn session(&self, identities: Vec<Identity>, options: MuxOptions) -> MuxSession {
        self.client().start_mux_queued(identities, options).unwrap()
    }

    /// A new random mailbox on the relay.
    fn fresh(&self) -> Identity {
        let mut bytes = [0_u8; 32];
        let secret = loop {
            getrandom::fill(&mut bytes).unwrap();
            if let Ok(secret) = SecretKey::from_array(bytes) {
                break secret;
            }
        };
        let address = EpicboxAddress::new(
            PublicKey::from_secret_key(&secret).unwrap(),
            Network::Mainnet,
            Domain::parse(&self.host).unwrap(),
            self.port,
        );
        Identity::new(secret, address).unwrap()
    }
}

/// The relay named by `LEPIC_MUX_RELAY`, or `None` after saying the case was skipped.
fn live(case: &str) -> Option<Live> {
    let Ok(url) = std::env::var("LEPIC_MUX_RELAY") else {
        println!("MUX_LIVE skipped {case}: LEPIC_MUX_RELAY is not set");
        return None;
    };
    Some(live_at(&url))
}

/// A relay by its `ws://` or `wss://` URL.
fn live_at(url: &str) -> Live {
    let (security, rest) = if let Some(rest) = url.strip_prefix("wss://") {
        (Security::Tls, rest)
    } else if let Some(rest) = url.strip_prefix("ws://") {
        (Security::Plain, rest)
    } else {
        panic!("LEPIC_MUX_RELAY must start with ws:// or wss://");
    };
    let authority = rest.split('/').next().unwrap();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host.to_owned(), Some(port.parse::<u16>().unwrap())),
        None => (authority.to_owned(), None),
    };
    let endpoint = RelayEndpoint::new(Domain::parse(&host).unwrap(), port, security);
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    Live {
        settings: client_settings(endpoint),
        connector: Arc::new(TcpConnector::new(Arc::new(tls))),
        host,
        port,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn secs(since: Instant) -> f64 {
    (since.elapsed().as_secs_f64() * 1000.0).round() / 1000.0
}

fn counters_json(counters: &MuxCounters) -> Value {
    json!({
        "sockets_opened": counters.sockets_opened,
        "signatures": counters.signatures,
        "attaches": counters.attaches,
        "resumes": counters.resumes,
        "token_unknown": counters.token_unknown,
        "mails": counters.mails,
        "duplicates": counters.duplicates,
        "acks": counters.acks,
        "holds": counters.holds,
        "waiting_probes": counters.waiting_probes,
        "stall_reconnects": counters.stall_reconnects,
    })
}

fn report(case: &str, mut figures: Value) {
    figures["case"] = json!(case);
    println!("MUX_LIVE {figures}");
}

async fn within<T>(limit: Duration, what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(limit, future).await {
        Ok(value) => value,
        Err(_) => panic!("timed out after {limit:?}: {what}"),
    }
}

/// Waits until `count` `Attached` events have been seen on `events`.
async fn wait_attached(events: &mut broadcast::Receiver<MuxEvent>, count: usize, limit: Duration) {
    within(limit, "mailboxes attached", async {
        let mut seen = HashSet::new();
        while seen.len() < count {
            match events.recv().await {
                Ok(MuxEvent::Attached { mailbox, .. }) => {
                    seen.insert(mailbox);
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("event stream closed"),
            }
        }
    })
    .await;
}

/// The next messages of `mailboxes` that the session queued.
async fn next_mail(
    session: &MuxSession,
    queued: &mut watch::Receiver<u64>,
    mailboxes: &[usize],
    limit: Duration,
) -> Vec<MailboxMessage> {
    within(limit, "mail queued", async {
        loop {
            let taken = session.take(mailboxes);
            if !taken.is_empty() {
                return taken;
            }
            queued.changed().await.unwrap();
        }
    })
    .await
}

async fn counters_reach(
    session: &MuxSession,
    limit: Duration,
    what: &str,
    wanted: impl Fn(&MuxCounters) -> bool,
) -> MuxCounters {
    within(limit, what, async {
        loop {
            let counters = session.counters();
            if wanted(&counters) {
                return counters;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

async fn wait_state(
    state: &mut watch::Receiver<MuxState>,
    limit: Duration,
    what: &str,
    wanted: impl Fn(&MuxState) -> bool,
) {
    within(limit, what, state.wait_for(wanted)).await.unwrap();
}

/// A POST of `body` to a plain `http://` URL; the status line and body.
async fn http_post(url: &str, body: &str) -> String {
    let rest = url.strip_prefix("http://").expect("an http:// URL");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let mut stream = tokio::net::TcpStream::connect(authority).await.unwrap();
    let request = format!(
        "POST /{path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    String::from_utf8_lossy(&answer).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_MUX_RELAY"]
async fn push_delivery() {
    let Some(live) = live("push_delivery") else {
        return;
    };
    let (sender, mailbox) = (live.fresh(), live.fresh());
    let session = live.session(vec![mailbox.clone()], MuxOptions::default());
    let mut events = session.events();
    let mut queued = session.queued();
    let attach_started = Instant::now();
    wait_attached(&mut events, 1, SHORT).await;
    let attach_s = secs(attach_started);

    let started = Instant::now();
    live.client()
        .post(&sender, mailbox.address(), "push delivery")
        .await
        .unwrap();
    let post_s = secs(started);
    let mail = next_mail(&session, &mut queued, &[0], SHORT).await;
    let post_to_queued_s = secs(started);
    assert_eq!(mail.len(), 1);
    session.settle(mail[0].msg_id(), Handled::Stored).unwrap();
    let counters = counters_reach(&session, SHORT, "ack sent", |c| c.acks >= 1).await;
    let ack_s = secs(started);
    session.stop().await.unwrap();

    report(
        "push_delivery",
        json!({
            "attach_s": attach_s,
            "post_s": post_s,
            "post_to_queued_s": post_to_queued_s,
            "post_to_ack_s": ack_s,
            "counters": counters_json(&counters),
        }),
    );
    assert_eq!(counters.mails, 1);
    assert_eq!(counters.acks, 1);
    assert_eq!(counters.sockets_opened, 1);
    assert_eq!(counters.signatures, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_MUX_RELAY"]
async fn hold_brings_the_message_back() {
    let Some(live) = live("hold") else {
        return;
    };
    let (sender, mailbox) = (live.fresh(), live.fresh());
    let options = MuxOptions::default().with_hold(Duration::from_secs(2));
    let session = live.session(vec![mailbox.clone()], options);
    let mut events = session.events();
    let mut queued = session.queued();
    wait_attached(&mut events, 1, SHORT).await;
    live.client()
        .post(&sender, mailbox.address(), "hold me")
        .await
        .unwrap();

    let first = next_mail(&session, &mut queued, &[0], SHORT).await;
    assert_eq!(first.len(), 1);
    let id = first[0].msg_id().clone();
    let held = Instant::now();
    session.settle(&id, Handled::Later).unwrap();
    let again = next_mail(&session, &mut queued, &[0], Duration::from_secs(60)).await;
    let back_s = held.elapsed();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].msg_id(), &id);
    session.settle(&id, Handled::Stored).unwrap();
    let counters = counters_reach(&session, SHORT, "ack sent", |c| c.acks >= 1).await;
    session.stop().await.unwrap();

    report(
        "hold",
        json!({
            "hold_s": 2,
            "settle_to_requeued_s": (back_s.as_secs_f64() * 1000.0).round() / 1000.0,
            "counters": counters_json(&counters),
        }),
    );
    assert!(
        back_s >= Duration::from_secs(2),
        "came back after {back_s:?}"
    );
    assert_eq!(counters.holds, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_MUX_RELAY"]
async fn replaced_session_hands_its_mail_over() {
    let Some(live) = live("replaced") else {
        return;
    };
    let (sender, mailbox) = (live.fresh(), live.fresh());
    let first = live.session(vec![mailbox.clone()], MuxOptions::default());
    let mut first_events = first.events();
    let mut first_queued = first.queued();
    wait_attached(&mut first_events, 1, SHORT).await;
    live.client()
        .post(&sender, mailbox.address(), "in flight")
        .await
        .unwrap();
    let flying = next_mail(&first, &mut first_queued, &[0], SHORT).await;
    assert_eq!(flying.len(), 1);
    let id = flying[0].msg_id().clone();

    let second = live.session(vec![mailbox.clone()], MuxOptions::default());
    let mut second_events = second.events();
    let mut second_queued = second.queued();
    let taken_over = Instant::now();
    let replaced = within(SHORT, "Replaced on session 1", async {
        loop {
            match first_events.recv().await {
                Ok(MuxEvent::Replaced { mailbox }) => return mailbox,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("event stream closed"),
            }
        }
    })
    .await;
    let replaced_s = secs(taken_over);
    wait_attached(&mut second_events, 1, SHORT).await;
    let handed = next_mail(&second, &mut second_queued, &[0], SHORT).await;
    let handed_s = secs(taken_over);
    assert_eq!(replaced, 0);
    assert_eq!(handed.len(), 1);
    assert_eq!(handed[0].msg_id(), &id);
    second.settle(&id, Handled::Stored).unwrap();
    let second_counters = counters_reach(&second, SHORT, "ack sent", |c| c.acks >= 1).await;
    let first_state = *first.state().borrow();
    let first_counters = first.counters();
    first.stop().await.unwrap();
    second.stop().await.unwrap();

    report(
        "replaced",
        json!({
            "replaced_after_s": replaced_s,
            "handed_over_after_s": handed_s,
            "first_state": format!("{first_state:?}"),
            "first": counters_json(&first_counters),
            "second": counters_json(&second_counters),
        }),
    );
    assert_eq!(second_counters.acks, 1);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_MUX_RELAY"]
async fn attach_rate_limit_reconnects() {
    let Some(live) = live("rate_limited") else {
        return;
    };
    let limit = env_u64("LEPIC_MUX_ATTACH_LIMIT", 30) as usize;
    let total = limit + 3;
    let first = live.fresh();
    let session = live.session(vec![first.clone()], MuxOptions::default());
    let mut events = session.events();
    let mut state = session.state();
    let delays = Arc::new(Mutex::new(Vec::<f64>::new()));
    let watcher = {
        let (delays, mut state) = (Arc::clone(&delays), session.state());
        tokio::spawn(async move {
            while state.changed().await.is_ok() {
                if let MuxState::Waiting { delay, .. } = *state.borrow_and_update() {
                    delays.lock().unwrap().push(delay.as_secs_f64());
                }
            }
        })
    };
    wait_attached(&mut events, 1, SHORT).await;

    let started = Instant::now();
    let mut mailboxes = vec![first];
    let mut refused = Vec::new();
    let mut slow_at = None;
    for _ in 1..total {
        let identity = live.fresh();
        let index = session.attach(identity.clone()).await.unwrap();
        mailboxes.push(identity);
        let answered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events.recv().await {
                    Ok(MuxEvent::Attached { mailbox, .. }) if mailbox == index => return,
                    Ok(MuxEvent::Refused { mailbox, code }) => {
                        refused.push(format!("{mailbox}:{code:?}"));
                        if mailbox == index {
                            return;
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => panic!("event stream closed"),
                }
            }
        })
        .await;
        if answered.is_err() {
            slow_at = Some(index);
            break;
        }
    }
    let attach_phase_s = secs(started);
    let sockets_in_phase = session.counters().sockets_opened;

    // Past the limit the socket ends and the session comes back with a resume.
    let recover_started = Instant::now();
    if slow_at.is_some() || sockets_in_phase > 1 {
        counters_reach(&session, Duration::from_secs(150), "second socket", |c| {
            c.sockets_opened >= 2
        })
        .await;
    }
    wait_state(
        &mut state,
        Duration::from_secs(150),
        "attached again",
        |s| *s == MuxState::Attached,
    )
    .await;
    let recovered_s = secs(recover_started);

    // The first and the last mailbox both still deliver.
    let sender = live.fresh();
    let mut queued = session.queued();
    let last = mailboxes.len() - 1;
    for index in [0, last] {
        live.client()
            .post(&sender, mailboxes[index].address(), "after the limit")
            .await
            .unwrap();
    }
    let mut got = HashSet::new();
    let ids = within(Duration::from_secs(150), "mail on both mailboxes", async {
        let mut ids = Vec::new();
        while got.len() < 2 {
            for mail in session.take(&[0, last]) {
                got.insert(mail.mailbox());
                ids.push(mail.msg_id().clone());
            }
            if got.len() < 2 {
                let _ = tokio::time::timeout(Duration::from_secs(1), queued.changed()).await;
            }
        }
        ids
    })
    .await;
    for id in &ids {
        session.settle(id, Handled::Stored).unwrap();
    }
    let counters = counters_reach(&session, SHORT, "acks sent", |c| c.acks >= 2).await;
    watcher.abort();
    session.stop().await.unwrap();

    report(
        "rate_limited",
        json!({
            "attach_limit": limit,
            "mailboxes": mailboxes.len(),
            "slow_at_mailbox": slow_at,
            "attach_phase_s": attach_phase_s,
            "recovered_after_s": recovered_s,
            "waiting_delays_s": *delays.lock().unwrap(),
            "refused_events": refused,
            "counters": counters_json(&counters),
        }),
    );
    assert!(
        counters.sockets_opened >= 2,
        "the socket was never replaced"
    );
    assert!(refused.is_empty(), "refused: {refused:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_MUX_RELAY and LEPIC_MUX_RESTART_CMD"]
async fn token_unknown_after_restart() {
    let Some(live) = live("token_unknown") else {
        return;
    };
    let Ok(command) = std::env::var("LEPIC_MUX_RESTART_CMD") else {
        println!("MUX_LIVE skipped token_unknown: LEPIC_MUX_RESTART_CMD is not set");
        return;
    };
    let identities: Vec<Identity> = (0..3).map(|_| live.fresh()).collect();
    let count = identities.len() as u64;
    let session = live.session(identities.clone(), MuxOptions::default());
    let mut events = session.events();
    let mut state = session.state();
    wait_attached(&mut events, identities.len(), SHORT).await;
    let before = session.counters();
    assert_eq!(before.signatures, count);

    let restarted = Instant::now();
    let run = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(run.success(), "the restart command failed: {run}");
    let restart_s = secs(restarted);
    wait_state(&mut state, Duration::from_secs(30), "socket lost", |s| {
        *s != MuxState::Attached
    })
    .await;
    wait_state(
        &mut state,
        Duration::from_secs(120),
        "attached again",
        |s| *s == MuxState::Attached,
    )
    .await;
    let back_s = secs(restarted);
    let after = counters_reach(&session, SHORT, "signed again", |c| {
        c.signatures >= before.signatures + count
    })
    .await;

    // The restarted relay delivers to the new socket.
    let sender = live.fresh();
    let mut queued = session.queued();
    live.client()
        .post(&sender, identities[2].address(), "after the restart")
        .await
        .unwrap();
    let mail = next_mail(&session, &mut queued, &[2], SHORT).await;
    session.settle(mail[0].msg_id(), Handled::Stored).unwrap();
    session.stop().await.unwrap();

    report(
        "token_unknown",
        json!({
            "mailboxes": count,
            "restart_command_s": restart_s,
            "restart_to_attached_s": back_s,
            "before": counters_json(&before),
            "after": counters_json(&after),
        }),
    );
    assert!(after.resumes >= 1);
    assert_eq!(after.token_unknown, 1);
    assert_eq!(after.signatures, before.signatures + count);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_MUX_RELAY and LEPIC_MUX_STALL_URL"]
async fn stalled_push_reconnects_with_a_resume() {
    let Some(live) = live("stall") else {
        return;
    };
    let Ok(url) = std::env::var("LEPIC_MUX_STALL_URL") else {
        println!("MUX_LIVE skipped stall: LEPIC_MUX_STALL_URL is not set");
        return;
    };
    let stall_s = env_u64("LEPIC_MUX_STALL_S", 14);
    let (sender, mailbox) = (live.fresh(), live.fresh());
    let options = MuxOptions::default().with_waiting_every(Some(Duration::from_secs(5)));
    let session = live.session(vec![mailbox.clone()], options);
    let mut events = session.events();
    let mut queued = session.queued();
    wait_attached(&mut events, 1, SHORT).await;
    let before = session.counters();

    let body = json!({"address": mailbox.address().key_text(), "seconds": stall_s}).to_string();
    let answer = http_post(&url, &body).await;
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "stall endpoint said: {answer}"
    );

    let started = Instant::now();
    live.client()
        .post(&sender, mailbox.address(), "during the stall")
        .await
        .unwrap();
    let mail = next_mail(&session, &mut queued, &[0], Duration::from_secs(90)).await;
    let arrived_s = secs(started);
    assert_eq!(mail.len(), 1);
    session.settle(mail[0].msg_id(), Handled::Stored).unwrap();
    let after = counters_reach(&session, SHORT, "ack sent", |c| c.acks >= 1).await;
    session.stop().await.unwrap();

    report(
        "stall",
        json!({
            "stall_s": stall_s,
            "waiting_every_s": 5,
            "post_to_queued_s": arrived_s,
            "before": counters_json(&before),
            "after": counters_json(&after),
        }),
    );
    assert!(after.stall_reconnects >= 1, "no stall reconnect");
    assert!(after.resumes >= 1, "no resume");
    assert_eq!(after.signatures, before.signatures);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_MUX_RELAY and LEPIC_MUX_IDLE_S"]
async fn idle_session() {
    let Some(live) = live("idle") else {
        return;
    };
    let idle_s = env_u64("LEPIC_MUX_IDLE_S", 0);
    if idle_s == 0 {
        println!("MUX_LIVE skipped idle: LEPIC_MUX_IDLE_S is 0");
        return;
    }
    let identities: Vec<Identity> = (0..6).map(|_| live.fresh()).collect();
    let session = live.session(identities.clone(), MuxOptions::default());
    let mut events = session.events();
    wait_attached(&mut events, identities.len(), SHORT).await;
    tokio::time::sleep(Duration::from_secs(idle_s)).await;
    let counters = session.counters();
    let state = *session.state().borrow();
    session.stop().await.unwrap();

    report(
        "idle",
        json!({
            "mailboxes": identities.len(),
            "idle_s": idle_s,
            "state": format!("{state:?}"),
            "counters": counters_json(&counters),
        }),
    );
}

/// Keeps the texts of the messages it is handed and acknowledges them.
#[derive(Default)]
struct Texts(Vec<String>);

impl MailboxHandler for Texts {
    fn handle(
        &mut self,
        message: MailboxMessage,
    ) -> lepic_transport::transport::BoxFuture<'_, Handled> {
        Box::pin(async move {
            if let MailboxContent::Opened(received) = message.content() {
                self.0.push(received.plaintext.expose_str().to_owned());
            }
            Handled::Stored
        })
    }
}

/// One message posted on the relay to a mailbox of `LEPIC_MUX_PEER`: the relay forwards it, and
/// a drain on the peer reads it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs two relays: LEPIC_MUX_RELAY and LEPIC_MUX_PEER"]
async fn forward_to_a_peer() {
    let Some(live) = live("forward_to_a_peer") else {
        return;
    };
    let Ok(peer_url) = std::env::var("LEPIC_MUX_PEER") else {
        println!("MUX_LIVE skipped forward_to_a_peer: LEPIC_MUX_PEER is not set");
        return;
    };
    let peer = live_at(&peer_url);
    let (sender, mailbox) = (live.fresh(), peer.fresh());
    let text = format!("forwarded {}", mailbox.address());
    let started = Instant::now();
    live.client()
        .post(&sender, mailbox.address(), &text)
        .await
        .unwrap();
    let post_s = secs(started);
    let mut drains = 0_u32;
    let read = loop {
        let mut texts = Texts::default();
        let drained = peer
            .client()
            .drain_once(std::slice::from_ref(&mailbox), &mut texts)
            .await;
        drains += 1;
        if let Err(error) = &drained {
            println!("MUX_LIVE forward drain {drains} failed: {error}");
        }
        if texts.0.contains(&text) {
            break secs(started);
        }
        assert!(
            started.elapsed() < Duration::from_secs(180),
            "not forwarded within 180 s"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    report(
        "forward_to_a_peer",
        json!({
            "to": mailbox.address().to_string(),
            "post_s": post_s,
            "post_to_read_on_peer_s": read,
            "drains": drains,
        }),
    );
}
