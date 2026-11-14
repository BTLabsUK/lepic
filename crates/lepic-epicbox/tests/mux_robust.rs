// SPDX-License-Identifier: Apache-2.0
//! Robustness of the mux/1 client and the 3.0.0 listener against a real relay that offers mux/1:
//! relay restarts, network drops, two devices on one mailbox, many mailboxes and relay limits.
//!
//! Every test is `#[ignore]` and returns early unless `LEPIC_ROBUST_RELAY` names a relay the
//! tester runs, for example `ws://127.0.0.1:3436`. Each case prints one line
//! `MUX_ROBUST {json}` with its figures. Run with:
//!
//! ```text
//! LEPIC_ROBUST_RELAY=ws://127.0.0.1:3436 cargo test -p lepic-epicbox --test mux_robust \
//!     -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Optional settings:
//! - `LEPIC_ROBUST_STOP_CMD` and `LEPIC_ROBUST_START_CMD`: shell commands that kill the relay
//!   (SIGKILL, so nothing is flushed) and start it again on the same store. The restart cases
//!   need both.
//! - `LEPIC_ROBUST_POST_LIMITED`: a relay whose post limit per IP is low. `LEPIC_ROBUST_POSTS`
//!   is how many posts the case sends in a row, default 40.
//! - `LEPIC_ROBUST_SOCKET_LIMITED`: a relay whose `sockets_per_ip` and `mux_sockets_per_ip` are
//!   low. `LEPIC_ROBUST_MUX_SOCKETS` and `LEPIC_ROBUST_SOCKETS` are those limits, default 2
//!   and 4.
//! - `LEPIC_ROBUST_OUTAGE_S`: how long the full outage case keeps the network down, default 120.
//! - `LEPIC_ROBUST_FLIPS`: how often the two-device case moves the mailbox, default 10.
//!
//! The network cases put a TCP proxy of their own between the client and the relay. It can
//! stop forwarding on the open connections while keeping them open (a blackhole), reset them,
//! or hold every new connection too (an outage). It also counts the connections clients make.
//! Mail is always posted straight to the relay.

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

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::testing::client_settings;
use lepic_epicbox::{
    ConnectionState, Connector, Domain, EpicboxAddress, EpicboxClient, Handled, Identity,
    ListenOptions, MailboxClient, MailboxContent, MailboxHandler, MailboxMessage, MuxCounters,
    MuxEvent, MuxOptions, MuxSession, MuxState, Network, RelayEndpoint, Security, Subscription,
    TcpConnector,
};
use lepic_transport::transport::Inbound;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, broadcast, watch};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const SHORT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------------------------
// The rig

struct Rig {
    host: String,
    port: Option<u16>,
    security: Security,
    connector: Arc<dyn Connector>,
}

impl Rig {
    fn at(url: &str) -> Self {
        let (security, rest) = if let Some(rest) = url.strip_prefix("wss://") {
            (Security::Tls, rest)
        } else if let Some(rest) = url.strip_prefix("ws://") {
            (Security::Plain, rest)
        } else {
            panic!("a relay URL must start with ws:// or wss://");
        };
        let authority = rest.split('/').next().unwrap();
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port.parse::<u16>().unwrap())),
            None => (authority.to_owned(), None),
        };
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        Self {
            host,
            port,
            security,
            connector: Arc::new(TcpConnector::new(Arc::new(tls))),
        }
    }

    /// The relay itself, or the proxy on loopback port `via` in front of it.
    fn endpoint(&self, via: Option<u16>) -> RelayEndpoint {
        match via {
            Some(port) => RelayEndpoint::new(
                Domain::parse("127.0.0.1").unwrap(),
                Some(port),
                Security::Plain,
            ),
            None => {
                RelayEndpoint::new(Domain::parse(&self.host).unwrap(), self.port, self.security)
            }
        }
    }

    fn client(&self, via: Option<u16>) -> MailboxClient {
        MailboxClient::new(
            client_settings(self.endpoint(via)),
            Arc::clone(&self.connector),
        )
    }

    fn session(
        &self,
        identities: Vec<Identity>,
        options: MuxOptions,
        via: Option<u16>,
    ) -> MuxSession {
        self.client(via)
            .start_mux_queued(identities, options)
            .unwrap()
    }

    /// A 3.0.0 listener with the app's watchdog: leave after three challenge intervals.
    fn listener(&self, identity: &Identity, via: Option<u16>) -> Subscription {
        EpicboxClient::new(
            client_settings(self.endpoint(via)),
            identity.clone(),
            Arc::clone(&self.connector),
        )
        .listen_with(ListenOptions {
            challenge_rounds: Some(3),
            ..ListenOptions::default()
        })
        .unwrap()
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

    async fn post(&self, from: &Identity, to: &Identity, text: &str) {
        self.client(None)
            .post(from, to.address(), text)
            .await
            .unwrap_or_else(|error| panic!("post failed: {error:?}"));
    }

    /// What a drain still finds for `mailbox` (and so takes away).
    async fn leftovers(&self, mailbox: &Identity) -> Vec<String> {
        let mut texts = Texts::default();
        self.client(None)
            .drain_once(std::slice::from_ref(mailbox), &mut texts)
            .await
            .unwrap();
        texts.0
    }
}

fn rig(case: &str) -> Option<Rig> {
    let Ok(url) = std::env::var("LEPIC_ROBUST_RELAY") else {
        println!("MUX_ROBUST skipped {case}: LEPIC_ROBUST_RELAY is not set");
        return None;
    };
    Some(Rig::at(&url))
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn secs(since: Instant) -> f64 {
    round3(since.elapsed().as_secs_f64())
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn report(case: &str, mut figures: Value) {
    figures["case"] = json!(case);
    println!("MUX_ROBUST {figures}");
}

async fn within<T>(limit: Duration, what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(limit, future).await {
        Ok(value) => value,
        Err(_) => panic!("timed out after {limit:?}: {what}"),
    }
}

/// Runs a shell command from the environment variable `name` and says whether it was set.
async fn run_cmd(name: &str) -> bool {
    let Ok(command) = std::env::var(name) else {
        return false;
    };
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(status.success(), "{name} failed: {status}");
    true
}

fn restart_cmds(case: &str) -> bool {
    let set = std::env::var("LEPIC_ROBUST_STOP_CMD").is_ok()
        && std::env::var("LEPIC_ROBUST_START_CMD").is_ok();
    if !set {
        println!("MUX_ROBUST skipped {case}: LEPIC_ROBUST_STOP_CMD or _START_CMD is not set");
    }
    set
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

/// Waits until `count` distinct mailboxes were attached.
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
            let _ = tokio::time::timeout(Duration::from_millis(500), queued.changed()).await;
        }
    })
    .await
}

/// Everything the session queues for `mailboxes` within `quiet`.
async fn more_mail(
    session: &MuxSession,
    queued: &mut watch::Receiver<u64>,
    mailboxes: &[usize],
    quiet: Duration,
) -> Vec<MailboxMessage> {
    let until = Instant::now() + quiet;
    let mut all = Vec::new();
    while Instant::now() < until {
        all.extend(session.take(mailboxes));
        let _ = tokio::time::timeout(Duration::from_millis(250), queued.changed()).await;
    }
    all.extend(session.take(mailboxes));
    all
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

fn text_of(mail: &MailboxMessage) -> String {
    match mail.content() {
        MailboxContent::Opened(received) => received.plaintext.expose_str().to_owned(),
        _ => "<not opened>".to_owned(),
    }
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
            self.0.push(text_of(&message));
            Handled::Stored
        })
    }
}

/// Every state a watch channel takes, with the seconds since `origin`.
struct StateLog<S> {
    entries: Arc<Mutex<Vec<(f64, S)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl<S: Clone + Send + Sync + 'static> StateLog<S> {
    fn start(mut state: watch::Receiver<S>, origin: Instant) -> Self {
        let entries = Arc::new(Mutex::new(vec![(secs(origin), state.borrow().clone())]));
        let task = {
            let entries = Arc::clone(&entries);
            tokio::spawn(async move {
                while state.changed().await.is_ok() {
                    let now = state.borrow_and_update().clone();
                    entries.lock().unwrap().push((secs(origin), now));
                }
            })
        };
        Self { entries, task }
    }

    fn snapshot(&self) -> Vec<(f64, S)> {
        self.entries.lock().unwrap().clone()
    }

    /// The first time after `after` that a state matching `wanted` was entered.
    fn first_after(&self, after: f64, wanted: impl Fn(&S) -> bool) -> Option<f64> {
        self.snapshot()
            .into_iter()
            .find(|(at, state)| *at >= after && wanted(state))
            .map(|(at, _)| at)
    }

    async fn wait_first_after(
        &self,
        after: f64,
        limit: Duration,
        what: &str,
        wanted: impl Fn(&S) -> bool,
    ) -> f64 {
        within(limit, what, async {
            loop {
                if let Some(at) = self.first_after(after, &wanted) {
                    return at;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
    }

    fn json(&self) -> Value
    where
        S: std::fmt::Debug,
    {
        json!(
            self.snapshot()
                .iter()
                .map(|(at, state)| format!("{at}:{state:?}"))
                .collect::<Vec<_>>()
        )
    }
}

impl<S> Drop for StateLog<S> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---------------------------------------------------------------------------------------------
// A TCP proxy the test controls

#[derive(Default)]
struct ConnCtl {
    frozen: AtomicBool,
    kill: Notify,
}

struct ProxyState {
    target: String,
    conns: Mutex<Vec<Arc<ConnCtl>>>,
    connects: Mutex<Vec<Instant>>,
    outage: AtomicBool,
}

struct Proxy {
    port: u16,
    state: Arc<ProxyState>,
    task: tokio::task::JoinHandle<()>,
}

impl Proxy {
    async fn start(target: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(ProxyState {
            target,
            conns: Mutex::new(Vec::new()),
            connects: Mutex::new(Vec::new()),
            outage: AtomicBool::new(false),
        });
        let task = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                loop {
                    let Ok((client, _)) = listener.accept().await else {
                        return;
                    };
                    state.connects.lock().unwrap().push(Instant::now());
                    let ctl = Arc::new(ConnCtl::default());
                    state.conns.lock().unwrap().push(Arc::clone(&ctl));
                    let outage = state.outage.load(Ordering::SeqCst);
                    let target = state.target.clone();
                    tokio::spawn(serve(client, target, ctl, outage));
                }
            })
        };
        Self { port, state, task }
    }

    /// Stops forwarding on every open connection and keeps it open.
    fn blackhole(&self) {
        for ctl in self.state.conns.lock().unwrap().iter() {
            ctl.frozen.store(true, Ordering::SeqCst);
        }
    }

    /// Resets every open connection on both sides.
    fn reset(&self) {
        for ctl in self.state.conns.lock().unwrap().drain(..) {
            ctl.kill.notify_one();
        }
    }

    /// While on, new connections are accepted and then hear nothing.
    fn outage(&self, on: bool) {
        self.state.outage.store(on, Ordering::SeqCst);
    }

    fn connects(&self) -> Vec<Instant> {
        self.state.connects.lock().unwrap().clone()
    }

    fn connects_since(&self, since: Instant) -> usize {
        self.connects().iter().filter(|at| **at >= since).count()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
        self.reset();
    }
}

async fn serve(mut client: TcpStream, target: String, ctl: Arc<ConnCtl>, outage: bool) {
    if outage {
        ctl.kill.notified().await;
        set_reset(&client);
        return;
    }
    let Ok(mut server) = TcpStream::connect(&target).await else {
        return;
    };
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    let killed = {
        let (mut client_read, mut client_write) = client.split();
        let (mut server_read, mut server_write) = server.split();
        tokio::select! {
            () = pump(&mut client_read, &mut server_write, &ctl) => false,
            () = pump(&mut server_read, &mut client_write, &ctl) => false,
            () = ctl.kill.notified() => true,
        }
    };
    if killed {
        set_reset(&client);
        set_reset(&server);
    }
}

#[allow(deprecated)]
fn set_reset(stream: &TcpStream) {
    let _ = stream.set_linger(Some(Duration::ZERO));
}

async fn pump(from: &mut ReadHalf<'_>, to: &mut WriteHalf<'_>, ctl: &ConnCtl) {
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let count = match from.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        if ctl.frozen.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if to.write_all(&buffer[..count]).await.is_err() {
            return;
        }
    }
}

/// Connections per minute over `connects`, counted in whole minutes from `since`.
fn per_minute(connects: &[Instant], since: Instant) -> Vec<usize> {
    let mut minutes: Vec<usize> = Vec::new();
    for at in connects.iter().filter(|at| **at >= since) {
        let minute = (at.duration_since(since).as_secs() / 60) as usize;
        if minutes.len() <= minute {
            minutes.resize(minute + 1, 0);
        }
        minutes[minute] += 1;
    }
    minutes
}

// ---------------------------------------------------------------------------------------------
// a. Relay killed and restarted while a message is in flight
//
// A relay that is killed (not shut down) keeps the lease of a message it had offered: the
// message can be offered again only when the lease ends, 60 s after the offer, and a mux/1
// socket finds it at the relay's next look over all its mailboxes, or sooner when new mail
// arrives for that mailbox. A clean shutdown releases it instead.

/// How long a message leased by a killed relay can take to come back to a mux/1 socket: the
/// lease ends 60 s after the offer and the relay looks at every attached mailbox only every
/// 120 s, so up to lease + sweep, plus a margin.
const REOFFER: Duration = Duration::from_secs(200);

/// An inner limit for helpers that an outer timeout already bounds.
const NEVER: Duration = Duration::from_secs(3600);

/// The relay pushes a message, the consumer has not yet stored it, and the relay dies (SIGKILL)
/// and comes back. The message is handed out again with the same id once the lease ends, is
/// stored and acknowledged once, and nothing is left on the relay.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY, _STOP_CMD, _START_CMD"]
async fn relay_killed_before_settle_mux_delivers_once() {
    let Some(rig) = rig("restart_unsettled_mux") else {
        return;
    };
    if !restart_cmds("restart_unsettled_mux") {
        return;
    }
    let (sender, mailbox) = (rig.fresh(), rig.fresh());
    let session = rig.session(vec![mailbox.clone()], MuxOptions::default(), None);
    let mut events = session.events();
    let mut queued = session.queued();
    let origin = Instant::now();
    let states = StateLog::start(session.state(), origin);
    wait_attached(&mut events, 1, SHORT).await;
    rig.post(&sender, &mailbox, "in flight at the kill").await;
    let first = next_mail(&session, &mut queued, &[0], SHORT).await;
    assert_eq!(first.len(), 1);
    let offered_at = secs(origin);
    let id = first[0].msg_id().clone();

    let killed_at = secs(origin);
    run_cmd("LEPIC_ROBUST_STOP_CMD").await;
    run_cmd("LEPIC_ROBUST_START_CMD").await;
    let back = states
        .wait_first_after(killed_at, Duration::from_secs(150), "attached again", |s| {
            *s == MuxState::Attached
        })
        .await;
    // The handed-out message is offered again on the new socket once its lease ends.
    let again = tokio::time::timeout(REOFFER, next_mail(&session, &mut queued, &[0], NEVER)).await;
    let again = again.unwrap_or_default();
    let again_at = secs(origin);
    let extra = more_mail(&session, &mut queued, &[0], Duration::from_secs(5)).await;
    let ids_again: Vec<String> = again
        .iter()
        .chain(&extra)
        .map(|m| m.msg_id().to_string())
        .collect();
    for mail in again.iter().chain(&extra) {
        session.settle(mail.msg_id(), Handled::Stored).unwrap();
    }
    let acked = tokio::time::timeout(
        SHORT,
        counters_reach(&session, NEVER, "ack", |c| c.acks >= 1),
    )
    .await
    .is_ok();
    // A message after the restart still arrives.
    rig.post(&sender, &mailbox, "after the restart").await;
    let after = next_mail(&session, &mut queued, &[0], SHORT).await;
    for mail in &after {
        session.settle(mail.msg_id(), Handled::Stored).unwrap();
    }
    let counters = tokio::time::timeout(
        SHORT,
        counters_reach(&session, NEVER, "acks", |c| c.acks >= 2),
    )
    .await
    .unwrap_or_else(|_| session.counters());
    let state_log = states.json();
    drop(states);
    session.stop().await.unwrap();
    let left = rig.leftovers(&mailbox).await;

    report(
        "restart_unsettled_mux",
        json!({
            "kill_to_attached_s": round3(back - killed_at),
            "offer_to_handed_again_s": round3(again_at - offered_at),
            "handed_again_ids": ids_again,
            "first_id": id.to_string(),
            "first_acked": acked,
            "after_texts": after.iter().map(text_of).collect::<Vec<_>>(),
            "left_on_relay": left,
            "states": state_log,
            "counters": counters_json(&counters),
        }),
    );
    assert_eq!(
        ids_again,
        vec![id.to_string()],
        "handed out again once, with the same id"
    );
    assert!(acked, "the message handed out again was not acknowledged");
    assert!(left.is_empty(), "left on the relay: {left:?}");
    assert_eq!(after.len(), 1);
    assert_eq!(counters.acks, 2, "each message acknowledged once");
}

/// The consumer stored the message, the acknowledgement waits in the ack window, and the relay
/// dies before it went out. When the lease ends the relay offers the message again; the session
/// must acknowledge it without handing it out a second time, and nothing is left on the relay.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY, _STOP_CMD, _START_CMD"]
async fn relay_killed_inside_the_ack_window_mux_hands_out_once() {
    let Some(rig) = rig("restart_ack_window_mux") else {
        return;
    };
    if !restart_cmds("restart_ack_window_mux") {
        return;
    }
    let (sender, mailbox) = (rig.fresh(), rig.fresh());
    let options = MuxOptions::default().with_ack_window(Duration::from_secs(5));
    let session = rig.session(vec![mailbox.clone()], options, None);
    let mut events = session.events();
    let mut queued = session.queued();
    let origin = Instant::now();
    let states = StateLog::start(session.state(), origin);
    wait_attached(&mut events, 1, SHORT).await;
    rig.post(&sender, &mailbox, "stored before the kill").await;
    let first = next_mail(&session, &mut queued, &[0], SHORT).await;
    let offered_at = secs(origin);
    let id = first[0].msg_id().clone();
    session.settle(&id, Handled::Stored).unwrap();
    let acks_before_kill = session.counters().acks;

    let killed_at = secs(origin);
    run_cmd("LEPIC_ROBUST_STOP_CMD").await;
    run_cmd("LEPIC_ROBUST_START_CMD").await;
    let back = states
        .wait_first_after(killed_at, Duration::from_secs(150), "attached again", |s| {
            *s == MuxState::Attached
        })
        .await;
    // The relay offers it again after the lease; the session acknowledges it on its own.
    let acked = tokio::time::timeout(
        REOFFER,
        counters_reach(&session, NEVER, "ack of the stored message", |c| {
            c.acks >= 1
        }),
    )
    .await
    .is_ok();
    let acked_at = secs(origin);
    let again = more_mail(&session, &mut queued, &[0], Duration::from_secs(5)).await;
    let counters = session.counters();
    let state_log = states.json();
    drop(states);
    session.stop().await.unwrap();
    let left = rig.leftovers(&mailbox).await;

    report(
        "restart_ack_window_mux",
        json!({
            "ack_window_s": 5,
            "acks_before_kill": acks_before_kill,
            "kill_to_attached_s": round3(back - killed_at),
            "offer_to_ack_s": acked.then_some(round3(acked_at - offered_at)),
            "handed_again": again.iter().map(|m| m.msg_id().to_string()).collect::<Vec<_>>(),
            "left_on_relay": left,
            "states": state_log,
            "counters": counters_json(&counters),
        }),
    );
    assert!(again.is_empty(), "handed out again: {again:?}");
    assert!(acked, "the stored message was never acknowledged");
    assert!(left.is_empty(), "left on the relay: {left:?}");
}

/// What identifies an envelope: its relay id, or its wire form when the relay sent none.
fn envelope_key(
    listener: &Subscription,
    envelope: &lepic_transport::transport::Envelope,
) -> String {
    listener.relay_message_id(envelope.ack_token()).map_or_else(
        || format!("wire:{:?}", envelope.wire()),
        |id| id.to_string(),
    )
}

/// The next envelope from the listener. `next_envelope` answers `None` at the end of each round
/// of what the relay had; this waits past those for a real envelope.
async fn next_real(listener: &Subscription) -> lepic_transport::transport::Envelope {
    loop {
        match listener.next_envelope().await {
            Ok(Some(envelope)) => return envelope,
            Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => panic!("listener failed: {e:?}"),
        }
    }
}

/// The 3.0.0 listener with the app's watchdog: a message handed out and not yet acknowledged
/// when the relay dies stays held. The relay offers it again after the restart; the listener
/// does not hand it out twice (the consumer still holds it), the message waits on the relay,
/// and the token from before the kill clears it once the consumer acknowledges.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY, _STOP_CMD, _START_CMD"]
async fn relay_killed_before_ack_listener_keeps_it_held() {
    listener_restart(false).await;
}

/// The same, but the consumer acknowledges the envelope it got before the kill once the
/// listener is back: the acknowledgement goes out on the new socket, the relay drops the
/// message, and nothing comes again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY, _STOP_CMD, _START_CMD"]
async fn relay_killed_before_ack_listener_late_ack_clears_it() {
    listener_restart(true).await;
}

async fn listener_restart(late_ack: bool) {
    let case = if late_ack {
        "restart_late_ack_listener"
    } else {
        "restart_unacked_listener"
    };
    let Some(rig) = rig(case) else {
        return;
    };
    if !restart_cmds(case) {
        return;
    }
    let (sender, mailbox) = (rig.fresh(), rig.fresh());
    let listener = rig.listener(&mailbox, None);
    let origin = Instant::now();
    let states = StateLog::start(listener.state(), origin);
    states
        .wait_first_after(0.0, SHORT, "subscribed", |s| {
            *s == ConnectionState::Subscribed
        })
        .await;
    rig.post(&sender, &mailbox, "unacked at the kill").await;
    let envelope = within(SHORT, "first envelope", next_real(&listener)).await;
    let offered_at = secs(origin);
    let key = envelope_key(&listener, &envelope);
    let has_relay_id = listener.relay_message_id(envelope.ack_token()).is_some();

    let killed_at = secs(origin);
    run_cmd("LEPIC_ROBUST_STOP_CMD").await;
    run_cmd("LEPIC_ROBUST_START_CMD").await;
    let back = states
        .wait_first_after(
            killed_at + 0.001,
            Duration::from_secs(200),
            "subscribed again",
            |s| *s == ConnectionState::Subscribed,
        )
        .await;
    // The token from before the kill, acknowledged on the new socket.
    let old_ack = if late_ack {
        Some(format!(
            "{:?}",
            listener.acknowledge(envelope.ack_token()).await
        ))
    } else {
        None
    };
    let again = tokio::time::timeout(REOFFER, next_real(&listener)).await;
    let again_at = secs(origin);
    let mut again_keys = Vec::new();
    if let Ok(envelope) = again {
        again_keys.push(envelope_key(&listener, &envelope));
        listener.acknowledge(envelope.ack_token()).await.unwrap();
    }
    // Nothing else comes.
    let extra = tokio::time::timeout(Duration::from_secs(10), next_real(&listener)).await;
    // Without a late acknowledgement the message still waits on the relay (a drain here would
    // take it away); the consumer now acknowledges with the token from before the kill.
    let held_ack = if late_ack {
        None
    } else {
        Some(format!(
            "{:?}",
            listener.acknowledge(envelope.ack_token()).await
        ))
    };
    let state_log = states.json();
    drop(states);
    listener.stop().await.unwrap();
    let left = rig.leftovers(&mailbox).await;

    report(
        case,
        json!({
            "kill_to_subscribed_s": round3(back - killed_at),
            "offer_to_redelivered_s": round3(again_at - offered_at),
            "old_token_ack": old_ack,
            "held_ack": held_ack,
            "has_relay_id": has_relay_id,
            "redelivered_same": again_keys.iter().filter(|k| **k == key).count(),
            "redelivered": again_keys.len(),
            "extra_envelope": extra.is_ok(),
            "left_on_relay": left,
            "states": state_log,
            "counters": format!("{:?}", listener.counters()),
        }),
    );
    if late_ack {
        assert_eq!(
            old_ack.as_deref(),
            Some("Ok(())"),
            "the late acknowledgement failed"
        );
        assert!(
            again_keys.is_empty(),
            "came again after the late acknowledgement"
        );
    } else {
        assert!(
            again_keys.is_empty(),
            "handed out again while the consumer holds it: {key}"
        );
        assert_eq!(
            held_ack.as_deref(),
            Some("Ok(())"),
            "the held acknowledgement failed"
        );
    }
    assert!(extra.is_err(), "a further envelope arrived");
    assert!(left.is_empty(), "left on the relay: {left:?}");
}

// ---------------------------------------------------------------------------------------------
// b. Network drops between client and relay

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Open connections stop carrying bytes and stay open; new ones work.
    Blackhole,
    /// Open connections are reset; new ones work.
    Reset,
    /// Open connections stop carrying bytes and new ones hear nothing, for a while.
    Outage,
}

impl Fault {
    fn name(self) -> &'static str {
        match self {
            Self::Blackhole => "blackhole",
            Self::Reset => "reset",
            Self::Outage => "outage",
        }
    }

    /// Applies the fault; an outage is lifted after `outage`.
    async fn apply(self, proxy: &Proxy, outage: Duration) {
        match self {
            Self::Blackhole => proxy.blackhole(),
            Self::Reset => proxy.reset(),
            Self::Outage => {
                proxy.outage(true);
                proxy.blackhole();
            }
        }
        if self == Self::Outage {
            let state = Arc::clone(&proxy.state);
            tokio::spawn(async move {
                tokio::time::sleep(outage).await;
                state.outage.store(false, Ordering::SeqCst);
                // Connections held during the outage are let go so their clients can retry.
                for ctl in state.conns.lock().unwrap().drain(..) {
                    ctl.kill.notify_one();
                }
            });
        }
    }
}

fn proxy_target(rig: &Rig) -> Option<String> {
    (rig.security == Security::Plain).then(|| format!("{}:{}", rig.host, rig.port.unwrap_or(80)))
}

async fn mux_drop(fault: Fault) {
    let case = format!("drop_{}_mux", fault.name());
    let Some(rig) = rig(&case) else {
        return;
    };
    let Some(target) = proxy_target(&rig) else {
        println!("MUX_ROBUST skipped {case}: the proxy needs a ws:// relay");
        return;
    };
    let outage = Duration::from_secs(env_u64("LEPIC_ROBUST_OUTAGE_S", 120));
    let proxy = Proxy::start(target).await;
    let (sender, mailbox) = (rig.fresh(), rig.fresh());
    let session = rig.session(
        vec![mailbox.clone()],
        MuxOptions::default(),
        Some(proxy.port),
    );
    let mut events = session.events();
    let mut queued = session.queued();
    let origin = Instant::now();
    let states = StateLog::start(session.state(), origin);
    wait_attached(&mut events, 1, SHORT).await;
    // Let the socket settle, so the drop is not right after the attach.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let before = session.counters();

    let dropped_at = secs(origin);
    let dropped = Instant::now();
    fault.apply(&proxy, outage).await;
    rig.post(&sender, &mailbox, "sent during the drop").await;
    let detected = states
        .wait_first_after(dropped_at, Duration::from_secs(200), "socket lost", |s| {
            *s != MuxState::Attached
        })
        .await;
    let back = states
        .wait_first_after(detected, Duration::from_secs(400), "attached again", |s| {
            *s == MuxState::Attached
        })
        .await;
    let mail = next_mail(&session, &mut queued, &[0], Duration::from_secs(200)).await;
    let arrived = secs(origin);
    for message in &mail {
        session.settle(message.msg_id(), Handled::Stored).unwrap();
    }
    let extra = more_mail(&session, &mut queued, &[0], Duration::from_secs(10)).await;
    rig.post(&sender, &mailbox, "after the drop").await;
    let after = next_mail(&session, &mut queued, &[0], SHORT).await;
    for message in &after {
        session.settle(message.msg_id(), Handled::Stored).unwrap();
    }
    let counters = counters_reach(&session, SHORT, "acks", |c| c.acks >= 2).await;
    let connects = proxy.connects_since(dropped);
    let state_log = states.json();
    drop(states);
    session.stop().await.unwrap();
    let left = rig.leftovers(&mailbox).await;

    report(
        &case,
        json!({
            "fault": fault.name(),
            "outage_s": (fault == Fault::Outage).then_some(outage.as_secs()),
            "drop_to_detect_s": round3(detected - dropped_at),
            "drop_to_attached_s": round3(back - dropped_at),
            "drop_to_mail_s": round3(arrived - dropped_at),
            "mail_texts": mail.iter().map(text_of).collect::<Vec<_>>(),
            "extra_handed": extra.len(),
            "connects_after_drop": connects,
            "left_on_relay": left,
            "states": state_log,
            "before": counters_json(&before),
            "counters": counters_json(&counters),
        }),
    );
    assert_eq!(mail.len(), 1, "one message from the drop");
    assert!(extra.is_empty(), "handed out again: {}", extra.len());
    assert_eq!(after.len(), 1);
    assert!(left.is_empty(), "left on the relay: {left:?}");
}

async fn listener_drop(fault: Fault) {
    let case = format!("drop_{}_listener", fault.name());
    let Some(rig) = rig(&case) else {
        return;
    };
    let Some(target) = proxy_target(&rig) else {
        println!("MUX_ROBUST skipped {case}: the proxy needs a ws:// relay");
        return;
    };
    let outage = Duration::from_secs(env_u64("LEPIC_ROBUST_OUTAGE_S", 120));
    let proxy = Proxy::start(target).await;
    let (sender, mailbox) = (rig.fresh(), rig.fresh());
    let listener = rig.listener(&mailbox, Some(proxy.port));
    let origin = Instant::now();
    let states = StateLog::start(listener.state(), origin);
    states
        .wait_first_after(0.0, SHORT, "subscribed", |s| {
            *s == ConnectionState::Subscribed
        })
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let dropped_at = secs(origin);
    let dropped = Instant::now();
    fault.apply(&proxy, outage).await;
    rig.post(&sender, &mailbox, "sent during the drop").await;
    let detected = states
        .wait_first_after(dropped_at, Duration::from_secs(300), "socket lost", |s| {
            *s != ConnectionState::Subscribed
        })
        .await;
    let back = states
        .wait_first_after(
            detected,
            Duration::from_secs(400),
            "subscribed again",
            |s| *s == ConnectionState::Subscribed,
        )
        .await;
    let mut texts = Vec::new();
    let mut ids = Vec::new();
    let envelope = within(
        Duration::from_secs(200),
        "message from the drop",
        next_real(&listener),
    )
    .await;
    let arrived = secs(origin);
    ids.push(envelope_key(&listener, &envelope));
    texts.push(
        format!("{:?}", envelope.wire())
            .chars()
            .take(60)
            .collect::<String>(),
    );
    listener.acknowledge(envelope.ack_token()).await.unwrap();
    let extra = tokio::time::timeout(Duration::from_secs(10), next_real(&listener)).await;
    rig.post(&sender, &mailbox, "after the drop").await;
    let after = within(SHORT, "message after the drop", next_real(&listener)).await;
    ids.push(envelope_key(&listener, &after));
    listener.acknowledge(after.ack_token()).await.unwrap();
    let connects = proxy.connects_since(dropped);
    let state_log = states.json();
    drop(states);
    listener.stop().await.unwrap();
    let left = rig.leftovers(&mailbox).await;

    report(
        &case,
        json!({
            "fault": fault.name(),
            "outage_s": (fault == Fault::Outage).then_some(outage.as_secs()),
            "drop_to_detect_s": round3(detected - dropped_at),
            "drop_to_subscribed_s": round3(back - dropped_at),
            "drop_to_mail_s": round3(arrived - dropped_at),
            "ids": ids,
            "extra_envelope": extra.is_ok(),
            "connects_after_drop": connects,
            "left_on_relay": left,
            "states": state_log,
            "counters": format!("{:?}", listener.counters()),
        }),
    );
    assert!(extra.is_err(), "the message came twice");
    assert_ne!(ids[0], ids[1]);
    assert!(left.is_empty(), "left on the relay: {left:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY (ws://)"]
async fn blackhole_mux_detects_reconnects_and_delivers_once() {
    mux_drop(Fault::Blackhole).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY (ws://)"]
async fn reset_mux_detects_reconnects_and_delivers_once() {
    mux_drop(Fault::Reset).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY (ws://)"]
async fn outage_mux_reconnects_after_it_and_delivers_once() {
    mux_drop(Fault::Outage).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY (ws://)"]
async fn blackhole_listener_detects_reconnects_and_delivers_once() {
    listener_drop(Fault::Blackhole).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY (ws://)"]
async fn reset_listener_detects_reconnects_and_delivers_once() {
    listener_drop(Fault::Reset).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY (ws://)"]
async fn outage_listener_reconnects_after_it_and_delivers_once() {
    listener_drop(Fault::Outage).await;
}

// ---------------------------------------------------------------------------------------------
// c. Two devices on one mailbox

/// Two sessions, A and B, take one mailbox from each other in turn: the one that loses it gets
/// `Replaced`, is holding one unsettled message at that moment, and that message is handed over
/// to the winner. A message posted after each move reaches the winner. No message is lost or
/// stored twice, and nothing is left on the relay.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY"]
async fn two_devices_flip_a_mailbox_without_loss_or_duplicates() {
    let Some(rig) = rig("two_devices") else {
        return;
    };
    let flips = env_u64("LEPIC_ROBUST_FLIPS", 10);
    let (sender, mailbox) = (rig.fresh(), rig.fresh());
    let sessions = [
        rig.session(vec![mailbox.clone()], MuxOptions::default(), None),
        rig.session(Vec::new(), MuxOptions::default(), None),
    ];
    let mut events: Vec<_> = sessions.iter().map(MuxSession::events).collect();
    let mut queued: Vec<_> = sessions.iter().map(MuxSession::queued).collect();
    // Where the mailbox is on each session, by index.
    let mut index: [Option<usize>; 2] = [Some(0), None];
    wait_attached(&mut events[0], 1, SHORT).await;

    let mut posted = Vec::new();
    let mut stored: HashMap<String, u32> = HashMap::new();
    let mut handed_over = 0;
    let mut rounds = Vec::new();
    let mut holder = 0_usize;
    for flip in 0..flips {
        let next = 1 - holder;
        // The holder takes a message and does not settle it.
        let text = format!("in flight at flip {flip}");
        rig.post(&sender, &mailbox, &text).await;
        posted.push(text.clone());
        let flying = next_mail(
            &sessions[holder],
            &mut queued[holder],
            &[index[holder].unwrap()],
            SHORT,
        )
        .await;
        // A second message may follow the first within a moment; collect what is there.
        let mut flying = flying;
        flying.extend(
            more_mail(
                &sessions[holder],
                &mut queued[holder],
                &[index[holder].unwrap()],
                Duration::from_millis(300),
            )
            .await,
        );
        assert_eq!(
            flying.len(),
            1,
            "flip {flip}: one post, handed out {}: {:?}",
            flying.len(),
            flying
                .iter()
                .map(|m| (m.mailbox(), m.msg_id().to_string(), text_of(m)))
                .collect::<Vec<_>>()
        );
        let flying_id = flying[0].msg_id().to_string();

        // The other device takes the mailbox.
        let moved = Instant::now();
        let mut detached = false;
        if let Some(old) = index[next] {
            detached = sessions[next].detach(mailbox.address()).await.unwrap();
            let _ = old;
        }
        let new_index = sessions[next].attach(mailbox.clone()).await.unwrap();
        index[next] = Some(new_index);
        let replaced = within(SHORT, "Replaced on the holder", async {
            loop {
                match events[holder].recv().await {
                    Ok(MuxEvent::Replaced { mailbox }) => return mailbox,
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => panic!("event stream closed"),
                }
            }
        })
        .await;
        let replaced_s = secs(moved);
        assert_eq!(Some(replaced), index[holder]);
        let handed = next_mail(&sessions[next], &mut queued[next], &[new_index], SHORT).await;
        let handed_s = secs(moved);
        let handed_ids: Vec<String> = handed.iter().map(|m| m.msg_id().to_string()).collect();
        if handed_ids.contains(&flying_id) {
            handed_over += 1;
        }
        for mail in &handed {
            sessions[next]
                .settle(mail.msg_id(), Handled::Stored)
                .unwrap();
            *stored.entry(text_of(mail)).or_default() += 1;
        }
        // The loser settles late: its settle must not store anything twice.
        let late = sessions[holder].settle(flying[0].msg_id(), Handled::Stored);

        let text = format!("after flip {flip}");
        rig.post(&sender, &mailbox, &text).await;
        posted.push(text.clone());
        let after = next_mail(&sessions[next], &mut queued[next], &[new_index], SHORT).await;
        for mail in &after {
            sessions[next]
                .settle(mail.msg_id(), Handled::Stored)
                .unwrap();
            *stored.entry(text_of(mail)).or_default() += 1;
        }
        // Anything the loser still queues for the mailbox is a duplicate.
        let stray = sessions[holder].take(&[index[holder].unwrap()]);
        rounds.push(json!({
            "flip": flip,
            "to": if next == 0 { "A" } else { "B" },
            "detached_first": detached,
            "replaced_s": replaced_s,
            "handed_over_s": handed_s,
            "handed_ids": handed_ids.len(),
            "late_settle": format!("{late:?}"),
            "stray_on_loser": stray.len(),
        }));
        assert!(stray.is_empty(), "the loser still got mail at flip {flip}");
        holder = next;
    }
    let extra: Vec<String> = more_mail(
        &sessions[holder],
        &mut queued[holder],
        &[index[holder].unwrap()],
        Duration::from_secs(5),
    )
    .await
    .iter()
    .map(text_of)
    .collect();
    let counters: Vec<Value> = sessions
        .iter()
        .map(|s| counters_json(&s.counters()))
        .collect();
    let [a, b] = sessions;
    a.stop().await.unwrap();
    b.stop().await.unwrap();
    let left = rig.leftovers(&mailbox).await;
    let lost: Vec<&String> = posted.iter().filter(|t| !stored.contains_key(*t)).collect();
    let twice: Vec<(&String, &u32)> = stored.iter().filter(|(_, n)| **n > 1).collect();

    report(
        "two_devices",
        json!({
            "flips": flips,
            "posted": posted.len(),
            "stored": stored.len(),
            "handed_over": handed_over,
            "lost": lost,
            "stored_twice": twice,
            "extra": extra,
            "left_on_relay": left,
            "rounds": rounds,
            "counters": counters,
        }),
    );
    assert!(lost.is_empty(), "lost: {lost:?}");
    assert!(twice.is_empty(), "stored twice: {twice:?}");
    assert!(left.is_empty(), "left on the relay: {left:?}");
    assert_eq!(handed_over, flips as usize);
}

// ---------------------------------------------------------------------------------------------
// d. Many mailboxes on one session

async fn many_mailboxes(case: &str, count: usize, one_by_one: bool) {
    let Some(rig) = rig(case) else {
        return;
    };
    let identities: Vec<Identity> = (0..count).map(|_| rig.fresh()).collect();
    let started = Instant::now();
    let (session, refused) = if one_by_one {
        let session = rig.session(vec![identities[0].clone()], MuxOptions::default(), None);
        let mut events = session.events();
        wait_attached(&mut events, 1, SHORT).await;
        let mut events = session.events();
        for identity in &identities[1..] {
            session.attach(identity.clone()).await.unwrap();
        }
        let refused = Arc::new(Mutex::new(Vec::new()));
        within(Duration::from_secs(300), "all attached", async {
            let mut seen = HashSet::from([0_usize]);
            while seen.len() < count {
                match events.recv().await {
                    Ok(MuxEvent::Attached { mailbox, .. }) => {
                        seen.insert(mailbox);
                    }
                    Ok(MuxEvent::Refused { mailbox, code }) => {
                        refused.lock().unwrap().push(format!("{mailbox}:{code:?}"));
                    }
                    Ok(MuxEvent::Resumed) => {
                        // A resume brings every mailbox of the session back at once.
                        if *session.state().borrow() == MuxState::Attached {
                            seen.extend(0..count);
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => panic!("event stream closed"),
                }
            }
        })
        .await;
        let refused = refused.lock().unwrap().clone();
        (session, refused)
    } else {
        let session = rig.session(identities.clone(), MuxOptions::default(), None);
        let mut events = session.events();
        wait_attached(&mut events, count, Duration::from_secs(300)).await;
        (session, Vec::new())
    };
    let attached_s = secs(started);
    let attach_counters = session.counters();

    let sender = rig.fresh();
    let mut queued = session.queued();
    let posted = Instant::now();
    for identity in &identities {
        rig.post(&sender, identity, &format!("to {}", identity.address()))
            .await;
    }
    let post_s = secs(posted);
    let all: Vec<usize> = (0..count).collect();
    let mut got: HashMap<usize, u32> = HashMap::new();
    within(Duration::from_secs(300), "mail on every mailbox", async {
        while got.len() < count {
            for mail in session.take(&all) {
                *got.entry(mail.mailbox()).or_default() += 1;
                session.settle(mail.msg_id(), Handled::Stored).unwrap();
            }
            let _ = tokio::time::timeout(Duration::from_millis(500), queued.changed()).await;
        }
    })
    .await;
    let delivered_s = secs(posted);
    let counters = counters_reach(&session, SHORT, "every ack", |c| c.acks >= count as u64).await;
    let twice = got.values().filter(|n| **n > 1).count();
    session.stop().await.unwrap();

    report(
        case,
        json!({
            "mailboxes": count,
            "one_by_one": one_by_one,
            "time_to_all_attached_s": attached_s,
            "post_all_s": post_s,
            "post_to_all_delivered_s": delivered_s,
            "delivered_twice": twice,
            "refused": refused,
            "after_attach": counters_json(&attach_counters),
            "counters": counters_json(&counters),
        }),
    );
    assert_eq!(counters.acks, count as u64);
    assert_eq!(twice, 0);
    assert!(refused.is_empty(), "refused: {refused:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY"]
async fn session_with_25_mailboxes() {
    many_mailboxes("many_25", 25, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY"]
async fn session_with_60_mailboxes_at_start() {
    many_mailboxes("many_60_start", 60, false).await;
}

/// 60 mailboxes attached one at a time after the start: more attach frames than the relay
/// takes per minute and socket.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_RELAY"]
async fn session_with_60_mailboxes_one_by_one() {
    many_mailboxes("many_60_one_by_one", 60, true).await;
}

// ---------------------------------------------------------------------------------------------
// e. Relay limits

/// Posts in a row to a relay with a low post limit per IP: the relay refuses some; after a
/// pause posting works again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_POST_LIMITED"]
async fn post_rate_limit_refuses_then_recovers() {
    let Ok(url) = std::env::var("LEPIC_ROBUST_POST_LIMITED") else {
        println!("MUX_ROBUST skipped post_limit: LEPIC_ROBUST_POST_LIMITED is not set");
        return;
    };
    let rig = Rig::at(&url);
    let count = env_u64("LEPIC_ROBUST_POSTS", 40);
    let sender = rig.fresh();
    let targets: Vec<Identity> = (0..4).map(|_| rig.fresh()).collect();
    let started = Instant::now();
    let mut outcomes = Vec::new();
    let mut first_refusal = None;
    let mut ok = 0;
    for n in 0..count {
        let to = &targets[n as usize % targets.len()];
        let result = rig
            .client(None)
            .post(&sender, to.address(), &format!("post {n}"))
            .await;
        match &result {
            Ok(()) => ok += 1,
            Err(_) if first_refusal.is_none() => first_refusal = Some(n),
            Err(_) => {}
        }
        outcomes.push(match result {
            Ok(()) => "ok".to_owned(),
            Err(error) => format!("{error:?}").chars().take(160).collect(),
        });
    }
    let burst_s = secs(started);
    // Recovery: one post every 5 s until one goes through.
    let recover_started = Instant::now();
    let mut tries = 0;
    let recovered_s = within(Duration::from_secs(180), "post accepted again", async {
        loop {
            tries += 1;
            if rig
                .client(None)
                .post(&sender, targets[0].address(), "after the limit")
                .await
                .is_ok()
            {
                return secs(recover_started);
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
    .await;
    let mut kinds: HashMap<String, u32> = HashMap::new();
    for outcome in &outcomes {
        *kinds.entry(outcome.clone()).or_default() += 1;
    }

    report(
        "post_limit",
        json!({
            "posts": count,
            "accepted": ok,
            "first_refusal_at": first_refusal,
            "burst_s": burst_s,
            "outcomes": kinds,
            "recovery_tries": tries,
            "recovered_after_s": recovered_s,
        }),
    );
    assert!(first_refusal.is_some(), "the limit never refused a post");
}

/// More mux/1 sessions from one IP than the relay allows: the relay answers the ones over the
/// limit without mux/1, they end `NotOffered` after one socket each (no reconnect loop), and a
/// new session attaches once the others leave.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_SOCKET_LIMITED"]
async fn mux_sockets_per_ip_limit_ends_extra_sessions_not_offered() {
    let Ok(url) = std::env::var("LEPIC_ROBUST_SOCKET_LIMITED") else {
        println!("MUX_ROBUST skipped mux_socket_limit: LEPIC_ROBUST_SOCKET_LIMITED is not set");
        return;
    };
    let rig = Rig::at(&url);
    let limit = env_u64("LEPIC_ROBUST_MUX_SOCKETS", 2) as usize;
    let total = limit + 2;
    let proxy = Proxy::start(proxy_target(&rig).expect("a ws:// relay")).await;
    let origin = Instant::now();
    let mut sessions = Vec::new();
    let mut logs = Vec::new();
    for _ in 0..total {
        let session = rig.session(vec![rig.fresh()], MuxOptions::default(), Some(proxy.port));
        logs.push(StateLog::start(session.state(), origin));
        sessions.push(session);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // Watch them for half a minute.
    tokio::time::sleep(SHORT).await;
    let attached_now: Vec<bool> = sessions
        .iter()
        .map(|s| *s.state().borrow() == MuxState::Attached)
        .collect();
    let per_session_sockets: Vec<u64> = sessions
        .iter()
        .map(|s| s.counters().sockets_opened)
        .collect();
    let watch_connects = per_minute(&proxy.connects(), origin);
    let states_watch: Vec<Value> = logs.iter().map(StateLog::json).collect();

    // A session over the cap is answered without mux/1 and ends `NotOffered`: the caller goes
    // on with the 3.0.0 listener. It must not keep reconnecting.
    let attached = attached_now.iter().filter(|a| **a).count();
    let not_offered: Vec<bool> = sessions
        .iter()
        .map(|s| *s.state().borrow() == MuxState::NotOffered)
        .collect();
    // Once the attached sessions leave, a new session gets mux/1 again.
    let left_at = secs(origin);
    let mut stops = Vec::new();
    for session in sessions {
        // A session that ended `NotOffered` says so again from `stop`.
        stops.push(format!("{:?}", session.stop().await.err()));
    }
    drop(logs);
    let fresh = rig.session(vec![rig.fresh()], MuxOptions::default(), Some(proxy.port));
    let fresh_log = StateLog::start(fresh.state(), origin);
    let fresh_attached = tokio::time::timeout(
        SHORT,
        fresh_log.wait_first_after(left_at, NEVER, "a new session attached", |s| {
            *s == MuxState::Attached
        }),
    )
    .await
    .ok();
    let all_connects = per_minute(&proxy.connects(), origin);
    let fresh_states = fresh_log.json();
    drop(fresh_log);
    fresh.stop().await.unwrap();

    report(
        "mux_socket_limit",
        json!({
            "limit": limit,
            "sessions": total,
            "attached_after_watch": attached_now,
            "not_offered_after_watch": not_offered,
            "sockets_opened_per_session": per_session_sockets,
            "connects_per_minute_watch": watch_connects,
            "connects_per_minute_all": all_connects,
            "new_session_attached_after_others_left_s": fresh_attached.map(|at| round3(at - left_at)),
            "states_watch": states_watch,
            "new_session_states": fresh_states,
            "stop_errors": stops,
        }),
    );
    assert_eq!(attached, limit, "attached: {attached_now:?}");
    assert_eq!(
        not_offered.iter().filter(|n| **n).count(),
        total - limit,
        "the sessions over the cap should end NotOffered: {not_offered:?}"
    );
    assert!(
        per_session_sockets.iter().all(|n| *n == 1),
        "a session opened more than one socket: {per_session_sockets:?}"
    );
    assert!(
        fresh_attached.is_some(),
        "a new session did not attach after the others left"
    );
}

/// More 3.0.0 listeners from one IP than the relay's socket limit allows: the ones over it are
/// refused, back off, and subscribe once the others leave.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a relay: LEPIC_ROBUST_SOCKET_LIMITED"]
async fn sockets_per_ip_limit_listeners_back_off_and_recover() {
    let Ok(url) = std::env::var("LEPIC_ROBUST_SOCKET_LIMITED") else {
        println!("MUX_ROBUST skipped socket_limit: LEPIC_ROBUST_SOCKET_LIMITED is not set");
        return;
    };
    let rig = Rig::at(&url);
    let limit = env_u64("LEPIC_ROBUST_SOCKETS", 4) as usize;
    let total = limit + 2;
    let proxy = Proxy::start(proxy_target(&rig).expect("a ws:// relay")).await;
    let origin = Instant::now();
    let mut listeners = Vec::new();
    let mut logs = Vec::new();
    for _ in 0..total {
        let listener = rig.listener(&rig.fresh(), Some(proxy.port));
        logs.push(StateLog::start(listener.state(), origin));
        listeners.push(listener);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    tokio::time::sleep(Duration::from_secs(120)).await;
    let subscribed: Vec<bool> = listeners
        .iter()
        .map(|l| *l.state().borrow() == ConnectionState::Subscribed)
        .collect();
    let watch_connects = per_minute(&proxy.connects(), origin);
    let states_watch: Vec<Value> = logs.iter().map(StateLog::json).collect();
    let waiting: Vec<usize> = (0..total).filter(|i| !subscribed[*i]).collect();
    let left_at = secs(origin);
    let mut stopped = 0;
    for (i, listener) in listeners.iter().enumerate() {
        if subscribed[i] && stopped < waiting.len() {
            listener.stop().await.unwrap();
            stopped += 1;
        }
    }
    let mut recovered = Vec::new();
    for i in &waiting {
        let at = logs[*i]
            .wait_first_after(
                left_at,
                Duration::from_secs(400),
                "subscribed after others left",
                |s| *s == ConnectionState::Subscribed,
            )
            .await;
        recovered.push(round3(at - left_at));
    }
    let all_connects = per_minute(&proxy.connects(), origin);
    let disconnects: Vec<String> = listeners
        .iter()
        .map(|l| {
            format!("{:?}", l.last_disconnect())
                .chars()
                .take(200)
                .collect()
        })
        .collect();
    drop(logs);
    for listener in &listeners {
        listener.stop().await.unwrap();
    }

    report(
        "socket_limit",
        json!({
            "limit": limit,
            "listeners": total,
            "subscribed_after_watch": subscribed,
            "connects_per_minute_watch": watch_connects,
            "connects_per_minute_all": all_connects,
            "recovered_after_others_left_s": recovered,
            "last_disconnects": disconnects,
            "states_watch": states_watch,
        }),
    );
    assert_eq!(waiting.len(), total - limit, "subscribed: {subscribed:?}");
    let max_per_minute = watch_connects.iter().copied().max().unwrap_or(0);
    assert!(
        max_per_minute <= 6 * total,
        "tight reconnect loop: {watch_connects:?}"
    );
}
