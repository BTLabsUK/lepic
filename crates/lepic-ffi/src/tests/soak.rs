//! Soak of the desktop app's Epicbox listener with its node polls, refreshes and invoice drains,
//! on a real runtime against public floonet servers. Ignored and opt-in (`docs/rules.md`):
//!
//! ```text
//! LEPIC_LIVE_TESTS=1 LEPIC_TEST_NODE_URL=https://<floonet node> \
//! LEPIC_TEST_RELAY=<floonet relay>[:port] SOAK_OUT=<dir> [SOAK_RUN=A|B|C] [SOAK_SECS=<s>] \
//! cargo test -p lepic-ffi soak -- --ignored --nocapture
//! ```
//!
//! Run `A` keeps the listener on and polls at the app's rates (tip 30 s, refresh 60 s, drain
//! 120 s); `B` polls ten times as fast; `C` restarts the listener 200 times. Every 15 s it writes
//! a row of RSS, threads, fds, established TCP sockets and tokio tasks to `run<RUN>.csv`, and
//! the listener's events to `run<RUN>.log`. Linux only: the samples come from `/proc/self`.

use std::collections::HashSet;
use std::fs::File;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lepic_keychain::KdfParams;
use zeroize::Zeroizing;

use crate::api::diagnostics::LogLevel;
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{Chain, ListenerEvent, ListenerEventKind, WalletConfig};
use crate::node::{NodeFactory, NodeSecret};
use crate::pin::PinPolicy;
use crate::session::{SeedOrigin, Session};

fn status_kb(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|rest| {
            rest.trim_start_matches(':')
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

fn entries(dir: &str) -> usize {
    std::fs::read_dir(dir).map_or(0, Iterator::count)
}

/// Established TCP sockets owned by this process.
fn established() -> usize {
    let inodes: HashSet<String> = std::fs::read_dir("/proc/self/fd")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            let target = target.to_string_lossy().into_owned();
            Some(
                target
                    .strip_prefix("socket:[")?
                    .trim_end_matches(']')
                    .to_owned(),
            )
        })
        .collect();
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .flat_map(|table| {
            std::fs::read_to_string(table)
                .unwrap_or_default()
                .lines()
                .skip(1)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|line| {
            let columns: Vec<&str> = line.split_whitespace().collect();
            columns.get(3) == Some(&"01") && columns.get(9).is_some_and(|i| inodes.contains(*i))
        })
        .count()
}

#[derive(Default)]
struct Counters {
    tip_ok: AtomicU64,
    tip_err: AtomicU64,
    refresh_ok: AtomicU64,
    refresh_err: AtomicU64,
    drain_ok: AtomicU64,
    drain_err: AtomicU64,
    cycles: AtomicU64,
    listener_connected: AtomicU64,
    listener_disconnected: AtomicU64,
}

#[derive(Clone)]
struct Log(Arc<Mutex<File>>, Instant);

impl Log {
    fn line(&self, message: &str) {
        let line = format!("[{:8.1}s] {message}\n", self.1.elapsed().as_secs_f64());
        let _ = self.0.lock().unwrap().write_all(line.as_bytes());
    }
}

fn count<T>(
    result: &Result<T, crate::api::error::WalletError>,
    ok: &AtomicU64,
    err: &AtomicU64,
    log: &Log,
    what: &str,
) {
    match result {
        Ok(_) => ok.fetch_add(1, SeqCst),
        Err(error) => {
            log.line(&format!("{what} failed: {error}"));
            err.fetch_add(1, SeqCst)
        }
    };
}

#[test]
#[ignore = "opt-in live soak against public floonet servers"]
fn soak() {
    assert_eq!(
        std::env::var("LEPIC_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set LEPIC_LIVE_TESTS=1"
    );
    let node_url = std::env::var("LEPIC_TEST_NODE_URL").expect("LEPIC_TEST_NODE_URL");
    let relay = std::env::var("LEPIC_TEST_RELAY").expect("LEPIC_TEST_RELAY");
    let (relay_domain, relay_port) = match relay.rsplit_once(':') {
        Some((domain, port)) => (domain.to_owned(), port.parse().unwrap()),
        None => (relay, 443),
    };
    let out = std::env::var("SOAK_OUT").expect("SOAK_OUT");
    let run = std::env::var("SOAK_RUN").unwrap_or_else(|_| "A".to_owned());
    let (secs, tip_every, refresh_every, drain_every) = match run.as_str() {
        "A" => (25 * 60, 30, 60, 120),
        "B" => (8 * 60, 3, 6, 12),
        _ => (3 * 60, 30, 60, 120),
    };
    let secs = std::env::var("SOAK_SECS")
        .ok()
        .and_then(|secs| secs.parse().ok())
        .unwrap_or(secs);
    let deadline = Duration::from_secs(secs);
    let t0 = Instant::now();
    let log = Log(
        Arc::new(Mutex::new(
            File::create(format!("{out}/run{run}.log")).unwrap(),
        )),
        t0,
    );
    let mut csv = File::create(format!("{out}/run{run}.csv")).unwrap();
    writeln!(
        csv,
        "elapsed_s,rss_kb,hwm_kb,threads,fds,tcp_established,tasks,tip_ok,tip_err,refresh_ok,\
         refresh_err,drain_ok,drain_err,cycles,listener_connected,listener_disconnected"
    )
    .unwrap();

    let runtime = LepicRuntime::start(
        LogLevel::Warn,
        NodeFactory::Http,
        KdfParams::DEFAULT,
        PinPolicy::DEFAULT,
    )
    .unwrap();
    let rt = runtime.inner.boundary.handle.clone();
    let data = tempfile::tempdir().unwrap();
    let mut config = WalletConfig {
        data_dir: data.path().to_string_lossy().into_owned(),
        chain: Chain::Floonet,
        node_url,
        node_api_secret: None,
        epicbox_domain: relay_domain,
        epicbox_port: relay_port,
    };
    let secret = NodeSecret::take(&mut config);
    let counters = Arc::new(Counters::default());

    let session = Arc::new(rt.block_on(async {
        let session = Session::new(
            &runtime.inner,
            &config,
            &secret,
            AppSecretStore::in_memory(),
        )
        .await
        .unwrap();
        session
            .create(SeedOrigin::Generate, Zeroizing::new("password".to_owned()))
            .await
            .unwrap();
        session
    }));
    log.line(&format!("run {run}: wallet created"));

    let report = {
        let (log, counters) = (log.clone(), Arc::clone(&counters));
        move |event: ListenerEvent| {
            match event.kind {
                ListenerEventKind::Connected => counters.listener_connected.fetch_add(1, SeqCst),
                ListenerEventKind::Disconnected => {
                    counters.listener_disconnected.fetch_add(1, SeqCst)
                }
                _ => 0,
            };
            log.line(&format!(
                "listener event {:?} reason={:?} retry_in_ms={:?}",
                event.kind, event.reason, event.retry_in_ms
            ));
        }
    };
    let spawn_listener = {
        let (session, log) = (Arc::clone(&session), log.clone());
        move || {
            session.claim_listener().unwrap().map(|handle| {
                let (session, report, log) = (Arc::clone(&session), report.clone(), log.clone());
                tokio::spawn(async move {
                    let result = session.listen(&handle, report).await;
                    log.line(&format!(
                        "listen ended: {:?}",
                        result.map_err(|e| e.to_string())
                    ));
                })
            })
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let (stop, counters, rt) = (Arc::clone(&stop), Arc::clone(&counters), rt.clone());
        std::thread::spawn(move || {
            let mut next = Duration::ZERO;
            while !stop.load(SeqCst) {
                if t0.elapsed() >= next {
                    next += Duration::from_secs(15);
                    let c = &counters;
                    let _ = writeln!(
                        csv,
                        "{:.0},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                        t0.elapsed().as_secs_f64(),
                        status_kb("VmRSS"),
                        status_kb("VmHWM"),
                        entries("/proc/self/task"),
                        entries("/proc/self/fd"),
                        established(),
                        rt.metrics().num_alive_tasks(),
                        c.tip_ok.load(SeqCst),
                        c.tip_err.load(SeqCst),
                        c.refresh_ok.load(SeqCst),
                        c.refresh_err.load(SeqCst),
                        c.drain_ok.load(SeqCst),
                        c.drain_err.load(SeqCst),
                        c.cycles.load(SeqCst),
                        c.listener_connected.load(SeqCst),
                        c.listener_disconnected.load(SeqCst),
                    );
                    let _ = csv.flush();
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        })
    };

    rt.block_on(async {
        let c = &counters;
        let mut listener = spawn_listener();
        if run == "C" {
            while t0.elapsed() < deadline && c.cycles.load(SeqCst) < 200 {
                tokio::time::sleep(Duration::from_millis(300)).await;
                session.stop_listener();
                if let Some(running) = listener.take()
                    && tokio::time::timeout(Duration::from_secs(30), running)
                        .await
                        .is_err()
                {
                    log.line("listen did not end within 30 s of a stop");
                }
                let refreshed = session.refresh().await;
                count(&refreshed, &c.refresh_ok, &c.refresh_err, &log, "refresh");
                listener = spawn_listener();
                if listener.is_none() {
                    log.line("claim_listener found a listener still running");
                }
                c.cycles.fetch_add(1, SeqCst);
            }
        } else {
            let mut tip = tokio::time::interval(Duration::from_secs(tip_every));
            let mut refresh = tokio::time::interval(Duration::from_secs(refresh_every));
            let mut drain = tokio::time::interval(Duration::from_secs(drain_every));
            while t0.elapsed() < deadline {
                tokio::select! {
                    _ = tip.tick() => {
                        let tip = session.node_tip_for(&config, &secret).await;
                        count(&tip, &c.tip_ok, &c.tip_err, &log, "node tip");
                    }
                    _ = refresh.tick() => {
                        let refreshed = session.refresh().await;
                        count(&refreshed, &c.refresh_ok, &c.refresh_err, &log, "refresh");
                    }
                    _ = drain.tick() => {
                        log.line("drain_epicbox start");
                        let drained = session.drain_epicbox().await;
                        count(&drained, &c.drain_ok, &c.drain_err, &log, "drain_epicbox");
                        log.line("drain_epicbox end");
                    }
                }
            }
        }
        session.stop_listener();
        if let Some(running) = listener.take() {
            let _ = tokio::time::timeout(Duration::from_secs(30), running).await;
        }
    });
    // One more sample after the listener stopped and the runtime settled.
    std::thread::sleep(Duration::from_secs(16));
    stop.store(true, SeqCst);
    sampler.join().unwrap();
    log.line(&format!("done run {run}"));
}
