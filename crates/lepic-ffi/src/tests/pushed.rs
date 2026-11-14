// SPDX-License-Identifier: Apache-2.0
//! Push sessions (mux/1) as a host ability: the listener reading through one, the contacts
//! setting, the view and the watch of the sessions.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lepic_epicbox::mock_mux::MuxMockRelay;

use super::{Fixture, eventually, kind};
use crate::api::error::WalletErrorKind;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    EpicboxSessionEvent, EpicboxSessionEventKind, EpicboxSessionState, ListenVia, ListenerEvent,
    ListenerEventKind, WalletConfig,
};
use crate::node::NodeSecret;
use crate::session::{SeedOrigin, Session};

type Listening = tokio::task::JoinHandle<Result<(), crate::api::error::WalletError>>;

struct Pushed {
    relay: MuxMockRelay,
    session: Arc<Session>,
    _fixture: Fixture,
}

impl Pushed {
    async fn start() -> Self {
        let relay = MuxMockRelay::new(lepic_epicbox::Network::Floonet);
        let mut fixture = Fixture::new();
        Arc::get_mut(&mut fixture.runtime.inner).unwrap().relay = Some(relay.connector());
        let mut config = WalletConfig {
            epicbox_domain: "epicbox.example".to_owned(),
            ..fixture.config()
        };
        let secret = NodeSecret::take(&mut config);
        let session = Arc::new(
            Session::new(
                &fixture.runtime.inner,
                &config,
                &secret,
                AppSecretStore::in_memory(),
            )
            .await
            .unwrap(),
        );
        session
            .create(
                SeedOrigin::Generate,
                zeroize::Zeroizing::new("password".to_owned()),
            )
            .await
            .unwrap();
        Self {
            relay,
            session,
            _fixture: fixture,
        }
    }

    /// Starts the listener through a session of `group` and returns what it reports.
    fn listen_via(&self, group: &str) -> (Arc<Mutex<Vec<ListenerEvent>>>, Listening) {
        let handle = self
            .session
            .claim_listener_via(via(group, None))
            .unwrap()
            .unwrap();
        let heard = Arc::new(Mutex::new(Vec::new()));
        let listening = tokio::spawn({
            let (session, heard) = (Arc::clone(&self.session), Arc::clone(&heard));
            async move {
                session
                    .listen(&handle, |event| heard.lock().unwrap().push(event))
                    .await
            }
        });
        (heard, listening)
    }
}

fn via(group: &str, waiting_every_s: Option<u32>) -> ListenVia {
    ListenVia {
        group: group.to_owned(),
        waiting_every_s,
    }
}

fn connected(heard: &Mutex<Vec<ListenerEvent>>) -> bool {
    heard
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == ListenerEventKind::Connected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_via_a_session_attaches_and_the_session_is_listed() {
    let pushed = Pushed::start().await;
    let (heard, listening) = pushed.listen_via("wallet");
    assert!(eventually(|| connected(&heard)).await);

    let sessions = pushed.session.epicbox_sessions();

    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].group, "wallet");
    assert_eq!(sessions[0].relay, "epicbox.example:443");
    assert_eq!(sessions[0].state, EpicboxSessionState::Attached);
    assert!(sessions[0].attaches >= 1);
    assert_eq!(pushed.relay.sockets_made(), 1);
    pushed.session.stop_listener();
    tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();
    assert!(
        eventually(|| pushed.session.epicbox_sessions().is_empty()).await,
        "the session ends with its last owner"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_choice_with_a_bad_group_or_interval_is_refused() {
    let pushed = Pushed::start().await;
    for bad in [
        via("", None),
        via(&"g".repeat(65), None),
        via("line\nbreak", None),
        via("wallet", Some(0)),
        via("wallet", Some(86_401)),
    ] {
        assert_eq!(
            kind(pushed.session.claim_listener_via(bad.clone())),
            WalletErrorKind::InvalidArgument,
            "{bad:?}"
        );
        assert_eq!(
            kind(pushed.session.contacts_push_start(bad.clone())),
            WalletErrorKind::InvalidArgument,
            "{bad:?}"
        );
    }
    assert!(
        !pushed.session.listener_running(),
        "a refused choice claims nothing"
    );
    assert_eq!(pushed.session.epicbox().unwrap().pushed().contacts(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_contacts_setting_is_kept_until_it_is_stopped() {
    let pushed = Pushed::start().await;

    pushed
        .session
        .contacts_push_start(via("contacts", Some(30)))
        .unwrap();
    let kept = pushed.session.epicbox().unwrap().pushed().contacts();
    pushed.session.contacts_push_stop().await.unwrap();

    let kept = kept.expect("set");
    assert_eq!(kept.group, "contacts");
    assert_eq!(kept.options.waiting_every, Some(Duration::from_secs(30)));
    assert_eq!(pushed.session.epicbox().unwrap().pushed().contacts(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_watch_reports_a_session_when_it_appears_and_when_it_ends() {
    let pushed = Pushed::start().await;
    let seen = Arc::new(Mutex::new(Vec::<EpicboxSessionEvent>::new()));
    let watching = tokio::spawn({
        let (session, seen) = (Arc::clone(&pushed.session), Arc::clone(&seen));
        async move {
            session
                .watch_epicbox_sessions(move |event| seen.lock().unwrap().push(event))
                .await
        }
    });
    let states = |seen: &Mutex<Vec<EpicboxSessionEvent>>| {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == EpicboxSessionEventKind::State)
            .filter_map(|event| event.state)
            .collect::<Vec<_>>()
    };

    let (heard, listening) = pushed.listen_via("wallet");
    assert!(eventually(|| connected(&heard)).await);
    assert!(
        eventually(|| states(&seen).contains(&EpicboxSessionState::Attached)).await,
        "{:?}",
        states(&seen)
    );
    pushed.session.stop_listener();
    tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();

    assert!(
        eventually(|| states(&seen).last() == Some(&EpicboxSessionState::Stopped)).await,
        "{:?}",
        states(&seen)
    );
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|event| event.group == "wallet" && event.relay == "epicbox.example:443")
    );
    watching.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_ends_the_sessions_and_the_contacts_setting() {
    let pushed = Pushed::start().await;
    pushed
        .session
        .contacts_push_start(via("contacts", None))
        .unwrap();
    let (heard, listening) = pushed.listen_via("wallet");
    assert!(eventually(|| connected(&heard)).await);

    pushed.session.lock();

    tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();
    let epicbox = pushed.session.epicbox().unwrap();
    assert!(epicbox.pushed().infos().is_empty());
    assert_eq!(epicbox.pushed().contacts(), None);
    assert!(eventually(|| pushed.relay.sockets_open() == 0).await);
}
