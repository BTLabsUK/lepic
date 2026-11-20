// SPDX-License-Identifier: Apache-2.0
//! The Epicbox listener's stream beside drains: a drain's connection never reads as the
//! listener's, and a payments drain stays off the relay while the listener runs.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lepic_epicbox::mock_relay::MockRelay;

use super::{Fixture, eventually};
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{InboxReport, ListenerEvent, ListenerEventKind, WalletConfig};
use crate::node::NodeSecret;
use crate::session::{SeedOrigin, Session};

struct Listening {
    relay: MockRelay,
    session: Arc<Session>,
    heard: Arc<Mutex<Vec<ListenerEvent>>>,
    listening: Option<tokio::task::JoinHandle<Result<(), crate::api::error::WalletError>>>,
    _fixture: Fixture,
}

impl Listening {
    /// A new wallet whose listener is connected to a mock relay.
    async fn start() -> Self {
        let relay = MockRelay::new(lepic_epicbox::Network::Floonet);
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
        let heard = Arc::new(Mutex::new(Vec::new()));
        let handle = session.claim_listener().unwrap().unwrap();
        let listening = tokio::spawn({
            let (session, heard) = (Arc::clone(&session), Arc::clone(&heard));
            async move {
                session
                    .listen(&handle, |event| heard.lock().unwrap().push(event))
                    .await
            }
        });
        let listening = Self {
            relay,
            session,
            heard,
            listening: Some(listening),
            _fixture: fixture,
        };
        assert!(eventually(|| listening.count(ListenerEventKind::Connected) == 1).await);
        listening
    }

    fn count(&self, kind: ListenerEventKind) -> usize {
        self.heard
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == kind)
            .count()
    }

    fn kinds(&self) -> Vec<ListenerEventKind> {
        self.heard
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.kind)
            .collect()
    }

    async fn stop(&mut self) {
        self.session.stop_listener();
        let listening = self.listening.take().unwrap();
        tokio::time::timeout(Duration::from_secs(5), listening)
            .await
            .expect("the listener ended")
            .unwrap()
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payments_drain_while_the_listener_runs_stays_off_the_relay() {
    let mut listening = Listening::start().await;

    let report = listening.session.drain_epicbox().await.unwrap();

    assert_eq!(report, InboxReport::default());
    assert_eq!(listening.relay.received("subscribe"), 1);
    assert_eq!(listening.kinds(), [ListenerEventKind::Connected]);
    listening.stop().await;
    listening.session.drain_epicbox().await.unwrap();
    assert_eq!(listening.relay.received("subscribe"), 2);
}
