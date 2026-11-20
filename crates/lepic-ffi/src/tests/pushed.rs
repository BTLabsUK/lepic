// SPDX-License-Identifier: Apache-2.0
//! Push sessions (mux/1) as a host ability: the listener reading through one, the delivery
//! loop's contacts sessions, the view and the watch of the sessions.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::{Domain, EpicboxAddress, Nonce, Salt, SignedMessage};
use lepic_wallet_contacts::epic1_testing::delivery_mailbox;

use super::{Fixture, eventually, kind};
use crate::api::error::WalletErrorKind;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    ContactKind, ContactRelayMode, EpicboxSessionEvent, EpicboxSessionEventKind,
    EpicboxSessionState, InviteExpiry, ListenVia, ListenerEvent, ListenerEventKind, PairingClass,
    WalletConfig,
};
use crate::node::NodeSecret;
use crate::session::{SeedOrigin, Session};

type Listening = tokio::task::JoinHandle<Result<(), crate::api::error::WalletError>>;

struct Pushed {
    relay: MuxMockRelay,
    session: Arc<Session>,
    store: AppSecretStore,
    fixture: Fixture,
}

impl Pushed {
    async fn start() -> Self {
        Self::on(MuxMockRelay::new(lepic_epicbox::Network::Floonet)).await
    }

    /// Makes a wallet that reaches its relay on `relay`.
    async fn on(relay: MuxMockRelay) -> Self {
        let mut fixture = Fixture::new();
        Arc::get_mut(&mut fixture.runtime.inner).unwrap().relay = Some(relay.connector());
        let store = AppSecretStore::in_memory();
        let session = Arc::new(Self::session(&fixture, store.clone()).await);
        session
            .create(SeedOrigin::Generate, password())
            .await
            .unwrap();
        Self {
            relay,
            session,
            store,
            fixture,
        }
    }

    /// A session of the wallet in `fixture`, not yet created or opened.
    async fn session(fixture: &Fixture, store: AppSecretStore) -> Session {
        let mut config = WalletConfig {
            epicbox_domain: "epicbox.example".to_owned(),
            ..fixture.config()
        };
        let secret = NodeSecret::take(&mut config);
        Session::new(&fixture.runtime.inner, &config, &secret, store)
            .await
            .unwrap()
    }

    /// Whether the delivery loop has set the contacts sessions' config.
    fn contacts_set(&self) -> bool {
        self.session
            .epicbox()
            .unwrap()
            .pushed()
            .contacts()
            .is_some()
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

    /// The mailboxes attached besides the public epic1 address's delivery mailbox, which
    /// every contacts claim holds; none while that one is not attached.
    fn claimed_beside_public(&self) -> Option<HashSet<String>> {
        let address = self.session.epic1_address().unwrap();
        let public = delivery_mailbox(&address.address, "epicbox.example").unwrap();
        let mut attached = self.relay.attached();
        attached.remove(&public.key_text()).then_some(attached)
    }

    /// Makes an invite to pair, as the app does, and returns the contact id it names.
    async fn invite(&self, name: &str) -> String {
        self.invite_full(name).await.contact_id
    }

    /// Makes an invite to pair, as the app does.
    async fn invite_full(&self, name: &str) -> crate::api::types::PairingInvite {
        self.session
            .pairing_invite(
                name.to_owned(),
                ContactKind::Person,
                InviteExpiry::OneDay,
                ContactRelayMode::Online,
                None,
                PairingClass::Contact,
                None,
            )
            .await
            .unwrap()
    }
}

fn password() -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new("password".to_owned())
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
        .set_delivery(ContactRelayMode::Online)
        .unwrap();
    assert!(eventually(|| pushed.contacts_set()).await);
    let kept = pushed.session.epicbox().unwrap().pushed().contacts();
    let task = pushed.session.delivery_task().expect("the loop runs");
    pushed
        .session
        .set_delivery(ContactRelayMode::Offline)
        .unwrap();

    // The loop's task ends, and the sessions stay released after its last poll.
    assert!(eventually(|| task.is_finished()).await);
    assert!(pushed.session.epicbox_sessions().is_empty());

    // Without tor or a listener, the contacts share the wallet's group.
    let kept = kept.expect("set");
    assert_eq!(kept.group, "main");
    assert_eq!(kept.options, lepic_epicbox::MuxOptions::default());
    assert_eq!(pushed.session.epicbox().unwrap().pushed().contacts(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_loop_starts_the_contacts_session_after_set_delivery_online() {
    let pushed = Pushed::start().await;
    assert_eq!(pushed.relay.sockets_made(), 0);

    pushed
        .session
        .set_delivery(ContactRelayMode::Online)
        .unwrap();

    assert!(
        eventually(|| pushed
            .session
            .epicbox_sessions()
            .iter()
            .any(
                |session| session.group == "main" && session.state == EpicboxSessionState::Attached
            ))
        .await,
        "{:?}",
        pushed.session.epicbox_sessions()
    );
    // The first tick claims the public address's delivery mailbox.
    assert!(
        eventually(|| pushed.claimed_beside_public().is_some()).await,
        "{:?}",
        pushed.relay.attached()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_delivery_offline_closes_the_contacts_socket() {
    let pushed = Pushed::start().await;
    pushed
        .session
        .set_delivery(ContactRelayMode::Online)
        .unwrap();
    assert!(eventually(|| pushed.claimed_beside_public().is_some()).await);

    pushed
        .session
        .set_delivery(ContactRelayMode::Offline)
        .unwrap();

    assert!(eventually(|| pushed.session.epicbox_sessions().is_empty()).await);
    assert!(eventually(|| pushed.relay.sockets_open() == 0).await);
    assert_eq!(pushed.session.epicbox().unwrap().pushed().contacts(), None);
}

/// Mail the relay pushes to a claimed mailbox is read by a tick within seconds, though the
/// loop's interval is 30 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_mail_is_read_without_a_wake() {
    let pushed = Pushed::start().await;
    pushed
        .session
        .set_delivery(ContactRelayMode::Online)
        .unwrap();
    assert!(eventually(|| pushed.claimed_beside_public().is_some()).await);
    let address = pushed.session.epic1_address().unwrap();
    let mailbox = delivery_mailbox(&address.address, "epicbox.example").unwrap();
    let sender = lepic_keychain::ExtendedPrivKey::new_master(&[7; 32]).unwrap();
    let from = EpicboxAddress::new(
        sender.public_key().unwrap(),
        lepic_epicbox::Network::Floonet,
        Domain::parse("epicbox.example").unwrap(),
        None,
    );
    let sealed = SignedMessage::seal(
        "not a payment",
        &mailbox,
        sender.secret_key(),
        Salt::from([4; 8]),
        Nonce::from([5; 12]),
    )
    .unwrap();

    let id = pushed.relay.store(&from, &mailbox, &sealed);

    // Only a tick takes mail off the relay.
    assert!(
        eventually(|| pushed.relay.is_acked(&id)).await,
        "holds {:?}",
        pushed.relay.holds(&id)
    );
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
        .set_delivery(ContactRelayMode::Online)
        .unwrap();
    let (heard, listening) = pushed.listen_via("wallet");
    assert!(eventually(|| connected(&heard)).await);
    assert!(eventually(|| pushed.contacts_set()).await);
    let task = pushed.session.delivery_task().expect("the loop runs");

    pushed.session.lock();

    // The loop's task ends, and the sessions stay released after its last poll.
    assert!(eventually(|| task.is_finished()).await);
    tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();
    let epicbox = pushed.session.epicbox().unwrap();
    assert!(epicbox.pushed().infos().is_empty());
    assert_eq!(epicbox.pushed().contacts(), None);
    assert!(eventually(|| pushed.relay.sockets_open() == 0).await);
    assert_eq!(
        kind(pushed.session.set_delivery(ContactRelayMode::Online)),
        WalletErrorKind::Locked
    );

    // The wallet opened again has no loop until the app sets the mode.
    let Pushed {
        relay,
        session,
        store,
        fixture,
    } = pushed;
    drop(session);
    let session = Arc::new(Pushed::session(&fixture, store.clone()).await);
    session.open(password()).await.unwrap();
    let reopened = Pushed {
        relay,
        session,
        store,
        fixture,
    };
    assert!(reopened.session.delivery_task().is_none());
    assert!(!reopened.contacts_set());
    reopened
        .session
        .set_delivery(ContactRelayMode::Online)
        .unwrap();
    assert!(eventually(|| reopened.contacts_set()).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invite_claims_its_reply_mailbox_on_the_contacts_session_at_once() {
    let pushed = Pushed::start().await;
    pushed
        .session
        .set_delivery(ContactRelayMode::Online)
        .unwrap();
    assert!(
        eventually(|| pushed
            .claimed_beside_public()
            .is_some_and(|keys| keys.is_empty()))
        .await
    );

    pushed.invite("Anna").await;
    let one = |keys: &HashSet<String>| keys.len() == 1;
    assert!(
        eventually(|| pushed
            .claimed_beside_public()
            .is_some_and(|keys| one(&keys)))
        .await,
        "{:?}",
        pushed.relay.attached()
    );
    let first = pushed.claimed_beside_public().unwrap();
    pushed.invite("Ben").await;

    // The second invite adds its mailbox to the claim; the first stays.
    let both = |keys: &HashSet<String>| keys.len() == 2 && keys.is_superset(&first);
    assert!(
        eventually(|| pushed
            .claimed_beside_public()
            .is_some_and(|keys| both(&keys)))
        .await,
        "{:?}",
        pushed.relay.attached()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invite_opens_no_session_while_the_contacts_read_no_pushed_mail() {
    let pushed = Pushed::start().await;

    pushed.invite("Anna").await;

    assert_eq!(pushed.relay.sockets_made(), 0);
    assert!(
        pushed
            .session
            .epicbox()
            .unwrap()
            .pushed()
            .infos()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invite_returns_while_a_collect_holds_the_contact_turn_and_claims_after() {
    let pushed = Pushed::start().await;
    pushed
        .session
        .set_delivery(ContactRelayMode::Online)
        .unwrap();
    // After the first tick, which claims the public address's delivery mailbox.
    assert!(
        eventually(|| pushed
            .claimed_beside_public()
            .is_some_and(|keys| keys.is_empty()))
        .await
    );
    let turn = pushed.session.engine_wallet().contact_turn().await;

    let made = tokio::time::timeout(Duration::from_secs(5), pushed.invite("Anna")).await;

    assert!(made.is_ok(), "the invite waited for the contact turn");
    assert_eq!(pushed.claimed_beside_public(), Some(HashSet::new()));
    drop(turn);
    // The reply mailbox, beside the public address's.
    assert!(
        eventually(|| pushed
            .claimed_beside_public()
            .is_some_and(|keys| keys.len() == 1))
        .await,
        "{:?}",
        pushed.relay.attached()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_claims_its_confirm_mailbox_on_the_contacts_session() {
    let anna = Pushed::start().await;
    let ben = Pushed::start().await;
    ben.session.set_delivery(ContactRelayMode::Online).unwrap();
    let invite = anna.invite_full("Ben").await;

    ben.session
        .pairing_accept(
            invite.link,
            "Anna".to_owned(),
            true,
            ContactRelayMode::Online,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();

    // The confirm mailbox, beside the public address's.
    assert!(
        eventually(|| ben
            .claimed_beside_public()
            .is_some_and(|keys| keys.len() == 1))
        .await,
        "{:?}",
        ben.relay.attached()
    );
}
