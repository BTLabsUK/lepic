// SPDX-License-Identifier: Apache-2.0
//! Collecting from a shared mux/1 session instead of a socket of its own.
//!
//! A pass on a relay whose session is attached takes the mail the session queued for the
//! mailboxes of this pass, hands it to the same handler a socket drain uses, and tells the
//! session what became of each message. The relay pushes mail as it arrives, so a pass costs no
//! socket and no round trip.

use std::collections::BTreeSet;
use std::sync::Arc;

use lepic_epicbox::{
    Handled, Identity, MailboxEnd, MailboxHandler, MuxSession, MuxState, RelayEndpoint,
};
use lepic_methods::epicbox::CONTACTS_OWNER;
use lepic_primitives::error_chain::ErrorChain;
use tracing::{debug, warn};

use lepic_node::NodeApi;
use lepic_store::ContactId;
use lepic_wallet::ports::{SecretVault, StoreOpener};

use super::collect::{CollectTrigger, group_by_relay, open_pushed};
use super::relay::mailbox_client;
use super::{ContactBook, ContactRelays};

/// The mailboxes of one collect pass, read from the mail a shared mux/1 session queued.
pub(crate) struct PushedMail {
    session: Arc<MuxSession>,
    /// The session's index of each mailbox, by position in the list given to `open`.
    indexes: Vec<usize>,
    /// The positions this claim added. The relay pushes what it holds only after the attach, so
    /// a pass cannot say it has seen them.
    fresh: BTreeSet<usize>,
    /// The session is attached: its queue says what the relay holds for the claimed mailboxes.
    live: bool,
}

impl PushedMail {
    /// Joins the contacts session of `host` and claims `identities` on it, or `None` when the
    /// contacts do not read pushed mail, the relay does not offer it, or the claim does not fit.
    /// With `add`, the claim keeps what it held and gains `identities`; otherwise it becomes
    /// exactly `identities`. The session is started on first use.
    pub(crate) async fn open(
        relays: &ContactRelays,
        host: &str,
        endpoint: RelayEndpoint,
        onion: Option<&str>,
        identities: &[Identity],
        add: bool,
    ) -> Option<Self> {
        let session = join_session(relays, host, endpoint, onion)?;
        let (keys, unique) = without_repeats(identities);
        let claimed = if add {
            session.add_to_claim(CONTACTS_OWNER, unique).await
        } else {
            session.set_claim(CONTACTS_OWNER, unique).await
        }
        .inspect_err(|error| {
            warn!(peer_relay = %host, error = %ErrorChain(error), "mux/1 claim not set");
        })
        .ok()?;
        let indexes = identities
            .iter()
            .map(|identity| {
                let key = identity.address().key_text();
                let place = keys.iter().position(|known| *known == key)?;
                claimed.indexes.get(place).copied()
            })
            .collect::<Option<Vec<usize>>>()?;
        let fresh = indexes
            .iter()
            .enumerate()
            .filter(|(_, index)| claimed.fresh.contains(index))
            .map(|(position, _)| position)
            .collect();
        let live = *session.state().borrow() == MuxState::Attached;
        Some(Self {
            session,
            indexes,
            fresh,
            live,
        })
    }

    /// Whether this pass can read the queue. A session that is connecting or waiting to
    /// reconnect says nothing about what the relay holds.
    pub(crate) fn is_live(&self) -> bool {
        self.live
    }

    /// Positions whose mail this pass could not have seen yet.
    pub(crate) fn fresh(&self) -> &BTreeSet<usize> {
        &self.fresh
    }

    /// Hands the queued mail to `handler`, numbered by position, and settles each message by the
    /// handler's answer. Returns how each mailbox ended.
    pub(crate) async fn collect(&self, handler: &mut impl MailboxHandler) -> Vec<MailboxEnd> {
        let mut kept: BTreeSet<usize> = BTreeSet::new();
        for message in self.session.take(&self.indexes) {
            let id = message.msg_id().clone();
            let Some(position) = self
                .indexes
                .iter()
                .position(|index| *index == message.mailbox())
            else {
                let _ = self.session.settle(&id, Handled::Later);
                continue;
            };
            let handled = handler.handle(message.renumbered(position)).await;
            if handled == Handled::Later {
                kept.insert(position);
            }
            if self.session.settle(&id, handled).is_err() {
                debug!("mux/1 session ended before a message was settled");
            }
        }
        (0..self.indexes.len())
            .map(|position| {
                if self.fresh.contains(&position) {
                    MailboxEnd::NotReached
                } else if kept.contains(&position) {
                    MailboxEnd::Kept
                } else {
                    MailboxEnd::Empty
                }
            })
            .collect()
    }
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Adds the mailboxes of `contact_id`, its pairing in progress included, to the claim of
    /// the contacts' push sessions, so a relay pushes the reply or confirm of a pairing made or
    /// answered since the last pass instead of holding it until the next one. Nothing is read
    /// and nothing fails: a mailbox left out is claimed by the next pass.
    ///
    /// Waits for the contact turn, so a pass that chose its mailboxes before this pairing was
    /// stored cannot replace the claim afterwards. A running pass holds that turn until it ends,
    /// so a host calls this after the pairing call has returned, off the caller's path.
    pub async fn claim_pushed(&self, relays: &ContactRelays, contact_id: ContactId) {
        if relays.epicbox.pushed().contacts().is_none() {
            return;
        }
        let _turn = self.wallet.contact_turn().await;
        let selection = match self
            .mailboxes_to_collect(
                relays,
                CollectTrigger::Push,
                Some(BTreeSet::from([contact_id])),
                true,
            )
            .await
        {
            Ok(selection) => selection,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "pairing mailboxes not claimed");
                return;
            }
        };
        for (host, mailboxes) in group_by_relay(selection.all) {
            if open_pushed(relays, &host, &mailboxes, true).await.is_some() {
                debug!(peer_relay = %host, count = mailboxes.len(), "pairing mailboxes claimed");
            }
        }
    }
}

/// The contacts session of `host`, started on first use, or `None` when the contacts do not
/// read pushed mail, it could not be started, or it has ended.
fn join_session(
    relays: &ContactRelays,
    host: &str,
    endpoint: RelayEndpoint,
    onion: Option<&str>,
) -> Option<Arc<MuxSession>> {
    let pushed = relays.epicbox.pushed();
    let config = pushed.contacts()?;
    let session = pushed
        .get_or_start(host, &config.group, CONTACTS_OWNER, || {
            mailbox_client(relays, endpoint, onion).start_mux_queued(Vec::new(), config.options)
        })
        .inspect_err(|error| {
            warn!(peer_relay = %host, error = %ErrorChain(error), "mux/1 session not started");
        })
        .ok()?;
    if session.state().borrow().has_ended() {
        return None;
    }
    Some(session)
}

/// `identities` once per address, in order, with the key text of each address.
fn without_repeats(identities: &[Identity]) -> (Vec<String>, Vec<Identity>) {
    let mut keys: Vec<String> = Vec::with_capacity(identities.len());
    let mut unique: Vec<Identity> = Vec::with_capacity(identities.len());
    for identity in identities {
        let key = identity.address().key_text();
        if !keys.contains(&key) {
            keys.push(key);
            unique.push(identity.clone());
        }
    }
    (keys, unique)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use lepic_crypto::{PublicKey, SecretKey};
    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::testing::client_settings;
    use lepic_epicbox::{
        Domain, EpicboxAddress, MailboxContent, MailboxMessage, MuxOptions, Network, Nonce,
        RelayEndpoint, Salt, Security, SignedMessage,
    };
    use lepic_methods::epicbox::{Epicbox, PushedConfig};
    use lepic_transport::transport::BoxFuture;

    use super::*;
    use crate::RelayMode;

    const HOST: &str = "relay.test:80";
    const GROUP: &str = "wallet";

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn address(byte: u8) -> lepic_epicbox::EpicboxAddress {
        EpicboxAddress::new(
            PublicKey::from_secret_key(&secret(byte)).unwrap(),
            Network::Mainnet,
            Domain::parse("relay.test").unwrap(),
            None,
        )
    }

    fn identity(byte: u8) -> Identity {
        Identity::new(secret(byte), address(byte)).unwrap()
    }

    fn endpoint() -> RelayEndpoint {
        RelayEndpoint::new(Domain::parse("relay.test").unwrap(), None, Security::Plain)
    }

    fn sealed(from: u8, to: u8, text: &str) -> SignedMessage {
        SignedMessage::seal(
            text,
            &address(to),
            &secret(from),
            Salt::from([4; 8]),
            Nonce::from([5; 12]),
        )
        .unwrap()
    }

    fn relays(relay: &MuxMockRelay, pushed: bool) -> ContactRelays {
        let epicbox = Epicbox::new(
            client_settings(endpoint()),
            Network::Mainnet,
            relay.connector(),
        );
        if pushed {
            epicbox.pushed().set_contacts(Some(PushedConfig {
                group: GROUP.to_owned(),
                options: MuxOptions {
                    waiting_every: None,
                    ..MuxOptions::default()
                },
            }));
        }
        ContactRelays {
            epicbox,
            meeting: Vec::new(),
            mode: RelayMode::Online,
        }
    }

    async fn open(relays: &ContactRelays, bytes: &[u8], add: bool) -> Option<PushedMail> {
        let identities: Vec<Identity> = bytes.iter().map(|byte| identity(*byte)).collect();
        PushedMail::open(relays, HOST, endpoint(), None, &identities, add).await
    }

    async fn attached(relays: &ContactRelays) -> Arc<MuxSession> {
        let session = relays.epicbox.pushed().get(HOST, GROUP).unwrap();
        let mut state = session.state();
        tokio::time::timeout(
            Duration::from_secs(5),
            state.wait_for(|state| *state == MuxState::Attached),
        )
        .await
        .unwrap()
        .unwrap();
        drop(state);
        session
    }

    async fn until(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[derive(Clone, Default)]
    struct Recorder {
        seen: Arc<Mutex<Vec<(usize, String)>>>,
        later: bool,
    }

    impl MailboxHandler for Recorder {
        fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
            Box::pin(async move {
                let text = match message.content() {
                    MailboxContent::Opened(received) => received.plaintext.expose_str().to_owned(),
                    _ => "unopened".to_owned(),
                };
                self.seen.lock().unwrap().push((message.mailbox(), text));
                if self.later {
                    Handled::Later
                } else {
                    Handled::Stored
                }
            })
        }
    }

    #[tokio::test]
    async fn contacts_that_do_not_read_pushed_mail_open_nothing() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let relays = relays(&relay, false);
        assert!(open(&relays, &[1], false).await.is_none());
        assert_eq!(relay.sockets_made(), 0);
    }

    #[tokio::test]
    async fn a_pass_takes_the_mail_the_session_queued_and_acknowledges_it() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let relays = relays(&relay, true);
        // A pass with no mailboxes starts the session.
        open(&relays, &[], false).await.unwrap();
        let session = attached(&relays).await;

        // A claim made after the attach has not heard what the relay holds: not reached.
        let pass = open(&relays, &[1, 2], false).await.unwrap();
        assert!(pass.is_live());
        assert_eq!(pass.fresh().len(), 2);
        let id = relay.store(&address(2), &address(1), &sealed(2, 1, "hello one"));
        until(|| session.counters().mails == 1).await;
        let mut recorder = Recorder::default();
        assert_eq!(
            pass.collect(&mut recorder).await,
            vec![MailboxEnd::NotReached, MailboxEnd::NotReached]
        );
        assert_eq!(
            *recorder.seen.lock().unwrap(),
            vec![(0, "hello one".to_owned())]
        );
        relay.wait_until(|relay| relay.is_acked(&id)).await;

        // The next pass finds the claim in place.
        let next = open(&relays, &[1, 2], false).await.unwrap();
        assert!(next.fresh().is_empty());
        let mut recorder = Recorder::default();
        assert_eq!(
            next.collect(&mut recorder).await,
            vec![MailboxEnd::Empty, MailboxEnd::Empty]
        );
        assert!(recorder.seen.lock().unwrap().is_empty());
        assert_eq!(relay.sockets_made(), 1);
    }

    #[tokio::test]
    async fn mail_the_handler_keeps_is_held_and_its_mailbox_ends_kept() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let relays = relays(&relay, true);
        open(&relays, &[1, 2], false).await.unwrap();
        let session = attached(&relays).await;
        open(&relays, &[1, 2], false).await.unwrap();
        let id = relay.store(&address(1), &address(2), &sealed(1, 2, "not now"));
        until(|| session.counters().mails == 1).await;
        let pass = open(&relays, &[1, 2], false).await.unwrap();
        let mut recorder = Recorder {
            later: true,
            ..Recorder::default()
        };
        assert_eq!(
            pass.collect(&mut recorder).await,
            vec![MailboxEnd::Empty, MailboxEnd::Kept]
        );
        relay.wait_until(|relay| !relay.holds(&id).is_empty()).await;
        assert!(!relay.is_acked(&id));
        // Mail in a mailbox this pass did not claim is not touched.
        let other = open(&relays, &[1], false).await.unwrap();
        let mut recorder = Recorder::default();
        assert_eq!(other.collect(&mut recorder).await, vec![MailboxEnd::Empty]);
        assert!(recorder.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn adding_keeps_the_claim_the_session_holds() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let relays = relays(&relay, true);
        open(&relays, &[1], false).await.unwrap();
        attached(&relays).await;
        open(&relays, &[1], false).await.unwrap();
        let added = open(&relays, &[2], true).await.unwrap();
        assert_eq!(added.fresh().len(), 1);
        let keys = [address(1).key_text(), address(2).key_text()];
        relay
            .wait_until(|relay| keys.iter().all(|key| relay.attached().contains(key)))
            .await;
    }

    #[tokio::test]
    async fn a_relay_without_mux_opens_nothing_and_is_not_dialed_again() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.offer_mux(false);
        let relays = relays(&relay, true);
        let _ = open(&relays, &[1], false).await;
        let session = relays.epicbox.pushed().get(HOST, GROUP).unwrap();
        let mut state = session.state();
        tokio::time::timeout(
            Duration::from_secs(5),
            state.wait_for(|state| *state == MuxState::NotOffered),
        )
        .await
        .unwrap()
        .unwrap();
        drop(state);
        assert!(open(&relays, &[1], false).await.is_none());
        assert_eq!(relay.sockets_made(), 1);
    }
}
