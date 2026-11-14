// SPDX-License-Identifier: Apache-2.0
//! Where an inbox run takes its messages from, and what it takes: [`Source`] is either a socket
//! subscription of the run's own or the payments mailbox of a shared mux/1 session, and both
//! hand out [`Item`]s.

use std::collections::{HashMap, VecDeque};
use std::error::Error as StdError;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lepic_epicbox::{
    ClientError, Identity, MailboxClient, MailboxContent, MuxError, MuxSession, RejectionReason,
    RelayMessageId, RelayedMail, Subscription,
};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::transport::{AckToken, Destination, Envelope, Inbound};
use lepic_wallet::inbox::InboxError;

/// What a failed acknowledgement or requeue reports.
pub(super) type Failure = Box<dyn StdError + Send + Sync>;

/// One message of a source, handed out under the relay message id the source knows it by.
pub(super) enum Item {
    /// A message that opened, with its relay message id if the source gave one.
    Envelope(Envelope, Option<RelayMessageId>),
    /// A message that could not be opened.
    Rejection(Rejected),
}

/// A message that could not be opened, to be recorded and acknowledged.
pub(super) struct Rejected {
    token: AckToken,
    msg_id: Option<RelayMessageId>,
    pub(super) reason: RejectionReason,
}

impl Item {
    fn ack_token(&self) -> &AckToken {
        match self {
            Self::Envelope(envelope, _) => envelope.ack_token(),
            Self::Rejection(rejected) => &rejected.token,
        }
    }

    fn relay_message_id(&self) -> Option<&RelayMessageId> {
        match self {
            Self::Envelope(_, msg_id) => msg_id.as_ref(),
            Self::Rejection(rejected) => rejected.msg_id.as_ref(),
        }
    }

    /// The relay message id as text, the key under which the wallet records the message.
    pub(super) fn msg_id(&self) -> Option<&str> {
        self.relay_message_id().map(RelayMessageId::as_str)
    }
}

/// Where a run takes its messages from: a socket of its own, or mail a shared mux/1 session
/// pushed.
pub(in crate::epicbox) enum Source<'a> {
    Socket(&'a Subscription),
    Pushed(&'a Pushed),
}

impl Source<'_> {
    /// The next message that could not be opened, if one is waiting.
    pub(super) fn next_rejection(&self) -> Option<Item> {
        match self {
            Self::Socket(subscription) => subscription.next_rejection().map(|rejection| {
                Item::Rejection(Rejected {
                    token: rejection.ack_token().clone(),
                    msg_id: rejection.msg_id().cloned(),
                    reason: rejection.reason(),
                })
            }),
            Self::Pushed(pushed) => pushed.next_rejection(),
        }
    }

    /// The next message that opened. A socket waits for the relay to hand one out, or for the
    /// subscription to end (`None`); a pushed mailbox answers from what the session queued.
    pub(super) async fn next_envelope(&self) -> Result<Option<Item>, InboxError> {
        match self {
            Self::Socket(subscription) => Ok(subscription
                .next_envelope()
                .await
                .map_err(InboxError::Transport)?
                .map(|envelope| {
                    let msg_id = subscription.relay_message_id(envelope.ack_token());
                    Item::Envelope(envelope, msg_id)
                })),
            Self::Pushed(pushed) => Ok(pushed.next_envelope()),
        }
    }

    /// Waits until a message may be waiting, or the source has ended.
    pub(super) async fn delivery_available(&self) {
        match self {
            Self::Socket(subscription) => subscription.delivery_available().await,
            Self::Pushed(pushed) => pushed.delivery_available().await,
        }
    }

    pub(super) fn has_ended(&self) -> bool {
        match self {
            Self::Socket(subscription) => subscription.state().borrow().has_ended(),
            Self::Pushed(pushed) => pushed.session.state().borrow().has_ended(),
        }
    }

    /// Tells the relay `item` is settled. A pushed session never fails here: one that ended has
    /// nothing to tell, and the relay offers the message again.
    pub(super) async fn acknowledge(&self, item: &Item) -> Result<(), Failure> {
        match self {
            Self::Socket(subscription) => subscription
                .acknowledge(item.ack_token())
                .await
                .map_err(Into::into),
            Self::Pushed(pushed) => {
                pushed.acknowledge(item);
                Ok(())
            }
        }
    }

    /// Posts the message of `item` back to the address, for another install.
    pub(super) async fn requeue(&self, item: &Item) -> Result<(), Failure> {
        match self {
            Self::Socket(subscription) => subscription
                .requeue(item.ack_token())
                .await
                .map_err(Into::into),
            Self::Pushed(pushed) => pushed.requeue(item).await,
        }
    }

    /// `item` stays unsettled because the run ends: a session asks the relay to hold it back.
    pub(super) fn keep(&self, item: &Item) {
        if let Self::Pushed(pushed) = self {
            pushed.keep(item);
        }
    }
}

/// The payments mailbox of a shared mux/1 session, read from the mail the session queued.
pub(in crate::epicbox) struct Pushed {
    session: Arc<MuxSession>,
    /// The index the session gave the payments claim.
    index: usize,
    identity: Identity,
    client: MailboxClient,
    local: Mutex<Local>,
}

#[derive(Default)]
struct Local {
    ready: VecDeque<Item>,
    rejected: VecDeque<Item>,
    /// How each taken message was signed, for [`Pushed::requeue`], until it is acknowledged.
    relayed: HashMap<AckToken, RelayedMail>,
}

impl Pushed {
    pub(super) fn new(
        session: Arc<MuxSession>,
        index: usize,
        identity: Identity,
        client: MailboxClient,
    ) -> Self {
        Self {
            session,
            index,
            identity,
            client,
            local: Mutex::new(Local::default()),
        }
    }

    fn local(&self) -> MutexGuard<'_, Local> {
        self.local.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves the mail the session queued for the mailbox into the local queues. Returns whether
    /// there is anything to deliver.
    fn fill(&self) -> bool {
        let taken = self.session.take(&[self.index]);
        let mut local = self.local();
        for message in taken {
            let (msg_id, relayed) = (message.msg_id().clone(), message.relayed().cloned());
            let token = AckToken::new(msg_id.as_str().to_owned());
            // After a reconnect the relay pushes a message again that was taken and is not
            // settled yet. The copy in hand stands; its settlement covers the new push too.
            if local.relayed.contains_key(&token) {
                continue;
            }
            if let Some(relayed) = relayed {
                local.relayed.insert(token.clone(), relayed);
            }
            match message.into_content() {
                MailboxContent::Opened(received) => {
                    let reply_to = Destination::new(received.sender.to_string());
                    let wire = WireSlate::text(
                        MediaType::JSON,
                        received.plaintext.expose_str().to_owned(),
                    );
                    local.ready.push_back(Item::Envelope(
                        Envelope::new(token, Some(reply_to), wire),
                        Some(msg_id),
                    ));
                }
                MailboxContent::Unopenable { reason, .. } => {
                    local.rejected.push_back(Item::Rejection(Rejected {
                        token,
                        msg_id: Some(msg_id),
                        reason,
                    }));
                }
                _ => {}
            }
        }
        !local.ready.is_empty() || !local.rejected.is_empty()
    }

    fn next_rejection(&self) -> Option<Item> {
        self.fill();
        self.local().rejected.pop_front()
    }

    fn next_envelope(&self) -> Option<Item> {
        self.fill();
        self.local().ready.pop_front()
    }

    /// Waits until mail is waiting or the session has ended.
    async fn delivery_available(&self) {
        let mut queued = self.session.queued();
        let mut state = self.session.state();
        loop {
            if self.fill() || state.borrow_and_update().has_ended() {
                return;
            }
            tokio::select! {
                changed = queued.changed() => if changed.is_err() { return },
                changed = state.changed() => if changed.is_err() { return },
            }
        }
    }

    fn acknowledge(&self, item: &Item) {
        self.local().relayed.remove(item.ack_token());
        if let Some(msg_id) = item.relay_message_id() {
            // A session that ended has nothing to tell the relay: it offers the message again.
            let _: Result<(), MuxError> =
                self.session.settle(msg_id, lepic_epicbox::Handled::Stored);
        }
    }

    async fn requeue(&self, item: &Item) -> Result<(), Failure> {
        let mail = self.local().relayed.get(item.ack_token()).cloned();
        let Some(mail) = mail else {
            return Err(Box::new(ClientError::NotHandedOut));
        };
        self.client
            .repost(&self.identity, &mail)
            .await
            .map_err(Into::into)
    }

    /// Hands `item` back to the session: the relay offers it again after the hold, as a new
    /// message to take.
    fn keep(&self, item: &Item) {
        self.local().relayed.remove(item.ack_token());
        if let Some(msg_id) = item.relay_message_id() {
            let _: Result<(), MuxError> =
                self.session.settle(msg_id, lepic_epicbox::Handled::Later);
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use std::time::Duration;

    use lepic_crypto::{PublicKey, SecretKey};
    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::{
        Domain, EpicboxAddress, MuxOptions, MuxState, Network, Nonce, RelayEndpoint, Salt,
        Security, SignedMessage,
    };

    use super::*;

    fn identity(byte: u8) -> Identity {
        let secret = SecretKey::from_array([byte; 32]).unwrap();
        let address = EpicboxAddress::new(
            PublicKey::from_secret_key(&secret).unwrap(),
            Network::Mainnet,
            Domain::parse("relay.test").unwrap(),
            Some(443),
        );
        Identity::new(secret, address).unwrap()
    }

    async fn until(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("timed out");
    }

    #[tokio::test]
    async fn a_message_pushed_again_while_still_in_hand_is_not_queued_twice() {
        let settings = lepic_epicbox::testing::client_settings(RelayEndpoint::new(
            Domain::parse("relay.test").unwrap(),
            None,
            Security::Plain,
        ));
        let relay = MuxMockRelay::new(Network::Mainnet);
        let receiver = identity(1);
        let sender = identity(2);
        let sender_secret = SecretKey::from_array([2; 32]).unwrap();
        let session = Arc::new(
            MuxSession::start_queued(
                settings.clone(),
                relay.connector(),
                vec![receiver.clone()],
                MuxOptions::default(),
            )
            .unwrap(),
        );
        let pushed = Pushed::new(
            Arc::clone(&session),
            0,
            receiver.clone(),
            MailboxClient::new(settings, relay.connector()),
        );
        until(|| *session.state().borrow() == MuxState::Attached).await;
        let message = SignedMessage::seal(
            "{}",
            receiver.address(),
            &sender_secret,
            Salt::from([4; 8]),
            Nonce::from([5; 12]),
        )
        .unwrap();
        let id = relay.store(sender.address(), receiver.address(), &message);
        until(|| session.counters().mails == 1).await;
        assert!(pushed.fill());
        assert_eq!(pushed.local().ready.len(), 1);

        // The socket drops with the message taken and not settled: the relay pushes it again.
        relay.drop_sockets();
        until(|| session.counters().mails == 2).await;
        pushed.fill();
        assert_eq!(pushed.local().ready.len(), 1, "queued once");

        // Settling the copy in hand acknowledges the message on the new socket.
        let item = pushed.next_envelope().unwrap();
        pushed.acknowledge(&item);
        relay.wait_until(|relay| relay.is_acked(&id)).await;
        assert!(pushed.next_envelope().is_none());
    }
}
