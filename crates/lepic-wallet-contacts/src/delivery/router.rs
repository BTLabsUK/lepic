// SPDX-License-Identifier: Apache-2.0
//! The router: hands the mail the carrier's sessions queued to the handler of its class.
//!
//! Mail goes to its handler in the order the relay pushed it, one message at a time. A message
//! is acknowledged only after its handler stored it; any other end, a hold, a missing handler, a
//! panic or a cancel, leaves it on the relay, which offers it again.
//!
//! A relay cancellation pushed for one of these mailboxes is acknowledged and dropped: nothing
//! in them applies one, and the relay pushes an unacknowledged cancellation again on every
//! attach or resume.

use std::collections::{HashMap, VecDeque};
use std::sync::PoisonError;

use lepic_epicbox::sessions::Owner;
use lepic_epicbox::{Handled, MailboxMessage, MuxEvent, MuxSession, RelayMessageId};
use lepic_primitives::error_chain::ErrorChain;
use lepic_store::MailClass;
use lepic_transport::transport::BoxFuture;
use thiserror::Error;
use tokio::sync::broadcast::error::TryRecvError;
use tracing::debug;

use super::carrier::{Carrier, Part};

/// A message the relay pushed, with the watched mailbox it came to.
pub(crate) struct Pushed {
    pub(crate) mail: MailboxMessage,
    pub(crate) key_ref: String,
    /// The relay as the watch row wrote it.
    pub(crate) relay: String,
    pub(crate) class: MailClass,
}

/// The handler stored the message: the relay may drop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stored;

/// The handler did not store the message: the relay keeps it and offers it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hold;

/// What becomes of the pushed mail of one class.
pub(crate) trait Handler: Send {
    fn handle(&mut self, mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>>;
}

/// Lends a handler to a router, so its owner reads what it gathered once the router is gone.
impl<H: Handler + ?Sized> Handler for &mut H {
    fn handle(&mut self, mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
        (**self).handle(mail)
    }
}

/// Why a handler was not registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum RouterError {
    #[error("a handler for this class of mail is already registered")]
    TakenClass(MailClass),
}

/// The handlers of pushed mail, one per class.
#[derive(Default)]
pub(crate) struct Router<'h> {
    handlers: Vec<Box<dyn Handler + 'h>>,
    /// The index in `handlers` of each class's handler.
    by_class: HashMap<MailClass, usize>,
}

impl<'h> Router<'h> {
    /// Sends the mail of `class` to `handler`. A class has one handler.
    pub(crate) fn register(
        &mut self,
        class: MailClass,
        handler: impl Handler + 'h,
    ) -> Result<(), RouterError> {
        self.register_for(&[class], handler)
    }

    /// Sends the mail of each of `classes` to the one `handler`. A class has one handler; when
    /// one of `classes` has one already, none is registered.
    pub(crate) fn register_for(
        &mut self,
        classes: &[MailClass],
        handler: impl Handler + 'h,
    ) -> Result<(), RouterError> {
        if let Some(class) = classes
            .iter()
            .find(|class| self.by_class.contains_key(class))
        {
            return Err(RouterError::TakenClass(*class));
        }
        let at = self.handlers.len();
        self.handlers.push(Box::new(handler));
        for class in classes {
            self.by_class.insert(*class, at);
        }
        Ok(())
    }

    /// Hands the mail queued on the carrier's sessions now to the handlers, and returns how many
    /// messages there were. For a host that reads once per trigger.
    pub(crate) async fn handle_queued(&mut self, carrier: &Carrier) -> usize {
        let mut count = 0usize;
        for part in carrier.parts() {
            count = count.saturating_add(self.handle_part(&part).await);
        }
        count
    }

    /// Takes the queued mail of `part`'s mailboxes and hands it out, oldest first.
    async fn handle_part(&mut self, part: &Part) -> usize {
        ack_cancelled(part);
        let indexes: Vec<usize> = part.mailboxes.keys().copied().collect();
        let mut taken = Taken {
            session: &part.session,
            host: &part.host,
            mail: part.session.take(&indexes).into(),
            current: None,
        };
        let count = taken.mail.len();
        while let Some(mail) = taken.mail.pop_front() {
            let id = mail.msg_id().clone();
            taken.current = Some(id.clone());
            let handled = match part.mailboxes.get(&mail.mailbox()) {
                None => Handled::Later,
                Some(watched) => match self
                    .by_class
                    .get(&watched.row.class)
                    .and_then(|at| self.handlers.get_mut(*at))
                {
                    None => {
                        debug!(peer_relay = %part.host, "pushed mail held: no handler for its class");
                        Handled::Later
                    }
                    Some(handler) => {
                        let pushed = Pushed {
                            mail,
                            key_ref: watched.row.key_ref.clone(),
                            relay: watched.row.relay.clone(),
                            class: watched.row.class,
                        };
                        match handler.handle(pushed).await {
                            Ok(Stored) => Handled::Stored,
                            Err(Hold) => Handled::Later,
                        }
                    }
                },
            };
            taken.current = None;
            taken.settle(&id, handled);
        }
        count
    }
}

/// Acknowledges the relay cancellations pushed since the last call for `part`'s own mailboxes,
/// and drops them. A mailbox the payments inbox claims too is left alone: that inbox applies a
/// cancellation before it acknowledges it.
fn ack_cancelled(part: &Part) {
    let payments = part.session.claimed_keys(Owner::Payments.as_str());
    let mut events = part.events.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        match events.try_recv() {
            Ok(MuxEvent::Cancelled { mailbox, txid }) => {
                let Some(watched) = part.mailboxes.get(&mailbox) else {
                    continue;
                };
                if payments.contains(&watched.identity.address().key_text()) {
                    continue;
                }
                debug!(peer_relay = %part.host, mailbox, kind = ?watched.row.class, "relay cancellation acknowledged");
                if let Err(error) = part.session.ack_cancelled(mailbox, &txid) {
                    debug!(peer_relay = %part.host, error = %ErrorChain(&error), "mux/1 session ended before a cancellation was acknowledged");
                }
            }
            // A lost cancellation comes again on the next attach or resume.
            Ok(_) | Err(TryRecvError::Lagged(_)) => {}
            Err(TryRecvError::Empty | TryRecvError::Closed) => break,
        }
    }
}

/// Mail taken from a session and not yet settled. Dropped early, by a panic or a cancel, it asks
/// the relay to hold what is left, so none of it is acknowledged.
struct Taken<'a> {
    session: &'a MuxSession,
    host: &'a str,
    mail: VecDeque<MailboxMessage>,
    /// The message a handler has now.
    current: Option<RelayMessageId>,
}

impl Taken<'_> {
    fn settle(&self, id: &RelayMessageId, handled: Handled) {
        if let Err(error) = self.session.settle(id, handled) {
            debug!(peer_relay = %self.host, error = %ErrorChain(&error), "mux/1 session ended before a message was settled");
        }
    }
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.current.take() {
            self.settle(&id, Handled::Later);
        }
        for mail in std::mem::take(&mut self.mail) {
            self.settle(mail.msg_id(), Handled::Later);
        }
    }
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
    use std::sync::Mutex;
    use std::time::Duration;

    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_epicbox::{MuxError, Network};
    use lepic_store::{MemoryStore, StoreKeys, WatchRow};
    use tokio::sync::Notify;

    use super::*;
    use crate::delivery::testing::{HOST, RELAY, Table, now, relays, row, sealed};
    use crate::delivery::testing::{address, attached, identity, until};

    /// What a handler was given: message id, key reference, relay and class.
    type Seen = (String, String, String, MailClass);

    /// Stores every message, and notes what it was given.
    struct Recorder<'a> {
        seen: &'a Mutex<Vec<Seen>>,
    }

    impl Handler for Recorder<'_> {
        fn handle(&mut self, mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
            Box::pin(async move {
                self.seen.lock().unwrap().push((
                    mail.mail.msg_id().as_str().to_owned(),
                    mail.key_ref,
                    mail.relay,
                    mail.class,
                ));
                Ok(Stored)
            })
        }
    }

    /// Stores nothing.
    struct Holder;

    impl Handler for Holder {
        fn handle(&mut self, _mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
            Box::pin(async { Err(Hold) })
        }
    }

    /// Never finishes, and says when it started.
    struct Stuck<'a> {
        started: &'a Notify,
    }

    impl Handler for Stuck<'_> {
        fn handle(&mut self, _mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
            Box::pin(async move {
                self.started.notify_one();
                std::future::pending().await
            })
        }
    }

    /// Hands out the queued mail again and again, as a host that reads on every trigger does.
    async fn keep_handling(router: &mut Router<'_>, carrier: &Carrier) {
        loop {
            router.handle_queued(carrier).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn watching(set: Vec<WatchRow>) -> (Carrier, MuxMockRelay) {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let classic = MockRelay::new(Network::Mainnet);
        let (relays, _) = relays(&relay, &classic, &[]);
        let carrier = Carrier::new(relays);
        let store = MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]));
        let table = Table::default()
            .with("k1", identity(1))
            .with("k2", identity(2));
        carrier.claim(set, &table, &store, now()).await.unwrap();
        attached(carrier.relays()).await;
        (carrier, relay)
    }

    #[tokio::test]
    async fn mail_reaches_its_class_handler_in_order_and_is_acked_once_stored() {
        let (carrier, relay) = watching(vec![
            row("k1", MailClass::Contact, None),
            row("k2", MailClass::Pairing, None),
        ])
        .await;
        let contact = Mutex::new(Vec::new());
        let pairing = Mutex::new(Vec::new());
        let mut router = Router::default();
        router
            .register(MailClass::Contact, Recorder { seen: &contact })
            .unwrap();
        router
            .register(MailClass::Pairing, Recorder { seen: &pairing })
            .unwrap();
        let first = relay.store(&address(3), &address(1), &sealed(3, 1, "one"));
        let second = relay.store(&address(3), &address(1), &sealed(3, 1, "two"));
        let third = relay.store(&address(3), &address(2), &sealed(3, 2, "three"));

        tokio::select! {
            () = keep_handling(&mut router, &carrier) => panic!("the router stopped"),
            () = relay.wait_until(|relay| {
                [&first, &second, &third].iter().all(|id| relay.is_acked(id))
            }) => {}
        }

        assert_eq!(
            *contact.lock().unwrap(),
            vec![
                (first, "k1".to_owned(), RELAY.to_owned(), MailClass::Contact),
                (
                    second,
                    "k1".to_owned(),
                    RELAY.to_owned(),
                    MailClass::Contact
                ),
            ]
        );
        assert_eq!(
            *pairing.lock().unwrap(),
            vec![(third, "k2".to_owned(), RELAY.to_owned(), MailClass::Pairing)]
        );
    }

    #[tokio::test]
    async fn held_mail_is_not_acked() {
        let (carrier, relay) = watching(vec![row("k1", MailClass::Contact, None)]).await;
        let mut router = Router::default();
        router.register(MailClass::Contact, Holder).unwrap();
        let id = relay.store(&address(3), &address(1), &sealed(3, 1, "held"));

        tokio::select! {
            () = keep_handling(&mut router, &carrier) => panic!("the router stopped"),
            () = relay.wait_until(|relay| !relay.holds(&id).is_empty()) => {}
        }

        assert!(!relay.is_acked(&id));
    }

    #[tokio::test]
    async fn mail_of_a_class_without_a_handler_is_held() {
        let (carrier, relay) = watching(vec![
            row("k1", MailClass::Contact, None),
            row("k2", MailClass::Address, None),
        ])
        .await;
        let seen = Mutex::new(Vec::new());
        let mut router = Router::default();
        router
            .register(MailClass::Contact, Recorder { seen: &seen })
            .unwrap();
        let id = relay.store(&address(3), &address(2), &sealed(3, 2, "no handler"));

        tokio::select! {
            () = keep_handling(&mut router, &carrier) => panic!("the router stopped"),
            () = relay.wait_until(|relay| !relay.holds(&id).is_empty()) => {}
        }

        assert!(!relay.is_acked(&id));
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_handler_leaves_its_mail_unacked() {
        let (carrier, relay) = watching(vec![row("k1", MailClass::Contact, None)]).await;
        let started = Notify::new();
        let mut router = Router::default();
        router
            .register(MailClass::Contact, Stuck { started: &started })
            .unwrap();
        let id = relay.store(&address(3), &address(1), &sealed(3, 1, "cut"));

        tokio::select! {
            () = keep_handling(&mut router, &carrier) => panic!("the router stopped"),
            () = started.notified() => {}
        }
        // The handling future is dropped with the handler still on the message.

        relay.wait_until(|relay| !relay.holds(&id).is_empty()).await;
        assert!(!relay.is_acked(&id));
    }

    /// Panics on every message.
    struct Panicker;

    impl Handler for Panicker {
        fn handle(&mut self, _mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
            Box::pin(async { panic!("the handler failed") })
        }
    }

    #[tokio::test]
    async fn a_panicking_handler_leaves_its_mail_unacked() {
        let (carrier, relay) = watching(vec![row("k1", MailClass::Contact, None)]).await;
        let carrier = std::sync::Arc::new(carrier);
        let id = relay.store(&address(3), &address(1), &sealed(3, 1, "panic"));

        let held = carrier.clone();
        let run = tokio::spawn(async move {
            let mut router = Router::default();
            router.register(MailClass::Contact, Panicker).unwrap();
            keep_handling(&mut router, &held).await;
        });

        assert!(run.await.unwrap_err().is_panic());
        relay.wait_until(|relay| !relay.holds(&id).is_empty()).await;
        assert!(!relay.is_acked(&id));
    }

    #[tokio::test]
    async fn mail_stored_while_the_sockets_were_down_reaches_its_handler() {
        let (carrier, relay) = watching(vec![row("k1", MailClass::Contact, None)]).await;
        let seen = Mutex::new(Vec::new());
        let mut router = Router::default();
        router
            .register(MailClass::Contact, Recorder { seen: &seen })
            .unwrap();
        let made = relay.sockets_made();

        tokio::select! {
            () = keep_handling(&mut router, &carrier) => panic!("the router stopped"),
            id = async {
                relay.drop_sockets();
                let id = relay.store(&address(3), &address(1), &sealed(3, 1, "while down"));
                relay.wait_until(|relay| relay.is_acked(&id)).await;
                id
            } => {
                assert_eq!(seen.lock().unwrap()[0].0, id);
            }
        }

        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(relay.sockets_made() > made);
    }

    #[tokio::test]
    async fn a_single_pass_hands_out_what_is_queued() {
        let (carrier, relay) = watching(vec![row("k1", MailClass::Contact, None)]).await;
        let seen = Mutex::new(Vec::new());
        let mut router = Router::default();
        router
            .register(MailClass::Contact, Recorder { seen: &seen })
            .unwrap();
        let id = relay.store(&address(3), &address(1), &sealed(3, 1, "once"));
        let session = carrier.parts()[0].session.clone();
        until(|| session.counters().mails == 1).await;

        assert_eq!(router.handle_queued(&carrier).await, 1);

        relay.wait_until(|relay| relay.is_acked(&id)).await;
        assert_eq!(router.handle_queued(&carrier).await, 0);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_class_takes_one_handler() {
        let mut router = Router::default();
        router.register(MailClass::Reply, Holder).unwrap();
        assert_eq!(
            router.register(MailClass::Reply, Holder),
            Err(RouterError::TakenClass(MailClass::Reply))
        );
        router.register(MailClass::InPerson, Holder).unwrap();
        assert_eq!(
            router.register_for(&[MailClass::Contact, MailClass::InPerson], Holder),
            Err(RouterError::TakenClass(MailClass::InPerson))
        );
        router.register(MailClass::Contact, Holder).unwrap();
    }

    #[tokio::test]
    async fn one_handler_takes_the_mail_of_several_classes() {
        let (carrier, relay) = watching(vec![
            row("k1", MailClass::Contact, None),
            row("k2", MailClass::Pairing, None),
        ])
        .await;
        let seen = Mutex::new(Vec::new());
        let mut recorder = Recorder { seen: &seen };
        let mut router = Router::default();
        router
            .register_for(&[MailClass::Contact, MailClass::Pairing], &mut recorder)
            .unwrap();
        let first = relay.store(&address(3), &address(1), &sealed(3, 1, "contact"));
        let second = relay.store(&address(3), &address(2), &sealed(3, 2, "pairing"));

        tokio::select! {
            () = keep_handling(&mut router, &carrier) => panic!("the router stopped"),
            () = relay.wait_until(|relay| relay.is_acked(&first) && relay.is_acked(&second)) => {}
        }

        drop(router);
        let mut keys: Vec<String> = recorder
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|seen| seen.1.clone())
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["k1".to_owned(), "k2".to_owned()]);
    }

    #[tokio::test]
    async fn a_cancellation_is_acked_in_a_delivery_mailbox_and_left_in_the_payments_one() {
        let (carrier, relay) = watching(vec![
            row("k1", MailClass::Reply, None),
            row("k2", MailClass::Address, None),
        ])
        .await;
        // The payments inbox shares the socket, with its own mailbox and one the contacts read
        // too.
        let payments = carrier
            .relays()
            .epicbox
            .pushed()
            .get_or_start(HOST, "wallet", Owner::Payments, || Err(MuxError::NoRuntime))
            .unwrap();
        payments
            .set_claim(Owner::Payments.as_str(), vec![identity(9), identity(2)])
            .await
            .unwrap();
        let mut router = Router::default();
        let [classic, shared, delivery] = [
            "0a0a0a0a0a0a4a0a8a0a0a0a0a0a0a0a",
            "0b0b0b0b0b0b4b0b8b0b0b0b0b0b0b0b",
            "0c0c0c0c0c0c4c0c8c0c0c0c0c0c0c0c",
        ];
        for (to, txid) in [(9, classic), (2, shared), (1, delivery)] {
            relay.store_with_txid(&address(3), &address(to), &sealed(3, to, "slate"), txid);
            assert!(relay.cancel_as(&address(3), txid));
        }

        tokio::select! {
            () = keep_handling(&mut router, &carrier) => panic!("the router stopped"),
            () = relay.wait_until(|relay| relay.unacked_cancels(&address(1)) == 0) => {}
        }

        assert_eq!(relay.cancel_pushes(classic), 1);
        assert_eq!(relay.cancel_pushes(shared), 1);
        assert_eq!(relay.unacked_cancels(&address(9)), 1);
        assert_eq!(relay.unacked_cancels(&address(2)), 1);
    }
}
